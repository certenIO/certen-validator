// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// REFACTORING SUMMARY:
// - Updated AccountHandler to use DataBackend interface (specialized for data retrieval)
// - Removed dependency on monolithic Backend interface
// - AccountHandler now focuses solely on account data operations
// - Improved separation of concerns: data retrieval vs proof generation
// - Enhanced testability through focused DataBackend interface

package types

import (
	"context"
	"fmt"
	"net/url"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// AccountHandler is responsible for retrieving and processing account data.
// It handles account type detection, data retrieval, type-specific processing, and URL validation.
//
// REFACTORED ARCHITECTURE:
// AccountHandler now uses DataBackend (specialized for data operations) instead of
// the monolithic Backend interface. This provides clear separation of concerns.
type AccountHandler struct {
	dataBackend  DataBackend
	accountCache AccountCache
}

// NewAccountHandler creates a new account handler with the given data backend.
// Creates its own cache - use this for standalone handlers.
func NewAccountHandler(dataBackend DataBackend, cache AccountCache) *AccountHandler {
	return &AccountHandler{
		dataBackend:  dataBackend,
		accountCache: cache,
	}
}

// NewAccountHandlerWithCache creates a new account handler with an external cache.
// Use this when you want to share caches across multiple handlers.
func NewAccountHandlerWithCache(dataBackend DataBackend, cache AccountCache) *AccountHandler {
	return &AccountHandler{
		dataBackend:  dataBackend,
		accountCache: cache,
	}
}

// GetAccountData retrieves account data for the specified account URL.
// It checks the cache first and falls back to network queries if needed.
func (ah *AccountHandler) GetAccountData(ctx context.Context, accountURL string) (*AccountData, error) {
	// Validate account URL

	if err := ah.validateAccountURL(accountURL); err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	// Check cache first
	if cachedData, found := ah.accountCache.GetAccountData(accountURL); found {
		// Mark as coming from cache
		cachedData.FromCache = true
		return cachedData, nil
	}

	accountData, err := ah.dataBackend.QueryAccount(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query account: %w", err)
	}

	result := &AccountData{
		URL:          accountData.URL,
		Type:         accountData.Type,
		Data:         accountData.Data,
		LastUpdated:  accountData.LastUpdated,
		FromCache:    false, // This data came from backend, not cache
		RawResponse:  accountData.RawResponse,
		Receipt:      accountData.Receipt,
		Height:       accountData.Height,
		Transactions: accountData.Transactions,
	}

	// Store in cache
	ah.accountCache.StoreAccountData(accountURL, result)

	fmt.Printf("\naccount.go - data stored in cache for url %+v\n", accountURL)

	return result, nil
}

// GetTokenBalance retrieves the balance for a token account.
func (ah *AccountHandler) GetTokenBalance(ctx context.Context, accountURL string) (*TokenBalanceInfo, error) {
	// Check cache first
	if cached, found := ah.accountCache.GetBalance(accountURL); found {
		return cached, nil
	}

	accountData, err := ah.GetAccountData(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get account data: %w", err)
	}

	if !accountData.IsTokenAccount() {
		return nil, fmt.Errorf("account %s is not a token account", accountURL)
	}

	var balanceInfo *TokenBalanceInfo

	switch accountData.Type {
	case protocol.AccountTypeLiteTokenAccount:
		liteToken, err := accountData.AsLiteTokenAccount()
		if err != nil {
			return nil, err
		}
		balanceInfo = &TokenBalanceInfo{
			AccountURL:  accountURL,
			AccountType: "lite_token",
			Balance:     liteToken.Balance.String(),
			TokenURL:    liteToken.TokenUrl.String(),
		}

	case protocol.AccountTypeTokenAccount:
		token, err := accountData.AsTokenAccount()
		if err != nil {
			return nil, err
		}
		balanceInfo = &TokenBalanceInfo{
			AccountURL:  accountURL,
			AccountType: "token",
			Balance:     token.Balance.String(),
			TokenURL:    token.TokenUrl.String(),
		}

	default:
		return nil, fmt.Errorf("unsupported token account type: %s", accountData.Type)
	}

	// Store in cache
	ah.accountCache.StoreBalance(accountURL, balanceInfo)
	return balanceInfo, nil
}

// GetIdentityInfo retrieves identity information for an ADI.
func (ah *AccountHandler) GetIdentityInfo(ctx context.Context, accountURL string) (*IdentityInfo, error) {
	// Check cache first
	if cached, found := ah.accountCache.GetIdentityInfo(accountURL); found {
		return cached, nil
	}

	accountData, err := ah.GetAccountData(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get account data: %w", err)
	}

	if !accountData.IsIdentityAccount() {
		return nil, fmt.Errorf("account %s is not an identity account", accountURL)
	}

	adi, err := accountData.AsADI()
	if err != nil {
		return nil, err
	}

	identityInfo := &IdentityInfo{
		AccountURL:  accountURL,
		IdentityURL: adi.Url.String(),
		KeyBook:     adi.KeyBook().String(),
	}

	// Store in cache
	ah.accountCache.StoreIdentityInfo(accountURL, identityInfo)
	return identityInfo, nil
}

// ProcessADIAccounts processes all accounts associated with an ADI.
// This method combines discovery and processing in a single operation.
func (ah *AccountHandler) ProcessADIAccounts(ctx context.Context, adiURL string) ([]string, error) {
	return ah.DiscoverADIAccounts(ctx, adiURL)
}

// DiscoverADIAccounts discovers all accounts associated with an ADI.
func (ah *AccountHandler) DiscoverADIAccounts(ctx context.Context, adiURL string) ([]string, error) {
	// Validate ADI URL
	if err := ah.validateAccountURL(adiURL); err != nil {
		return nil, fmt.Errorf("invalid ADI URL: %w", err)
	}

	// Note: ADI account discovery is not cached in this implementation
	// Each account will be cached individually when retrieved

	// Get identity info to discover accounts
	identityInfo, err := ah.GetAccountData(ctx, adiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity info: %w", err)
	}

	// Start with the ADI itself
	accountURLs := []string{adiURL}

	// Add token accounts and key book using properly typed ADI struct
	adi, err := identityInfo.AsADI()
	if err != nil {
		return nil, fmt.Errorf("failed to get ADI data: %w", err)
	}

	// Add authorities (key books) from the ADI's AccountAuth
	for _, authority := range adi.AccountAuth.Authorities {
		if authority.Url != nil {
			authorityURL := authority.Url.String()
			accountURLs = append(accountURLs, authorityURL)

			// If this authority is a key book, get its key pages
			keyBookData, err := ah.GetAccountData(ctx, authorityURL)
			if err == nil && keyBookData.Type == protocol.AccountTypeKeyBook {
				keyBook, ok := keyBookData.Data.(*protocol.KeyBook)
				if ok && keyBook != nil {
					// Key books don't directly contain page URLs in the struct
					// They are discovered by querying the key book's directory
					// Construct key page URLs using proper URL parsing based on PageCount
					baseURL, err := url.Parse(authorityURL)
					if err != nil {
						continue // Skip malformed authority URLs
					}
					for i := uint64(1); i <= keyBook.PageCount; i++ {
						keyPageURL := baseURL.JoinPath(fmt.Sprintf("%d", i)).String()
						accountURLs = append(accountURLs, keyPageURL)
					}
				}
			}
		}
	}

	return accountURLs, nil
}

// ============================================================================
// CACHE MANAGEMENT METHODS
// ============================================================================

// RemoveAccount removes cached data for a specific account.
// This provides the AccountHandler layer's interface for cache management.
func (ah *AccountHandler) RemoveAccount(accountURL string) {
	ah.accountCache.RemoveAccount(accountURL)
}

// RemoveADIAndAccounts removes all cached data for an ADI and its associated accounts.
// This method handles the logic of discovering and removing all related accounts.
func (ah *AccountHandler) RemoveADIAndAccounts(ctx context.Context, adiURL string) error {
	// Try to discover all accounts under this ADI if it's cached
	if _, found := ah.accountCache.GetAccountData(adiURL); found {
		accountURLs, err := ah.DiscoverADIAccounts(ctx, adiURL)
		if err == nil {
			// Remove each account from cache
			for _, accountURL := range accountURLs {
				ah.accountCache.RemoveAccount(accountURL)
			}
		}
	}

	// Remove the ADI itself
	ah.accountCache.RemoveAccount(adiURL)
	return nil
}

// PruneExpired removes all expired entries from the cache.
func (ah *AccountHandler) PruneExpired() {
	ah.accountCache.PruneExpired()
}

// ClearCache removes all cached data.
func (ah *AccountHandler) ClearCache() {
	ah.accountCache.Clear()
}

// GetCachedURLs returns all account URLs currently in the cache.
func (ah *AccountHandler) GetCachedURLs() []string {
	return ah.accountCache.GetCachedURLs()
}

// ============================================================================
// VALIDATION HELPERS (Internal)
// ============================================================================

// validateAccountURL validates account URL format using standard URL parsing
func (ah *AccountHandler) validateAccountURL(accountURL string) error {
	if accountURL == "" {
		return fmt.Errorf("empty account url")
	}

	// Use standard URL package for basic validation
	_, err := url.Parse(accountURL)
	if err != nil {
		return fmt.Errorf("invalid account url format: %w", err)
	}

	return nil
}
