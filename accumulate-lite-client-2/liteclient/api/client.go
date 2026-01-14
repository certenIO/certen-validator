// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/core"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// Client is the simplified public interface for the Accumulate Lite Client.
// Users specify an account URL and get all data - proofs, caching, and validation are handled automatically.
type Client struct {
	config *Config
	core   *core.LiteClient
}

// NewClient creates a new lite client with the provided configuration.
// If config is nil, DefaultConfig() will be used.
func NewClient(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create internal lite client with the unified architecture
	core, err := core.NewLiteClient(config.Network.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create lite client: %w", err)
	}

	return &Client{
		config: config,
		core:   core,
	}, nil
}

// PruneADI removes all cached data for a specific ADI and all its associated accounts.
// This function will:
// 1. If the URL is an ADI, remove the ADI itself and all accounts under it
// 2. If the URL is an individual account, remove just that account
// Returns an error if the URL is invalid or empty.
func (c *Client) PruneADI(adiURL string) error {
	if adiURL == "" {
		return fmt.Errorf("ADI URL cannot be empty")
	}

	// Check if this is an ADI identity
	if isADIIdentity(adiURL) {
		// For ADI identities, get all account URLs and prune each one
		ctx := context.Background()
		accountURLs, err := c.core.ProcessADIAccounts(ctx, adiURL)
		if err != nil {
			return fmt.Errorf("failed to get ADI accounts for pruning: %w", err)
		}

		// Prune each account individually
		for _, accountURL := range accountURLs {
			c.core.PruneAccount(accountURL)
		}
		return nil
	} else {
		// For individual accounts, delegate to LiteClient
		c.core.PruneAccount(adiURL)
		return nil
	}
}

// PruneAccount removes cached data for a specific account.
// This provides fine-grained control over cache management.
// Returns an error if the account URL is invalid or empty.
func (c *Client) PruneAccount(accountURL string) error {
	if accountURL == "" {
		return fmt.Errorf("account URL cannot be empty")
	}

	// Delegate to LiteClient layer
	c.core.PruneAccount(accountURL)
	return nil
}

// ClearCache removes all cached data.
// Use with caution as this will force all subsequent requests to fetch fresh data.
func (c *Client) ClearCache() {
	// Delegate to LiteClient layer
	c.core.ClearCache()
}

// GetCachedAccountURLs returns a list of all account URLs currently in the cache.
// This provides visibility into what data is currently cached.
func (c *Client) GetCachedAccountURLs() []string {
	// Delegate to LiteClient layer
	return c.core.GetCachedAccountURLs()
}

// GetAccount is the main entry point that retrieves information about any Accumulate account
// It intelligently detects whether the input is an ADI identity or individual account and processes accordingly
// Automatically handles cache freshness verification and canonical receipt construction/verification
func (c *Client) GetAccount(ctx context.Context, accountURL string) (*APIResponse, error) {
	if accountURL == "" {
		return nil, fmt.Errorf("account URL cannot be empty")
	}

	// Create base response
	response := &APIResponse{
		RequestURL: accountURL,
		Timestamp:  time.Now(),
	}

	// Step 1: Detect if the input is an ADI or individual account
	if isADIIdentity(accountURL) {
		// Handle ADI request
		response.ResponseType = "adi"

		// Step 2: If it's an ADI, extract all account URLs
		accountURLs, err := c.core.ProcessADIAccounts(ctx, accountURL)
		if err != nil {
			return nil, fmt.Errorf("failed to process ADI accounts: %w", err)
		}

		// Step 3: Process each account URL individually
		if len(accountURLs) == 0 {
			return nil, fmt.Errorf("no accounts found for ADI: %s", accountURL)
		}

		var accounts []*AccountInfo
		for _, url := range accountURLs {
			accountData, err := c.core.ProcessIndividualAccount(ctx, url)
			if err != nil {
				// Check if this is a trust path failure (critical security issue)
				if strings.Contains(err.Error(), "TRUST PATH FAILURE") || strings.Contains(err.Error(), "PROOF VALIDATION FAILURE") {
					fmt.Printf("SECURITY WARNING: Trust path validation failed for account %s: %v\n", url, err)
					// For ADI processing, we continue but log the security issue
					continue
				}
				fmt.Printf("Warning: failed to process account %s: %v\n", url, err)
				continue
			}

			account := c.convertAccountDataToAccountInfo(accountData)
			accounts = append(accounts, account)
		}

		if len(accounts) == 0 {
			return nil, fmt.Errorf("failed to process any accounts for ADI: %s", accountURL)
		}

		// Create ADI info
		adiInfo := &ADIInfo{
			URL:         accountURL,
			Name:        extractADIName(accountURL),
			Accounts:    accounts,
			AccountURLs: accountURLs,
			LastUpdated: time.Now(),
		}

		response.ADI = adiInfo
		return response, nil
	}

	// Step 4: Handle individual account request
	response.ResponseType = "account"

	accountData, err := c.core.ProcessIndividualAccount(ctx, accountURL)
	if err != nil {
		return nil, fmt.Errorf("failed to process individual account: %w", err)
	}

	account := c.convertAccountDataToAccountInfo(accountData)
	response.Account = account
	return response, nil
}

// convertAccountDataToAccountInfo converts AccountData to comprehensive AccountInfo format
func (c *Client) convertAccountDataToAccountInfo(accountData *types.AccountData) *AccountInfo {
	// Convert transactions to APITransaction format
	transactions := make([]*APITransaction, 0, len(accountData.Transactions))
	for _, tx := range accountData.Transactions {
		transactions = append(transactions, &APITransaction{
			TxID:        tx.TxID,
			Type:        tx.Type,
			Status:      tx.Status,
			Timestamp:   time.Unix(tx.Timestamp, 0),
			BlockHeight: tx.Height,
			From:        tx.From,
			To:          tx.To,
			Amount:      tx.Amount,
			Data:        tx.Data,
		})
	}

	// Create base account info
	accountInfo := &AccountInfo{
		URL:          accountData.URL,
		Type:         accountData.Type.String(),
		TypeName:     c.computeTypeName(accountData.Type),
		Category:     c.determineAccountCategory(accountData),
		LastUpdated:  accountData.LastUpdated,
		Transactions: transactions,
		BlockHeight:  accountData.Height,
		RawResponse:  accountData.RawResponse,
	}

	// Add receipt info if available
	if accountData.Receipt != nil {
		accountInfo.Receipt = &ReceiptInfo{
			Exists:      true,
			Valid:       true,
			BlockHeight: accountData.Height,
			VerifiedAt:  time.Now(),
			RawReceipt:  accountData.Receipt,
		}
	}

	// Populate type-specific data based on account type
	c.populateTypeSpecificData(accountInfo, accountData)

	return accountInfo
}

func isADIIdentity(url string) bool {
	// ADI URLs have format: acc://identity.acme (no path after the domain)
	// Account URLs have format: acc://identity.acme/account-name

	// Remove the acc:// prefix
	if !strings.HasPrefix(url, "acc://") {
		return false
	}
	path := strings.TrimPrefix(url, "acc://")

	// If there's no slash after the domain, it's an ADI
	// If there's a slash, it's an account under that ADI
	return !strings.Contains(path, "/")
}
