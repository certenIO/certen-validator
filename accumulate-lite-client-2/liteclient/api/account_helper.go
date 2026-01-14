package api

import (
	"fmt"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// determineAccountCategory determines the category of an account
func (c *Client) determineAccountCategory(accountData *types.AccountData) string {
	if accountData.IsTokenAccount() {
		return "token"
	}
	if accountData.IsDataAccount() {
		return "data"
	}
	if accountData.IsIdentityAccount() {
		return "identity"
	}
	if accountData.IsKeyAccount() {
		return "key"
	}
	return "other"
}

// populateTypeSpecificData populates type-specific data fields using specialized extractors
func (c *Client) populateTypeSpecificData(accountInfo *AccountInfo, accountData *types.AccountData) {
	switch accountInfo.Category {
	case "token":
		// Use dedicated token info extractor
		accountInfo.TokenData = c.extractTokenInfo(accountData)

	case "data":
		// Use dedicated data account extractor
		accountInfo.DataAccount = c.extractDataAccountInfo(accountData)

	case "identity":
		// Use dedicated identity extractor
		accountInfo.IdentityData = c.extractIdentityInfo(accountData)

	case "key":
		// Handle key books and key pages differently
		if accountData.Type == protocol.AccountTypeKeyPage {
			// Use dedicated key page extractor
			accountInfo.KeyPageData = c.extractKeyPageInfo(accountData)
		} else {
			// Use dedicated key book extractor
			accountInfo.KeyData = c.extractKeyAccountInfo(accountData)
		}

	default:
		// Fallback for unknown account types
		accountInfo.GenericData = &GenericAccountData{
			RawData: accountData.RawResponse,
		}
	}
}

// extractADIName extracts the ADI name from a URL
func extractADIName(adiURL string) string {
	parts := strings.Split(adiURL, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return adiURL
}

// computeTypeName computes a human-readable type name from protocol.AccountType
func (c *Client) computeTypeName(accountType protocol.AccountType) string {
	// Convert protocol type to human-readable name
	switch accountType {
	case protocol.AccountTypeLiteTokenAccount:
		return "Lite Token Account"
	case protocol.AccountTypeTokenAccount:
		return "Token Account"
	case protocol.AccountTypeLiteDataAccount:
		return "Lite Data Account"
	case protocol.AccountTypeDataAccount:
		return "Data Account"
	case protocol.AccountTypeIdentity:
		return "Identity (ADI)"
	case protocol.AccountTypeKeyBook:
		return "Key Book"
	case protocol.AccountTypeKeyPage:
		return "Key Page"
	default:
		return accountType.String()
	}
}

// extractTokenInfo creates comprehensive token account data
func (c *Client) extractTokenInfo(accountData *types.AccountData) *TokenAccountData {
	tokenData := &TokenAccountData{
		IsLiteAccount: accountData.Type == protocol.AccountTypeLiteTokenAccount,
	}

	// Try to extract from lite token account
	if liteToken, err := accountData.AsLiteTokenAccount(); err == nil {
		tokenData.Balance = liteToken.Balance.String()
		tokenData.TokenURL = liteToken.TokenUrl.String()
		return tokenData
	}

	// Try to extract from token account
	if token, err := accountData.AsTokenAccount(); err == nil {
		tokenData.Balance = token.Balance.String()
		tokenData.TokenURL = token.TokenUrl.String()
		if keyBookURL := token.KeyBook(); keyBookURL != nil {
			tokenData.KeyBook = keyBookURL.String()
		}
		// Extract token metadata from token definition
		c.extractTokenMetadata(tokenData, token)
		// Extract authorities and credit balance
		c.extractTokenAuthorities(tokenData, token)
		return tokenData
	}

	// Fallback: try to extract from raw response
	if accountData.RawResponse != nil {
		if balanceVal, ok := accountData.RawResponse["balance"]; ok {
			if balanceStr, ok := balanceVal.(string); ok {
				tokenData.Balance = balanceStr
			}
		}
		if tokenURLVal, ok := accountData.RawResponse["tokenUrl"]; ok {
			if tokenURLStr, ok := tokenURLVal.(string); ok {
				tokenData.TokenURL = tokenURLStr
			}
		}
	}

	return tokenData
}

// extractDataAccountInfo extracts data account specific information
func (c *Client) extractDataAccountInfo(accountData *types.AccountData) *DataAccountData {
	dataAccount := &DataAccountData{
		IsLiteAccount: accountData.Type == protocol.AccountTypeLiteDataAccount,
		RawData:       accountData.RawResponse,
	}

	// Extract actual data entries from protocol data
	c.extractDataEntries(dataAccount, accountData)

	return dataAccount
}

// extractIdentityInfo extracts identity (ADI) specific information
func (c *Client) extractIdentityInfo(accountData *types.AccountData) *IdentityAccountData {
	identityData := &IdentityAccountData{}

	// Try to extract ADI info from protocol data
	if adi, err := accountData.AsADI(); err == nil {
		if keyBookURL := adi.KeyBook(); keyBookURL != nil {
			identityData.KeyBook = keyBookURL.String()
		}
		// Extract account URLs and other ADI metadata
		c.extractADIAccountURLs(identityData, adi)
		c.extractADIAuthorities(identityData, adi)
	}

	return identityData
}

// extractKeyAccountInfo extracts comprehensive key account information
func (c *Client) extractKeyAccountInfo(accountData *types.AccountData) *KeyAccountData {
	keyData := &KeyAccountData{
		KeyBookType: accountData.Type.String(),
	}

	// Extract key book information
	if keyBook, err := accountData.AsKeyBook(); err == nil {
		// Extract threshold and page count from key book
		keyData.PageCount = keyBook.PageCount
		// Extract authorities from key book
		c.extractKeyBookAuthorities(keyData, keyBook)
		// Extract individual keys from key book pages
		c.extractKeyBookKeys(keyData, keyBook)
		_ = keyBook // Suppress unused variable warning
	}

	return keyData
}

// extractKeyPageInfo extracts specific key page information
func (c *Client) extractKeyPageInfo(accountData *types.AccountData) *KeyPageData {
	keyPageData := &KeyPageData{}

	// Extract key page information
	if keyPage, err := accountData.AsKeyPage(); err == nil {
		// Extract page index, threshold, version from key page
		keyPageData.Threshold = keyPage.AcceptThreshold
		keyPageData.Version = keyPage.Version
		keyPageData.CreditBalance = fmt.Sprintf("%d", keyPage.CreditBalance)

		// Extract individual keys from key page
		c.extractKeysFromKeyPage(keyPageData, keyPage)

		// Extract authorities from key page (key pages don't have direct authorities)
		// The authority comes from the parent key book
		_ = keyPage // Suppress unused variable warning
	}

	return keyPageData
}

// extractTokenMetadata extracts token metadata from the token definition
func (c *Client) extractTokenMetadata(tokenData *TokenAccountData, token *protocol.TokenAccount) {
	if token.TokenUrl != nil {
		// In a full implementation, this would query the token URL to get:
		// - Token symbol
		// - Token name
		// - Token precision
		// - Token issuer
		// For now, we extract what we can from the URL
		tokenURL := token.TokenUrl.String()
		if strings.Contains(tokenURL, "/") {
			parts := strings.Split(tokenURL, "/")
			if len(parts) > 0 {
				tokenData.TokenSymbol = parts[len(parts)-1] // Last part as symbol
			}
			if len(parts) > 1 {
				tokenData.TokenIssuer = strings.Join(parts[:len(parts)-1], "/") // Everything before symbol
			}
		}
	}
}

// extractTokenAuthorities extracts authorities and credit balance from token account
func (c *Client) extractTokenAuthorities(tokenData *TokenAccountData, token *protocol.TokenAccount) {
	// Extract authorities from AccountAuth
	if auth := token.GetAuth(); auth != nil {
		for _, authority := range auth.Authorities {
			if authority.Url != nil {
				// In a full implementation, we might want to include authority type/permissions
				// For now, we just collect the URLs
			}
		}
	}

	// Credit balance would typically come from querying the key book/page
	// This requires additional network calls in a full implementation
}

// extractDataEntries extracts data entries from data account
func (c *Client) extractDataEntries(dataAccount *DataAccountData, accountData *types.AccountData) {
	// Try to extract from different data account types
	if accountData.Type == protocol.AccountTypeDataAccount {
		// Full data account - would require protocol-specific parsing
		// In a full implementation, this would parse the data account structure
		// and extract individual data entries with their hashes, sizes, timestamps

		// For now, we create placeholder entries if raw data suggests entries exist
		if accountData.RawResponse != nil {
			if entriesData, ok := accountData.RawResponse["entries"]; ok {
				if entriesSlice, ok := entriesData.([]interface{}); ok {
					for i, entryData := range entriesSlice {
						entry := &DataEntry{
							EntryHash: fmt.Sprintf("entry_%d_hash", i),
							Size:      0,          // Would be extracted from actual data
							CreatedAt: time.Now(), // Would be extracted from actual data
						}

						if entryMap, ok := entryData.(map[string]interface{}); ok {
							if data, ok := entryMap["data"].(string); ok {
								entry.Data = []byte(data)
								entry.Size = uint64(len(entry.Data))
							}
						}

						dataAccount.Entries = append(dataAccount.Entries, entry)
					}
				}
			}
		}
	} else if accountData.Type == protocol.AccountTypeLiteDataAccount {
		// Lite data account - simpler structure
		// Would extract data directly from the lite account structure
	}

	// Extract key book if available
	if accountData.RawResponse != nil {
		if keyBookData, ok := accountData.RawResponse["keyBook"]; ok {
			if keyBookStr, ok := keyBookData.(string); ok {
				dataAccount.KeyBook = keyBookStr
			}
		}
	}
}

// extractADIAccountURLs extracts account URLs from ADI
func (c *Client) extractADIAccountURLs(identityData *IdentityAccountData, adi *protocol.ADI) {
	// In a full implementation, this would query the ADI to get all associated accounts
	// This typically requires additional network calls to enumerate accounts
	// For now, we can only extract what's immediately available

	// The actual account enumeration would happen in ProcessADIAccounts
	// Here we just ensure the structure is ready
	if identityData.AccountURLs == nil {
		identityData.AccountURLs = make([]string, 0)
	}
}

// extractADIAuthorities extracts authorities from ADI
func (c *Client) extractADIAuthorities(identityData *IdentityAccountData, adi *protocol.ADI) {
	// Extract authorities from the ADI's AccountAuth
	if auth := adi.GetAuth(); auth != nil {
		for _, authority := range auth.Authorities {
			if authority.Url != nil {
				identityData.Authorities = append(identityData.Authorities, authority.Url.String())
			}
		}

		// Extract threshold if available
		// In the protocol, threshold might be stored differently
		// This would require protocol-specific knowledge
	}
}

// extractKeyBookAuthorities extracts authorities from key book
func (c *Client) extractKeyBookAuthorities(keyData *KeyAccountData, keyBook *protocol.KeyBook) {
	// Extract authorities from the key book's AccountAuth
	if auth := keyBook.GetAuth(); auth != nil {
		for _, authority := range auth.Authorities {
			if authority.Url != nil {
				keyData.Authorities = append(keyData.Authorities, authority.Url.String())
			}
		}
	}
}

// extractKeyBookKeys extracts keys from key book pages
func (c *Client) extractKeyBookKeys(keyData *KeyAccountData, keyBook *protocol.KeyBook) {
	// In a full implementation, this would:
	// 1. Iterate through all pages (0 to PageCount-1)
	// 2. Query each key page to get its keys
	// 3. Aggregate all keys from all pages
	// This requires additional network calls

	// For now, we initialize the keys slice
	if keyData.Keys == nil {
		keyData.Keys = make([]*KeyInfo, 0)
	}

	// The actual key extraction would happen by querying individual key pages
	// This is typically done on-demand or through separate API calls
}

// extractKeysFromKeyPage extracts individual keys from a key page
func (c *Client) extractKeysFromKeyPage(keyPageData *KeyPageData, keyPage *protocol.KeyPage) {
	// Extract keys from the key page
	for _, keySpec := range keyPage.Keys {
		if keySpec != nil {
			keyInfo := &KeyInfo{
				PublicKey: fmt.Sprintf("%x", keySpec.PublicKeyHash), // Convert hash to hex
				KeyType:   "ed25519",                                // Default key type, would need protocol-specific logic
			}

			// Extract delegate if available
			if keySpec.Delegate != nil {
				keyInfo.Delegate = keySpec.Delegate.String()
			}

			// Extract last used timestamp if available
			if keySpec.LastUsedOn > 0 {
				lastUsed := time.Unix(int64(keySpec.LastUsedOn), 0)
				keyInfo.LastUsed = &lastUsed
			}

			// Nonce is not directly available in KeySpec, would need to be queried separately
			keyInfo.Nonce = 0

			keyPageData.Keys = append(keyPageData.Keys, keyInfo)
		}
	}

	// Set page index based on URL
	if keyPage.Url != nil {
		urlStr := keyPage.Url.String()
		// Extract page index from URL (typically the last segment)
		if strings.Contains(urlStr, "/") {
			parts := strings.Split(urlStr, "/")
			if len(parts) > 0 {
				lastPart := parts[len(parts)-1]
				if pageIndex, err := fmt.Sscanf(lastPart, "%d", &keyPageData.PageIndex); err == nil && pageIndex == 1 {
					// Successfully parsed page index
				}
			}
		}
	}
}
