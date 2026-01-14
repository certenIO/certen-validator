// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package api

import "time"

// =============================================================================
// Core API Response Types
// =============================================================================

// APIResponse is the unified response type that can contain either account or ADI data
type APIResponse struct {
	// Response metadata
	RequestURL   string    `json:"requestUrl"`
	ResponseType string    `json:"responseType"` // "account" or "adi"
	Timestamp    time.Time `json:"timestamp"`

	// Account data (for individual accounts)
	Account *AccountInfo `json:"account,omitempty"`

	// ADI data (for ADI requests)
	ADI *ADIInfo `json:"adi,omitempty"`
}

// =============================================================================
// ADI (Account Directory Identity) Types
// =============================================================================

// ADIInfo represents complete information about an ADI and all its accounts
type ADIInfo struct {
	URL         string         `json:"url"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	KeyBook     string         `json:"keyBook,omitempty"`
	Accounts    []*AccountInfo `json:"accounts"`
	AccountURLs []string       `json:"accountUrls"` // Quick reference
	LastUpdated time.Time      `json:"lastUpdated"`

	// Proof and verification data
	Receipt     *ReceiptInfo `json:"receipt,omitempty"`
	BlockHeight int64        `json:"blockHeight,omitempty"`
	RawResponse interface{}  `json:"rawResponse,omitempty"`
}

// =============================================================================
// Account Information Types
// =============================================================================

// AccountInfo represents comprehensive information about any account type
type AccountInfo struct {
	// Basic account information
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	TypeName    string    `json:"typeName"`
	Category    string    `json:"category"` // "token", "data", "identity", "key", "other"
	LastUpdated time.Time `json:"lastUpdated"`

	// Type-specific data (only populated based on account type)
	TokenData    *TokenAccountData    `json:"tokenData,omitempty"`
	DataAccount  *DataAccountData     `json:"dataAccount,omitempty"`
	IdentityData *IdentityAccountData `json:"identityData,omitempty"`
	KeyData      *KeyAccountData      `json:"keyData,omitempty"`
	KeyPageData  *KeyPageData         `json:"keyPageData,omitempty"`
	GenericData  *GenericAccountData  `json:"genericData,omitempty"`

	// Transaction history
	Transactions []*APITransaction `json:"transactions,omitempty"`

	// Proof and verification data
	Receipt     *ReceiptInfo `json:"receipt,omitempty"`
	BlockHeight int64        `json:"blockHeight,omitempty"`
	RawResponse interface{}  `json:"rawResponse,omitempty"`
}

// =============================================================================
// Account Type-Specific Data Structures
// =============================================================================

// TokenAccountData contains information specific to token accounts
type TokenAccountData struct {
	Balance       string `json:"balance"`
	TokenURL      string `json:"tokenUrl"`
	TokenSymbol   string `json:"tokenSymbol,omitempty"`
	TokenName     string `json:"tokenName,omitempty"`
	CreditBalance uint64 `json:"creditBalance,omitempty"`
	KeyBook       string `json:"keyBook,omitempty"`

	// Lite token account specific
	IsLiteAccount bool `json:"isLiteAccount"`

	// Token account specific
	TokenIssuer string `json:"tokenIssuer,omitempty"`
}

// DataAccountData contains information specific to data accounts
type DataAccountData struct {
	IsLiteAccount bool         `json:"isLiteAccount"`
	Entries       []*DataEntry `json:"entries,omitempty"`
	KeyBook       string       `json:"keyBook,omitempty"`
	Authorities   []string     `json:"authorities,omitempty"`
	RawData       interface{}  `json:"rawData,omitempty"`
}

// DataEntry represents a single data entry in a data account
type DataEntry struct {
	EntryHash string    `json:"entryHash"`
	Data      []byte    `json:"data"`
	Size      uint64    `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

// IdentityAccountData contains comprehensive identity (ADI) information
type IdentityAccountData struct {
	KeyBook     string   `json:"keyBook,omitempty"`
	AccountURLs []string `json:"accountUrls,omitempty"`
	Authorities []string `json:"authorities,omitempty"`
	Threshold   uint64   `json:"threshold,omitempty"`
}

// KeyAccountData contains comprehensive key account information
type KeyAccountData struct {
	KeyBookType string     `json:"keyBookType"`
	Keys        []*KeyInfo `json:"keys,omitempty"`
	Threshold   uint64     `json:"threshold,omitempty"`
	PageCount   uint64     `json:"pageCount,omitempty"`
	Authorities []string   `json:"authorities,omitempty"`
}

// KeyInfo represents detailed information about a cryptographic key
type KeyInfo struct {
	PublicKey     string     `json:"publicKey"`
	KeyType       string     `json:"keyType"`
	Delegate      string     `json:"delegate,omitempty"`
	LastUsed      *time.Time `json:"lastUsed,omitempty"`
	Nonce         uint64     `json:"nonce,omitempty"`
	CreditBalance string     `json:"creditBalance,omitempty"`
}

// KeyPageData contains specific key page information
type KeyPageData struct {
	PageIndex     uint64     `json:"pageIndex"`
	Keys          []*KeyInfo `json:"keys"`
	Threshold     uint64     `json:"threshold"`
	Version       uint64     `json:"version"`
	CreditBalance string     `json:"creditBalance,omitempty"`
	Authorities   []string   `json:"authorities,omitempty"`
}

// GenericAccountData contains information for unknown or unsupported account types
type GenericAccountData struct {
	RawData map[string]interface{} `json:"rawData"`
}

// =============================================================================
// Transaction Information Types
// =============================================================================

// APITransaction represents comprehensive transaction information
type APITransaction struct {
	TxID        string    `json:"txId"`
	Type        string    `json:"type"`
	TypeName    string    `json:"typeName,omitempty"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	BlockHeight int64     `json:"blockHeight,omitempty"`

	// Transaction participants
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	// Transaction amounts (for token transfers)
	Amount   string `json:"amount,omitempty"`
	TokenURL string `json:"tokenUrl,omitempty"`

	// Transaction data
	Data        interface{}            `json:"data,omitempty"`
	RawResponse map[string]interface{} `json:"rawResponse,omitempty"`

	// Proof information
	Receipt *ReceiptInfo `json:"receipt,omitempty"`
}

// =============================================================================
// Receipt and Proof Types
// =============================================================================

// ReceiptInfo contains receipt verification information
type ReceiptInfo struct {
	Exists      bool        `json:"exists"`
	Valid       bool        `json:"valid"`
	MerkleRoot  string      `json:"merkleRoot,omitempty"`
	BlockHeight int64       `json:"blockHeight,omitempty"`
	VerifiedAt  time.Time   `json:"verifiedAt"`
	RawReceipt  interface{} `json:"rawReceipt,omitempty"`
}
