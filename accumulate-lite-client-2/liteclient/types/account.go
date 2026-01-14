// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package types

import (
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Data structures for account information

// TokenBalanceInfo contains balance information for token accounts
type TokenBalanceInfo struct {
	AccountURL    string `json:"accountUrl"`
	AccountType   string `json:"accountType"`
	Balance       string `json:"balance"`
	TokenURL      string `json:"tokenUrl"`
	CreditBalance uint64 `json:"creditBalance"`
}

// IdentityInfo contains information about identity accounts
type IdentityInfo struct {
	AccountURL  string `json:"accountUrl"`
	IdentityURL string `json:"identityUrl"`
	KeyBook     string `json:"keyBook"`
}

// DataAccountInfo contains information about data accounts
type DataAccountInfo struct {
	AccountURL  string `json:"accountUrl"`
	AccountType string `json:"accountType"`
	DataURL     string `json:"dataUrl"`
	KeyBook     string `json:"keyBook"`
}

// AccountSummary provides a unified view of any account type
type AccountSummary struct {
	AccountURL  string `json:"accountUrl"`
	AccountType string `json:"accountType"`
	Category    string `json:"category"`
	Balance     string `json:"balance,omitempty"`
	TokenURL    string `json:"tokenUrl,omitempty"`
	KeyBook     string `json:"keyBook,omitempty"`
}

// Helper methods for working with AccountData

// IsTokenAccount returns true if this is any type of token account.
func (ad *AccountData) IsTokenAccount() bool {
	return ad.Type == protocol.AccountTypeLiteTokenAccount || ad.Type == protocol.AccountTypeTokenAccount
}

// IsDataAccount returns true if this is any type of data account.
func (ad *AccountData) IsDataAccount() bool {
	return ad.Type == protocol.AccountTypeDataAccount || ad.Type == protocol.AccountTypeLiteDataAccount
}

// IsIdentityAccount returns true if this is an ADI (Identity) account.
func (ad *AccountData) IsIdentityAccount() bool {
	return ad.Type == protocol.AccountTypeIdentity
}

// IsKeyAccount returns true if this is a key management account.
func (ad *AccountData) IsKeyAccount() bool {
	return ad.Type == protocol.AccountTypeKeyPage || ad.Type == protocol.AccountTypeKeyBook
}

// AsLiteTokenAccount returns the account data as a LiteTokenAccount if applicable.
func (ad *AccountData) AsLiteTokenAccount() (*protocol.LiteTokenAccount, error) {
	if ad.Type != protocol.AccountTypeLiteTokenAccount {
		return nil, fmt.Errorf("account is not a lite token account")
	}

	// Data is now always a properly typed protocol.Account
	liteToken, ok := ad.Data.(*protocol.LiteTokenAccount)
	if !ok {
		return nil, fmt.Errorf("account data type mismatch: expected *protocol.LiteTokenAccount, got %T", ad.Data)
	}

	return liteToken, nil
}

// AsTokenAccount returns the account data as a TokenAccount if applicable.
func (ad *AccountData) AsTokenAccount() (*protocol.TokenAccount, error) {
	if ad.Type != protocol.AccountTypeTokenAccount {
		return nil, fmt.Errorf("account is not a token account")
	}

	// Data is now always a properly typed protocol.Account
	token, ok := ad.Data.(*protocol.TokenAccount)
	if !ok {
		return nil, fmt.Errorf("account data type mismatch: expected *protocol.TokenAccount, got %T", ad.Data)
	}

	return token, nil
}

// AsADI returns the account data as an ADI (Identity) if applicable.
func (ad *AccountData) AsADI() (*protocol.ADI, error) {
	if ad.Type != protocol.AccountTypeIdentity {
		return nil, fmt.Errorf("account is not an ADI")
	}

	// Data is now always a properly typed protocol.Account
	adi, ok := ad.Data.(*protocol.ADI)
	if !ok {
		return nil, fmt.Errorf("account data type mismatch: expected *protocol.ADI, got %T", ad.Data)
	}

	return adi, nil
}

// AsKeyBook returns the account data as a KeyBook if applicable.
func (ad *AccountData) AsKeyBook() (*protocol.KeyBook, error) {
	if ad.Type != protocol.AccountTypeKeyBook {
		return nil, fmt.Errorf("account is not a key book")
	}

	// Data is now always a properly typed protocol.Account
	keyBook, ok := ad.Data.(*protocol.KeyBook)
	if !ok {
		return nil, fmt.Errorf("account data type mismatch: expected *protocol.KeyBook, got %T", ad.Data)
	}

	return keyBook, nil
}

// AsKeyPage returns the account data as a KeyPage if applicable.
func (ad *AccountData) AsKeyPage() (*protocol.KeyPage, error) {
	if ad.Type != protocol.AccountTypeKeyPage {
		return nil, fmt.Errorf("account is not a key page")
	}

	// Data is now always a properly typed protocol.Account
	keyPage, ok := ad.Data.(*protocol.KeyPage)
	if !ok {
		return nil, fmt.Errorf("account data type mismatch: expected *protocol.KeyPage, got %T", ad.Data)
	}

	return keyPage, nil
}
