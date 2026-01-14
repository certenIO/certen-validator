// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package types

import (
	"context"
	"net/url"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// VerifiedAccount contains an account URL and its cryptographic proof.
type VerifiedAccount struct {
	Url     string
	Receipt *merkle.Receipt
	Height  int64
}

// Transaction represents transaction data (unified struct)
type Transaction struct {
	TxID      string
	Type      string
	Status    string
	Timestamp int64
	Amount    string
	From      string
	To        string
	Account   string
	Height    int64
	Data      interface{} // Raw transaction data
}

// AccountData represents internal account information optimized for storage and caching.
// This structure preserves raw protocol data and minimizes storage overhead.
// For API responses, use AccountInfo which provides user-friendly structured data.
type AccountData struct {
	// Core identification
	URL  string               `json:"url"`
	Type protocol.AccountType `json:"type"`

	// Raw protocol data (the source of truth)
	Data           interface{} `json:"data"` // The actual protocol account struct
	MainChainRoots [][]byte    `json:"mainChainRoots,omitempty"`

	// Storage metadata
	LastUpdated time.Time              `json:"lastUpdated"`
	FromCache   bool                   `json:"fromCache"`   // Indicates if data was retrieved from cache
	RawResponse map[string]interface{} `json:"rawResponse"` // Original API response for debugging

	// Verification data
	Receipt       *merkle.Receipt `json:"receipt,omitempty"`       // Primary cryptographic proof (combined receipt)
	CompleteProof interface{}     `json:"completeProof,omitempty"` // Full trust path proof chain
	Height        int64           `json:"height,omitempty"`        // Block height

	// Transaction references (IDs only for storage efficiency)
	TransactionIDs []string       `json:"transactionIds,omitempty"` // Reference to transactions
	Transactions   []*Transaction `json:"-"`                        // Populated on demand, not stored
}

// DataBackend defines the interface for account data retrieval operations.
type DataBackend interface {
	QueryAccount(ctx context.Context, url string) (*AccountData, error)
	GetNetworkStatus(ctx context.Context) (*NetworkStatus, error)
	GetRoutingTable(ctx context.Context) (*protocol.RoutingTable, error)
	GetMainChainReceipt(ctx context.Context, accountUrl string, startHash []byte) (*merkle.Receipt, error)
	GetBVNAnchorReceipt(ctx context.Context, partition string, anchor []byte) (*merkle.Receipt, error)
	GetDNAnchorReceipt(ctx context.Context, anchor []byte) (*merkle.Receipt, error)
	GetDNIntermediateAnchorReceipt(ctx context.Context, bvnRootAnchor []byte) (*merkle.Receipt, error)
	GetBPTReceipt(ctx context.Context, partition string, hash []byte) (*merkle.Receipt, error)
	GetMainChainRootInDNAnchorChain(ctx context.Context, partition string, mainChainRoot []byte) (*merkle.Receipt, error)
}

// AccountCache defines the interface for caching account data
type AccountCache interface {
	GetAccountData(url string) (*AccountData, bool)
	StoreAccountData(url string, data *AccountData, ttl ...time.Duration)
	RemoveAccount(accountURL string)
	GetBalance(url string) (*TokenBalanceInfo, bool)
	StoreBalance(url string, balance *TokenBalanceInfo, ttl ...time.Duration)
	GetIdentityInfo(url string) (*IdentityInfo, bool)
	StoreIdentityInfo(url string, identity *IdentityInfo, ttl ...time.Duration)
	PruneExpired()
	Clear()
	GetCachedURLs() []string
	GetMetrics() *Metrics
}

// NetworkStatus represents network status information for partition discovery
type NetworkStatus struct {
	Partitions []PartitionInfo
}

// PartitionInfo represents information about a network partition
type PartitionInfo struct {
	ID   string
	Type string // Using string for compatibility with v2 API
	URL  *url.URL
}

// CacheStats represents cache statistics for the public API
type CacheStats struct {
	AccountDataEntries int           `json:"accountDataEntries"`
	TransactionEntries int           `json:"transactionEntries"`
	BalanceEntries     int           `json:"balanceEntries"`
	ProofEntries       int           `json:"proofEntries"`
	TotalEntries       int           `json:"totalEntries"`
	HitRate            float64       `json:"hitRate"`
	AverageAge         time.Duration `json:"averageAge"`
}

// Validator represents a consensus validator
type Validator struct {
	Address     []byte `json:"address"`
	PublicKey   []byte `json:"publicKey"`
	VotingPower int64  `json:"votingPower"`
}

// ValidatorSignature represents a validator's signature on consensus data
type ValidatorSignature struct {
	ValidatorIndex   int    `json:"validatorIndex"`
	ValidatorAddress []byte `json:"validatorAddress"`
	Signature        []byte `json:"signature"`
}

// ValidatorSet represents a set of validators
type ValidatorSet struct {
	Height     int64       `json:"height"`
	Validators []Validator `json:"validators"`
	TotalPower int64       `json:"totalPower"`
}

// ValidatorTransition represents a transition between validator sets
type ValidatorTransition struct {
	FromHeight    int64       `json:"fromHeight"`
	ToHeight      int64       `json:"toHeight"`
	OldValidators []Validator `json:"oldValidators"`
	NewValidators []Validator `json:"newValidators"`
	Signatures    [][]byte    `json:"signatures"` // Ed25519 signatures from old validators
}

// VerificationResult represents the result of proof verification
type VerificationResult struct {
	Valid           bool   `json:"valid"`
	Layer1Verified  bool   `json:"layer1Verified"`
	Layer2Verified  bool   `json:"layer2Verified"`
	Layer3Verified  bool   `json:"layer3Verified"`
	Layer4Verified  bool   `json:"layer4Verified"`
	Error           string `json:"error"`
	VerifiedHeight  int64  `json:"verifiedHeight"`
	TrustPath       string `json:"trustPath"`
}

// Block represents a blockchain block
type Block struct {
	Height    int64     `json:"height"`
	Hash      []byte    `json:"hash"`
	AppHash   []byte    `json:"appHash"`
	Timestamp time.Time `json:"timestamp"`
	ChainID   string    `json:"chainId"`
}

// StateComponents represents the components that make up the state hash
type StateComponents struct {
	BPTRoot       []byte `json:"bptRoot"`
	MainChain     []byte `json:"mainChain"`
	MinorRoots    []byte `json:"minorRoots"`
	ReceiptRoot   []byte `json:"receiptRoot"`
	SyntheticRoot []byte `json:"syntheticRoot"`
}

// ProofChain represents a complete proof chain
type ProofChain struct {
	AccountState    *AccountState         `json:"accountState"`
	Block           *Block               `json:"block"`
	StateComponents *StateComponents     `json:"stateComponents"`
	ConsensusProof  *ConsensusProof      `json:"consensusProof"`
	ValidatorChain  []ValidatorTransition `json:"validatorChain"`
}

// AccountState represents the state of an account with its proof
type AccountState struct {
	AccountData  *AccountData  `json:"accountData"`
	MerkleProof  *MerkleProof  `json:"merkleProof"`
	Data         []byte        `json:"data"`        // Raw account data for proof
	Hash         []byte        `json:"hash"`        // Hash of account data
	Height       int64         `json:"height"`      // Block height
}

// MerkleProof represents a Merkle proof for account inclusion
type MerkleProof struct {
	Hashes [][]byte `json:"hashes"`
	Index  int64    `json:"index"`
}

// ConsensusProof represents consensus-level proof data
type ConsensusProof struct {
	BlockHash          []byte                `json:"blockHash"`
	ValidatorSignatures []ValidatorSignature `json:"validatorSignatures"`
	ValidatorSet        ValidatorSet         `json:"validatorSet"`
	SignedPower        int64                `json:"signedPower"`
	TotalPower         int64                `json:"totalPower"`
	Timestamp          time.Time            `json:"timestamp"`
}
