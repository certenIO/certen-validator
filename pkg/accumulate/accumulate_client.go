// Package accumulate provides the canonical Accumulate network client interface for Certen validators.
// All Accumulate integration MUST use this interface to ensure consistency and testability.
package accumulate

import (
	"context"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/api"
)

// Client defines the canonical interface for all Accumulate network operations.
// This is the ONLY interface that validator code should depend on for Accumulate integration.
type Client interface {
	// Core account and transaction operations
	GetAccount(ctx context.Context, url string) (*api.APIResponse, error)
	GetTransaction(ctx context.Context, hash string) (*Transaction, error)

	// CERTEN-specific operations for intent discovery and proof generation
	SearchCertenTransactions(ctx context.Context, fromHeight int64) ([]*CertenTransaction, error)
	GetMerkleProofForCertenTx(ctx context.Context, tx *CertenTransaction) (*MerkleProof, error)

	// Block and network operations
	GetBlock(ctx context.Context, height uint64) (*Block, error)
	GetLatestBlock(ctx context.Context) (*Block, error)

	// Key management operations (production-grade only)
	GetKeyBook(ctx context.Context, url string) (*KeyBook, error)
	GetKeyPage(ctx context.Context, url string) (*KeyPage, error)
	VerifySignature(ctx context.Context, message, signature, publicKey string) (bool, error)

	// Transaction governance data (M-of-N key page threshold)
	GetTransactionGovernanceData(ctx context.Context, txHash string, accountURL string) (*TransactionGovernanceData, error)

	// Network health and lifecycle
	Health(ctx context.Context) error
	Close() error
}

// TransactionGovernanceData contains the key page governance data from a transaction
// Extracted from signatureBooks in the Accumulate transaction query response
type TransactionGovernanceData struct {
	// ThresholdN is the acceptThreshold from the key page (required signatures to authorize)
	ThresholdN int `json:"threshold_n"`
	// ThresholdM is the number of signatures actually collected
	ThresholdM int `json:"threshold_m"`
	// AuthorityURL is the key book authority that authorized the transaction
	AuthorityURL string `json:"authority_url"`
	// KeyPageURL is the key page that signed the transaction
	KeyPageURL string `json:"key_page_url"`
}

// AccountResponse represents account data from Accumulate
type AccountResponse = api.APIResponse

// TxResponse represents transaction data from Accumulate
type TxResponse struct {
	Hash        string                 `json:"hash"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Signatures  []Signature            `json:"signatures"`
	BlockHeight uint64                 `json:"block_height"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Note: MinorBlock type is defined in liteclient_adapter.go for now
// TODO: Move to interface when migration is complete

// ProofBundle represents a complete cryptographic proof from Accumulate
type ProofBundle struct {
	AnchorHash []byte                 `json:"anchor_hash"`
	ProofData  map[string]interface{} `json:"proof_data"`
	Validated  bool                   `json:"validated"`
}

// Transaction represents an Accumulate transaction
type Transaction struct {
	Hash        string                 `json:"hash"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Signatures  []Signature            `json:"signatures"`
	BlockHeight uint64                 `json:"block_height"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Signature represents a transaction signature
type Signature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Nonce     uint64 `json:"nonce"`
}

// ADI represents an Accumulate Digital Identifier
type ADI struct {
	URL         string            `json:"url"`
	KeyBook     string            `json:"key_book"`
	Manager     string            `json:"manager"`
	Authorities []string          `json:"authorities"`
	Data        map[string]string `json:"data"`
}

// MerkleProof represents a Merkle proof for a transaction
type MerkleProof struct {
	TransactionHash string   `json:"transaction_hash"`
	Path            []string `json:"path"`
	Root            string   `json:"root"`
	BlockHeight     uint64   `json:"block_height"`
}

// Block represents an Accumulate block header
type Block struct {
	Height     uint64    `json:"height"`
	Hash       string    `json:"hash"`
	MerkleRoot string    `json:"merkle_root"`
	Timestamp  time.Time `json:"timestamp"`
	PrevHash   string    `json:"prev_hash"`
}

// ValidatorInfo represents validator information from Accumulate
type ValidatorInfo struct {
	ValidatorID     string  `json:"validator_id"`
	PublicKey       string  `json:"public_key"`
	VotingPower     int64   `json:"voting_power"`
	Status          string  `json:"status"` // "active", "inactive", "slashed"
	LastBlockSigned uint64  `json:"last_block_signed"`
	Uptime          float64 `json:"uptime"`
}

// KeyBook represents an Accumulate Key Book
type KeyBook struct {
	URL       string    `json:"url"`
	Pages     []string  `json:"pages"`     // URLs of key pages
	Threshold int       `json:"threshold"` // Signature threshold
	CreatedAt time.Time `json:"created_at"`
}

// KeyPage represents an Accumulate Key Page
type KeyPage struct {
	URL         string    `json:"url"`
	PublicKeys  []string  `json:"public_keys"`
	Threshold   int       `json:"threshold"`
	CreditLimit int64     `json:"credit_limit"`
	CreatedAt   time.Time `json:"created_at"`
}

// Note: CertenTransaction type is defined in liteclient_adapter.go for now
// TODO: Move to interface when migration is complete