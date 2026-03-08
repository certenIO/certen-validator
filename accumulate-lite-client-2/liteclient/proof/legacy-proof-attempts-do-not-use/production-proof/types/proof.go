// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package types

import (
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ProofBundle contains all proof data for an account
type ProofBundle struct {
	// Metadata
	AccountURL string    `json:"accountUrl"`
	Generated  time.Time `json:"generated"`
	Version    string    `json:"version"`

	// Account data
	Account protocol.Account `json:"account"`

	// Layer 1: Merkle proof
	MerkleProof *MerkleProof `json:"merkleProof,omitempty"`

	// Layer 2: Block commitment
	BlockCommitment *BlockCommitment `json:"blockCommitment,omitempty"`

	// Layer 3: Consensus proof
	ConsensusProof *ConsensusProof `json:"consensusProof,omitempty"`

	// Layer 4: Trust chain (future)
	TrustChain *TrustChain `json:"trustChain,omitempty"`
}

// MerkleProof represents Layer 1 proof data
type MerkleProof struct {
	AccountHash  []byte                    `json:"accountHash"`
	BPTRoot      []byte                    `json:"bptRoot"`
	ProofEntries []ProofEntry              `json:"proofEntries"`
	Anchor       *protocol.PartitionAnchor `json:"anchor"`
}

// ProofEntry represents a single merkle proof entry
type ProofEntry struct {
	Hash  []byte `json:"hash"`
	Right bool   `json:"right"` // True if hash is on the right
}

// BlockCommitment represents Layer 2 proof data
type BlockCommitment struct {
	BlockHeight int64     `json:"blockHeight"`
	BlockHash   []byte    `json:"blockHash"`
	AppHash     []byte    `json:"appHash"`
	BlockTime   time.Time `json:"blockTime"`
	ChainID     string    `json:"chainId"`
}

// ConsensusProof represents Layer 3 proof data
type ConsensusProof struct {
	Validators  []Validator    `json:"validators"`
	Signatures  []ValidatorSig `json:"signatures"`
	TotalPower  int64          `json:"totalPower"`
	SignedPower int64          `json:"signedPower"`
	Threshold   int64          `json:"threshold"`
}

// Validator represents a validator in the consensus
type Validator struct {
	Address     string `json:"address"`
	PubKey      []byte `json:"pubKey"`
	VotingPower int64  `json:"votingPower"`
}

// ValidatorSig represents a validator's signature
type ValidatorSig struct {
	ValidatorIndex int       `json:"validatorIndex"`
	Signature      []byte    `json:"signature"`
	Timestamp      time.Time `json:"timestamp"`
}

// TrustChain represents Layer 4 proof data (future)
type TrustChain struct {
	GenesisHash      []byte               `json:"genesisHash"`
	ValidatorHistory []ValidatorSetChange `json:"validatorHistory"`
}

// ValidatorSetChange represents a validator set transition
type ValidatorSetChange struct {
	Height     int64          `json:"height"`
	OldSet     []Validator    `json:"oldSet"`
	NewSet     []Validator    `json:"newSet"`
	Signatures []ValidatorSig `json:"signatures"`
}

// VerificationStatus tracks the status of each layer
type VerificationStatus struct {
	Layer1 LayerVerification `json:"layer1"`
	Layer2 LayerVerification `json:"layer2"`
	Layer3 LayerVerification `json:"layer3"`
	Layer4 LayerVerification `json:"layer4"`
}

// LayerVerification represents the verification status of a single layer
type LayerVerification struct {
	Name       string        `json:"name"`
	Verified   bool          `json:"verified"`
	Message    string        `json:"message,omitempty"`
	Error      string        `json:"error,omitempty"`
	Duration   time.Duration `json:"duration,omitempty"`
	TrustLevel string        `json:"trustLevel,omitempty"`
}
