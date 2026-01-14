// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Layer1Verifier handles Account State → BPT Root verification
type Layer1Verifier struct {
	client APIClient
	debug  bool
}

// NewLayer1Verifier creates a new Layer 1 verifier
func NewLayer1Verifier(client APIClient) *Layer1Verifier {
	return &Layer1Verifier{client: client}
}

// VerifyAccountToBPT verifies Layer 1: Account State → BPT Root
// This layer proves that an account's state is correctly included in the BPT
func (v *Layer1Verifier) VerifyAccountToBPT(ctx context.Context, accountURL *url.URL) (*Layer1Result, error) {
	result := &Layer1Result{
		AccountURL: accountURL.String(),
	}

	// Step 1: Query account with proof
	query := &api.DefaultQuery{
		IncludeReceipt: &api.ReceiptOptions{ForAny: true},
	}

	resp, err := v.client.Query(ctx, accountURL, query)
	if err != nil {
		return result, fmt.Errorf("failed to query account: %w", err)
	}

	accountResp, ok := resp.(*api.AccountRecord)
	if !ok {
		return result, fmt.Errorf("unexpected response type: %T", resp)
	}

	// Validate response has required data
	if accountResp.Account == nil {
		return result, fmt.Errorf("no account data in response")
	}

	if accountResp.Receipt == nil {
		return result, fmt.Errorf("no receipt in response")
	}

	// Extract proof from receipt
	receipt := accountResp.Receipt
	if receipt == nil || len(receipt.Anchor) == 0 {
		return result, fmt.Errorf("no anchor in receipt")
	}

	// Step 2: Calculate account state hash
	accountHash := v.calculateAccountHash(accountResp.Account)
	result.AccountHash = hex.EncodeToString(accountHash)

	// Validate receipt structure (from Paul's ValidateProofStructure)
	if err := v.validateReceiptStructure(receipt); err != nil {
		return result, fmt.Errorf("invalid receipt structure: %w", err)
	}

	if v.debug {
		fmt.Printf("Layer 1 Verification:\n")
		fmt.Printf("  Account Hash: %x\n", accountHash[:16])
		fmt.Printf("  Proof Entries: %d\n", len(receipt.Entries))
		fmt.Printf("  Receipt Anchor: %x\n", receipt.Anchor[:16])
	}

	// Step 3: Use the anchor as BPT root for now
	// The Receipt.Anchor field is actually the merkle root hash
	bptRoot := receipt.Anchor

	// Verify proof entries connect account to BPT root
	if len(receipt.Entries) == 0 {
		return result, fmt.Errorf("no proof entries")
	}

	// Calculate BPT root from proof
	currentHash := accountHash
	for i, entry := range receipt.Entries {
		if entry.Hash == nil {
			return result, fmt.Errorf("proof entry %d has no hash", i)
		}

		// Combine hashes based on proof path
		if entry.Right {
			currentHash = combineHashes(entry.Hash, currentHash)
		} else {
			currentHash = combineHashes(currentHash, entry.Hash)
		}
	}

	// Store the BPT root
	result.BPTRoot = hex.EncodeToString(bptRoot)
	result.ProofEntries = len(receipt.Entries)

	// Verify the proof produces the expected root
	if hex.EncodeToString(currentHash) != result.BPTRoot {
		return result, fmt.Errorf("proof verification failed: computed root doesn't match")
	}

	// Layer 1 verification successful
	result.Verified = true
	// Use local block as block index
	result.BlockIndex = receipt.LocalBlock

	// Store additional metadata
	if !accountResp.Receipt.LocalBlockTime.IsZero() {
		result.BlockTime = uint64(accountResp.Receipt.LocalBlockTime.Unix())
	}

	return result, nil
}

// calculateAccountHash computes the hash of an account's state
func (v *Layer1Verifier) calculateAccountHash(account protocol.Account) []byte {
	// Use protocol's standard hashing
	h := sha256.New()

	// Hash account data according to protocol rules
	accountData, _ := account.MarshalBinary()
	h.Write(accountData)

	return h.Sum(nil)
}

// combineHashes combines two hashes in merkle tree order
func combineHashes(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// validateReceiptStructure validates the structure of a merkle receipt (Paul's ValidateProofStructure equivalent)
func (v *Layer1Verifier) validateReceiptStructure(receipt *api.Receipt) error {
	if receipt == nil {
		return fmt.Errorf("receipt is nil")
	}

	if len(receipt.Anchor) != 32 {
		return fmt.Errorf("invalid anchor hash length: expected 32, got %d", len(receipt.Anchor))
	}

	if len(receipt.Entries) == 0 {
		return fmt.Errorf("receipt has no proof entries")
	}

	// Check each proof entry
	for i, entry := range receipt.Entries {
		if entry.Hash == nil || len(entry.Hash) != 32 {
			return fmt.Errorf("invalid hash length at entry %d: expected 32, got %d",
				i, len(entry.Hash))
		}
	}

	return nil
}

// computeMerkleRootFromReceipt recomputes the merkle root from account hash and receipt (Paul's ComputeMerkleRoot equivalent)
func (v *Layer1Verifier) computeMerkleRootFromReceipt(accountHash []byte, receipt *api.Receipt) ([]byte, error) {
	if len(accountHash) != 32 {
		return nil, fmt.Errorf("invalid account hash length: expected 32, got %d", len(accountHash))
	}

	currentHash := accountHash

	if v.debug {
		fmt.Printf("  Starting hash: %x\n", currentHash[:16])
	}

	// Apply each proof entry
	for i, entry := range receipt.Entries {
		var combined []byte

		if entry.Right {
			// Entry is on the right, current hash on the left
			combined = append(currentHash, entry.Hash...)
		} else {
			// Entry is on the left, current hash on the right
			combined = append(entry.Hash, currentHash...)
		}

		hasher := sha256.New()
		hasher.Write(combined)
		currentHash = hasher.Sum(nil)

		if v.debug {
			fmt.Printf("  Step %d: %x (right=%v) = %x\n",
				i+1,
				entry.Hash[:8],
				entry.Right,
				currentHash[:8])
		}
	}

	if v.debug {
		fmt.Printf("  Final computed root: %x\n", currentHash[:16])
	}

	return currentHash, nil
}

// SetDebug enables or disables debug output
func (v *Layer1Verifier) SetDebug(debug bool) {
	v.debug = debug
}

// Layer1Result contains the results of Layer 1 verification
type Layer1Result struct {
	Verified     bool   `json:"verified"`
	AccountURL   string `json:"accountUrl"`
	AccountHash  string `json:"accountHash"`
	BPTRoot      string `json:"bptRoot"`
	ProofEntries int    `json:"proofEntries"`
	BlockIndex   uint64 `json:"blockIndex"`
	BlockTime    uint64 `json:"blockTime,omitempty"`
	Error        string `json:"error,omitempty"`
}
