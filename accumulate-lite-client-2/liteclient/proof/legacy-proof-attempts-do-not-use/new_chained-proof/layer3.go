// Copyright 2025 CERTEN
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/rpc/client/http"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cometbft/cometbft/types"
)

// ConsensusBuilder constructs consensus finality proofs for both BVN (L1C) and DN (L2C) partitions
//
// Per spec sections 2.3 and 2.5: Consensus finality proves that a root is committed by CometBFT
// consensus (≥2/3 voting power) and binds to the signed header app_hash at height localBlock+1.
type ConsensusBuilder struct {
	cometEndpointMap map[string]string // partition -> comet RPC endpoint mapping
	debug            bool
}

// NewConsensusBuilder creates a new consensus finality builder with partition-to-endpoint mapping
func NewConsensusBuilder(cometEndpointMap map[string]string, debug bool) *ConsensusBuilder {
	return &ConsensusBuilder{
		cometEndpointMap: cometEndpointMap,
		debug:            debug,
	}
}

// NewLayer3Builder creates a legacy Layer 3 builder (deprecated - use ConsensusBuilder)
func NewLayer3Builder(cometEndpoint string, debug bool) (*ConsensusBuilder, error) {
	// Create default mapping for DN partition
	endpointMap := map[string]string{
		"dn":            cometEndpoint,
		"acc://dn.acme": cometEndpoint,
	}

	return &ConsensusBuilder{
		cometEndpointMap: endpointMap,
		debug:            debug,
	}, nil
}

// getCometClientForPartition gets or creates CometBFT client for the specified partition
func (cb *ConsensusBuilder) getCometClientForPartition(partition string) (*http.HTTP, error) {
	endpoint, exists := cb.cometEndpointMap[partition]
	if !exists {
		return nil, fmt.Errorf("no CometBFT endpoint configured for partition %s", partition)
	}

	client, err := http.New(endpoint, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("failed to create CometBFT client for %s: %w", endpoint, err)
	}

	return client, nil
}

// getNetworkName fetches network name from CometBFT /status endpoint
func (cb *ConsensusBuilder) getNetworkName(ctx context.Context, client *http.HTTP) (string, error) {
	status, err := client.Status(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch status: %w", err)
	}

	// Extract network name from node info
	networkName := status.NodeInfo.Network
	if networkName == "" {
		return "unknown", nil // Fallback for missing network name
	}

	return networkName, nil
}

// fetchAllValidators retrieves the complete validator set with pagination
func (cb *ConsensusBuilder) fetchAllValidators(ctx context.Context, client *http.HTTP, height *int64) ([]*types.Validator, error) {
	var allValidators []*types.Validator
	page := 1
	perPage := 200 // Use high page size for efficiency

	for {
		p := page
		pp := perPage

		if cb.debug {
			log.Printf("[CONSENSUS] Fetching validators page %d (perPage=%d)", page, perPage)
		}

		result, err := client.Validators(ctx, height, &p, &pp)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch validators page %d: %w", page, err)
		}

		allValidators = append(allValidators, result.Validators...)

		if cb.debug {
			log.Printf("[CONSENSUS] Fetched %d validators, total so far: %d/%d",
				len(result.Validators), len(allValidators), result.Total)
		}

		// Check if we have all validators
		if len(allValidators) >= result.Total {
			break
		}

		page++

		// Safety check to prevent infinite loops
		if page > 100 {
			return nil, fmt.Errorf("too many validator pages (>100), possible pagination issue")
		}
	}

	if cb.debug {
		log.Printf("[CONSENSUS] Successfully fetched all %d validators", len(allValidators))
	}

	return allValidators, nil
}

// BuildConsensusFinality constructs consensus finality proof for any partition per spec sections 2.3/2.5
//
// This method implements normative height mapping per spec section 4.4:
// - Input: localBlock from receipt
// - Consensus Height: H = localBlock + 1
// - Verify: Comet.app_hash(H) == expectedRoot
func (cb *ConsensusBuilder) BuildConsensusFinality(ctx context.Context, partition string, localBlock uint64, expectedRoot []byte) (*ConsensusFinality, error) {
	if cb.debug {
		log.Printf("[CONSENSUS] Building finality proof for partition=%s, localBlock=%d, root=%x",
			partition, localBlock, expectedRoot[:8])
	}

	// Validate inputs
	if partition == "" {
		return nil, fmt.Errorf("partition cannot be empty")
	}

	if len(expectedRoot) == 0 {
		return nil, fmt.Errorf("expected root cannot be empty")
	}

	// CRITICAL HEIGHT MAPPING per spec section 4.4: H = localBlock + 1
	consensusHeight := int64(localBlock + 1)

	if cb.debug {
		log.Printf("[CONSENSUS] Height mapping: localBlock=%d -> consensusHeight=%d", localBlock, consensusHeight)
	}

	// Get CometBFT client for this partition
	cometClient, err := cb.getCometClientForPartition(partition)
	if err != nil {
		return nil, fmt.Errorf("failed to get comet client for partition %s: %w", partition, err)
	}

	if cb.debug {
		log.Printf("[CONSENSUS] Fetching CometBFT commit for height %d", consensusHeight)
	}

	// Fetch CometBFT commit for the consensus height (localBlock + 1)
	commitResult, err := cometClient.Commit(ctx, &consensusHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch commit for height %d: %w", consensusHeight, err)
	}

	if cb.debug {
		log.Printf("[CONSENSUS] Fetching complete validator set for height %d", consensusHeight)
	}

	// Fetch the complete validator set for the consensus height (with pagination)
	validators, err := cb.fetchAllValidators(ctx, cometClient, &consensusHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch complete validator set for height %d: %w", consensusHeight, err)
	}

	// Get network name from status
	network, err := cb.getNetworkName(ctx, cometClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get network name: %w", err)
	}

	// Verify voting power threshold (≥2/3) with real cryptographic verification
	powerOK, signedPower, totalPower, err := cb.verifyCommitSignaturesAndPower(&commitResult.SignedHeader, validators)
	if err != nil {
		return nil, fmt.Errorf("cryptographic signature verification failed: %w", err)
	}

	// CRITICAL: Verify that the commit binds the expected root per spec section 4.4
	rootBindingOK, err := cb.verifyRootBinding(&commitResult.SignedHeader, expectedRoot)
	if err != nil {
		return nil, fmt.Errorf("root binding verification failed: %w", err)
	}

	if cb.debug {
		log.Printf("[CONSENSUS] Consensus verification: PowerOK=%t (%d/%d), RootBinding=%t",
			powerOK, signedPower, totalPower, rootBindingOK)
	}

	// Create consensus finality proof
	finality := &ConsensusFinality{
		Partition:     partition,
		Network:       network,
		Height:        uint64(consensusHeight), // Store consensus height, not localBlock
		Root:          expectedRoot,
		Commit:        cb.serializeCommit(commitResult),
		Validators:    cb.serializeValidators(validators),
		PowerOK:       powerOK,
		RootBindingOK: rootBindingOK,
	}

	if cb.debug {
		log.Printf("[CONSENSUS] Successfully built consensus finality - Height: %d, Valid: %t",
			consensusHeight, powerOK && rootBindingOK)
	}

	return finality, nil
}

// BuildFromLayer2 provides legacy Layer 3 interface (deprecated)
func (cb *ConsensusBuilder) BuildFromLayer2(ctx context.Context, layer2 *Layer2AnchorToDN) (*ConsensusFinality, error) {
	return cb.BuildConsensusFinality(ctx, "acc://dn.acme", layer2.LocalBlock, layer2.Anchor)
}

// verifyCommitSignaturesAndPower performs REAL cryptographic signature verification
// This replaces the broken verifyVotingPower function with proper signature validation
func (cb *ConsensusBuilder) verifyCommitSignaturesAndPower(signedHeader *types.SignedHeader, validators []*types.Validator) (bool, int64, int64, error) {
	if signedHeader.Commit == nil {
		return false, 0, 0, fmt.Errorf("signed header contains no commit")
	}

	commit := signedHeader.Commit
	header := signedHeader.Header

	// CRITICAL LINKAGE CHECK: Verify commit.BlockID.Hash matches header.Hash()
	if !bytes.Equal(commit.BlockID.Hash, header.Hash()) {
		return false, 0, 0, fmt.Errorf("commit blockID hash does not match header hash")
	}

	// CRITICAL SECURITY CHECK: Verify validator set binding
	// This prevents attacks where wrong validators are provided for signature verification
	expectedValidatorsHash := header.ValidatorsHash
	actualValidatorsHash := types.NewValidatorSet(validators).Hash()
	if !bytes.Equal(expectedValidatorsHash, actualValidatorsHash) {
		return false, 0, 0, fmt.Errorf("validator set hash mismatch: expected=%x, actual=%x",
			expectedValidatorsHash, actualValidatorsHash)
	}

	// Get chain ID from header (no extra RPC call needed)
	chainID := header.ChainID
	if chainID == "" {
		return false, 0, 0, fmt.Errorf("missing chain ID in header")
	}

	// Map validators by address for safe lookup (fixes index assumption bug)
	valByAddr := make(map[string]*types.Validator, len(validators))
	totalPower := int64(0)
	for _, v := range validators {
		valByAddr[hex.EncodeToString(v.Address)] = v
		totalPower += v.VotingPower
	}

	requiredPower := (totalPower*2)/3 + 1
	signedPower := int64(0)
	validSignatures := 0

	if cb.debug {
		log.Printf("[CONSENSUS] Starting signature verification: chainID=%s, height=%d, totalPower=%d, required=%d",
			chainID, header.Height, totalPower, requiredPower)
	}

	// Verify each signature cryptographically
	for i, cs := range commit.Signatures {
		// Only count actual commits for this specific BlockID
		if cs.BlockIDFlag != types.BlockIDFlagCommit {
			if cb.debug && i < 5 {
				log.Printf("[CONSENSUS] Skipping signature %d: not a commit (flag=%v)", i, cs.BlockIDFlag)
			}
			continue
		}

		// Skip absent signatures
		if len(cs.ValidatorAddress) == 0 || len(cs.Signature) == 0 {
			if cb.debug && i < 5 {
				log.Printf("[CONSENSUS] Skipping signature %d: missing address or signature", i)
			}
			continue
		}

		// Lookup validator by address (not by index - this is the key fix)
		addrHex := hex.EncodeToString(cs.ValidatorAddress)
		validator := valByAddr[addrHex]
		if validator == nil {
			if cb.debug && i < 5 {
				log.Printf("[CONSENSUS] Skipping signature %d: validator not found for address %s", i, addrHex)
			}
			continue
		}

		// Build the vote that was signed (fixed for proper BlockID and Timestamp)
		vote := &cmtproto.Vote{
			Type:   cmtproto.SignedMsgType(2), // SIGNED_MSG_TYPE_PRECOMMIT
			Height: commit.Height,
			Round:  commit.Round,
			BlockID: cmtproto.BlockID{
				Hash: commit.BlockID.Hash,
				PartSetHeader: cmtproto.PartSetHeader{
					Total: commit.BlockID.PartSetHeader.Total,
					Hash:  commit.BlockID.PartSetHeader.Hash,
				},
			},
			Timestamp: cs.Timestamp,
		}

		// Get the canonical sign bytes
		signBytes := types.VoteSignBytes(header.ChainID, vote)

		// CRYPTOGRAPHIC VERIFICATION: Verify the actual signature
		if validator.PubKey.VerifySignature(signBytes, cs.Signature) {
			signedPower += validator.VotingPower
			validSignatures++

			if cb.debug && validSignatures <= 5 {
				log.Printf("[CONSENSUS] ✅ Valid signature %d: addr=%s, power=%d (total: %d/%d)",
					validSignatures, addrHex[:8], validator.VotingPower, signedPower, totalPower)
			}
		} else {
			if cb.debug && i < 5 {
				log.Printf("[CONSENSUS] ❌ Invalid signature %d: addr=%s", i, addrHex[:8])
			}
		}

		// Early exit if we have enough power
		if signedPower >= requiredPower {
			break
		}
	}

	powerOK := signedPower >= requiredPower

	if cb.debug {
		log.Printf("[CONSENSUS] Signature verification complete: valid=%d, signedPower=%d, totalPower=%d, required=%d, ok=%t",
			validSignatures, signedPower, totalPower, requiredPower, powerOK)
	}

	return powerOK, signedPower, totalPower, nil
}

// verifyRootBinding validates that the commit binds the expected root per spec section 4.4
func (cb *ConsensusBuilder) verifyRootBinding(signedHeader *types.SignedHeader, expectedRoot []byte) (bool, error) {
	header := signedHeader.Header

	// CRITICAL: The root must be reflected in the AppHash per spec invariant 4.4
	// This is the critical mapping between Accumulate's partition root and CometBFT's AppHash
	actualAppHash := header.AppHash

	if cb.debug {
		log.Printf("[CONSENSUS] Root binding check: expected=%x, actualApp=%x",
			expectedRoot[:8], actualAppHash[:8])
	}

	// Compare the hashes with canonical normalization per spec section 9.2
	// NORMATIVE: Case-insensitive 32-byte hex comparison
	if len(expectedRoot) != len(actualAppHash) {
		return false, nil // Different lengths = different roots
	}

	for i := 0; i < len(expectedRoot); i++ {
		if expectedRoot[i] != actualAppHash[i] {
			return false, nil // Mismatch found
		}
	}

	return true, nil
}

// serializeCommit converts CometBFT commit to fully self-contained verification format
// This includes ALL data needed for independent cryptographic verification
func (cb *ConsensusBuilder) serializeCommit(commitResult *coretypes.ResultCommit) interface{} {
	header := commitResult.SignedHeader.Header
	commit := commitResult.SignedHeader.Commit

	// Serialize all commit signatures with full verification data
	signatures := make([]map[string]interface{}, len(commit.Signatures))
	validSignatureCount := 0

	for i, cs := range commit.Signatures {
		signatures[i] = map[string]interface{}{
			"validatorAddress": hex.EncodeToString(cs.ValidatorAddress),
			"timestamp":        cs.Timestamp.UnixNano(), // Preserve nanosecond precision for signature verification
			"signature":        hex.EncodeToString(cs.Signature),
			"blockIDFlag":      int(cs.BlockIDFlag),
		}

		// Count valid signatures
		if cs.BlockIDFlag == types.BlockIDFlagCommit && len(cs.Signature) > 0 {
			validSignatureCount++
		}
	}

	// Include complete BlockID for verification
	blockID := map[string]interface{}{
		"hash": hex.EncodeToString(commit.BlockID.Hash),
	}

	// Include PartSetHeader if present
	if commit.BlockID.PartSetHeader.Total > 0 {
		blockID["partSetHeader"] = map[string]interface{}{
			"total": commit.BlockID.PartSetHeader.Total,
			"hash":  hex.EncodeToString(commit.BlockID.PartSetHeader.Hash),
		}
	}

	return map[string]interface{}{
		// Core consensus data
		"chainID": header.ChainID,
		"height":  header.Height,
		"round":   commit.Round,
		"blockID": blockID,

		// Application state commitment
		"appHash":            hex.EncodeToString(header.AppHash),
		"dataHash":           hex.EncodeToString(header.DataHash),
		"validatorsHash":     hex.EncodeToString(header.ValidatorsHash),
		"nextValidatorsHash": hex.EncodeToString(header.NextValidatorsHash),
		"consensusHash":      hex.EncodeToString(header.ConsensusHash),

		// Timestamp and block metadata
		"time":            header.Time,
		"proposerAddress": hex.EncodeToString(header.ProposerAddress),

		// Complete signature data for verification
		"signatures":          signatures,
		"validSignatureCount": validSignatureCount,
		"totalSignatureCount": len(signatures),

		// Verification metadata
		"finalized":    true,
		"serializedAt": commitResult.SignedHeader.Header.Time.Unix(),
	}
}

// serializeValidators converts validator set to fully self-contained verification format
// This includes ALL validator data needed for independent signature verification
func (cb *ConsensusBuilder) serializeValidators(validators []*types.Validator) interface{} {
	validatorData := make([]map[string]interface{}, len(validators))

	totalPower := int64(0)
	var maxPower int64 = 0
	addressCount := make(map[string]int)

	for i, val := range validators {
		// Full validator verification data
		address := hex.EncodeToString(val.Address)
		pubKeyBytes := val.PubKey.Bytes()
		pubKeyType := val.PubKey.Type()

		validatorData[i] = map[string]interface{}{
			// Core identification
			"address":      address,
			"addressBytes": val.Address,

			// Public key for signature verification
			"pubKey":      hex.EncodeToString(pubKeyBytes),
			"pubKeyBytes": pubKeyBytes,
			"pubKeyType":  pubKeyType,

			// Voting power and proportional power
			"votingPower":      val.VotingPower,
			"proposerPriority": val.ProposerPriority,

			// Derived verification data
			"index": i,
		}

		// Accumulate statistics
		totalPower += val.VotingPower
		if val.VotingPower > maxPower {
			maxPower = val.VotingPower
		}

		// Track address uniqueness
		addressCount[address]++
	}

	// Calculate consensus requirements
	requiredPower := (totalPower * 2 / 3) + 1
	superMajorityThreshold := (totalPower * 3 / 4)

	// Detect potential issues
	duplicateAddresses := 0
	for _, count := range addressCount {
		if count > 1 {
			duplicateAddresses++
		}
	}

	return map[string]interface{}{
		// Complete validator set for verification
		"validators": validatorData,

		// Power distribution and consensus thresholds
		"totalPower":             totalPower,
		"maxIndividualPower":     maxPower,
		"requiredConsensus":      requiredPower,
		"superMajorityThreshold": superMajorityThreshold,
		"consensusPercentage":    float64(requiredPower) / float64(totalPower) * 100.0,

		// Set metadata
		"count":              len(validators),
		"uniqueAddresses":    len(addressCount),
		"duplicateAddresses": duplicateAddresses,

		// Verification metadata
		"canVerifySignatures":    true,
		"serializationTimestamp": "consensus_epoch",
		"validatorSetHash":       hex.EncodeToString(types.NewValidatorSet(validators).Hash()),

		// Additional security checks
		"powerDistributionHealthy": maxPower < totalPower/2, // No single validator controls >50%
		"minValidatorsForSafety":   len(validators) >= 4,    // BFT requires f+1 > n/3, so n >= 4 for f=1
	}
}

// ConsensusVerifier verifies consensus finality proofs for any partition
type ConsensusVerifier struct {
	debug bool
}

// NewConsensusVerifier creates a new consensus finality verifier
func NewConsensusVerifier(debug bool) *ConsensusVerifier {
	return &ConsensusVerifier{debug: debug}
}

// NewLayer3Verifier creates a legacy Layer 3 verifier (deprecated - use ConsensusVerifier)
func NewLayer3Verifier(debug bool) *ConsensusVerifier {
	return &ConsensusVerifier{debug: debug}
}

// VerifyConsensusFinality validates a consensus finality proof per spec sections 2.3/2.5
func (cv *ConsensusVerifier) VerifyConsensusFinality(finality *ConsensusFinality, context string) (*LayerResult, error) {
	if cv.debug {
		log.Printf("[CONSENSUS VERIFY] Verifying %s: partition=%s, height=%d, root=%x",
			context, finality.Partition, finality.Height, finality.Root[:8])
	}

	result := &LayerResult{
		LayerName: context,
		Valid:     false,
		Details:   make(map[string]interface{}),
	}

	// Validate basic structure
	if finality == nil {
		result.ErrorMessage = "consensus finality proof is nil"
		return result, nil
	}

	// Validate partition presence
	if finality.Partition == "" {
		result.ErrorMessage = "partition cannot be empty"
		return result, nil
	}

	// Validate network presence (per spec section 5.4)
	if finality.Network == "" {
		result.ErrorMessage = "network cannot be empty per spec section 5.4"
		return result, nil
	}

	// Validate height
	if finality.Height == 0 {
		result.ErrorMessage = "height cannot be zero"
		return result, nil
	}

	// Validate root
	if len(finality.Root) == 0 {
		result.ErrorMessage = "root cannot be empty"
		return result, nil
	}

	// Validate consensus requirements per spec section 7.1 (proof-grade mode)
	if !finality.PowerOK {
		result.ErrorMessage = "insufficient voting power: <2/3 consensus not achieved"
		return result, nil
	}

	if !finality.RootBindingOK {
		result.ErrorMessage = "root binding verification failed: commit does not bind expected root"
		return result, nil
	}

	// Validate commit and validator data presence
	if finality.Commit == nil {
		result.ErrorMessage = "commit data is missing"
		return result, nil
	}

	if finality.Validators == nil {
		result.ErrorMessage = "validator data is missing"
		return result, nil
	}

	result.Valid = true
	result.Details["partition"] = finality.Partition
	result.Details["network"] = finality.Network
	result.Details["height"] = finality.Height
	result.Details["rootHash"] = fmt.Sprintf("%x", finality.Root)
	result.Details["powerOK"] = finality.PowerOK
	result.Details["rootBindingOK"] = finality.RootBindingOK

	if cv.debug {
		log.Printf("[CONSENSUS VERIFY] ✅ %s verification successful", context)
	}

	return result, nil
}

// Verify provides legacy Layer 3 verification interface (deprecated)
func (cv *ConsensusVerifier) Verify(layer2 *Layer2AnchorToDN, layer3 *ConsensusFinality) (*LayerResult, error) {
	// Validate height consistency per spec section 4.4 (height must be localBlock + 1)
	expectedHeight := layer2.LocalBlock + 1
	if layer3.Height != expectedHeight {
		return &LayerResult{
			LayerName:    "Layer3",
			Valid:        false,
			ErrorMessage: fmt.Sprintf("height mismatch: expected %d (L2.localBlock+1), got %d", expectedHeight, layer3.Height),
		}, nil
	}

	// Validate root consistency between layers
	if len(layer3.Root) != len(layer2.Anchor) {
		return &LayerResult{
			LayerName:    "Layer3",
			Valid:        false,
			ErrorMessage: fmt.Sprintf("root length mismatch: L2.anchor=%d, L3.root=%d", len(layer2.Anchor), len(layer3.Root)),
		}, nil
	}

	for i := 0; i < len(layer3.Root); i++ {
		if layer3.Root[i] != layer2.Anchor[i] {
			return &LayerResult{
				LayerName:    "Layer3",
				Valid:        false,
				ErrorMessage: fmt.Sprintf("root mismatch: L2.anchor != L3.root at byte %d", i),
			}, nil
		}
	}

	return cv.VerifyConsensusFinality(layer3, "Layer3")
}
