// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package core

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// Layer3Verifier handles Block Hash → Validator Signatures verification
type Layer3Verifier struct {
	cometURL string
	debug    bool
}

// NewLayer3Verifier creates a new Layer 3 verifier
// chainID is determined dynamically from block headers
func NewLayer3Verifier(cometURL string) *Layer3Verifier {
	return &Layer3Verifier{
		cometURL: cometURL,
	}
}

// VerifyBlockToValidators verifies Layer 3: Block Hash → Validator Signatures.
// This layer proves that a block was signed by the validator set with ≥ 2/3 power.
func (v *Layer3Verifier) VerifyBlockToValidators(ctx context.Context, blockHash string, blockHeight int64) (*Layer3Result, error) {
	result := &Layer3Result{
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
	}

	// Check if we have CometBFT access
	if v.cometURL == "" {
		result.Status = "CometBFT endpoint not configured"
		result.APILimitation = true
		return result, nil
	}

	// Discover the chain ID from the block header so VoteSignBytes is correct
	chainID, err := v.getChainID(blockHeight)
	if err != nil {
		result.Status = "Failed to fetch block header for chain ID"
		result.Error = fmt.Sprintf("failed to get block header: %v", err)
		result.APILimitation = true
		return result, nil
	}
	result.ChainID = chainID

	// Get commit (validator signatures) for the block
	commit, err := v.getBlockCommit(blockHeight)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get commit: %v", err)
		result.APILimitation = true
		return result, nil
	}
	result.Round = commit.Round

	// Get validator set for the block
	validators, err := v.getValidators(blockHeight)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get validators: %v", err)
		result.APILimitation = true
		return result, nil
	}

	// Build an address→validator map and compute total power
	type valInfo struct {
		PubKeyB64   string
		VotingPower int64
	}
	validatorMap := make(map[string]valInfo, len(validators.Validators))
	totalPower := int64(0)

	for _, val := range validators.Validators {
		validatorMap[val.Address] = valInfo{
			PubKeyB64:   val.PubKey.Value,
			VotingPower: val.VotingPower,
		}
		totalPower += val.VotingPower
	}

	// Verify signatures using address mapping
	validSignatures := 0
	signedPower := int64(0)

	for _, sig := range commit.Signatures {
		if sig.Signature == "" {
			continue // Validator didn't sign this block
		}

		info, ok := validatorMap[sig.ValidatorAddress]
		if !ok {
			// Signature from unknown validator (e.g., removed set); ignore
			continue
		}

		// Parse the timestamp from the signature
		timestamp, err := time.Parse(time.RFC3339Nano, sig.Timestamp)
		if err != nil {
			// If timestamp parse fails, skip this signature
			continue
		}

		verified := v.verifyValidatorSignature(
			chainID,
			info.PubKeyB64,
			sig.Signature,
			blockHash,
			blockHeight,
			commit.Round,
			timestamp,
		)

		if verified {
			validSignatures++
			signedPower += info.VotingPower
			result.ValidatorSignatures = append(result.ValidatorSignatures, ValidatorSig{
				Address:     sig.ValidatorAddress,
				PubKey:      info.PubKeyB64,
				VotingPower: info.VotingPower,
				Verified:    true,
			})
		}
	}

	// Populate aggregate stats
	result.TotalValidators = len(validators.Validators)
	result.SignedValidators = validSignatures
	result.TotalPower = totalPower
	result.SignedPower = signedPower

	// Byzantine fault tolerance requires 2/3+ of voting power
	threshold := (totalPower * 2 / 3) + 1
	result.ThresholdMet = signedPower >= threshold
	result.Verified = result.ThresholdMet

	if result.Verified {
		result.Status = "2/3+ validator signatures verified"
	} else {
		result.Error = fmt.Sprintf("insufficient voting power: %d/%d (need %d)",
			signedPower, totalPower, threshold)
	}

	return result, nil
}

// getBlockCommit fetches the commit (signatures) for a block
func (v *Layer3Verifier) getBlockCommit(height int64) (*CommitResponse, error) {
	url := fmt.Sprintf("%s/commit?height=%d", v.cometURL, height)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result struct {
			SignedHeader struct {
				Commit CommitResponse `json:"commit"`
			} `json:"signed_header"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result.Result.SignedHeader.Commit, nil
}

// getValidators fetches the validator set for a block
func (v *Layer3Verifier) getValidators(height int64) (*ValidatorSetResponse, error) {
	url := fmt.Sprintf("%s/validators?height=%d", v.cometURL, height)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result ValidatorSetResponse `json:"result"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result.Result, nil
}

// getChainID inspects the block header to determine the correct chain ID.
func (v *Layer3Verifier) getChainID(height int64) (string, error) {
	url := fmt.Sprintf("%s/block?height=%d", v.cometURL, height)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Result struct {
			Block struct {
				Header struct {
					ChainID string `json:"chain_id"`
				} `json:"header"`
			} `json:"block"`
		} `json:"result"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Result.Block.Header.ChainID, nil
}

// verifyValidatorSignature verifies a single validator's signature using CometBFT VoteSignBytes
func (v *Layer3Verifier) verifyValidatorSignature(chainID, pubKeyB64, signature, blockHash string, height int64, round int32, timestamp time.Time) bool {
	// Decode public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	// Decode block hash
	blockHashBytes, err := hex.DecodeString(blockHash)
	if err != nil {
		return false
	}

	// Construct the canonical vote that was signed - CRITICAL: include timestamp
	vote := &cmtproto.Vote{
		Type:      cmtproto.SignedMsgType(2), // SIGNED_MSG_TYPE_PRECOMMIT
		Height:    height,
		Round:     round,
		Timestamp: timestamp, // BREAKTHROUGH: This was the missing piece
		BlockID: cmtproto.BlockID{
			Hash: blockHashBytes,
			// Part set header would be here in full implementation
		},
	}

	// Get the bytes that were signed using the real chain ID
	signBytes := types.VoteSignBytes(chainID, vote)

	// Verify the signature
	return ed25519.Verify(pubKey, signBytes, sigBytes)
}

// VerifyValidatorSet validates that a validator set meets consensus requirements
// This is Paul Snow's generic validator set validation helper
func (v *Layer3Verifier) VerifyValidatorSet(validators *ValidatorSetResponse) (*ValidatorSetCheck, error) {
	check := &ValidatorSetCheck{
		TotalValidators: len(validators.Validators),
	}

	if check.TotalValidators == 0 {
		check.Valid = false
		check.Issues = append(check.Issues, "No validators in set")
		return check, fmt.Errorf("empty validator set")
	}

	totalPower := int64(0)
	uniqueAddresses := make(map[string]bool)
	uniquePubKeys := make(map[string]bool)

	for i, val := range validators.Validators {
		// Check for duplicate addresses
		if uniqueAddresses[val.Address] {
			check.Issues = append(check.Issues, fmt.Sprintf("Duplicate validator address: %s", val.Address))
			check.Valid = false
		}
		uniqueAddresses[val.Address] = true

		// Check for duplicate public keys
		if uniquePubKeys[val.PubKey.Value] {
			check.Issues = append(check.Issues, fmt.Sprintf("Duplicate public key: %s", val.PubKey.Value))
			check.Valid = false
		}
		uniquePubKeys[val.PubKey.Value] = true

		// Validate voting power is positive
		if val.VotingPower <= 0 {
			check.Issues = append(check.Issues, fmt.Sprintf("Invalid voting power for validator %d: %d", i, val.VotingPower))
			check.Valid = false
		}

		// Validate public key format
		pubKeyBytes, err := base64.StdEncoding.DecodeString(val.PubKey.Value)
		if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
			check.Issues = append(check.Issues, fmt.Sprintf("Invalid public key format for validator %d", i))
			check.Valid = false
		}

		totalPower += val.VotingPower
		check.ValidValidators++
	}

	check.TotalPower = totalPower

	// Ensure total power is positive
	if totalPower <= 0 {
		check.Valid = false
		check.Issues = append(check.Issues, "Total voting power must be positive")
	}

	// If no issues found, set as valid
	if len(check.Issues) == 0 {
		check.Valid = true
	}

	return check, nil
}

// VerifyByzantineAgreement checks if the signed power meets Byzantine fault tolerance
// This implements Paul Snow's Byzantine agreement verification helper
func (v *Layer3Verifier) VerifyByzantineAgreement(totalPower, signedPower int64, signatures []ValidatorSig) (*ByzantineCheck, error) {
	check := &ByzantineCheck{
		TotalPower:       totalPower,
		SignedPower:      signedPower,
		TotalSignatures:  len(signatures),
	}

	if totalPower <= 0 {
		check.Valid = false
		check.Issues = append(check.Issues, "Total voting power must be positive")
		return check, fmt.Errorf("invalid total power: %d", totalPower)
	}

	// Count valid signatures
	validSigs := 0
	for _, sig := range signatures {
		if sig.Verified {
			validSigs++
		}
	}
	check.ValidSignatures = validSigs

	// Calculate Byzantine fault tolerance threshold (2/3 + 1)
	threshold := (totalPower * 2 / 3) + 1
	check.RequiredPower = threshold

	// Check if signed power meets or exceeds threshold
	check.ThresholdMet = signedPower >= threshold
	check.Valid = check.ThresholdMet

	// Calculate power percentage
	if totalPower > 0 {
		check.PowerPercentage = float64(signedPower) / float64(totalPower) * 100.0
	}

	// Add diagnostic information
	if !check.ThresholdMet {
		check.Issues = append(check.Issues,
			fmt.Sprintf("Insufficient voting power: %d/%d (%.2f%%) < required %d (66.67%%)",
				signedPower, totalPower, check.PowerPercentage, threshold))
	}

	// Check for validator set health
	if validSigs < len(signatures)/2 {
		check.Issues = append(check.Issues,
			fmt.Sprintf("Low signature verification rate: %d/%d signatures verified",
				validSigs, len(signatures)))
	}

	return check, nil
}

// Layer3Result contains the results of Layer 3 verification
type Layer3Result struct {
	Verified            bool           `json:"verified"`
	BlockHash           string         `json:"blockHash"`
	BlockHeight         int64          `json:"blockHeight"`
	ChainID             string         `json:"chainId"`
	Round               int32          `json:"round"`
	TotalValidators     int            `json:"totalValidators"`
	SignedValidators    int            `json:"signedValidators"`
	TotalPower          int64          `json:"totalPower"`
	SignedPower         int64          `json:"signedPower"`
	ThresholdMet        bool           `json:"thresholdMet"`
	ValidatorSignatures []ValidatorSig `json:"validatorSignatures,omitempty"`
	Status              string         `json:"status,omitempty"`
	APILimitation       bool           `json:"apiLimitation,omitempty"`
	Error               string         `json:"error,omitempty"`
}

// ValidatorSig represents a validator's signature verification
type ValidatorSig struct {
	Address     string `json:"address"`
	PubKey      string `json:"pubKey"`
	VotingPower int64  `json:"votingPower"`
	Verified    bool   `json:"verified"`
}

// CommitResponse represents the commit data from CometBFT
type CommitResponse struct {
	Height     string `json:"height"`
	Round      int32  `json:"round"`
	Signatures []struct {
		BlockIDFlag      int    `json:"block_id_flag"`
		ValidatorAddress string `json:"validator_address"`
		Timestamp        string `json:"timestamp"`
		Signature        string `json:"signature"`
	} `json:"signatures"`
}

// ValidatorSetResponse represents validators from CometBFT
type ValidatorSetResponse struct {
	BlockHeight string `json:"block_height"`
	Validators  []struct {
		Address     string `json:"address"`
		PubKey      struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"pub_key"`
		VotingPower int64 `json:"voting_power,string"`
	} `json:"validators"`
}

// ValidatorSetCheck represents the result of Paul Snow's validator set validation
type ValidatorSetCheck struct {
	Valid           bool     `json:"valid"`
	TotalValidators int      `json:"totalValidators"`
	ValidValidators int      `json:"validValidators"`
	TotalPower      int64    `json:"totalPower"`
	Issues          []string `json:"issues,omitempty"`
}

// ByzantineCheck represents the result of Paul Snow's Byzantine agreement verification
type ByzantineCheck struct {
	Valid            bool     `json:"valid"`
	TotalPower       int64    `json:"totalPower"`
	SignedPower      int64    `json:"signedPower"`
	RequiredPower    int64    `json:"requiredPower"`
	PowerPercentage  float64  `json:"powerPercentage"`
	ThresholdMet     bool     `json:"thresholdMet"`
	TotalSignatures  int      `json:"totalSignatures"`
	ValidSignatures  int      `json:"validSignatures"`
	Issues           []string `json:"issues,omitempty"`
}

// SetDebug enables or disables debug output for Layer 3 verification
func (v *Layer3Verifier) SetDebug(debug bool) {
	v.debug = debug
}