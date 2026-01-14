// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Layer4Verifier handles validator set to genesis trust chain (Validator Set → Genesis Trust)
type Layer4Verifier struct {
	debug        bool
	genesisHash  []byte
	genesisVals  []Validator
}

// NewLayer4Verifier creates a new Layer 4 verifier
func NewLayer4Verifier(genesisHash []byte, genesisValidators []Validator, debug bool) *Layer4Verifier {
	return &Layer4Verifier{
		debug:       debug,
		genesisHash: genesisHash,
		genesisVals: genesisValidators,
	}
}

// VerifyValidatorChain verifies the chain of validator transitions from genesis to current
func (v *Layer4Verifier) VerifyValidatorChain(currentValidators []Validator,
	currentHeight int64, transitions []ValidatorTransition) (bool, error) {

	if v.genesisHash == nil || len(v.genesisHash) == 0 {
		return false, fmt.Errorf("genesis hash not set")
	}

	if len(v.genesisVals) == 0 {
		return false, fmt.Errorf("genesis validators not set")
	}

	if v.debug {
		fmt.Printf("Layer 4 Verification:\n")
		fmt.Printf("  Genesis Hash: %x\n", v.genesisHash[:16])
		fmt.Printf("  Genesis Validators: %d\n", len(v.genesisVals))
		fmt.Printf("  Current Height: %d\n", currentHeight)
		fmt.Printf("  Transitions: %d\n", len(transitions))
	}

	// Start with genesis validators
	currentVals := v.genesisVals
	lastHeight := int64(0)

	// Process each transition in order
	for i, transition := range transitions {
		if v.debug {
			fmt.Printf("  Transition %d: Height %d -> %d\n",
				i+1, transition.FromHeight, transition.ToHeight)
		}

		// Verify height continuity
		if transition.FromHeight != lastHeight {
			return false, fmt.Errorf("transition gap at index %d: expected from %d, got %d",
				i, lastHeight, transition.FromHeight)
		}

		// Verify the transition is signed by 2/3+ of the old validators
		if !v.verifyTransition(currentVals, transition) {
			if v.debug {
				fmt.Printf("  ❌ Invalid transition at index %d\n", i)
			}
			return false, fmt.Errorf("invalid transition at index %d", i)
		}

		// Update to new validator set
		currentVals = transition.NewValidators
		lastHeight = transition.ToHeight

		if v.debug {
			fmt.Printf("  ✓ Transition verified: %d validators -> %d validators\n",
				len(transition.OldValidators), len(transition.NewValidators))
		}
	}

	// Verify final validator set matches current
	if !v.validatorSetsEqual(currentVals, currentValidators) {
		if v.debug {
			fmt.Printf("  ❌ Final validator set mismatch!\n")
		}
		return false, fmt.Errorf("final validator set does not match current")
	}

	if v.debug {
		fmt.Printf("  ✅ Validator chain verified from genesis!\n")
	}

	return true, nil
}

// verifyTransition verifies that a validator set transition is properly signed
func (v *Layer4Verifier) verifyTransition(oldValidators []Validator,
	transition ValidatorTransition) bool {

	// Calculate total voting power of old validators
	totalPower := int64(0)
	for _, val := range oldValidators {
		totalPower += val.VotingPower
	}

	// Need 2/3 + 1 of voting power
	requiredPower := (totalPower * 2 / 3) + 1
	signedPower := int64(0)

	// Create message to be signed (hash of new validator set)
	message := v.createTransitionMessage(transition)

	// Verify signatures from old validators
	for i, sig := range transition.Signatures {
		if i >= len(oldValidators) {
			continue
		}

		validator := oldValidators[i]

		// Verify the signature
		if ed25519.Verify(validator.PublicKey, message, sig) {
			signedPower += validator.VotingPower
		}
	}

	return signedPower >= requiredPower
}

// createTransitionMessage creates the message that validators sign for a transition
func (v *Layer4Verifier) createTransitionMessage(transition ValidatorTransition) []byte {
	hasher := sha256.New()

	// Include height range
	binary.Write(hasher, binary.BigEndian, transition.FromHeight)
	binary.Write(hasher, binary.BigEndian, transition.ToHeight)

	// Include hash of old validator set
	for _, val := range transition.OldValidators {
		hasher.Write(val.Address)
		hasher.Write(val.PublicKey)
		binary.Write(hasher, binary.BigEndian, val.VotingPower)
	}

	// Include hash of new validator set
	for _, val := range transition.NewValidators {
		hasher.Write(val.Address)
		hasher.Write(val.PublicKey)
		binary.Write(hasher, binary.BigEndian, val.VotingPower)
	}

	return hasher.Sum(nil)
}

// validatorSetsEqual checks if two validator sets are equal
func (v *Layer4Verifier) validatorSetsEqual(set1, set2 []Validator) bool {
	if len(set1) != len(set2) {
		return false
	}

	for i := range set1 {
		if !bytes.Equal(set1[i].Address, set2[i].Address) {
			return false
		}
		if !bytes.Equal(set1[i].PublicKey, set2[i].PublicKey) {
			return false
		}
		if set1[i].VotingPower != set2[i].VotingPower {
			return false
		}
	}

	return true
}

// VerifyGenesisLink verifies that a validator set can be traced back to genesis
func (v *Layer4Verifier) VerifyGenesisLink(validators []Validator, height int64) (bool, error) {
	// For height 0 or 1, validators should match genesis
	if height <= 1 {
		if !v.validatorSetsEqual(validators, v.genesisVals) {
			return false, fmt.Errorf("validators at height %d do not match genesis", height)
		}
		return true, nil
	}

	// For other heights, we need the transition chain
	// This would be provided by the API in a full implementation
	return false, fmt.Errorf("validator transitions not available for height %d", height)
}

// ComputeGenesisHash computes the hash of the genesis state
func (v *Layer4Verifier) ComputeGenesisHash(genesisValidators []Validator) []byte {
	hasher := sha256.New()

	// Hash the validator set
	for _, val := range genesisValidators {
		hasher.Write(val.Address)
		hasher.Write(val.PublicKey)
		binary.Write(hasher, binary.BigEndian, val.VotingPower)
	}

	return hasher.Sum(nil)
}

// GetTrustRoot returns the trust root (genesis hash)
func (v *Layer4Verifier) GetTrustRoot() []byte {
	return v.genesisHash
}

// SetGenesisValidators updates the genesis validators
func (v *Layer4Verifier) SetGenesisValidators(validators []Validator) {
	v.genesisVals = validators
}

// TracePath traces the validator transition path from genesis to a given height
func (v *Layer4Verifier) TracePath(targetHeight int64, transitions []ValidatorTransition) ([]int64, error) {
	if targetHeight <= 0 {
		return []int64{0}, nil
	}

	path := []int64{0} // Start from genesis
	currentHeight := int64(0)

	for _, transition := range transitions {
		if transition.FromHeight != currentHeight {
			return nil, fmt.Errorf("gap in transition chain at height %d", currentHeight)
		}

		path = append(path, transition.ToHeight)
		currentHeight = transition.ToHeight

		if currentHeight >= targetHeight {
			break
		}
	}

	if currentHeight < targetHeight {
		return nil, fmt.Errorf("transitions do not reach target height %d", targetHeight)
	}

	return path, nil
}

// ValidateTransitionChain validates the structure of a transition chain
func (v *Layer4Verifier) ValidateTransitionChain(transitions []ValidatorTransition) error {
	if len(transitions) == 0 {
		return nil // Empty chain is valid
	}

	lastHeight := int64(0)

	for i, transition := range transitions {
		// Check height continuity
		if transition.FromHeight != lastHeight {
			return fmt.Errorf("transition %d: height gap from %d to %d",
				i, lastHeight, transition.FromHeight)
		}

		// Check height ordering
		if transition.ToHeight <= transition.FromHeight {
			return fmt.Errorf("transition %d: invalid height range %d to %d",
				i, transition.FromHeight, transition.ToHeight)
		}

		// Check validator sets are not empty
		if len(transition.OldValidators) == 0 {
			return fmt.Errorf("transition %d: empty old validator set", i)
		}

		if len(transition.NewValidators) == 0 {
			return fmt.Errorf("transition %d: empty new validator set", i)
		}

		// Check signatures exist
		if len(transition.Signatures) == 0 {
			return fmt.Errorf("transition %d: no signatures", i)
		}

		lastHeight = transition.ToHeight
	}

	if v.debug {
		fmt.Printf("Transition chain validated: %d transitions from height 0 to %d\n",
			len(transitions), lastHeight)
	}

	return nil
}

// PrintValidatorSetInfo prints information about a validator set
func (v *Layer4Verifier) PrintValidatorSetInfo(validators []Validator, label string) {
	if !v.debug {
		return
	}

	totalPower := int64(0)
	for _, val := range validators {
		totalPower += val.VotingPower
	}

	fmt.Printf("%s:\n", label)
	fmt.Printf("  Validators: %d\n", len(validators))
	fmt.Printf("  Total Power: %d\n", totalPower)

	for i, val := range validators {
		fmt.Printf("    [%d] %s: %d power\n",
			i,
			hex.EncodeToString(val.Address[:8]),
			val.VotingPower)
	}
}