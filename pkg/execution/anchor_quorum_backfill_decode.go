package execution

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// DecodeExecuteComprehensiveProof turns a verify transaction's calldata back into what it asserted.
//
// It decodes with the SAME generated ABI the submitter packs with, so a shape the submitter could not
// have produced fails here rather than becoming a half-understood row. Nothing decoded is trusted:
// VerifyBackfilledQuorum checks every field against anchor state and the on-chain registry.
func DecodeExecuteComprehensiveProof(input []byte) (*DecodedVerifyCall, error) {
	parsed, err := contracts.CertenAnchorV4MetaData.GetAbi()
	if err != nil {
		return nil, fmt.Errorf("anchor ABI: %w", err)
	}
	method, ok := parsed.Methods["executeComprehensiveProof"]
	if !ok {
		return nil, fmt.Errorf("the anchor ABI has no executeComprehensiveProof method")
	}
	if len(input) < 4 {
		return nil, fmt.Errorf("calldata is %d bytes, too short for a selector", len(input))
	}
	if !bytes.Equal(input[:4], method.ID) {
		return nil, fmt.Errorf("selector 0x%x is not executeComprehensiveProof (0x%x)", input[:4], method.ID)
	}

	args, err := method.Inputs.Unpack(input[4:])
	if err != nil {
		return nil, fmt.Errorf("unpacking arguments: %w", err)
	}
	if len(args) != 2 {
		return nil, fmt.Errorf("expected 2 arguments, got %d", len(args))
	}

	anchorID, ok := args[0].([32]byte)
	if !ok {
		return nil, fmt.Errorf("first argument is not a bytes32 anchor id")
	}
	proof := abi.ConvertType(args[1], new(contracts.CertenAnchorV4CertenProof)).(*contracts.CertenAnchorV4CertenProof)
	if proof == nil {
		return nil, fmt.Errorf("second argument is not a CertenProof")
	}

	bls := proof.BlsProof
	if len(bls.ValidatorAddresses) != len(bls.VotingPowers) {
		return nil, fmt.Errorf("proof declares %d signer addresses and %d powers",
			len(bls.ValidatorAddresses), len(bls.VotingPowers))
	}

	signers := make([]string, 0, len(bls.ValidatorAddresses))
	powers := make([]*big.Int, 0, len(bls.VotingPowers))
	for i, a := range bls.ValidatorAddresses {
		signers = append(signers, strings.ToLower(a.Hex()))
		if bls.VotingPowers[i] == nil {
			return nil, fmt.Errorf("signer %s carries a nil power", a.Hex())
		}
		powers = append(powers, new(big.Int).Set(bls.VotingPowers[i]))
	}

	call := &DecodedVerifyCall{
		BundleID:    anchorID,
		MerkleRoot:  proof.MerkleRoot,
		MessageHash: bls.MessageHash,
		// The operation id a batch proof commits to is the operation COMMITMENT; the submitter sets it
		// from batchOperationID and the anchor requires it to equal its own stored value.
		OperationID:       proof.Commitments.OperationCommitment,
		Signers:           signers,
		SignerPowers:      powers,
		SignedVotingPower: copyInt(bls.SignedVotingPower),
		TotalVotingPower:  copyInt(bls.TotalVotingPower),
	}
	return call, nil
}

func copyInt(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	return new(big.Int).Set(v)
}
