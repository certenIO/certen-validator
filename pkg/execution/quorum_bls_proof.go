package execution

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// One path from a quorum aggregate to the BLSProofData a CertenAnchorV8_2 checks (verifyQuorumAttestation and
// _verifyBLSProof): the batch anchor's attestation and the outcome record (RB5 D4) both go through it, so the rules
// are written once.
//
// It is strict (RB5-F55). The proof is generated against the AGGREGATE public key the quorum's signature verifies
// under - never another key - and is verified locally and again from its exact ABI bytes before it is used. Every
// failure is an error naming its cause; nothing returns an empty proof to be submitted anyway.

// ErrQuorumProof is wrapped by every failure to produce a quorum's BLS proof.
var ErrQuorumProof = errors.New("quorum BLS proof")

// quorumSignerSet is the signer set the contract recomputes: the SIGNERS, each at its registered power, in the
// aggregate's order - never the roster.
//
// _verifyBLSQuorum does not take signedVotingPower on trust. It walks validatorAddresses, looks each address up in
// the anchor's own registry, refuses unregistered entries, duplicates and mis-declared powers, and then requires
//
//	blsProof.signedVotingPower == sum(registered power of validatorAddresses)
//
// Passing the full seven-validator roster alongside a 600/700 signed power therefore fails: the contract recomputes
// 700 and rejects. That is exactly what a 6-of-7 batch hit live on 2026-08-02 - the aggregate and the ZK proof were
// both correct, and the submission was rejected on the declared signer SET. The roster still reaches the contract,
// via totalVotingPower, which it compares against its own stored total.
func quorumSignerSet(agg *consensus.QuorumAggregate) (validators []common.Address, powers []*big.Int, err error) {
	if agg == nil {
		return nil, nil, fmt.Errorf("%w: nil quorum aggregate; refusing to submit an unattested batch root", ErrQuorumProof)
	}
	if agg.SignedVotingPower == nil || agg.SignedVotingPower.Sign() <= 0 {
		return nil, nil, fmt.Errorf("%w: quorum aggregate reports no signed voting power", ErrQuorumProof)
	}
	if agg.TotalVotingPower == nil || agg.TotalVotingPower.Sign() <= 0 {
		return nil, nil, fmt.Errorf("%w: the aggregate reports no total voting power", ErrQuorumProof)
	}
	if len(agg.Signers) < 2 {
		// AggregateBatchAttestations already enforces the threshold by power; this is against a degenerate registry
		// producing a single-signer aggregate that the anchor's authorized-subset commitments would reject anyway.
		return nil, nil, fmt.Errorf("%w: refusing to submit a %d-signer aggregate: the anchor's authorized pubkey "+
			"commitments cover subsets of 5, 6 and 7 only", ErrQuorumProof, len(agg.Signers))
	}
	if len(agg.SignerPowers) != len(agg.Signers) {
		return nil, nil, fmt.Errorf("%w: aggregate reports %d signers but %d powers; refusing to submit an inconsistent "+
			"signer set", ErrQuorumProof, len(agg.Signers), len(agg.SignerPowers))
	}
	check := big.NewInt(0)
	for i, s := range agg.Signers {
		if !common.IsHexAddress(s) {
			return nil, nil, fmt.Errorf("%w: signer %q is not an EVM address", ErrQuorumProof, s)
		}
		p := agg.SignerPowers[i]
		if p == nil || p.Sign() <= 0 {
			return nil, nil, fmt.Errorf("%w: signer %s has no power", ErrQuorumProof, s)
		}
		validators = append(validators, common.HexToAddress(s))
		powers = append(powers, new(big.Int).Set(p))
		check.Add(check, p)
	}
	// The contract's own rule, restated so a mismatch is named here rather than reverted there.
	if check.Cmp(agg.SignedVotingPower) != 0 {
		return nil, nil, fmt.Errorf("%w: declared signed power %s does not equal the sum of the signers' registered powers %s; "+
			"the anchor would reject this", ErrQuorumProof, agg.SignedVotingPower, check)
	}
	return validators, powers, nil
}

// proveQuorumBLSWithKey is the Groth16 proof that the BLS signature sig over messageHash verifies under pubKey with the
// given powers, as the anchor's verifier checks it: generated, verified locally, serialized, and verified again from
// those exact bytes. It returns the proof bytes and the pubkey commitment, or an error naming the step that failed.
func (ecm *EthereumContractManager) proveQuorumBLSWithKey(
	sig []byte, messageHash [32]byte, signed, total *big.Int, pubKey []byte,
) ([]byte, [32]byte, error) {
	var zero [32]byte
	if len(sig) == 0 {
		return nil, zero, fmt.Errorf("%w: empty aggregate signature", ErrQuorumProof)
	}
	if len(pubKey) < 96 {
		return nil, zero, fmt.Errorf("%w: public key is %d bytes, a BLS12-381 G2 key is 96", ErrQuorumProof, len(pubKey))
	}
	if signed == nil || total == nil || !signed.IsUint64() || !total.IsUint64() {
		return nil, zero, fmt.Errorf("%w: voting powers %v/%v do not fit the circuit's inputs", ErrQuorumProof, signed, total)
	}
	prover, err := GetBLSZKProver()
	if err != nil {
		return nil, zero, fmt.Errorf("%w: the ZK prover is not available: %v", ErrQuorumProof, err)
	}
	if prover == nil {
		return nil, zero, fmt.Errorf("%w: the ZK prover is not available", ErrQuorumProof)
	}
	witness, err := bls_zkp.CreateWitnessFromBLSData(messageHash, sig, pubKey, signed.Uint64(), total.Uint64())
	if err != nil {
		return nil, zero, fmt.Errorf("%w: witness: %v", ErrQuorumProof, err)
	}
	proof, err := prover.GenerateProof(witness)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: Groth16 proof: %v", ErrQuorumProof, err)
	}
	if ok, err := prover.VerifyProofLocally(proof); err != nil || !ok {
		return nil, zero, fmt.Errorf("%w: the proof does not verify locally (ok=%v): %v", ErrQuorumProof, ok, err)
	}
	proofBytes, err := proof.ToSolidityCalldata()
	if err != nil {
		return nil, zero, fmt.Errorf("%w: serialize: %v", ErrQuorumProof, err)
	}
	// The bytes that go on chain, verified again: a serialization bug would otherwise be found by a revert.
	if ok, err := prover.VerifyFromABIBytes(proofBytes); err != nil || !ok {
		return nil, zero, fmt.Errorf("%w: the serialized proof does not verify (ok=%v): %v", ErrQuorumProof, ok, err)
	}
	return proofBytes, proof.PubkeyCommitment, nil
}

// proveQuorumBLS proves an aggregate against its own AGGREGATE public key (hex), the key the aggregate signature
// verifies under - AggregateBatchAttestations checked exactly that relation. There is no other key to fall back to.
func (ecm *EthereumContractManager) proveQuorumBLS(sig []byte, messageHash [32]byte, signed, total *big.Int, aggPubKeyHex string) ([]byte, [32]byte, error) {
	h := strings.TrimPrefix(strings.TrimSpace(aggPubKeyHex), "0x")
	if h == "" {
		return nil, [32]byte{}, fmt.Errorf("%w: the aggregate carries no public key", ErrQuorumProof)
	}
	pub, err := hex.DecodeString(h)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: the aggregate public key is not hex: %v", ErrQuorumProof, err)
	}
	return ecm.proveQuorumBLSWithKey(sig, messageHash, signed, total, pub)
}

// BuildQuorumBLSProofData is the BLSProofData for a quorum aggregate over messageHash: the Groth16 blob as
// aggregateSignature, the signers at their registered powers, the totals, and thresholdMet COMPUTED from them, never
// asserted (an asserted flag would let a sub-threshold aggregate claim compliance the arithmetic does not support).
func (ecm *EthereumContractManager) BuildQuorumBLSProofData(agg *consensus.QuorumAggregate, messageHash [32]byte) (contracts.CertenAnchorV4BLSProofData, [32]byte, error) {
	var none contracts.CertenAnchorV4BLSProofData
	validators, powers, err := quorumSignerSet(agg)
	if err != nil {
		return none, [32]byte{}, err
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(agg.AggregateSignatureHex, "0x"))
	if err != nil {
		return none, [32]byte{}, fmt.Errorf("%w: the aggregate signature is not hex: %v", ErrQuorumProof, err)
	}
	proofBytes, commitment, err := ecm.proveQuorumBLS(sig, messageHash, agg.SignedVotingPower, agg.TotalVotingPower, agg.AggregatePublicKeyHex)
	if err != nil {
		return none, [32]byte{}, err
	}
	return contracts.CertenAnchorV4BLSProofData{
		AggregateSignature: proofBytes,
		ValidatorAddresses: validators,
		VotingPowers:       powers,
		TotalVotingPower:   new(big.Int).Set(agg.TotalVotingPower),
		SignedVotingPower:  new(big.Int).Set(agg.SignedVotingPower),
		ThresholdMet: new(big.Int).Mul(agg.SignedVotingPower, big.NewInt(batchQuorumThresholdDen)).
			Cmp(new(big.Int).Mul(agg.TotalVotingPower, big.NewInt(batchQuorumThresholdNum))) >= 0,
		MessageHash: messageHash,
	}, commitment, nil
}
