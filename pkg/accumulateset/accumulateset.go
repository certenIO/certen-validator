// Copyright 2026 Certen Protocol
//
// Package accumulateset is THE one reduction of an Accumulate validator set to the root CertenAnchorV8_2 commits (RB5 Phase B, design D2).
//
// Every path that produces or checks the committed root calls this file: the BLS signing of a member, both batch
// paths, the L5 artifact and cmd/proofverify. Two independent reductions of the same evidence is exactly how a signed
// value and a verified value drift apart, so there is only one.
//
// WHICH SET. The committed set is the one the proof's Directory L4 leg was verified against: the validator set and
// accept threshold in force at the partition that executed the Directory anchor, as of the block that executed it
// (layer4_validator_set.go). The Directory quorum certifies the whole L1-L3 chain - the BVN's root reaches the
// Directory's signed state through L2/L3 - so its set is the one the anchor certifies. A BVN leg's set is reported
// against this root by CompareLegSet, never folded into it.
package accumulateset

import (
	"encoding/hex"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// AccumulateSetRootInputs reduces a validator set and accept threshold, under an incarnation, to the canonical
// inputs of the certen:accval:v1 root. It validates every key; ordering is normalised by the root computation.
func AccumulateSetRootInputs(set []chained_proof.ValidatorKey, thr chained_proof.Rational, incarnation [32]byte) (
	contracts.AccumulateValidatorSetRootInputs, error,
) {
	out := contracts.AccumulateValidatorSetRootInputs{
		Incarnation:          incarnation,
		ThresholdNumerator:   thr.Numerator,
		ThresholdDenominator: thr.Denominator,
	}
	if len(set) == 0 {
		return out, fmt.Errorf("accumulate validator set: empty")
	}
	for i, v := range set {
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v.PublicKey)), "0x"))
		if err != nil || len(raw) != 32 {
			return out, fmt.Errorf("accumulate validator set: validator %d: public key must be 32 bytes of hex", i)
		}
		var pk [32]byte
		copy(pk[:], raw)
		activeOn := make([]string, len(v.ActiveOn))
		copy(activeOn, v.ActiveOn)
		out.Validators = append(out.Validators, contracts.AccumulateValidator{PublicKey: pk, ActiveOn: activeOn})
	}
	return out, nil
}

// AccumulateSetRoot is the certen:accval:v1 root of a validator set and threshold under an incarnation.
func AccumulateSetRoot(set []chained_proof.ValidatorKey, thr chained_proof.Rational, incarnation [32]byte) ([32]byte, error) {
	in, err := AccumulateSetRootInputs(set, thr, incarnation)
	if err != nil {
		return [32]byte{}, err
	}
	return contracts.ComputeAccumulateValidatorSetRoot(in)
}

// CommittedAccumulateSetInputs returns the inputs of the root a V8.2 anchor commits for a proof: its Directory leg's
// set and threshold. A proof without a Directory leg, or whose leg is not the Directory's, has no committable set.
func CommittedAccumulateSetInputs(dn *chained_proof.Layer4, incarnation [32]byte) (contracts.AccumulateValidatorSetRootInputs, error) {
	if dn == nil {
		return contracts.AccumulateValidatorSetRootInputs{}, fmt.Errorf("the proof carries no Directory L4 leg, so it " +
			"cannot say which Accumulate validator set it was checked against")
	}
	if !strings.EqualFold(dn.Partition, "Directory") {
		return contracts.AccumulateValidatorSetRootInputs{}, fmt.Errorf("the committed set is the Directory leg's; "+
			"this leg is partition %q", dn.Partition)
	}
	return AccumulateSetRootInputs(dn.ValidatorSet, dn.AcceptThreshold, incarnation)
}

// CommittedAccumulateSetRoot is the root a V8.2 anchor commits for a proof (see CommittedAccumulateSetInputs).
func CommittedAccumulateSetRoot(dn *chained_proof.Layer4, incarnation [32]byte) ([32]byte, error) {
	in, err := CommittedAccumulateSetInputs(dn, incarnation)
	if err != nil {
		return [32]byte{}, err
	}
	return contracts.ComputeAccumulateValidatorSetRoot(in)
}

// LegSetState is how a BVN leg's validator set relates to the committed (Directory-leg) root.
type LegSetState string

const (
	// LegSetCommitted: the BVN leg was checked against exactly the committed set.
	LegSetCommitted LegSetState = "committed"
	// LegSetNotCommitted: the BVN leg was checked against a different set - possible only while a validator-set change
	// is in flight between the two partitions' blocks. Not a failure: the Directory leg is what the anchor certifies;
	// this leg's set is named, with both roots, rather than claimed.
	LegSetNotCommitted LegSetState = "bvn_leg_set_not_committed"
)

// CompareLegSet reports a BVN leg's set against the committed root.
func CompareLegSet(bvn *chained_proof.Layer4, committed [32]byte, incarnation [32]byte) (LegSetState, [32]byte, error) {
	if bvn == nil {
		return "", [32]byte{}, fmt.Errorf("no BVN leg")
	}
	root, err := AccumulateSetRoot(bvn.ValidatorSet, bvn.AcceptThreshold, incarnation)
	if err != nil {
		return "", [32]byte{}, fmt.Errorf("BVN leg %s: %w", bvn.Partition, err)
	}
	if root == committed {
		return LegSetCommitted, root, nil
	}
	return LegSetNotCommitted, root, nil
}
