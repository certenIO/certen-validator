// Copyright 2026 Certen Protocol
//
// The L5 extension — carrying the Accumulate half.
//
// # WHAT THIS ADDS, AND WHY L5 IS THE RIGHT PLACE
//
// V8.2's anchor pre-exec message commits two new fields:
// accumulateValidatorSetRoot and accumulateIncarnation. A commitment nobody can
// expand is decoration that looks like coverage, so something has to carry the
// expansion. L5 carries it, for three reasons:
//
//  1. L5 is the layer that already reaches the external chain. The root is
//     committed in the anchor transaction L5 already names; the expansion
//     belongs beside the coordinates that point at it.
//  2. L5 is NOT hashed into govRoot. govRoot commits L1-L4 and G0-G2 only, so
//     adding a field here moves no signed preimage. TestP6_GovRootInvariant_GoldenSlots
//     and TestP6_CanonicalShapesUnchanged must keep passing unmodified.
//  3. An external anchor is the only artefact that survives a re-genesis, so it
//     is exactly where the INCARNATION identity needs to be recorded. A
//     permanent on-chain record that cannot say which chain it refers to is
//     worth less than it looks.
//
// # WHAT IT DOES NOT CHANGE
//
// L5's claim is still EXISTENCE AND TIME. The extension does not upgrade it, and
// nothing here should be read as making L5 a governance proof. What changes is
// that a reader can now expand the root the anchor committed and see the
// validator set behind it, instead of taking it on faith.
//
// # MANDATORY TO RECORD, NEVER MANDATORY TO VERIFY
//
// A proof lacking the extension is in a named weaker state, never a rejection.
// If a missing extension invalidated a proof, an anchoring or evidence outage
// would become a governance-proof failure — the capability-limit-as-governance-
// rejection defect this codebase has removed twice.
package execution

import (
	"encoding/hex"
	"fmt"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// AccumulateBinding is the L5 extension: which Accumulate chain this proof is
// about, and the evidence for the validator set the anchor committed to.
//
// It rides BESIDE Layer5's verified fields. Layer5.VerifyOffline's existing
// steps 1-4 are untouched, and a Layer5 with a nil binding verifies exactly as
// it did before.
type AccumulateBinding struct {
	// Incarnation is the genesis root anchor of the Accumulate chain —
	// anchor(directory)-root[0]. Nothing in an L4 leg identifies its chain: the
	// signed preimage is a SequencedMessage over a PartitionAnchor, and every
	// URL in it is a protocol constant identical across MainNet, Kermit, and
	// every incarnation of both.
	Incarnation string `json:"incarnation,omitempty"` // hex32

	// ValidatorSetRoot is the value CertenAnchorV8_2's pre-exec message commits,
	// restated here so a reader can compare it against the anchor transaction
	// without re-deriving it. It is RECOMPUTED from ValidatorSetProof during
	// verification and is not trusted.
	ValidatorSetRoot string `json:"validatorSetRoot,omitempty"` // hex32

	// ValidatorSetProof expands ValidatorSetRoot: the account bytes, the BPT
	// membership path, and the chain roots that bind the account's own history
	// length. Without it the committed root cannot be checked by anyone.
	ValidatorSetProof *certenproof.ValidatorSetProof `json:"validatorSetProof,omitempty"`
}

// AccumulateBindingResult is what a verifier learns from the extension. It is
// deliberately separate from Layer5.VerifyOffline's error return: the extension
// being absent or unbindable is a named state, not a failure of L5.
type AccumulateBindingResult struct {
	// Present is false when no extension was recorded.
	Present bool

	// Verdict is the ValidatorSetProof's verdict, or empty when Present is false.
	Verdict certenproof.Verdict

	// Err is set only when the extension is present and PROVEN WRONG.
	Err error
}

// Claim renders the result as a sentence an operator can act on, never
// overstating what was established.
func (r AccumulateBindingResult) Claim() string {
	switch {
	case r.Err != nil:
		return fmt.Sprintf("the Accumulate binding is present and does NOT check out: %v", r.Err)
	case !r.Present:
		return "no Accumulate binding recorded; the validator set that signed L4 is asserted " +
			"by this proof rather than derived from chain state"
	case r.Verdict == certenproof.VerdictVerified:
		return "the Accumulate validator set was derived from chain state, bound to a " +
			"quorum-signed anchor, and matches the pinned incarnation"
	default:
		return fmt.Sprintf("the Accumulate binding is present and reached %q — a weaker state "+
			"than a full verification; nothing about it is known to be wrong", r.Verdict)
	}
}

// VerifyAccumulateBinding checks the extension, if present.
//
// pinnedIncarnation is the verifier's OUT-OF-BAND value and may be nil. Without
// it the best reachable verdict is incarnation_unverified, because the
// derivation is otherwise circular: the validator set authenticates the anchor
// and the anchor authenticates the set.
//
// boundStateTreeAnchor is the Directory L4 leg's StateTreeAnchor, or empty when
// the caller has none. Empty yields validator_set_unbound rather than an error —
// see pkg/proof/validator_set_builder.go for why that is the normal outcome
// today rather than an anomaly.
func (b *AccumulateBinding) Verify(
	assertedSet []chained_proof.ValidatorKey,
	assertedThreshold chained_proof.Rational,
	boundStateTreeAnchor string,
	pinnedIncarnation *string,
) AccumulateBindingResult {
	if b == nil || b.ValidatorSetProof == nil {
		return AccumulateBindingResult{Present: false}
	}

	// The restated root must equal what the evidence actually produces, or the
	// value a reader would compare against the anchor transaction is a fiction.
	if b.ValidatorSetRoot != "" {
		got, err := AccumulateSetRoot(b.ValidatorSetProof)
		if err != nil {
			return AccumulateBindingResult{Present: true, Err: err}
		}
		if !strings.EqualFold(got, strings.TrimPrefix(b.ValidatorSetRoot, "0x")) {
			return AccumulateBindingResult{Present: true, Err: fmt.Errorf(
				"the restated validatorSetRoot is not what this evidence produces: "+
					"computed=%s restated=%s", got[:16], b.ValidatorSetRoot[:16])}
		}
	}

	// The incarnation is recorded in two places; they must agree.
	if b.Incarnation != "" && b.ValidatorSetProof.Incarnation != "" &&
		!strings.EqualFold(b.Incarnation, b.ValidatorSetProof.Incarnation) {
		return AccumulateBindingResult{Present: true, Err: fmt.Errorf(
			"the binding and its validator-set proof name different incarnations: %s vs %s",
			b.Incarnation[:16], b.ValidatorSetProof.Incarnation[:16])}
	}

	verdict, err := b.ValidatorSetProof.Verify(certenproof.VerifyInput{
		AssertedSet:          assertedSet,
		AssertedThreshold:    assertedThreshold,
		BoundStateTreeAnchor: boundStateTreeAnchor,
		PinnedIncarnation:    pinnedIncarnation,
	})
	if err != nil {
		return AccumulateBindingResult{Present: true, Err: err}
	}
	return AccumulateBindingResult{Present: true, Verdict: verdict}
}

// AccumulateSetRoot computes the canonical root that CertenAnchorV8_2's pre-exec
// message commits, from the evidence a ValidatorSetProof carries.
//
// It lives here rather than in pkg/proof because the canonical encoding is in
// pkg/execution/contracts, which is deliberately free of certen-internal imports
// so both the signing and submission paths can use it without a cycle. Computing
// it in one place is what stops the artifact and the anchor message disagreeing
// about what was committed.
func AccumulateSetRoot(p *certenproof.ValidatorSetProof) (string, error) {
	if p == nil {
		return "", fmt.Errorf("no validator-set proof")
	}
	set, thr, err := p.DerivedSet()
	if err != nil {
		return "", err
	}
	incRaw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(p.Incarnation), "0x"))
	if err != nil || len(incRaw) != 32 {
		return "", fmt.Errorf("incarnation must be 32 bytes of hex")
	}
	in := contracts.AccumulateValidatorSetRootInputs{
		ThresholdNumerator:   thr.Numerator,
		ThresholdDenominator: thr.Denominator,
	}
	copy(in.Incarnation[:], incRaw)
	for i, v := range set {
		pk, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(v.PublicKey), "0x"))
		if err != nil || len(pk) != 32 {
			return "", fmt.Errorf("validator %d: public key must be 32 bytes of hex", i)
		}
		var k [32]byte
		copy(k[:], pk)
		activeOn := make([]string, len(v.ActiveOn))
		copy(activeOn, v.ActiveOn)
		in.Validators = append(in.Validators, contracts.AccumulateValidator{
			PublicKey: k, ActiveOn: activeOn,
		})
	}
	root, err := contracts.ComputeAccumulateValidatorSetRoot(in)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(root[:]), nil
}
