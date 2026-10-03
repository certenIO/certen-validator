package execution

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// Wiring the Accumulate validator-set evidence into every V8.2 proof (RB5-F4).
//
// The L5 extension (AccumulateBinding) and its verifier existed, but nothing produced it: every stored proof's layer 5
// carried no validator-set evidence, so the set its L4 was verified against stayed ASSERTED by the proof itself. Each
// V8.2 proof now carries a ValidatorSetProof - the Directory's validator set and threshold DERIVED from the
// acc://dn.acme/network and /globals account bytes with their BPT membership paths - and proofverify checks it.
//
// What it reaches today is VerdictValidatorSetUnbound, by construction: an account query proves into the serving node's
// CURRENT BPT root, which is not the root of the anchor the proof's L4 signed. Binding it there needs a membership proof
// against a HISTORICAL root (AIP-058; RB6). The evidence is attached only when the set it derives is the very set this
// anchor committed (its accumulateSetRoot): a set that has changed since cannot be offered as evidence of the one that
// signed.

// ValidatorSetProver builds the Directory's current validator-set evidence.
type ValidatorSetProver func(ctx context.Context) (*certenproof.ValidatorSetProof, error)

// ValidatorSetAttachment says what became of a proof's validator-set evidence.
type ValidatorSetAttachment string

const (
	// ValidatorSetAttached: the evidence derives the set the anchor committed and rides in layer 5.
	ValidatorSetAttached ValidatorSetAttachment = "attached"
	// ValidatorSetNoV8_2Commitment: the layer records no V8.2 commitment to compare the evidence with.
	ValidatorSetNoV8_2Commitment ValidatorSetAttachment = "no_v8_2_commitment"
	// ValidatorSetChanged: the set the chain holds now is not the set the anchor committed; evidence of the committed
	// set needs historical state (AIP-058).
	ValidatorSetChanged ValidatorSetAttachment = "set_changed_since_anchor"
)

// AttachValidatorSetProof builds the validator-set evidence and attaches it to l5 when it derives the committed set.
// An error is a failure to build or check the evidence; the caller names it, and the proof's layer 5 then states that
// it carries none (Layer5.ExternalClaim).
func AttachValidatorSetProof(ctx context.Context, l5 *Layer5, prove ValidatorSetProver) (ValidatorSetAttachment, error) {
	if l5 == nil || l5.Commitment == nil || l5.Commitment.Version != string(contracts.BatchAnchorV8_2) {
		return ValidatorSetNoV8_2Commitment, nil
	}
	if prove == nil {
		return "", fmt.Errorf("no validator-set prover is configured")
	}
	vsp, err := prove(ctx)
	if err != nil {
		return "", fmt.Errorf("build the validator-set evidence: %w", err)
	}
	root, err := AccumulateSetRoot(vsp)
	if err != nil {
		return "", fmt.Errorf("the validator-set evidence does not reduce to a set root: %w", err)
	}
	committed := strings.TrimPrefix(strings.ToLower(l5.Commitment.AccumulateSetRoot), "0x")
	if !strings.EqualFold(root, committed) {
		return ValidatorSetChanged, nil
	}
	inc := strings.TrimPrefix(strings.ToLower(l5.Commitment.Incarnation), "0x")
	if !strings.EqualFold(strings.TrimPrefix(vsp.Incarnation, "0x"), inc) {
		return "", fmt.Errorf("the validator-set evidence is of incarnation %s…, the anchor committed %s…",
			short16(vsp.Incarnation), short16(inc))
	}
	l5.Accumulate = &AccumulateBinding{Incarnation: inc, ValidatorSetRoot: root, ValidatorSetProof: vsp}
	return ValidatorSetAttached, nil
}

// CachedValidatorSetProver reuses one build of the evidence for ttl: every proof in that window is about the same
// Directory set, and each build is several network round trips that retry until the two accounts share a root.
func CachedValidatorSetProver(prove ValidatorSetProver, ttl time.Duration) ValidatorSetProver {
	var (
		mu    sync.Mutex
		built time.Time
		last  *certenproof.ValidatorSetProof
	)
	return func(ctx context.Context) (*certenproof.ValidatorSetProof, error) {
		mu.Lock()
		defer mu.Unlock()
		if last != nil && time.Since(built) < ttl {
			return last, nil
		}
		p, err := prove(ctx)
		if err != nil {
			return nil, err
		}
		last, built = p, time.Now()
		return p, nil
	}
}
