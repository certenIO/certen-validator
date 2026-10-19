// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
)

// The shadow main.go installs (Lazy) is the cross-checker discovery asks for. crossCheckV1Pages finds it by a type assertion, which is
// false and silent for a type that drifts from the interface: this makes the drift a compile error.
var _ ProofV2CrossChecker = (*proofv2shadow.Lazy)(nil)
var _ ProofV2CrossChecker = (*proofv2shadow.Shadow)(nil)

// RB9-F6 (B1): captureV2 reaches the activation-aware capture through two runtime type assertions, which fall back to Capture silently for a type that
// drifts from the interface. The shadow main.go installs (Lazy), the shadow itself and the gate (the validator app) must satisfy them: a drift is a compile error.
var _ ProofV2G1Capturer = (*proofv2shadow.Lazy)(nil)
var _ ProofV2G1Capturer = (*proofv2shadow.Shadow)(nil)
var _ ProofV2G1Gate = (*consensus.ValidatorApp)(nil)

// C5-D2: the proof v2 shadow's page cross-check (v1's replayed pages against v2's captured pages) is the instrument of the owner's
// shadow-exit rule (PROOF_V2 section 11: zero v1/v2 page disagreements). It needs v1's vote evidence, and that evidence is first set on
// the CertenProof by the BFT stage (BFTValidator, certenProof.GovVoteEvidence), which runs AFTER proveV2 on the same *proof.CertenProof.
// proveV2 used to ask for the cross-check only when the evidence was already there, so it never ran on the live path.
//
// processIntent and processMultiLegIntent each run, on one proof, proveV2 and then executeCanonical. These tests run exactly those two
// stages with a fake shadow (ProofV2CrossChecker) and a fake consensus that sets the evidence the way the real one does.

// crossCall is one CrossCheck call the shadow received.
type crossCall struct {
	intentID string
	ev       *govvote.Evidence
}

// crossShadow is a ProofV2Shadow that is also a ProofV2CrossChecker and records every call, in order, with the consensus fake.
type crossShadow struct {
	mu     sync.Mutex
	calls  []crossCall
	events *[]string
}

func (s *crossShadow) Capture(intentID, account, tx, keyBook, keyPage string) {}
func (s *crossShadow) Build(intentID, account, tx, bvn string)                {}
func (s *crossShadow) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	return &proofv2.Evidence{Version: proofv2.Version}, nil
}
func (s *crossShadow) CrossCheck(intentID string, ev *govvote.Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, crossCall{intentID, ev})
	if s.events != nil {
		*s.events = append(*s.events, "crosscheck")
	}
}
func (s *crossShadow) recorded() []crossCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]crossCall(nil), s.calls...)
}

// bftStep is what one pass through the BFT stage does to the proof it is handed. Setting evidence mirrors
// bft_integration.go ("certenProof.GovVoteEvidence = govVoteEvidence", after the G1 proof is complete and before the block is signed and
// broadcast); a stage that fails earlier leaves the field as it was.
type bftStep struct {
	evidence *govvote.Evidence
	err      error
}

// scriptedBFT is a consensus whose passes follow a script.
type scriptedBFT struct {
	script []bftStep
	pass   int
	events *[]string
}

func (b *scriptedBFT) run(cp *proof.CertenProof) error {
	step := b.script[b.pass]
	b.pass++
	if b.events != nil {
		*b.events = append(*b.events, "bft")
	}
	if step.evidence != nil {
		cp.GovVoteEvidence = step.evidence
	}
	return step.err
}

// plainBFT offers only the error-only method of BFTConsensusProtocol.
type plainBFT struct{ scriptedBFT }

func (b *plainBFT) ExecuteCanonicalIntentWithBFTConsensus(_ context.Context, _ *consensus.CertenIntent, cp *proof.CertenProof, _ uint64) error {
	return b.run(cp)
}

// outcomeBFT also offers the settlement outcome, as the real BFTValidator does.
type outcomeBFT struct{ plainBFT }

func (b *outcomeBFT) ExecuteCanonicalIntentWithOutcome(_ context.Context, _ *consensus.CertenIntent, cp *proof.CertenProof, _ uint64) (consensus.TargetChainOutcome, error) {
	if err := b.run(cp); err != nil {
		return consensus.TargetChainFailed, err
	}
	return consensus.TargetChainPending, nil
}

func evidenceFor(account string) *govvote.Evidence {
	return &govvote.Evidence{Version: govvote.EvidenceVersion, Account: account}
}

func singleLegIntent(t *testing.T, id string) *CertenIntent {
	t.Helper()
	return convertedIntent(t, blockTx(fmt.Sprintf("%x", "single-"+id), id, 700))
}

func multiLegIntent(t *testing.T, id string) *CertenIntent {
	t.Helper()
	ci := convertedIntent(t, blockTx(fmt.Sprintf("%x", "multi-"+id), id, 701))
	ci.CrossChainData = []byte(`{"legs":[{"legId":"a","chain":"ethereum","chainId":11155111},{"legId":"b","chain":"base","chainId":84532}]}`)
	if multi, err := ci.IsMultiLeg(); err != nil || !multi {
		t.Fatalf("the fixture is not a multi-leg intent (%v, %v)", multi, err)
	}
	return ci
}

// stages runs one pass of what both intent paths run between "the chained proof is built" and "the outcome is returned": proveV2, then
// the BFT stage, on one proof. The proof is built fresh for every pass, as buildChainedCertenProof does.
func stages(id *IntentDiscovery, ci *CertenIntent) (*proof.CertenProof, consensus.TargetChainOutcome, error) {
	cp := &proof.CertenProof{}
	ctx := context.Background()
	if err := id.proveV2(ctx, ci.IntentID, ci.AccountURL, ci.TransactionHash, ci.ProofPartition, cp); err != nil {
		return cp, consensus.TargetChainFailed, err
	}
	out, err := id.executeCanonical(ctx, ci, cp, 100)
	return cp, out, err
}

func crossDiscovery(sh ProofV2Shadow, gate ProofV2Gate, bft BFTConsensusProtocol) *IntentDiscovery {
	id := &IntentDiscovery{logger: log.New(io.Discard, "", 0)}
	id.SetProofV2Shadow(sh)
	id.SetProofV2Gate(gate)
	id.bftConsensus = bft
	return id
}

// Once the BFT stage has produced v1's vote evidence, the shadow is asked to cross-check exactly that evidence, once, for a single-leg and
// a multi-leg intent, whether the chain requires proof v2 yet (the shadow builds in the background) or not (it proves for the certificate),
// and whether the consensus offers the settlement outcome or not.
func TestCrossCheckIsAskedOnceWithTheEvidenceTheBFTStageProduced(t *testing.T) {
	for _, kind := range []struct {
		name string
		make func(*testing.T, string) *CertenIntent
	}{{"single-leg", singleLegIntent}, {"multi-leg", multiLegIntent}} {
		for _, gate := range []struct {
			name string
			g    ProofV2Gate
		}{{"v3 required", g1Gate{required: true}}, {"v3 not yet required", g1Gate{required: false}}} {
			for _, consensusKind := range []string{"with outcome", "error only"} {
				t.Run(kind.name+"/"+gate.name+"/"+consensusKind, func(t *testing.T) {
					var events []string
					ev := evidenceFor("acc://cust.acme/data")
					script := scriptedBFT{script: []bftStep{{evidence: ev}}, events: &events}
					var bft BFTConsensusProtocol
					if consensusKind == "with outcome" {
						bft = &outcomeBFT{plainBFT{scriptedBFT: script}}
					} else {
						bft = &plainBFT{scriptedBFT: script}
					}
					sh := &crossShadow{events: &events}
					ci := kind.make(t, "x"+kind.name)
					id := crossDiscovery(sh, gate.g, bft)

					cp, _, err := stages(id, ci)
					if err != nil {
						t.Fatal(err)
					}
					calls := sh.recorded()
					if len(calls) != 1 {
						t.Fatalf("the shadow's cross-check was asked %d times for the intent; want exactly 1, after the BFT stage (events %v)", len(calls), events)
					}
					if calls[0].intentID != ci.IntentID || calls[0].ev != ev || calls[0].ev != cp.GovVoteEvidence {
						t.Fatalf("the cross-check was asked about %q with evidence %p; want intent %q and the evidence the BFT stage produced (%p)",
							calls[0].intentID, calls[0].ev, ci.IntentID, ev)
					}
					if strings.Join(events, ",") != "bft,crosscheck" {
						t.Fatalf("the cross-check ran out of order: %v; it needs the evidence the BFT stage produces", events)
					}
				})
			}
		}
	}
}

// The cross-check is never given nil evidence: not before the BFT stage has produced any, not when the stage fails before it produced any,
// and not when the shadow is absent or cannot cross-check.
func TestCrossCheckIsNeverAskedWithoutEvidence(t *testing.T) {
	boom := errors.New("governance proof unavailable")

	// The stage fails before v1's vote evidence exists (the governance proofs are the first thing it builds): the proof carries none.
	for _, mk := range []func(scriptedBFT) BFTConsensusProtocol{
		func(s scriptedBFT) BFTConsensusProtocol { return &outcomeBFT{plainBFT{scriptedBFT: s}} },
		func(s scriptedBFT) BFTConsensusProtocol { return &plainBFT{scriptedBFT: s} },
	} {
		sh := &crossShadow{}
		id := crossDiscovery(sh, g1Gate{required: true}, mk(scriptedBFT{script: []bftStep{{err: boom}}}))
		cp, _, err := stages(id, singleLegIntent(t, "early-fail"))
		if !errors.Is(err, boom) || cp.GovVoteEvidence != nil {
			t.Fatalf("the failing stage: %v (evidence %v)", err, cp.GovVoteEvidence)
		}
		if calls := sh.recorded(); len(calls) != 0 {
			t.Fatalf("a stage that produced no evidence still cross-checked: %+v", calls)
		}
	}

	// proveV2 alone has no evidence to give: the stage that produces it has not run.
	sh := &crossShadow{}
	id := crossDiscovery(sh, g1Gate{required: true}, &outcomeBFT{plainBFT{scriptedBFT: scriptedBFT{script: []bftStep{{}}}}})
	if err := id.proveV2(context.Background(), "i1", "acc://a.acme/x", "tx", "BVN1", &proof.CertenProof{}); err != nil {
		t.Fatal(err)
	}
	if calls := sh.recorded(); len(calls) != 0 {
		t.Fatalf("proveV2 asked for a cross-check before the BFT stage ran: %+v", calls)
	}

	// A consensus that returns success without having produced evidence is not cross-checked either.
	id = crossDiscovery(sh, g1Gate{required: true}, &outcomeBFT{plainBFT{scriptedBFT: scriptedBFT{script: []bftStep{{}}}}})
	if _, _, err := stages(id, singleLegIntent(t, "no-evidence")); err != nil {
		t.Fatal(err)
	}
	if calls := sh.recorded(); len(calls) != 0 {
		t.Fatalf("an intent with no evidence was cross-checked: %+v", calls)
	}

	// No shadow, a nil-interface shadow, and a shadow that does not cross-check (a prover only) are all fine: nothing is asked, nothing panics.
	for name, shadow := range map[string]ProofV2Shadow{"no shadow": nil, "prover only": &plainProver{}} {
		id := crossDiscovery(shadow, g1Gate{required: false}, &outcomeBFT{plainBFT{scriptedBFT: scriptedBFT{script: []bftStep{{evidence: evidenceFor("acc://a.acme/x")}}}}})
		if _, _, err := stages(id, singleLegIntent(t, "none-"+strings.ReplaceAll(name, " ", "-"))); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A retried intent is cross-checked once. The retry loop (handleRetryJob) re-runs processIntent only for errChainedProofUnavailable,
// which is raised before the BFT stage (the chained proof or proveV2), so those passes carry no evidence and ask nothing; but an intent
// whose BFT stage failed AFTER producing evidence (the broadcast of the certified block, C5-F4) is failed, not retried by that loop, and is
// found again (a re-scan, ReprocessIntent) and run again, producing new evidence for the same transaction. The comparison is of v1's
// replay against v2's capture of the same pages, so the second pass would only repeat it: the intent is asked about once.
func TestCrossCheckRunsOncePerIntentAcrossRetries(t *testing.T) {
	broadcast := errors.New("BroadcastTxSync: request body too large")
	first, second := evidenceFor("acc://cust.acme/data"), evidenceFor("acc://cust.acme/data")
	sh := &crossShadow{}
	bft := &outcomeBFT{plainBFT{scriptedBFT: scriptedBFT{script: []bftStep{
		{err: broadcast},                   // pass 1 (intent A): fails before evidence
		{evidence: first, err: broadcast},  // pass 2 (intent A): evidence produced, then the broadcast fails
		{evidence: second},                 // pass 3 (intent A): found again; produces evidence again and settles
		{evidence: evidenceFor("acc://b")}, // pass 4 (intent B): its own
		{err: broadcast},                   // pass 5 (intent A): fails early again
	}}}}
	id := crossDiscovery(sh, g1Gate{required: true}, bft)
	a, b := singleLegIntent(t, "retried"), multiLegIntent(t, "other")

	if _, _, err := stages(id, a); !errors.Is(err, broadcast) {
		t.Fatalf("pass 1: %v", err)
	}
	if calls := sh.recorded(); len(calls) != 0 {
		t.Fatalf("pass 1 produced no evidence yet it asked: %+v", calls)
	}
	if _, _, err := stages(id, a); !errors.Is(err, broadcast) {
		t.Fatalf("pass 2: %v", err)
	}
	if calls := sh.recorded(); len(calls) != 1 || calls[0].intentID != a.IntentID || calls[0].ev != first {
		t.Fatalf("pass 2 produced evidence and then failed; the cross-check, which does not depend on the broadcast, must have been asked once with it: %+v", calls)
	}
	if _, _, err := stages(id, a); err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if _, _, err := stages(id, b); err != nil {
		t.Fatalf("pass 4: %v", err)
	}
	if _, _, err := stages(id, a); !errors.Is(err, broadcast) {
		t.Fatalf("pass 5: %v", err)
	}
	calls := sh.recorded()
	if len(calls) != 2 {
		t.Fatalf("%d cross-checks for two intents over five passes; want 2: %+v", len(calls), calls)
	}
	if calls[0].intentID != a.IntentID || calls[1].intentID != b.IntentID || calls[0].ev == second {
		t.Fatalf("each intent is asked once, the retried one with its first evidence: %+v", calls)
	}
}

// Both intent paths give the BFT stage the proof proveV2 completed, and the one place that asks for the cross-check is the BFT stage's
// wrapper, which both paths call: a path that ran its own copy would drift.
func TestBothIntentPathsReachTheOneCrossCheckSite(t *testing.T) {
	src := readSource(t, "discovery.go")
	for _, fn := range []string{"processIntent", "processMultiLegIntent"} {
		start := strings.Index(src, "func (id *IntentDiscovery) "+fn+"(")
		if start < 0 {
			t.Fatalf("%s not found", fn)
		}
		end := strings.Index(src[start:], "\n}\n")
		body := src[start : start+end]
		proveAt, execAt := strings.Index(body, "id.proveV2("), strings.Index(body, "id.executeCanonical(")
		if proveAt < 0 || execAt < 0 || proveAt > execAt {
			t.Errorf("%s must complete the proof with proveV2 and then run the BFT stage through executeCanonical", fn)
		}
		if strings.Count(body, "id.executeCanonical(") != 1 || strings.Contains(body, "CrossCheck") {
			t.Errorf("%s must reach the BFT stage once, through executeCanonical, and leave the cross-check to it", fn)
		}
	}
	if n := strings.Count(src, ".CrossCheck("); n != 1 {
		t.Errorf("discovery.go asks the shadow for the cross-check at %d places; want the one, after the BFT stage", n)
	}
	start := strings.Index(src, "func (id *IntentDiscovery) proveV2(")
	end := strings.Index(src[start:], "\n}\n")
	if strings.Contains(src[start:start+end], "CrossCheck") {
		t.Error("proveV2 runs before the BFT stage produces the evidence: it cannot cross-check")
	}
}
