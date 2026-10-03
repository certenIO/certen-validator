// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"strings"
	"testing"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB5-F18 (survey §5 item 11): HandlePeerAttestationRequest's docstring said the re-observed transaction must be
// "finalized, successful" - but a reverted settlement is attested, by design (a revert is a finalized, verifiable
// outcome). The docstring now states what the handler does; this pins each of its step-3 claims.

// settlementChain re-observes one settlement as the peer's chain strategy would.
type settlementChain struct {
	chain.ChainExecutionStrategy
	obs *chain.ObservationResult
}

func (c settlementChain) ChainID() string { return "84532" }
func (c settlementChain) ObserveTransaction(context.Context, string) (*chain.ObservationResult, error) {
	return c.obs, nil
}

func TestThePeerHandlerDoesWhatItsDocstringSays(t *testing.T) {
	result := levelHash("the settlement's result")
	ask := func(t *testing.T, obs *chain.ObservationResult) *PeerAttestationResponse {
		t.Helper()
		reg := strategy.NewRegistry()
		bls, err := attestation.NewBLSStrategyWithNewKey("peer", 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.RegisterAttestationStrategy(bls); err != nil {
			t.Fatal(err)
		}
		if err := reg.RegisterChainStrategy("84532", &chain.ChainConfig{Platform: chain.ChainPlatformEVM}, settlementChain{obs: obs}); err != nil {
			t.Fatal(err)
		}
		o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "peer", Registry: reg}}
		resp, err := o.HandlePeerAttestationRequest(context.Background(), &PeerAttestationRequest{
			CycleID: "c", RequestingID: "requester", Scheme: attestation.AttestationSchemeBLS12381,
			Message: &attestation.AttestationMessage{IntentID: "i", TargetChain: "84532", AnchorTxHash: "0xsettlement", ResultHash: result},
		})
		if err != nil || resp == nil {
			t.Fatalf("%v %v", resp, err)
		}
		return resp
	}

	if r := ask(t, &chain.ObservationResult{IsFinalized: false, Status: 1, ResultHash: result}); r.Success || r.Retryable ||
		!strings.Contains(r.Error, "not finalized") {
		t.Fatalf("an observation that is not final: %+v", r)
	}
	if r := ask(t, &chain.ObservationResult{IsFinalized: true, Status: 1, ResultHash: levelHash("another result")}); r.Success ||
		!strings.Contains(r.Error, "result hash does not match") {
		t.Fatalf("a result that does not recompute: %+v", r)
	}
	// A reverted settlement is not refused for reverting: the handler goes on to verify the committed effect, which
	// this test's peer cannot (it has no Accumulate client to fetch the user-signed intent from), and names that.
	r := ask(t, &chain.ObservationResult{IsFinalized: true, Status: 0, ResultHash: result})
	if r.Success || !strings.Contains(r.Error, "committed-effect verification failed") {
		t.Fatalf("a final reverted settlement was refused before its committed effect was verified: %+v", r)
	}
}
