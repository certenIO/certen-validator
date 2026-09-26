package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB-3: quorum-confirmed result attestation.
//
// A result is final only when validators holding >= 2/3 of the REGISTERED voting power signed the
// identical result message, and a validator that observed a different result (a forked or lying RPC)
// can neither join nor block that quorum. These ran against the legacy AttestationCollector, which no
// live path used; they now run against the Phase 8 fold that decides every write-back.
//
// RB3-F41: that fold counted each attestation's self-declared Weight over whatever key it carried,
// with no dedupe, against len(peers)+1 - one responder declaring Weight 100 met the threshold alone.

type rb3Validator struct {
	addr  string
	strat *attestation.BLSStrategy
}

func rb3Validators(t *testing.T, n int) ([]rb3Validator, map[string]consensus.ValidatorRegistryEntry) {
	t.Helper()
	vals := make([]rb3Validator, n)
	reg := make(map[string]consensus.ValidatorRegistryEntry, n)
	for i := 0; i < n; i++ {
		s, err := attestation.NewBLSStrategyWithNewKey(fmt.Sprintf("validator-%d", i+1), uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("0x%040x", i+1)
		vals[i] = rb3Validator{addr: addr, strat: s}
		reg[addr] = consensus.ValidatorRegistryEntry{
			EVMAddress:   addr,
			PublicKeyHex: hex.EncodeToString(s.PublicKey()),
			VotingPower:  big.NewInt(1),
		}
	}
	return vals, reg
}

func rb3Message(result byte) *attestation.AttestationMessage {
	return &attestation.AttestationMessage{
		IntentID:     "intent-1",
		ResultHash:   [32]byte{result},
		AnchorTxHash: "0xabc",
		BlockNumber:  100,
		TargetChain:  "11155111",
		ChainID:      "11155111",
		Timestamp:    1_700_000_000,
		CycleID:      "cycle-1",
		BundleID:     [32]byte{0x01},
	}
}

func rb3Sign(t *testing.T, v rb3Validator, msg *attestation.AttestationMessage) *attestation.Attestation {
	t.Helper()
	att, err := v.strat.Sign(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func rb3Fold(t *testing.T, vals []rb3Validator, reg map[string]consensus.ValidatorRegistryEntry, msg *attestation.AttestationMessage, atts []*attestation.Attestation) (*attestation.AggregatedAttestation, []ExcludedResultAttestation, error) {
	t.Helper()
	return foldResultAttestations(context.Background(), vals[0].strat, msg, atts, reg, attestation.DefaultThresholdConfig())
}

// >= 2/3 of registered power signing the same result finalizes, and the aggregate verifies.
func TestRB3_QuorumFinalizesOnAgreement(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	msg := rb3Message(0xAA)

	two := []*attestation.Attestation{rb3Sign(t, vals[0], msg), rb3Sign(t, vals[1], msg)}
	agg, _, err := rb3Fold(t, vals, reg, msg, two)
	if err != nil {
		t.Fatal(err)
	}
	if agg.ThresholdMet {
		t.Fatalf("2 of 4 registered power met the quorum (achieved=%d required=%d)", agg.AchievedWeight, agg.ThresholdWeight)
	}

	three := append(two, rb3Sign(t, vals[2], msg))
	agg, excluded, err := rb3Fold(t, vals, reg, msg, three)
	if err != nil {
		t.Fatal(err)
	}
	if !agg.ThresholdMet || len(excluded) != 0 {
		t.Fatalf("3 of 4 must finalize: met=%v excluded=%v", agg.ThresholdMet, excluded)
	}
	if agg.TotalWeight != 4 || agg.AchievedWeight != 3 {
		t.Fatalf("weights achieved=%d total=%d, want 3/4", agg.AchievedWeight, agg.TotalWeight)
	}
	if len(agg.ValidatorBitfield) == 0 {
		t.Error("aggregate carries no validator bitfield")
	}
	ok, err := vals[0].strat.VerifyAggregated(context.Background(), agg)
	if err != nil || !ok {
		t.Fatalf("aggregate signature must verify: ok=%v err=%v", ok, err)
	}
}

// A validator that observed a different result signs a different message. It is excluded by name and
// cannot help the honest result; with a 2/2 split nothing finalizes.
func TestRB3_DivergentRPCCannotJoinQuorum(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	honest, forked := rb3Message(0xAA), rb3Message(0xBB)
	atts := []*attestation.Attestation{
		rb3Sign(t, vals[0], honest), rb3Sign(t, vals[1], honest),
		rb3Sign(t, vals[2], forked), rb3Sign(t, vals[3], forked),
	}

	for name, msg := range map[string]*attestation.AttestationMessage{"honest": honest, "forked": forked} {
		agg, excluded, err := rb3Fold(t, vals, reg, msg, atts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if agg.ThresholdMet {
			t.Errorf("%s result finalized on 2 of 4", name)
		}
		if len(excluded) != 2 || !strings.Contains(excluded[0].Reason, "different result") {
			t.Errorf("%s: the divergence must be named, got %v", name, excluded)
		}
	}
}

// 3 honest + 1 forked: the honest result finalizes. The forked attestation used to abort the whole
// aggregate ("different message hash"), so a single divergent peer denied the write-back.
func TestRB3_HonestSupermajorityWinsDespiteFork(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	honest, forked := rb3Message(0xAA), rb3Message(0xBB)
	atts := []*attestation.Attestation{
		rb3Sign(t, vals[3], forked),
		rb3Sign(t, vals[0], honest), rb3Sign(t, vals[1], honest), rb3Sign(t, vals[2], honest),
	}
	agg, excluded, err := rb3Fold(t, vals, reg, honest, atts)
	if err != nil {
		t.Fatalf("a forked peer must not block the honest quorum: %v", err)
	}
	if !agg.ThresholdMet || len(excluded) != 1 {
		t.Fatalf("met=%v excluded=%v", agg.ThresholdMet, excluded)
	}
}

// An attestation whose message hash does not bind this result does not count.
func TestRB3_MessageHashMismatchRejected(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	msg := rb3Message(0xAA)
	bad := rb3Sign(t, vals[0], msg)
	bad.MessageHash = [32]byte{0xDE, 0xAD}
	_, excluded, err := rb3Fold(t, vals, reg, msg, []*attestation.Attestation{bad})
	if err == nil || len(excluded) != 1 {
		t.Fatalf("an attestation over another message counted: err=%v excluded=%v", err, excluded)
	}
}

// RB3-F41: the attester's Weight is never read - a validator counts its registered power.
func TestRB3F41_SelfDeclaredWeightIsIgnored(t *testing.T) {
	vals, reg := rb3Validators(t, 7)
	msg := rb3Message(0xAA)
	att := rb3Sign(t, vals[1], msg)
	att.Weight = 100
	agg, _, err := rb3Fold(t, vals, reg, msg, []*attestation.Attestation{rb3Sign(t, vals[0], msg), att})
	if err != nil {
		t.Fatal(err)
	}
	if agg.AchievedWeight != 2 || agg.ThresholdMet {
		t.Fatalf("self-declared weight counted: achieved=%d met=%v", agg.AchievedWeight, agg.ThresholdMet)
	}
}

// RB3-F41: a valid signature from a key the registry does not hold counts for nothing.
func TestRB3F41_UnregisteredKeyDoesNotCount(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	outsider, _ := rb3Validators(t, 1)
	msg := rb3Message(0xAA)
	atts := []*attestation.Attestation{
		rb3Sign(t, vals[0], msg), rb3Sign(t, vals[1], msg), rb3Sign(t, outsider[0], msg),
	}
	agg, excluded, err := rb3Fold(t, vals, reg, msg, atts)
	if err != nil {
		t.Fatal(err)
	}
	if agg.ThresholdMet || agg.AchievedWeight != 2 {
		t.Fatalf("an unregistered key counted: achieved=%d met=%v", agg.AchievedWeight, agg.ThresholdMet)
	}
	if len(excluded) != 1 || !strings.Contains(excluded[0].Reason, "not a registered") {
		t.Fatalf("the outsider must be excluded by name, got %v", excluded)
	}
}

// RB3-F41: one validator counts once, however many copies of its attestation arrive.
func TestRB3F41_DuplicateValidatorCountsOnce(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	msg := rb3Message(0xAA)
	a := rb3Sign(t, vals[0], msg)
	b := rb3Sign(t, vals[1], msg)
	agg, excluded, err := rb3Fold(t, vals, reg, msg, []*attestation.Attestation{a, b, a, b})
	if err != nil {
		t.Fatal(err)
	}
	if agg.AchievedWeight != 2 || agg.ThresholdMet || len(excluded) != 2 {
		t.Fatalf("duplicates counted: achieved=%d met=%v excluded=%v", agg.AchievedWeight, agg.ThresholdMet, excluded)
	}
}

// RB3-F41: registered power, not a head count, decides - a heavy validator is weighted as registered.
func TestRB3F41_ThresholdIsRegisteredPower(t *testing.T) {
	vals, reg := rb3Validators(t, 4)
	heavy := reg[vals[0].addr]
	heavy.VotingPower = big.NewInt(10) // total 13, need > 26/3 => 9
	reg[vals[0].addr] = heavy
	msg := rb3Message(0xAA)

	agg, _, err := rb3Fold(t, vals, reg, msg, []*attestation.Attestation{rb3Sign(t, vals[1], msg), rb3Sign(t, vals[2], msg), rb3Sign(t, vals[3], msg)})
	if err != nil {
		t.Fatal(err)
	}
	if agg.ThresholdMet || agg.TotalWeight != 13 {
		t.Fatalf("3 light validators (3 of 13) met the quorum: total=%d", agg.TotalWeight)
	}
	agg, _, err = rb3Fold(t, vals, reg, msg, []*attestation.Attestation{rb3Sign(t, vals[0], msg), rb3Sign(t, vals[1], msg), rb3Sign(t, vals[2], msg)})
	if err != nil {
		t.Fatal(err)
	}
	if !agg.ThresholdMet || agg.AchievedWeight != 12 {
		t.Fatalf("12 of 13 must meet: achieved=%d met=%v", agg.AchievedWeight, agg.ThresholdMet)
	}
}

// RB3-F41 end to end through Phase 8: the repro that met the quorum at 996e608 (one unregistered peer
// declaring Weight 100) no longer does, and the total is the registry's power, not the peer count.
func TestRB3F41_Phase8CountsAgainstTheRegistry(t *testing.T) {
	vals, reg := rb3Validators(t, 7)
	forger, _ := rb3Validators(t, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req PeerAttestationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		att, _ := forger[0].strat.Sign(r.Context(), req.Message)
		att.Weight = 100
		_ = json.NewEncoder(w).Encode(&PeerAttestationResponse{CycleID: req.CycleID, Success: true, Attestation: att})
	}))
	defer srv.Close()

	o := &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{
			ValidatorID:        "validator-1",
			AttestationPeers:   []string{srv.URL},
			AttestationTimeout: 5 * time.Second,
			ResultQuorumRegistry: func(ctx context.Context, chainID string) (map[string]consensus.ValidatorRegistryEntry, error) {
				if chainID != "11155111" {
					return nil, fmt.Errorf("unexpected chain %s", chainID)
				}
				return reg, nil
			},
		},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	cycle := &activeCycle{
		CycleID: "c1",
		Request: &UnifiedProofCycleRequest{IntentID: "i1", TxHashes: []string{"0xabc"}, TargetChain: "11155111"},
		Result: &UnifiedProofCycleResult{
			ChainID:            "11155111",
			ObservationResults: []*chain.ObservationResult{{TxHash: "0xabc", BlockNumber: 7, ResultHash: [32]byte{0xAA}}},
		},
	}
	if err := o.executePhase8(context.Background(), cycle, vals[0].strat); err != nil {
		t.Fatal(err)
	}
	agg := cycle.Result.AggregatedAttestation
	if cycle.Result.ThresholdMet || agg.AchievedWeight != 1 || agg.TotalWeight != 7 {
		t.Fatalf("achieved=%d total=%d met=%v, want 1/7 not met", agg.AchievedWeight, agg.TotalWeight, cycle.Result.ThresholdMet)
	}
	if len(cycle.Result.Attestations) != 1 {
		t.Fatalf("the uncounted attestation was recorded with the result: %d", len(cycle.Result.Attestations))
	}
}

// Phase 8 without a registry refuses by name; so does building an orchestrator without one.
func TestRB3F41_RegistryIsRequired(t *testing.T) {
	vals, _ := rb3Validators(t, 1)
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "v", AttestationTimeout: time.Second}}
	cycle := &activeCycle{
		CycleID: "c1",
		Request: &UnifiedProofCycleRequest{TxHashes: []string{"0xabc"}},
		Result:  &UnifiedProofCycleResult{ChainID: "11155111", ObservationResults: []*chain.ObservationResult{{ResultHash: [32]byte{1}}}},
	}
	if err := o.executePhase8(context.Background(), cycle, vals[0].strat); err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("phase 8 without a registry: %v", err)
	}
	_, err := NewUnifiedOrchestrator(&UnifiedOrchestratorConfig{ValidatorID: "v", Registry: strategy.NewRegistry()})
	if err == nil || !strings.Contains(err.Error(), "validator registry source") {
		t.Fatalf("orchestrator built without a validator registry source: %v", err)
	}
}
