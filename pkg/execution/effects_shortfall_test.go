// Copyright 2026 Certen Protocol

package execution

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// RB3-F67: a settlement that executed without a committed effect is attested and written back as that.
// These pin the parts that do not need a chain; effects_shortfall_live_test.go proves the chain side.

func shortfallClaim() *attestation.EffectsShortfallClaim {
	return &attestation.EffectsShortfallClaim{
		ChainID: 84532, TxHash: "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7",
		Account: "0x184aef98beacaf3e73ca4a77c72e8f11e9b790a7", OperationID: "0x" + "11" + "00000000000000000000000000000000000000000000000000000000000000"[:62],
		Leaf: "0x" + "22" + "00000000000000000000000000000000000000000000000000000000000000"[:62], MissingEvents: []string{"0:1"},
	}
}

func TestEffectsShortfallResultHashIsBoundToEveryFactAndDomainSeparated(t *testing.T) {
	observed := [32]byte{9}
	base := effectsShortfallResultHash(observed, shortfallClaim())
	if base == observed {
		t.Fatal("a shortfall must not sign the settlement's own result hash - it would read as a success")
	}
	if effectsShortfallResultHash(observed, shortfallClaim()) != base {
		t.Fatal("not deterministic")
	}
	// Case of hex does not change the fact.
	upper := shortfallClaim()
	upper.TxHash = "0x7A2C8522FB60D37E63FA2B68BF1ABC69C6A70DD25DA501AB21EC02C1B50204E7"
	if effectsShortfallResultHash(observed, upper) != base {
		t.Fatal("hex case changed the hash")
	}
	for name, mutate := range map[string]func(*attestation.EffectsShortfallClaim){
		"chain":           func(c *attestation.EffectsShortfallClaim) { c.ChainID = 11155111 },
		"tx":              func(c *attestation.EffectsShortfallClaim) { c.TxHash = "0x01" },
		"account":         func(c *attestation.EffectsShortfallClaim) { c.Account = "0x02" },
		"operation":       func(c *attestation.EffectsShortfallClaim) { c.OperationID = "0x03" },
		"leaf":            func(c *attestation.EffectsShortfallClaim) { c.Leaf = "0x04" },
		"missing events":  func(c *attestation.EffectsShortfallClaim) { c.MissingEvents = []string{"0:0"} },
		"unset state":     func(c *attestation.EffectsShortfallClaim) { c.UnsetState = []string{"0:0"} },
		"moved to state":  func(c *attestation.EffectsShortfallClaim) { c.MissingEvents, c.UnsetState = nil, []string{"0:1"} },
		"observed result": nil,
	} {
		c := shortfallClaim()
		obs := observed
		if mutate != nil {
			mutate(c)
		} else {
			obs = [32]byte{8}
		}
		if effectsShortfallResultHash(obs, c) == base {
			t.Fatalf("changing the %s did not change the hash", name)
		}
	}
	if !sameShortfall(shortfallClaim(), upper) {
		t.Fatal("the same facts in another hex case are the same claim")
	}
	other := shortfallClaim()
	other.MissingEvents = []string{"0:0"}
	if sameShortfall(shortfallClaim(), other) || sameShortfall(nil, other) {
		t.Fatal("different or absent claims must not match")
	}
}

func TestEventPresenceFollowsTheSuccessGatesRule(t *testing.T) {
	weth := common.HexToAddress("0x4200000000000000000000000000000000000006")
	approval := crypto.Keccak256Hash([]byte("Approval(address,address,uint256)"))
	logs := []LogEntry{{Address: weth, Topics: []common.Hash{approval}, Data: []byte{1}}}
	if !eventPresent(logs, ExpectedEvent{Contract: weth, Topic0: approval}) {
		t.Fatal("the emitted event is present")
	}
	if eventPresent(logs, ExpectedEvent{Contract: common.HexToAddress("0x01"), Topic0: approval}) {
		t.Fatal("the same topic from another contract is not the committed event")
	}
	if eventPresent(logs, ExpectedEvent{Contract: weth, Topic0: approval, DataHash: [32]byte(crypto.Keccak256Hash([]byte{2}))}) {
		t.Fatal("a committed data hash the log does not match is absent")
	}
	if !eventPresent(logs, ExpectedEvent{Contract: weth, Topic0: approval, DataHash: [32]byte(crypto.Keccak256Hash([]byte{1}))}) {
		t.Fatal("a matching data hash is present")
	}
}

func TestMemberOutcomeStatesWhetherEffectsWereProven(t *testing.T) {
	if cycleEffectsProven(&activeCycle{}) != nil {
		t.Fatal("no committed call: nothing to state")
	}
	if p := cycleEffectsProven(&activeCycle{CommittedEffects: true, VerifiedCalls: verifiedCallProofs{"ab": &ExternalChainResult{Status: 1}}}); p == nil || !*p {
		t.Fatal("proven effects must be stated proven")
	}
	// A native member committed no effect; a reverted settlement assessed none: neither is "proven".
	if p := cycleEffectsProven(&activeCycle{VerifiedCalls: verifiedCallProofs{"ab": &ExternalChainResult{Status: 1}}}); p != nil {
		t.Fatal("a member that committed no effect has none to state")
	}
	if p := cycleEffectsProven(&activeCycle{CommittedEffects: true, VerifiedCalls: verifiedCallProofs{"ab": &ExternalChainResult{Status: 0}}}); p != nil {
		t.Fatal("a reverted settlement's effects were never assessed")
	}
	if p := cycleEffectsProven(&activeCycle{EffectsShortfall: shortfallClaim(), VerifiedCalls: verifiedCallProofs{"ab": nil}}); p == nil || *p {
		t.Fatal("a proven shortfall must be stated not proven, whatever else the gate saw")
	}
}

func TestShortfallIsWrittenBackAsItsOutcome(t *testing.T) {
	obs := &chain.ObservationResult{TxHash: "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7", Status: 1, IsFinalized: true, BlockNumber: 47368146,
		BlockHash: "0x1111111111111111111111111111111111111111111111111111111111111111"}
	c := memberCycle("i-shortfall", "84532", []int64{84532}, 1, obs)
	c.EffectsShortfall = shortfallClaim()
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{}, resultChains: map[string]*ResultHashChain{}}
	bundle, _, err := o.buildAttestationBundleFromCycle(c)
	if err != nil || bundle == nil || bundle.Result == nil {
		t.Fatalf("no bundle: %v", err)
	}
	if bundle.Result.Outcome != ResultOutcomeEffectsNotProven || bundle.Result.OutcomeReason == "" {
		t.Fatalf("outcome %q (%q); want %q with the missing effects named", bundle.Result.Outcome, bundle.Result.OutcomeReason, ResultOutcomeEffectsNotProven)
	}
	entry := &CertenDataEntry{Outcome: bundle.Result.Outcome, OutcomeReason: bundle.Result.OutcomeReason}
	found := false
	for _, e := range entry.ToDoubleHashFormat() {
		if string(e) == "outcome="+ResultOutcomeEffectsNotProven || string(e) == "outcome:"+ResultOutcomeEffectsNotProven {
			found = true
		}
	}
	if !found {
		t.Fatal("the written record does not carry the outcome")
	}
}
