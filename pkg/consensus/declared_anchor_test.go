package consensus

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// RB4-F9: a leg is settled on the anchor it declares, and the block records what will execute
// =============================================================================
//
// The batch path settled every leg on the chain's configured anchor with createBatchAnchor while the
// intent declared another (a retired 0x8398D7EB…5339 commitAnchor, or nothing), and the validator
// block recorded the declaration as "what will execute": the declared address or the anchor's type
// string, with call data made up from sha256 (a "selector" and sha256(expiry) for a uint256).

// withAnchor rewrites leg i's declared anchor.
func withAnchor(t *testing.T, ci *CertenIntent, i int, anchor map[string]interface{}) *CertenIntent {
	t.Helper()
	var env map[string]interface{}
	if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
		t.Fatal(err)
	}
	leg := env["legs"].([]interface{})[i].(map[string]interface{})
	if anchor == nil {
		delete(leg, "anchorContract")
	} else {
		leg["anchorContract"] = anchor
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ci.CrossChainData = b
	return ci
}

func TestTheBatchAnchorSelectorIsCreateBatchAnchor(t *testing.T) {
	if got := fmt.Sprintf("0x%x", BatchAnchorCreateSelector); got != "0x5d22872b" {
		t.Fatalf("createBatchAnchor selector %s, want 0x5d22872b", got)
	}
}

func TestALegIsSettledOnTheAnchorItDeclares(t *testing.T) {
	const retired = "0x8398D7EB4bF1C1F3D7F8aF9e5eFbDfC0c1b85339"
	for name, anchor := range map[string]map[string]interface{}{
		"the live anchor, by signature": {"address": testAnchor(84532).Hex(), "functionSelector": BatchAnchorCreateSignature},
		"the live anchor, by selector":  {"address": strings.ToLower(testAnchor(84532).Hex()), "functionSelector": "0x5d22872b"},
	} {
		if err := enqueue(refusalValidator(newFakeEnqueuer()), withAnchor(t, batchableIntent(t, "i1", 84532), 0, anchor)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		anchor map[string]interface{}
		names  []string
	}{
		"a retired anchor":                  {map[string]interface{}{"address": retired, "functionSelector": "commitAnchor(bytes32,bytes)"}, []string{common.HexToAddress(retired).Hex(), testAnchor(84532).Hex()}},
		"the live anchor, but another call": {map[string]interface{}{"address": testAnchor(84532).Hex(), "functionSelector": "commitAnchor(bytes32,bytes)"}, []string{"createBatchAnchor"}},
		"no anchor at all":                  {nil, []string{"declares no anchor address", testAnchor(84532).Hex()}},
		"an anchor type, no address":        {map[string]interface{}{"type": "evm_contract"}, []string{"declares no anchor address"}},
		"no call":                           {map[string]interface{}{"address": testAnchor(84532).Hex()}, []string{"no function declared"}},
	} {
		f := newFakeEnqueuer()
		err := enqueue(refusalValidator(f), withAnchor(t, batchableIntent(t, "i1", 84532), 0, c.anchor))
		var r *BatchRefusal
		if !errors.As(err, &r) || !r.Permanent || !errors.Is(err, ErrDeclaredAnchorNotLive) {
			t.Errorf("%s: want a permanent refusal naming ErrDeclaredAnchorNotLive, got %v", name, err)
			continue
		}
		for _, n := range c.names {
			if !strings.Contains(err.Error(), n) {
				t.Errorf("%s: the refusal does not name %q: %v", name, n, err)
			}
		}
		if f.adds != 0 {
			t.Errorf("%s: a refused intent was queued", name)
		}
	}
	// One leg of two on the wrong anchor refuses the intent.
	err := enqueue(refusalValidator(newFakeEnqueuer()), withAnchor(t, batchableIntent(t, "i2", 84532, 421614), 1,
		map[string]interface{}{"address": testAnchor(84532).Hex(), "functionSelector": BatchAnchorCreateSignature}))
	if !errors.Is(err, ErrDeclaredAnchorNotLive) {
		t.Errorf("a second leg declaring another chain's anchor was not refused: %v", err)
	}
}

func TestAnAnchorCERTENCannotNameIsRetriedNotRefused(t *testing.T) {
	f := newFakeEnqueuer()
	f.anchorErr = map[int64]error{84532: errors.New("chain 84532 has no CertenAnchorV8 configured")}
	err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532))
	var r *BatchRefusal
	if !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("CERTEN unable to name the anchor must be retried, got %v", err)
	}
}

func TestTheBlockRecordsTheCallThatWillExecute(t *testing.T) {
	whole := AccumulateAnchorReference{BlockHash: strings.Repeat("ab", 32), BlockHeight: 1234, TxHash: strings.Repeat("cd", 32), AccountURL: "acc://org.acme/data"}
	build := func(ci *CertenIntent) (*ValidatorBlock, error) {
		return NewValidatorBlockBuilder(BuilderConfig{ValidatorID: "validator-test", BLSValidatorSetPubKey: "aa"}).BuildFromIntent(BuilderInputs{
			Intent:      ci,
			Governance:  GovernanceInputs{BLSAggregateSignature: "bb", GovernanceLevel: "G2"},
			Execution:   ExecutionInputs{Stage: ExecutionStagePre, ProofClass: "on_cadence", ValidatorSignatures: []string{"cc"}},
			AnchorRef:   whole,
			BlockHeight: 7,
		})
	}
	vb, err := build(batchableIntent(t, "i1", 84532))
	if err != nil {
		t.Fatal(err)
	}
	tg := vb.CrossChainProof.ChainTargets[0]
	if tg.ContractAddress != testAnchor(84532).Hex() || tg.FunctionSelector != "0x5d22872b" {
		t.Fatalf("chain target %s %s; want the anchor %s called with createBatchAnchor (0x5d22872b)", tg.ContractAddress, tg.FunctionSelector, testAnchor(84532).Hex())
	}
	raw, err := json.Marshal(vb.CrossChainProof.ChainTargets)
	if err != nil {
		t.Fatal(err)
	}
	if tg.EncodedCallData != "" || strings.Contains(string(raw), "encoded_call_data") {
		t.Fatalf("the block states call data that nothing will send: %s", raw)
	}
	// A leg with no address is not given its anchor type as one.
	if vb, err := build(withAnchor(t, batchableIntent(t, "i2", 84532), 0, map[string]interface{}{"type": "evm_contract"})); err == nil {
		t.Fatalf("built with contract address %q for a leg that declares none", vb.CrossChainProof.ChainTargets[0].ContractAddress)
	}
}
