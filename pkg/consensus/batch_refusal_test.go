package consensus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// The batch path either queues an intent or refuses it by name - never anything else
// =============================================================================
//
// Owner decision 2026-09-26: an intent the batch path cannot settle is refused with its reason;
// the per-intent path it used to fall through to is gone. These tests drive enqueueForBatch with
// a fake enqueuer and check the three outcomes consensus must tell apart - queued (including the
// same intent arriving again), refused for good (the intent's own defect or a replay), and
// retried (CERTEN cannot settle on the chain right now) - plus that a multi-chain intent is
// queued all-or-nothing.

type fakeEnqueuer struct {
	checkErr map[int64]error // CheckMember result per chain
	addErr   map[int64]error // EnqueueForBatch/EnqueueOnDemand result per chain (after the first add)
	queued   map[string]bool
	removed  []string
	adds     int
}

func newFakeEnqueuer() *fakeEnqueuer {
	return &fakeEnqueuer{checkErr: map[int64]error{}, addErr: map[int64]error{}, queued: map[string]bool{}}
}

func (f *fakeEnqueuer) add(intentID string, chainID int64) error {
	f.adds++
	if err := f.addErr[chainID]; err != nil {
		return err
	}
	key := fmt.Sprintf("%s|%d", intentID, chainID)
	if f.queued[key] {
		return fmt.Errorf("%w: %s", ErrMemberAlreadyQueued, key)
	}
	f.queued[key] = true
	return nil
}

func (f *fakeEnqueuer) EnqueueForBatch(intentID, _ string, chainID int64, _ [20]byte, _ [32]byte, _, _ interface{},
	_ uint64, _ string, _ time.Time, _ string) error {
	return f.add(intentID, chainID)
}

func (f *fakeEnqueuer) EnqueueOnDemand(intentID, _ string, chainID int64, _ [20]byte, _ [32]byte, _, _ interface{},
	_ uint64, _ string, _ time.Time, _ string) error {
	return f.add(intentID, chainID)
}

func (f *fakeEnqueuer) CheckMember(_ bool, _ string, _ string, chainID int64, _ [20]byte, _ [32]byte, _ interface{}, _ uint64) error {
	return f.checkErr[chainID]
}

func (f *fakeEnqueuer) RemoveMember(_ bool, intentID string, chainID int64, _ [32]byte) {
	key := fmt.Sprintf("%s|%d", intentID, chainID)
	delete(f.queued, key)
	f.removed = append(f.removed, key)
}

// batchableIntent is an intent the batch path can represent: one leg per given chain, all from the
// same account, with a real target.
func batchableIntent(t *testing.T, id string, chains ...int64) *CertenIntent {
	t.Helper()
	legs := make([]map[string]interface{}, 0, len(chains))
	for i, c := range chains {
		legs = append(legs, map[string]interface{}{
			"legId": fmt.Sprintf("leg-%d", i), "chain": "evm", "chainId": c,
			"from": "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B",
			"executionPayload": map[string]interface{}{
				"target": "0x1111111111111111111111111111111111111111", "value": "1000", "chainId": c,
			},
		})
	}
	must := func(v interface{}) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &CertenIntent{
		IntentID:        id,
		OrganizationADI: "acc://org.acme",
		AccountURL:      "acc://org.acme/data",
		IntentData:      must(map[string]interface{}{"intent_id": id, "proof_class": "on_cadence"}),
		// "parallel": a cross-chain intent is settled one chain member at a time, independently -
		// the only cross-chain mode CERTEN implements (declared_semantics.go).
		CrossChainData: must(map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": legs, "execution_mode": "parallel"}),
		GovernanceData: must(map[string]interface{}{"organizationAdi": "acc://org.acme"}),
		ReplayData:     must(map[string]interface{}{"nonce": id}),
		// The consensus block time every admitted intent has (RB3-F49).
		BlockTime: time.Unix(1_800_000_000, 0).UTC(),
	}
}

func enqueue(bv *BFTValidator, ci *CertenIntent) error {
	return bv.enqueueForBatch(ci, nil, nil, 7, nil, nil, nil, "", nil, "", 7)
}

func refusalValidator(e BatchEnqueuer) *BFTValidator {
	return &BFTValidator{validatorID: "validator-test", logger: quietLogger(), batchEnqueuer: e}
}

func TestEnqueueForBatch_QueuesABatchableIntent(t *testing.T) {
	f := newFakeEnqueuer()
	if err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532)); err != nil {
		t.Fatalf("a batchable intent was not queued: %v", err)
	}
	if !f.queued["i1|84532"] {
		t.Fatal("the member was not handed to the enqueuer")
	}
}

// RB3-F34: the same intent running the workflow again must be reported as queued - never refused,
// and never handed on to be executed a second time.
func TestEnqueueForBatch_SameIntentAgainIsQueued(t *testing.T) {
	f := newFakeEnqueuer()
	bv := refusalValidator(f)
	ci := batchableIntent(t, "i1", 84532)
	if err := enqueue(bv, ci); err != nil {
		t.Fatal(err)
	}
	if err := enqueue(bv, ci); err != nil {
		t.Fatalf("a re-run of a queued intent must be treated as queued, got %v", err)
	}
	if len(f.removed) != 0 {
		t.Fatalf("a re-run must not roll anything back: %v", f.removed)
	}
}

func TestEnqueueForBatch_UnbatchableIntentIsRefusedForGood(t *testing.T) {
	cases := map[string]*CertenIntent{
		"legs from two accounts": func() *CertenIntent {
			ci := batchableIntent(t, "i2", 84532, 84532)
			var env map[string]interface{}
			_ = json.Unmarshal(ci.CrossChainData, &env)
			env["legs"].([]interface{})[1].(map[string]interface{})["from"] = "0x2222222222222222222222222222222222222222"
			ci.CrossChainData, _ = json.Marshal(env)
			return ci
		}(),
		"no ADI": func() *CertenIntent {
			ci := batchableIntent(t, "i3", 84532)
			ci.OrganizationADI, ci.AccountURL = "", ""
			return ci
		}(),
		"unreadable legs": func() *CertenIntent {
			ci := batchableIntent(t, "i4", 84532)
			ci.CrossChainData = []byte("{not json")
			return ci
		}(),
	}
	for name, ci := range cases {
		err := enqueue(refusalValidator(newFakeEnqueuer()), ci)
		var r *BatchRefusal
		if !errors.As(err, &r) || !r.Permanent {
			t.Errorf("%s: want a permanent BatchRefusal, got %v", name, err)
		}
	}
}

func TestEnqueueForBatch_ReplayIsRefusedForGood(t *testing.T) {
	f := newFakeEnqueuer()
	f.checkErr[84532] = fmt.Errorf("%w: held by intent other", ErrOperationAlreadyQueued)
	err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532))
	var r *BatchRefusal
	if !errors.As(err, &r) || !r.Permanent || !errors.Is(err, ErrOperationAlreadyQueued) {
		t.Fatalf("a replay must be a permanent refusal naming ErrOperationAlreadyQueued, got %v", err)
	}
	if f.adds != 0 {
		t.Fatal("nothing may be queued for a refused intent")
	}
}

func TestEnqueueForBatch_OutageIsRetriedNotRefused(t *testing.T) {
	f := newFakeEnqueuer()
	f.checkErr[84532] = fmt.Errorf("%w: chain 84532 has no orchestrator", ErrBatchUnavailable)
	err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532))
	var r *BatchRefusal
	if !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("CERTEN's outage must be a retryable refusal, got %v", err)
	}
}

// A multi-chain intent is queued on every chain or on none: a failure on its second chain rolls
// back the member already queued on its first.
func TestEnqueueForBatch_MultiChainIsAllOrNothing(t *testing.T) {
	f := newFakeEnqueuer()
	f.addErr[421614] = fmt.Errorf("%w: raced by another intent", ErrOperationAlreadyQueued)
	err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532, 421614))
	var r *BatchRefusal
	if !errors.As(err, &r) || !r.Permanent {
		t.Fatalf("want a permanent refusal, got %v", err)
	}
	if f.queued["i1|84532"] {
		t.Fatal("the first chain's member was left queued after the second failed")
	}
	if len(f.removed) != 1 || f.removed[0] != "i1|84532" {
		t.Fatalf("expected exactly the first chain's member rolled back, got %v", f.removed)
	}
}

func TestEnqueueForBatch_NoEnqueuerIsAnOutage(t *testing.T) {
	err := refusalValidator(nil).enqueueForBatch(batchableIntent(t, "i1", 84532), nil, nil, 7, nil, nil, nil, "", nil, "", 7)
	var r *BatchRefusal
	if !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("a validator with no batch path cannot settle anything; that is its outage, got %v", err)
	}
}

// The executor's part of the workflow ends at "queued". Nothing after the batch enqueue may submit
// an intent individually or hand it to a cadence scheduler.
func TestWorkflowHasNoPerIntentSubmission(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func (bv *BFTValidator) executeCanonicalBFTWorkflow(")
	if start < 0 {
		t.Fatal("workflow not found")
	}
	end := strings.Index(src[start:], "\n}\n")
	body := src[start : start+end]
	for _, forbidden := range []string{"SubmitAnchorFromValidatorBlock", "QueueForCadence", "anchorScheduler"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("executeCanonicalBFTWorkflow still reaches %s", forbidden)
		}
	}
}

// The batch plan is checked - and a refusal returned - before the validator block is built,
// signed or broadcast, so no signature exists for an intent the batch path will not settle.
func TestBatchPlanIsCheckedBeforeAnythingIsSigned(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	check := strings.Index(src, "bv.checkBatchable(certenIntent, blockHeight)")
	build := strings.Index(src, "builderInputs := BuilderInputs{")
	if check < 0 || build < 0 || check > build {
		t.Fatalf("batch plan check at %d, validator block build at %d: the check must come first", check, build)
	}
}
