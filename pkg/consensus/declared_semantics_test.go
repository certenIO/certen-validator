package consensus

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RB3-F52/F53: an intent is executed as it declares, or refused by name - never executed against
// its declaration. These drive the admission path (enqueueForBatch) with the declarations the
// intent builder really sends.

func declaring(t *testing.T, chains []int64, mutate func(env map[string]any, legs []map[string]any)) *CertenIntent {
	t.Helper()
	ci := batchableIntent(t, "i1", chains...)
	var env map[string]any
	if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
		t.Fatal(err)
	}
	delete(env, "execution_mode") // each case declares its own
	raw := env["legs"].([]any)
	legs := make([]map[string]any, len(raw))
	for i := range raw {
		legs[i] = raw[i].(map[string]any)
		legs[i]["legId"] = "leg-" + string(rune('a'+i))
	}
	mutate(env, legs)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ci.CrossChainData = b
	return ci
}

func refusedWith(t *testing.T, ci *CertenIntent, want error) {
	t.Helper()
	err := enqueue(refusalValidator(newFakeEnqueuer()), ci)
	var r *BatchRefusal
	if err == nil || !errors.As(err, &r) || !r.Permanent || !errors.Is(err, want) {
		t.Fatalf("want a permanent refusal wrapping %v, got %v", want, err)
	}
}

// A cross-chain declaration CERTEN does not implement - atomic, all-or-nothing, rollback - or an order
// one member per chain cannot honour, is refused by name.
func TestCrossChainSemanticsNotImplementedAreRefused(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, []map[string]any){
		"atomic": func(e map[string]any, _ []map[string]any) { e["execution_mode"] = "atomic" },
		"unknown mode": func(e map[string]any, _ []map[string]any) {
			e["execution_mode"] = "eventually"
		},
		"sequential contradicted": func(e map[string]any, _ []map[string]any) {
			e["execution_mode"] = "sequential"
			e["execution_constraints"] = map[string]any{"parallel_execution": true}
		},
		"sequence_order on some legs only": func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "sequential"
			legs[0]["sequence_order"] = 0
		},
		"two chains at the same step": func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "sequential"
			legs[0]["sequence_order"] = 0
			legs[1]["sequence_order"] = 0
		},
		"parallel contradicted": func(e map[string]any, _ []map[string]any) {
			e["execution_mode"] = "parallel"
			e["execution_constraints"] = map[string]any{"parallel_execution": false}
		},
		"all-or-nothing atomicity": func(e map[string]any, _ []map[string]any) {
			e["execution_mode"] = "parallel"
			e["atomicity"] = map[string]any{"mode": "all_or_nothing", "partial_execution_allowed": false}
		},
		"rollback": func(e map[string]any, _ []map[string]any) {
			e["execution_mode"] = "parallel"
			e["rollback_policy"] = map[string]any{"mode": "rollback_all"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, declaring(t, []int64{84532, 421614}, mutate), ErrUnimplementedSemantics)
		})
	}
}

func TestCrossChainParallelBestEffortIsQueued(t *testing.T) {
	ci := declaring(t, []int64{84532, 421614}, func(e map[string]any, _ []map[string]any) {
		e["execution_mode"] = "parallel"
		e["atomicity"] = map[string]any{"mode": "best_effort", "rollback_strategy": "partial_allowed", "partial_execution_allowed": true}
		e["rollback_policy"] = map[string]any{"mode": "continue_on_failure", "partial_execution_allowed": true}
	})
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("a parallel best-effort cross-chain intent is what CERTEN implements: %v", err)
	}
}

// RB3-F52: a sequential cross-chain intent is queued in its declared order, each later member after the
// one before it. The shape is the api-bridge multi-leg builder's (the gateway's path): sequence_order
// per leg, execution_constraints echoing the mode, rollback_policy continue_on_failure, best effort.
func TestSequentialCrossChainIsQueuedInItsDeclaredOrder(t *testing.T) {
	ci := declaring(t, []int64{84532, 421614, 11155111}, func(e map[string]any, legs []map[string]any) {
		e["execution_mode"] = "sequential"
		e["execution_constraints"] = map[string]any{"mode": "sequential", "parallel_execution": false}
		e["rollback_policy"] = map[string]any{"mode": "continue_on_failure", "partial_execution_allowed": true}
		e["atomicity"] = map[string]any{"mode": "best_effort", "rollback_strategy": "partial_allowed", "partial_execution_allowed": true}
		e["leg_dependencies"] = []any{}
		// Declared order: 11155111, then 84532, then 421614 - not the listing order.
		legs[0]["sequence_order"] = 1
		legs[1]["sequence_order"] = 2
		legs[2]["sequence_order"] = 0
		for _, l := range legs {
			l["depends_on_legs"] = []string{}
			l["conditional_execution"] = false
		}
	})
	f := newFakeEnqueuer()
	if err := enqueue(refusalValidator(f), ci); err != nil {
		t.Fatalf("a sequential cross-chain intent is implemented: %v", err)
	}
	if want := []int64{11155111, 84532, 421614}; len(f.order) != 3 || f.order[0] != want[0] || f.order[1] != want[1] || f.order[2] != want[2] {
		t.Fatalf("queued in order %v, want the declared order %v", f.order, want)
	}
	if _, ok := f.after[11155111]; ok {
		t.Fatal("the first member waits on nothing")
	}
	for chain, want := range map[int64]SequencePredecessor{
		84532:  {ChainID: 11155111, Position: 1, ContinueOnFailure: true},
		421614: {ChainID: 84532, Position: 2, ContinueOnFailure: true},
	} {
		got, ok := f.after[chain]
		if !ok || got.ChainID != want.ChainID || got.Position != want.Position || got.ContinueOnFailure != want.ContinueOnFailure {
			t.Fatalf("chain %d queued after %+v, want after chain %d at position %d (continue %v)", chain, got, want.ChainID, want.Position, want.ContinueOnFailure)
		}
		if got.OperationID == ([32]byte{}) {
			t.Fatalf("chain %d's predecessor names no member", chain)
		}
	}
}

// With no rollback policy a member that does not settle stops the ones after it; with no
// sequence_order the listing order is the order.
func TestSequentialCrossChainDefaultsStopOnFailureInListingOrder(t *testing.T) {
	ci := declaring(t, []int64{421614, 84532}, func(map[string]any, []map[string]any) {})
	f := newFakeEnqueuer()
	if err := enqueue(refusalValidator(f), ci); err != nil {
		t.Fatalf("the default mode, sequential, is implemented: %v", err)
	}
	if len(f.order) != 2 || f.order[0] != 421614 || f.order[1] != 84532 {
		t.Fatalf("queued in order %v, want listing order", f.order)
	}
	if a := f.after[84532]; a.ChainID != 421614 || a.Position != 1 || a.ContinueOnFailure {
		t.Fatalf("second member queued after %+v, want after chain 421614, stopping on its failure", a)
	}
}

// A cross-chain dependency is honoured by the declared order when its target settles first - and only
// when a failure of that target stops the dependent leg.
func TestCrossChainDependencyFollowsTheDeclaredOrder(t *testing.T) {
	ci := declaring(t, []int64{84532, 421614}, func(e map[string]any, legs []map[string]any) {
		e["execution_mode"] = "sequential"
		legs[1]["depends_on_legs"] = []string{"leg-a"}
	})
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("leg-b depends on leg-a, which the declared order settles first: %v", err)
	}
	// The api-bridge's leg_dependencies shape names the same dependency.
	ci = declaring(t, []int64{84532, 421614}, func(e map[string]any, legs []map[string]any) {
		e["execution_mode"] = "sequential"
		e["leg_dependencies"] = []any{map[string]any{"legId": "leg-b", "dependsOn": []string{"leg-a"}, "condition": "success"}}
	})
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("the bridge's dependency shape, honoured by the order: %v", err)
	}
}

// One chain: legs run in one transaction, in listing order, all-or-nothing - "sequential" holds.
func TestSingleChainSequentialIsQueued(t *testing.T) {
	ci := declaring(t, []int64{84532, 84532}, func(e map[string]any, legs []map[string]any) {
		e["execution_mode"] = "sequential"
		legs[0]["sequence_order"] = 0
		legs[1]["sequence_order"] = 1
		legs[1]["depends_on_legs"] = []string{"leg-a"}
	})
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("single-chain sequential is honoured by the member's transaction: %v", err)
	}
}

func TestDependenciesAndOrderThatCannotBeHonouredAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		chains []int64
		mutate func(map[string]any, []map[string]any)
	}{
		"depends on another chain's leg": {[]int64{84532, 421614}, func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "parallel"
			legs[1]["depends_on_legs"] = []string{"leg-a"}
		}},
		"depends on a chain the order settles later": {[]int64{84532, 421614}, func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "sequential"
			legs[0]["depends_on_legs"] = []string{"leg-b"}
		}},
		"depends on another chain's leg, but continues on its failure": {[]int64{84532, 421614}, func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "sequential"
			e["rollback_policy"] = map[string]any{"mode": "continue_on_failure"}
			legs[1]["depends_on_legs"] = []string{"leg-a"}
		}},
		"one chain's legs split around another's": {[]int64{84532, 421614, 84532}, func(e map[string]any, legs []map[string]any) {
			e["execution_mode"] = "sequential"
		}},
		"bridge dependency naming an unknown leg": {[]int64{84532}, func(e map[string]any, _ []map[string]any) {
			e["leg_dependencies"] = []any{map[string]any{"legId": "leg-a", "dependsOn": []string{"leg-z"}}}
		}},
		"depends on a later leg": {[]int64{84532, 84532}, func(_ map[string]any, legs []map[string]any) {
			legs[0]["depends_on_legs"] = []string{"leg-b"}
		}},
		"depends on an unknown leg": {[]int64{84532}, func(e map[string]any, _ []map[string]any) {
			e["leg_dependencies"] = []any{map[string]any{"leg_id": "leg-a", "depends_on_leg_id": "leg-z"}}
		}},
		"sequence_order against listing order": {[]int64{84532, 84532}, func(_ map[string]any, legs []map[string]any) {
			legs[0]["sequence_order"] = 1
			legs[1]["sequence_order"] = 0
		}},
		"conditional execution": {[]int64{84532}, func(_ map[string]any, legs []map[string]any) {
			legs[0]["conditional_execution"] = true
		}},
	} {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, declaring(t, tc.chains, tc.mutate), ErrUnimplementedSemantics)
		})
	}
}

func TestLegWrittenAfterItsDeadlineIsRefused(t *testing.T) {
	ci := declaring(t, []int64{84532}, func(_ map[string]any, legs []map[string]any) {
		legs[0]["deadline_timestamp"] = 1_700_000_000
	})
	ci.BlockTime = time.Unix(1_700_000_001, 0)
	refusedWith(t, ci, ErrPastDeadline)

	// Written before its deadline, but too close to it for any settlement to land.
	ci.BlockTime = time.Unix(1_700_000_000, 0).Add(-MinSettlementLead + time.Second)
	refusedWith(t, ci, ErrDeadlineTooSoon)

	ci.BlockTime = time.Unix(1_700_000_000, 0).Add(-MinSettlementLead)
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("a leg written with the settlement lead to spare is admitted: %v", err)
	}
}

// The live intent 5a2ebba0 - single chain, sequential, best-effort, its deadline ahead of its
// block time - is admitted.
func TestLiveIntentDeclarationsAreAdmitted(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "intent_5a2ebba0", "blob1.json"))
	if err != nil {
		t.Fatal(err)
	}
	ci := &CertenIntent{IntentID: "5a2ebba0", CrossChainData: b}
	if err := CheckDeclaredSemantics(ci, time.Unix(1789949925-3600, 0)); err != nil {
		t.Fatalf("the live intent's declarations are ones CERTEN implements: %v", err)
	}
}

// RB3-F53: a leg's signed deadline travels with it into the batch member, where it is enforced.
func TestBatchLegCarriesItsSignedDeadline(t *testing.T) {
	ci := declaring(t, []int64{84532}, func(_ map[string]any, legs []map[string]any) {
		legs[0]["deadline_timestamp"] = 1_800_000_600
	})
	legs, _, _, _, err := refusalValidator(newFakeEnqueuer()).batchInputsFromIntentForChain(ci, 84532)
	if err != nil {
		t.Fatal(err)
	}
	if len(legs) != 1 || legs[0].Deadline != 1_800_000_600 {
		t.Fatalf("legs %+v; the leg's deadline did not reach the member", legs)
	}
}
