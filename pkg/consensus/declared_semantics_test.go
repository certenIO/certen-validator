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

func TestCrossChainIntentMustDeclareParallel(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, []map[string]any){
		"no mode (the default is sequential)": func(map[string]any, []map[string]any) {},
		"sequential":                          func(e map[string]any, _ []map[string]any) { e["execution_mode"] = "sequential" },
		"atomic":                              func(e map[string]any, _ []map[string]any) { e["execution_mode"] = "atomic" },
		"sequential via constraints": func(e map[string]any, _ []map[string]any) {
			e["execution_constraints"] = map[string]any{"mode": "sequential"}
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

	ci.BlockTime = time.Unix(1_699_999_999, 0)
	if err := enqueue(refusalValidator(newFakeEnqueuer()), ci); err != nil {
		t.Fatalf("a leg written before its deadline is admitted: %v", err)
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
