// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// A window the process budget cannot cover is the named state finality_memory_budget_exceeded: nothing more is read, nothing is built,
// and the process does not grow past its budget (RB12-F3).
func TestRB12ABuildThatCannotReserveItsWindowIsAMemoryBudgetStateNotAnAllocation(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	s, l2 := rbLeg(t, rbFirstBlock+5*250)       // fifty blocks in the window: about 7 MB of rows, 10 MB to reserve
	budget := finality.NewMemoryBudget(1 << 20) // 1 MiB
	ctx := finality.WithMemoryBudget(context.Background(), budget)
	_, pend, err := rbBuilder(t, st, l2).Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if pend != nil {
		t.Fatalf("a refused reservation is not a pending: %v", pend)
	}
	se, named := finality.AsNamed(err)
	if !named || se.Code != finality.CodeMemoryBudget || se.Fields["what"] != "base_posted_window" {
		t.Fatalf("want finality_memory_budget_exceeded for base_posted_window, got %v", err)
	}
	if budget.Used() != 0 {
		t.Fatalf("the failed build kept %d bytes reserved", budget.Used())
	}
	if got := st.bytes.Load(); got > 12<<20 {
		t.Fatalf("the refusal came after %d bytes were read", got)
	}
	// the same leg under a budget that covers it is judged as before
	roomy := finality.WithMemoryBudget(context.Background(), finality.NewMemoryBudget(1<<30))
	if _, pend, err := rbBuilder(t, st, l2).Build(roomy, s, haveIncludedOnly, finality.LevelL1Posted); err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("pend=%v err=%v", pend, err)
	}
}
