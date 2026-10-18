// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func encodedLen(t *testing.T, ev *Evidence) int {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

// A closure that cannot travel in one consensus transaction is the named state g1_closure_exceeds_budget{pages, limit}, judged at the
// transaction's partition and block; one byte under the budget passes. The budget is what CometBFT's max_tx_bytes (1 MiB) leaves after the
// certificate's reserve (xbudget.go).
func TestEvidenceBudgetIsExactlyTheConsensusTransactionLimitLessTheReserve(t *testing.T) {
	if MaxEvidenceBytes != 720896 {
		t.Fatalf("budget %d", MaxEvidenceBytes)
	}
	x := xAnchor{id: "BVN1", block: 50}
	ev := &Evidence{Version: Version21, Account: "acc://a.acme/data", Pages: []PageState{{URL: "acc://a.acme/data"}}}
	base := encodedLen(t, ev)
	pad := func(n int) { ev.Transaction = strings.Repeat("0", n) }
	// Transaction is an omitempty string: its quoted field adds len(`,"transaction":""`) + n bytes.
	pad(1)
	overhead := encodedLen(t, ev) - base - 1
	pad(MaxEvidenceBytes - base - overhead)
	if got := encodedLen(t, ev); got != MaxEvidenceBytes {
		t.Fatalf("calibration: %d, want %d", got, MaxEvidenceBytes)
	}
	if err := CheckEvidenceBudget(ev, x); err != nil {
		t.Fatalf("an evidence exactly at the budget: %v", err)
	}
	pad(MaxEvidenceBytes - base - overhead + 1)
	err := CheckEvidenceBudget(ev, x)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StateClosureExceedsBudget || ns.Partition != "BVN1" || ns.Block != 50 || !strings.Contains(ns.Detail, "pages=1 limit=720896") {
		t.Fatalf("an evidence one byte over the budget: %v", err)
	}
}

// The capture's check, before the evidence exists.
func TestClosureBudgetRefusesAClosureThatCannotFit(t *testing.T) {
	small := []PageState{{URL: "acc://a.acme/book", State: strings.Repeat("ab", 600)}}
	if err := CheckClosureBudget(small, nil, "BVN1", 50); err != nil {
		t.Fatalf("a small closure: %v", err)
	}
	room := MaxEvidenceBytes - FixedEvidenceBytes
	big := []PageState{{URL: "acc://a.acme/book", State: hex.EncodeToString(make([]byte, room/2))}}
	err := CheckClosureBudget(big, nil, "BVN1", 50)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StateClosureExceedsBudget || ns.Partition != "BVN1" || ns.Block != 50 || !strings.Contains(ns.Detail, "pages=1 limit=720896") {
		t.Fatalf("a closure over the budget: %v", err)
	}
}
