package execution

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RB3-F53: a leg's signed deadline_timestamp was parsed and enforced nowhere - a queued, retried or
// failed-over member could execute after the deadline its signer set. It is now the member's deadline:
// its settlement carries it as the proof's expiresAt, which CertenAccountV7 enforces on chain
// (block.timestamp <= proof.expiresAt), and a member already past it is not sent.

func memberWithDeadlines(commit time.Time, deadlines ...int64) *PendingBatchIntent {
	p := odMember(1, odChain, 100)
	p.CommitTime = commit
	p.Legs = nil
	for i, d := range deadlines {
		p.Legs = append(p.Legs, LegExecution{LegID: string(rune('a' + i)), ChainID: odChain, Deadline: d})
	}
	return p
}

func TestMemberDeadline_IsTheEarliestOfItsLegsAndTheHorizon(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	if d, ok := memberWithDeadlines(commit, 1_800_000_900, 1_800_000_600).Deadline(); !ok || d.Unix() != 1_800_000_600 {
		t.Fatalf("deadline %v, want the earlier leg's", d)
	}
	// A leg deadline beyond the settlement horizon is capped by the horizon.
	if d, ok := memberWithDeadlines(commit, 1_800_009_999).Deadline(); !ok || !d.Equal(commit.Add(maxGasDeferral)) {
		t.Fatalf("deadline %v, want the horizon %v", d, commit.Add(maxGasDeferral))
	}
	// No declared deadline: the horizon alone.
	if d, ok := memberWithDeadlines(commit, 0).Deadline(); !ok || !d.Equal(commit.Add(maxGasDeferral)) {
		t.Fatalf("deadline %v", d)
	}
	// Neither known: no deadline, never a guessed one.
	if _, ok := memberWithDeadlines(time.Time{}, 0).Deadline(); ok {
		t.Fatal("a member with no declared deadline and no commit time has a deadline")
	}
}

func TestSettlementExpiry_CarriesTheMemberDeadline(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	p := memberWithDeadlines(commit, 1_800_000_600)
	exp, err := settlementExpiry(p, 1_800_000_100, time.Time{})
	if err != nil || exp != 1_800_000_600 {
		t.Fatalf("expiresAt %d err %v; want the member's deadline, not the hour", exp, err)
	}
	// A window fence earlier than the deadline still wins.
	exp, err = settlementExpiry(p, 1_800_000_100, time.Unix(1_800_000_300, 0))
	if err != nil || exp != 1_800_000_300 {
		t.Fatalf("expiresAt %d err %v; want the fence", exp, err)
	}
	// Past the deadline on chain: not sent, and the member's outcome.
	if _, err := settlementExpiry(p, 1_800_000_600, time.Time{}); !errors.Is(err, errMemberPastDeadline) {
		t.Fatalf("a settlement at the deadline was allowed: %v", err)
	}
	// A closed window is not the member's outcome.
	if _, err := settlementExpiry(p, 1_800_000_400, time.Unix(1_800_000_300, 0)); !errors.Is(err, errSettlementWindowClosed) {
		t.Fatalf("closed window: %v", err)
	}
}

// The deadline survives a restart, or a restored member would execute unbounded.
func TestMemberDeadline_IsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	st, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	m := NewBatchMempool(BatchMempoolConfig{})
	m.SetStore(st, nil)
	p := odMember(1, odChain, 100)
	p.Legs[0].Deadline = 1_800_000_600
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}

	st2, _ := NewBatchMempoolStore(path, jsonCodec{}, nil)
	after := NewBatchMempool(BatchMempoolConfig{})
	after.SetStore(st2, nil)
	got := after.PeriodMembers(odChain, 100, 100)
	if len(got) != 1 || got[0].Legs[0].Deadline != 1_800_000_600 {
		t.Fatalf("restored legs %+v; the deadline was lost", got)
	}
}

// An on-demand member past its deadline is terminal - not deferred to be retried for ever.
func TestOD_MemberPastItsDeadlineIsTerminal(t *testing.T) {
	f := &fakeODChain{settleErr: errMemberPastDeadline, anchorTx: odAnchorTx}
	out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), odMember(1, odChain, 100), proveOK)
	if !errors.Is(err, errMemberPastDeadline) || (out != nil && (out.Deferred || out.Settled)) {
		t.Fatalf("outcome %+v err %v; a member past its deadline must end, with that cause", out, err)
	}
}

// A failure with no transaction is recorded with its cause; one with a transaction is proved from it.
func TestOD_DisposeWithoutATransactionRecordsTheCause(t *testing.T) {
	s, calls := settlementSubmitter(t, &fakeODChain{})
	var dropped []string
	s.cfg.OnDropped = func(_ context.Context, _ *PendingBatchIntent, cause string) { dropped = append(dropped, cause) }
	m := odMember(1, odChain, 100)
	_ = s.cfg.Stack.Mempool.AddOnDemand(m)
	s.dispose(context.Background(), m, &OnDemandOutcome{}, false, errMemberPastDeadline)
	if len(*calls) != 0 || len(dropped) != 1 || !strings.Contains(dropped[0], "past its deadline") {
		t.Fatalf("attest %+v dropped %v; want the cause recorded through the drop handler", *calls, dropped)
	}
}
