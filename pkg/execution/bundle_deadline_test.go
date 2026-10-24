// Copyright 2026 Certen Protocol

package execution

import (
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

// deadlineMember is a member whose chain deadline is outcomeTestCommit + after (its earliest leg deadline).
func deadlineMember(t *testing.T, chainID int64, id, value string, after time.Duration) *PendingBatchIntent {
	t.Helper()
	p := outcomeTestMember(t, chainID, id, f77NativeLeg(chainID, value))
	want := outcomeTestCommit.Add(after)
	p.Legs[0].Deadline = want.Unix()
	if d, ok := memberChainDeadline(p); !ok || d.Unix() != want.Unix() {
		t.Fatalf("fixture: member %s has chain deadline %v (%v), want %v", id, d, ok, want)
	}
	return p
}

func deadlineStack(t *testing.T) *BatchStack {
	t.Helper()
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &BatchStack{Mempool: NewBatchMempool(DefaultBatchMempoolConfig()), OutcomeTrees: store}
}

// retainBundle keeps the tree of members as the signer does and queues the members in the mempool; it returns the bundle id.
func retainBundle(t *testing.T, s *BatchStack, chainID int64, members ...*PendingBatchIntent) [32]byte {
	t.Helper()
	tree, byOp := outcomeTestTree(t, chainID, members...)
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.OutcomeTrees.Retain(kept); err != nil {
		t.Fatal(err)
	}
	s.Mempool.mu.Lock()
	s.Mempool.pool[chainID] = append(s.Mempool.pool[chainID], members...)
	s.Mempool.mu.Unlock()
	return [32]byte(tree.BundleID)
}

func wantDeadline(t *testing.T, what string, got BundleDeadline, state BundleDeadlineState, pending, undated int, earliest, latest time.Time) {
	t.Helper()
	if got.State != state || got.Pending != pending || got.Undated != undated || !got.Earliest.Equal(earliest) || !got.Latest.Equal(latest) {
		t.Fatalf("%s: got %+v, want state %s pending %d undated %d earliest %v latest %v", what, got, state, pending, undated, earliest, latest)
	}
	if got.Known() != (state == BundleDeadlineKnown) {
		t.Fatalf("%s: Known() = %v in state %s", what, got.Known(), state)
	}
}

func TestBundleChainDeadlineIsTheEarliestAndLatestOfThePendingMembersOfTheBundleOnItsChain(t *testing.T) {
	s := deadlineStack(t)
	const baseChain, otherChain = int64(84532), int64(11155111)
	at := func(m time.Duration) time.Time { return outcomeTestCommit.Add(m).UTC() }
	a1 := deadlineMember(t, baseChain, "alpha", "7", 10*time.Minute)
	a2 := deadlineMember(t, baseChain, "beta", "8", 20*time.Minute)
	a3 := deadlineMember(t, baseChain, "gamma", "9", 30*time.Minute)
	b1 := deadlineMember(t, otherChain, "delta", "7", 5*time.Minute)
	bundleA := retainBundle(t, s, baseChain, a1, a2, a3)
	bundleB := retainBundle(t, s, otherChain, b1)
	zero := time.Time{}

	held, _ := s.Mempool.FindMember(baseChain, a1.OperationID)
	wantDeadline(t, "all three pending", s.BundleChainDeadline(baseChain, bundleA), BundleDeadlineKnown, 3, 0, at(10*time.Minute), at(30*time.Minute))
	if after, _ := s.Mempool.FindMember(baseChain, a1.OperationID); !reflect.DeepEqual(held, after) {
		t.Fatal("reading the deadline changed the pending member")
	}
	wantDeadline(t, "the other chain", s.BundleChainDeadline(otherChain, bundleB), BundleDeadlineKnown, 1, 0, at(5*time.Minute), at(5*time.Minute))

	// A bundle id is read on its own chain only, and a bundle never kept is not held.
	wantDeadline(t, "bundle of another chain", s.BundleChainDeadline(otherChain, bundleA), BundleDeadlineTreeNotHeld, 0, 0, zero, zero)
	wantDeadline(t, "bundle on the wrong chain", s.BundleChainDeadline(baseChain, bundleB), BundleDeadlineTreeNotHeld, 0, 0, zero, zero)
	wantDeadline(t, "unknown bundle", s.BundleChainDeadline(baseChain, [32]byte{9}), BundleDeadlineTreeNotHeld, 0, 0, zero, zero)

	// A settled member stops counting: the bundle's deadline is the one of the members that can still execute.
	s.Mempool.MarkOutcome([]*PendingBatchIntent{a1}, MemberSettled)
	wantDeadline(t, "first settled", s.BundleChainDeadline(baseChain, bundleA), BundleDeadlineKnown, 2, 0, at(20*time.Minute), at(30*time.Minute))
	// A member the mempool no longer holds is finished too.
	s.Mempool.DropMembers([]*PendingBatchIntent{a2})
	wantDeadline(t, "second forgotten", s.BundleChainDeadline(baseChain, bundleA), BundleDeadlineKnown, 1, 0, at(30*time.Minute), at(30*time.Minute))
	// Past a deadline is still a deadline: the caller stops following the anchor.
	a3.Legs[0].Deadline = at(-time.Hour).Unix()
	if got := s.BundleChainDeadline(baseChain, bundleA); !got.Known() || !got.Latest.Before(outcomeTestCommit) {
		t.Fatalf("a past deadline: %+v", got)
	}
	a3.Legs[0].Deadline = at(30 * time.Minute).Unix()
	s.Mempool.MarkOutcome([]*PendingBatchIntent{a3}, MemberSettledElsewhere)
	wantDeadline(t, "all finished", s.BundleChainDeadline(baseChain, bundleA), BundleDeadlineMembersFinished, 0, 0, zero, zero)
	wantDeadline(t, "the other chain is unaffected", s.BundleChainDeadline(otherChain, bundleB), BundleDeadlineKnown, 1, 0, at(5*time.Minute), at(5*time.Minute))
}

func TestBundleChainDeadlineIsUnknownWhileAPendingMemberHasNoDeadline(t *testing.T) {
	s := deadlineStack(t)
	c1 := deadlineMember(t, 84532, "alpha", "7", 40*time.Minute)
	c2 := deadlineMember(t, 84532, "beta", "8", 50*time.Minute)
	bundle := retainBundle(t, s, 84532, c1, c2)
	c2.Legs[0].Deadline = 0
	c2.CommitTime, c2.FirstSeen, c2.EnqueuedAt = time.Time{}, time.Time{}, time.Time{}
	if _, ok := memberChainDeadline(c2); ok {
		t.Fatal("fixture: the member still has a chain deadline")
	}
	// One pending member that nothing can bound makes the whole bundle unbounded: the reach bound alone applies.
	wantDeadline(t, "one undated pending member", s.BundleChainDeadline(84532, bundle), BundleDeadlineNoMemberDeadline, 1, 1, time.Time{}, time.Time{})
}

func TestBundleChainDeadlineNamesWhatItCannotRead(t *testing.T) {
	s := deadlineStack(t)
	a := deadlineMember(t, 84532, "alpha", "7", 10*time.Minute)
	bundle := retainBundle(t, s, 84532, a)
	zero := time.Time{}
	var nilStack *BatchStack
	wantDeadline(t, "nil stack", nilStack.BundleChainDeadline(84532, bundle), BundleDeadlineNotWired, 0, 0, zero, zero)
	wantDeadline(t, "empty stack", (&BatchStack{}).BundleChainDeadline(84532, bundle), BundleDeadlineNotWired, 0, 0, zero, zero)
	wantDeadline(t, "no store", (&BatchStack{Mempool: s.Mempool}).BundleChainDeadline(84532, bundle), BundleDeadlineNotWired, 0, 0, zero, zero)
	wantDeadline(t, "no mempool", (&BatchStack{OutcomeTrees: s.OutcomeTrees}).BundleChainDeadline(84532, bundle), BundleDeadlineNotWired, 0, 0, zero, zero)
	if err := os.WriteFile(s.OutcomeTrees.path(84532, bundle), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantDeadline(t, "corrupt tree", s.BundleChainDeadline(84532, bundle), BundleDeadlineTreeUnreadable, 0, 0, zero, zero)
}

func TestBundleChainDeadlineReadsBesideSettlementWithoutRacingIt(t *testing.T) {
	s := deadlineStack(t)
	ms := []*PendingBatchIntent{
		deadlineMember(t, 84532, "alpha", "7", 10*time.Minute),
		deadlineMember(t, 84532, "beta", "8", 20*time.Minute),
		deadlineMember(t, 84532, "gamma", "9", 30*time.Minute),
	}
	bundle := retainBundle(t, s, 84532, ms...)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.BundleChainDeadline(84532, bundle)
				}
			}
		}()
	}
	for _, m := range ms {
		s.Mempool.MarkOutcome([]*PendingBatchIntent{m}, MemberSettled)
	}
	close(stop)
	wg.Wait()
	wantDeadline(t, "after settlement", s.BundleChainDeadline(84532, bundle), BundleDeadlineMembersFinished, 0, 0, time.Time{}, time.Time{})
}
