package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// RB3-F54: the leader and its co-signing peers must derive a period's trees by the same rule.
// The leader screened each member's account and dropped the unusable ones from its tree and its
// mempool; a peer rebuilt from its full mempool without screening. One unusable member made every
// peer derive a different bundleId, no quorum formed, and after the bounded retries the whole period
// was dropped as failed. A leader that had settled some members and re-formed the period from the
// rest diverged the same way, as did the second tree of a period larger than one tree.

func bundleOf(t *testing.T, members []*PendingBatchIntent, cutoff uint64) string {
	t.Helper()
	inputs := make([]BatchLeafInput, 0, len(members))
	for _, m := range members {
		in, err := m.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}
	tree, err := BuildBatchTree(11155111, withAccSet(inputs), cutoff, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	return "0x" + hex.EncodeToString(tree.BundleID[:])
}

func memberNamed(t *testing.T, s *BatchStack, id string) *PendingBatchIntent {
	t.Helper()
	for _, m := range s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks) {
		if m.IntentID == id {
			return m
		}
	}
	t.Fatalf("member %s not in the period", id)
	return nil
}

// reproduced asserts the peer derived exactly the proposer's tree - it fails, without a loaded BLS
// key, only at the signing step.
func reproduced(t *testing.T, resp *BatchAttestationResponse, want string) {
	t.Helper()
	if resp.BundleID != want || resp.Code == CodeBundleMismatch {
		t.Fatalf("peer did not reproduce the leader's tree %s: derived %s, %s (%s)", want, resp.BundleID, resp.Error, resp.Code)
	}
}

// A member whose account cannot take part is left out of the tree by the peer exactly as by the leader.
func TestPeriodAgreement_PeerExcludesAnIneligibleMemberAsTheLeaderDoes(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	addMember(t, s, "beta", 100, 0xBB, 2000)
	s.Orchestrators[11155111].screen = func(_ context.Context, p *PendingBatchIntent) error {
		if p.IntentID == "alpha" {
			return errors.New("account is bound to a different ADI")
		}
		return nil
	}
	chunks, excluded, err := s.Orchestrators[11155111].periodChunks(context.Background(),
		s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks), s.Mempool.MaxBatchSize())
	if err != nil || len(excluded) != 1 || len(chunks) != 1 || len(chunks[0]) != 1 || chunks[0][0].IntentID != "beta" {
		t.Fatalf("leader's trees = %v excluded = %v err = %v, want [[beta]] excluding alpha", chunks, excluded, err)
	}
	want := bundleOf(t, chunks[0], 100)
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: want}, attesterID())
	reproduced(t, resp, want)
}

// A tree does not change as its members settle: the leader re-forming the period to settle the rest
// derives the tree its peers still derive.
func TestPeriodAgreement_TreeIsUnchangedAfterSomeMembersSettle(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	addMember(t, s, "beta", 100, 0xBB, 2000)
	want := derivedBundle(t, s, 100)
	s.Mempool.MarkOutcome([]*PendingBatchIntent{memberNamed(t, s, "alpha")}, MemberSettled)

	chunks, _, err := s.Orchestrators[11155111].periodChunks(context.Background(),
		s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks), s.Mempool.MaxBatchSize())
	if err != nil || len(chunks) != 1 || bundleOf(t, chunks[0], 100) != want {
		t.Fatal("the leader's tree changed after one of its members settled")
	}
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: want}, attesterID())
	reproduced(t, resp, want)
}

// A period larger than one tree is cut identically, so a peer co-signs its later trees too.
func TestPeriodAgreement_PeerReproducesAPeriodsSecondTree(t *testing.T) {
	s := stackForChain(t, 11155111)
	s.Mempool = newTestMempool(BatchMempoolConfig{MaxBatchSize: 2})
	for i, id := range []string{"a", "bb", "ccc"} {
		addMember(t, s, id, 100, byte(0xA0+i), int64(1000+i))
	}
	chunks := chunkMembers(s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks), 2)
	if len(chunks) != 2 {
		t.Fatalf("want 2 trees, got %d", len(chunks))
	}
	want := bundleOf(t, chunks[1], 100)
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: want}, attesterID())
	reproduced(t, resp, want)
}

// A screening read that fails decides nothing: the peer says it is not ready, never that it disagrees.
func TestPeriodAgreement_UnreadableAccountIsNotReady(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	s.Orchestrators[11155111].screen = func(context.Context, *PendingBatchIntent) error {
		return readErr(errors.New("rpc timeout"))
	}
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100, BundleID: derivedBundle(t, s, 100)}, attesterID())
	if resp.Code != CodeNotReady || !strings.Contains(resp.Error, "rpc timeout") {
		t.Fatalf("a failed read must be not_ready, got %s: %s", resp.Code, resp.Error)
	}
}
