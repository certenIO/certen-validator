package execution

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

// RB5-F45: a cadence tree whose every pending member is past its deadline is refused before its anchor is created.
// Period 10244900 (2026-10-02) was anchored (340,916 gas) and attested (561,855 gas) for its one member, which every
// settlement then refused as past its deadline.

func memberDue(id string, deadline time.Time) *PendingBatchIntent {
	return &PendingBatchIntent{IntentID: id, ChainID: 84532,
		Legs: []LegExecution{{LegID: "l0", ChainID: 84532, Deadline: deadline.Unix()}}}
}

func TestATreeWhoseEveryMemberIsPastItsDeadlineIsNotAnchored(t *testing.T) {
	const head = uint64(1000)
	node := &prunedNode{head: head}
	client := node.serve(t)
	o := &BatchOrchestrator{ecm: &EthereumContractManager{client: client}, logf: func(string, ...interface{}) {}, clock: newChainClock(84532, client)}
	chainNow := time.Unix(int64(1790680000+head), 0) // the stub's head timestamp
	ctx := context.Background()

	past := []*PendingBatchIntent{memberDue("a", chainNow.Add(-time.Minute)), memberDue("b", chainNow)}
	if expired, err := o.allPendingPastDeadline(ctx, past); err != nil || !expired {
		t.Fatalf("every member past its deadline at the chain's time: expired=%v err=%v", expired, err)
	}
	mixed := append(append([]*PendingBatchIntent(nil), past...), memberDue("c", chainNow.Add(time.Minute)))
	if expired, err := o.allPendingPastDeadline(ctx, mixed); err != nil || expired {
		t.Fatalf("a member still within its deadline is anchored for: expired=%v err=%v", expired, err)
	}
	if expired, err := o.allPendingPastDeadline(ctx, append(past, &PendingBatchIntent{IntentID: "no-deadline"})); err != nil || expired {
		t.Fatalf("a member with no deadline: expired=%v err=%v", expired, err)
	}
	if expired, _ := o.allPendingPastDeadline(ctx, nil); expired {
		t.Fatal("no members is not an expired tree")
	}

	// A head that cannot be read decides nothing.
	unreachable, err := ethclient.Dial("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	broken := &BatchOrchestrator{ecm: &EthereumContractManager{client: unreachable}, logf: func(string, ...interface{}) {},
		clock: newChainClock(84532, unreachable)}
	if _, err := broken.allPendingPastDeadline(ctx, past); err == nil {
		t.Fatal("an unreadable chain head was judged")
	}
}

// The check runs before the anchor is created: after it, the gas is already spent.
func TestTheDeadlineCheckPrecedesTheAnchor(t *testing.T) {
	b, err := os.ReadFile("batch_orchestrator.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "func (o *BatchOrchestrator) FlushChain(")
	if start < 0 {
		t.Fatal("FlushChain not found")
	}
	body := src[start:]
	check, anchor := strings.Index(body, "o.allPendingPastDeadline(ctx, pendingMembers)"), strings.Index(body, "o.createBatchAnchor(ctx, tree)")
	if check < 0 || anchor < 0 || check > anchor {
		t.Fatalf("the all-expired check (at %d) must precede createBatchAnchor (at %d) in FlushChain", check, anchor)
	}
}
