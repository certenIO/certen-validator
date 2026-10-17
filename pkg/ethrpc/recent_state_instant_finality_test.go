package ethrpc

import (
	"context"
	"testing"
	"time"
)

// RB7-ADIRI-F1: Telcoin Adiri makes a block only when a transaction lands and a block is final the moment it exists, so
// after an anchor's transaction and a settlement the head is the anchor's own block. Contract state read at "head minus
// 3" (the depth that keeps providers in step on a chain whose heads move) is read BEFORE the anchor existed.
func TestAnInstantFinalityChainReadsContractStateAtItsHead(t *testing.T) {
	shortenVerification(t)
	final := header(testHeight, "final")
	a, b := adiriProvider(adiriGenesis(t), final), adiriProvider(adiriGenesis(t), final)
	for _, p := range []*stubProvider{a, b} {
		p.latest = testHeight // the head IS the block the anchor landed in
	}
	r, err := NewAgreeingReader(context.Background(), 2017, urlsOf(t, a, b), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	at, err := r.RecentAgreedHeader(context.Background())
	if err != nil || at.Number.Uint64() != testHeight {
		t.Fatalf("the recent agreed header of an idle instant-finality chain is %v (%v), want its head %d", at, err, testHeight)
	}
}
