package execution

import (
	"context"
	"errors"
	"testing"
)

// The commit time is read from a BVN block only: a Directory block, or no block, is refused by name.
func TestResolveCommitTimeReadsOnlyACommitBlock(t *testing.T) {
	chain := &ctChain{}
	if got, err := ResolveCommitTime(context.Background(), chain.read, ctBVNURL, uint64(ctBVNBlock)); err != nil ||
		!got.Equal(ctTime(ctAdmission)) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ResolveCommitTime(context.Background(), chain.read, ctDN, ctDNHeight); err == nil {
		t.Fatal("a Directory block was read as a commit block")
	}
	if _, err := ResolveCommitTime(context.Background(), chain.read, "", 0); !errors.Is(err, ErrNoCommitBlock) {
		t.Fatalf("no commit block: %v", err)
	}
	// The member's commit block survives a restart.
	att := f57AttWithCommitBlock(ctBVN, ctBVNBlock)
	part, block := commitBlockOf(att)
	if part != ctBVNURL || block != uint64(ctBVNBlock) {
		t.Fatalf("commit block %s@%d", part, block)
	}
}
