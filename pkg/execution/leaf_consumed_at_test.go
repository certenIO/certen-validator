// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB3-F63: a leaf read at a block where the account has no code is "not consumed", not a failed read.
// Seen live on intent 3b990fe3: the Base member's leader read its Sepolia predecessor at the finalized
// block 11792066, before the account was deployed at 11792092, and logged a read failure every pass.
func TestLeafConsumedAtABlockWithoutTheAccountIsNotConsumed(t *testing.T) {
	account, leaf := common.HexToAddress("0x58F490700e8bEB42a282b4EE83C7542335CEd455"), [32]byte{0xaa}
	ctx := context.Background()

	// No account at the head: nothing consumed.
	p := &prunedNode{head: 11792200, hasCode: false, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, 11792066); err != nil || consumed {
		t.Fatalf("no code: consumed=%v err=%v; want not consumed and no error", consumed, err)
	}
	// Deployed at 11792092, after the block read, and its leaf consumed later still: not consumed as of 11792066.
	p = &prunedNode{head: 11792200, hasCode: true, consumed: true, consumedAt: 11792100, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, 11792066); err != nil || consumed {
		t.Fatalf("deployed and consumed after the block: consumed=%v err=%v", consumed, err)
	}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, 11792152); err != nil || !consumed {
		t.Fatalf("deployed and consumed before the block: consumed=%v err=%v", consumed, err)
	}
	p = &prunedNode{head: 11792200, hasCode: true, consumed: false, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, 11792152); err != nil || consumed {
		t.Fatalf("deployed, not consumed: consumed=%v err=%v", consumed, err)
	}
	// A read that genuinely fails still decides nothing.
	p = &prunedNode{head: 11792200, hasCode: true, callErr: true, leaf: leaf}
	if _, err := leafConsumedAt(ctx, p.serve(t), account, leaf, 11792152); err == nil {
		t.Fatal("a failed call must stay an error")
	}
}
