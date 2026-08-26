// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"fmt"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Binding every partition leg to ONE Directory root.
//
// THE PROBLEM.
//
// A proof whose signers span two partitions has a leg per partition. Each leg's
// L2 receipt is a merkle path from that partition's anchor entry up to a
// Directory root - but the two partitions' anchors are recorded in DIFFERENT DN
// blocks, so two receipts taken "for any" anchor terminate at DIFFERENT roots.
// L3 proves one of them into the DN state tree. The other leg then has no proven
// path to the Directory state the proof is about. Observed live on Kermit for
// corpus case F: 7769803 and 7769799.
//
// THE SOLUTION, AND WHY IT IS COMPLETE RATHER THAN A PATCH.
//
// A receipt can be asked to terminate at a CHOSEN height of the DN minor root
// chain: ReceiptOptions.ForHeight. Its name misleads - it is a height on that
// chain, not a block number - and asking for a height later than the entry's own
// returns a genuine merkle path extended forward to the root at that height.
// Verified against Kermit: the same BVN2 entry yields a 17-hop path to the root
// at block 7769799 and a 21-hop path to the root at block 7781647.
//
// So every leg is asked for the SAME height, and every leg then carries a real
// merkle path to the SAME Directory root. Nothing is asserted and no hop is
// skipped: each leg proves itself into the common root, and L3 proves that root
// into the DN state tree. The chain is complete for every partition.
//
// CHOOSING THE HEIGHT DETERMINISTICALLY.
//
// The height must not come from "wherever the chain happens to be now" - two
// validators building the same proof at different moments would pick different
// heights, produce different bytes, and disagree about govRoot. That is the
// intermittent, unreproducible failure canonical ordering exists to prevent.
//
// It is derived from the proof instead. Every leg already states the DN block
// its anchor was recorded in; take the LATEST of those, and find the first
// Directory root at or after it. The Directory's `root-index` chain is exactly
// that mapping - each entry pairs a root chain height (source) with the block it
// closed (blockIndex) - so the answer is a function of the transaction and of
// immutable chain history, and never of when the question was asked.

// dnLedger is the account whose root chain the Directory anchors into, and whose
// root-index chain maps that chain's heights to block indices.
const (
	dnLedgerURL       = "acc://dn.acme/ledger"
	dnRootChain       = "root"
	dnRootIndexChain  = "root-index"
	rootIndexMaxProbe = 64 // binary search bound; 2^64 covers any real chain
)

// resolveDNRootChainHeight returns the smallest DN minor root chain height whose
// block index is at or after dnBlock.
//
// That is the first Directory root that contains every leg anchored at or before
// dnBlock, which is what makes one height serve all of them.
func resolveDNRootChainHeight(ctx context.Context, c *jsonrpc.Client, dnBlock uint64) (uint64, error) {
	if c == nil {
		return 0, fmt.Errorf("dn root height: missing v3 client")
	}
	ledger, err := acc_url.Parse(dnLedgerURL)
	if err != nil {
		return 0, err
	}

	total, err := indexChainCount(ctx, c, ledger)
	if err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, fmt.Errorf("dn root height: %s %s is empty", dnLedgerURL, dnRootIndexChain)
	}

	// Binary search for the first entry with blockIndex >= dnBlock. The index
	// chain is append-only and ordered by block, so this is exact rather than
	// approximate - there is no scanning and no tolerance.
	lo, hi := uint64(0), total-1
	var found *dnRootIndexEntry
	for i := 0; lo <= hi && i < rootIndexMaxProbe; i++ {
		mid := lo + (hi-lo)/2
		e, err := readRootIndexEntry(ctx, c, ledger, mid)
		if err != nil {
			return 0, err
		}
		if e.BlockIndex >= dnBlock {
			found = e
			if mid == 0 {
				break
			}
			hi = mid - 1
		} else {
			lo = mid + 1
		}
	}
	if found == nil {
		return 0, fmt.Errorf("dn root height: no Directory root at or after block %d yet; the "+
			"anchor has not been recorded in a Directory block that has closed", dnBlock)
	}
	return found.Source, nil
}

type dnRootIndexEntry struct {
	Source     uint64
	BlockIndex uint64
}

func indexChainCount(ctx context.Context, c *jsonrpc.Client, ledger *acc_url.URL) (uint64, error) {
	rec, err := c.Query(ctx, ledger, &v3.ChainQuery{Name: dnRootIndexChain})
	if err != nil {
		return 0, fmt.Errorf("dn root height: query %s: %w", dnRootIndexChain, err)
	}
	cr, ok := rec.(*v3.ChainRecord)
	if !ok {
		return 0, fmt.Errorf("dn root height: %s is a %T, not a chain record", dnRootIndexChain, rec)
	}
	return cr.Count, nil
}

func readRootIndexEntry(ctx context.Context, c *jsonrpc.Client, ledger *acc_url.URL, at uint64) (*dnRootIndexEntry, error) {
	idx := at
	rec, err := c.Query(ctx, ledger, &v3.ChainQuery{Name: dnRootIndexChain, Index: &idx})
	if err != nil {
		return nil, fmt.Errorf("dn root height: read %s[%d]: %w", dnRootIndexChain, at, err)
	}
	ce, ok := rec.(*v3.ChainEntryRecord[v3.Record])
	if !ok {
		return nil, fmt.Errorf("dn root height: %s[%d] is a %T", dnRootIndexChain, at, rec)
	}
	ie, ok := ce.Value.(*v3.IndexEntryRecord)
	if !ok || ie.Value == nil {
		return nil, fmt.Errorf("dn root height: %s[%d] carries no index entry (%T); without the "+
			"height-to-block mapping a common Directory root cannot be chosen and legs would be "+
			"bound to different roots", dnRootIndexChain, at, ce.Value)
	}
	return &dnRootIndexEntry{Source: ie.Value.Source, BlockIndex: ie.Value.BlockIndex}, nil
}
