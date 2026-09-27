// Copyright 2026 Certen Protocol

package accumulate

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// The BVN blocks a Directory Network block anchored, read in pieces the endpoint can always deliver
// (RB3-F125).
//
// A DN block record carries them under "anchored" - every anchored BVN block with all of its entries -
// on the same page as the DN anchor pool's own main-chain entry. On Kermit that one page can exceed what
// the endpoint delivers (responses are cut near 98 KB), and no page size avoids it. So the anchored
// blocks are derived exactly as the server derives them (internal/api/v3 loadAnchoredBlocks): the anchor
// pool's main-index chain has one entry per DN block that received anchors, {source: main-chain index,
// blockIndex: DN block}; the block's anchors are the main-chain entries after the previous index entry's
// source up to its own; each anchor names its partition and minor block. Where the server skips a record
// it cannot read ("Bad, but ignore"), this is an error: an anchored block that is not read is not searched.

const dnAnchorPool = "acc://dn.acme/anchors"

// AnchoredBlock is a partition minor block anchored into a DN block.
type AnchoredBlock struct {
	Source string // partition URL, e.g. acc://bvn-BVN1.acme
	Index  int64  // the partition's minor block index
}

// anchorIndexCursor remembers the last DN block found on the index chain, so consecutive DN blocks are
// found without a search.
type anchorIndexCursor struct {
	mu    sync.Mutex
	pos   int64 // index-chain position
	block int64 // its DN block
}

type anchorIndexEntry struct {
	source     int64 // main-chain index
	blockIndex int64 // DN block
}

func (l *LiteClientAdapter) anchorIndexEntryAt(ctx context.Context, pos int64) (anchorIndexEntry, error) {
	recs, err := l.chainRange(ctx, dnAnchorPool, "main-index", pos, 1)
	if err != nil {
		return anchorIndexEntry{}, err
	}
	v, _ := recs[0]["value"].(map[string]interface{})
	inner, _ := v["value"].(map[string]interface{})
	src, ok1 := inner["source"].(float64)
	blk, ok2 := inner["blockIndex"].(float64)
	if !ok1 || !ok2 {
		return anchorIndexEntry{}, fmt.Errorf("anchor index entry %d is not an index entry: %v", pos, v)
	}
	return anchorIndexEntry{source: int64(src), blockIndex: int64(blk)}, nil
}

// chainRange reads count entries of an account chain from start, expanded, and requires exactly them.
func (l *LiteClientAdapter) chainRange(ctx context.Context, account, chain string, start, count int64) ([]map[string]interface{}, error) {
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": account,
		"query": map[string]interface{}{
			"queryType": "chain", "name": chain,
			"range": map[string]interface{}{"start": start, "count": count, "expand": true},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%s %s chain from %d: %w", account, chain, start, err)
	}
	raw, _ := result["records"].([]interface{})
	if int64(len(raw)) != count {
		return nil, fmt.Errorf("%s %s chain from %d: %d of %d entries", account, chain, start, len(raw), count)
	}
	out := make([]map[string]interface{}, len(raw))
	for i, r := range raw {
		m, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s %s chain entry %d is not a record", account, chain, start+int64(i))
		}
		if idx, ok := m["index"].(float64); !ok || int64(idx) != start+int64(i) {
			return nil, fmt.Errorf("%s %s chain: asked for entry %d, got %v", account, chain, start+int64(i), m["index"])
		}
		out[i] = m
	}
	return out, nil
}

func (l *LiteClientAdapter) chainCount(ctx context.Context, account, chain string) (int64, error) {
	result, err := l.queryV3API(ctx, "query", map[string]interface{}{
		"scope": account, "query": map[string]interface{}{"queryType": "chain", "name": chain},
	})
	if err != nil {
		return 0, fmt.Errorf("%s %s chain: %w", account, chain, err)
	}
	if rt, _ := result["recordType"].(string); rt != "chain" {
		return 0, fmt.Errorf("%s %s chain: the answer is a %q record", account, chain, rt)
	}
	c, ok := result["count"].(float64)
	if !ok || c < 0 {
		return 0, fmt.Errorf("%s %s chain states no count", account, chain)
	}
	return int64(c), nil
}

// findAnchorIndex returns the index-chain position of DN block h, or found=false when h received no
// anchors. The chain is ordered by DN block.
func (l *LiteClientAdapter) findAnchorIndex(ctx context.Context, h int64) (int64, bool, error) {
	l.anchorCursor.mu.Lock()
	pos, blk := l.anchorCursor.pos, l.anchorCursor.block
	l.anchorCursor.mu.Unlock()
	remember := func(p, b int64) {
		l.anchorCursor.mu.Lock()
		l.anchorCursor.pos, l.anchorCursor.block = p, b
		l.anchorCursor.mu.Unlock()
	}
	// Consecutive discovery: the next entry is usually the one after the last one found.
	if blk > 0 && blk < h {
		if e, err := l.anchorIndexEntryAt(ctx, pos+1); err == nil {
			if e.blockIndex == h {
				remember(pos+1, h)
				return pos + 1, true, nil
			}
			if e.blockIndex > h {
				return 0, false, nil
			}
		}
	}
	count, err := l.chainCount(ctx, dnAnchorPool, "main-index")
	if err != nil {
		return 0, false, err
	}
	lo, hi := int64(0), count-1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		e, err := l.anchorIndexEntryAt(ctx, mid)
		if err != nil {
			return 0, false, err
		}
		switch {
		case e.blockIndex == h:
			remember(mid, h)
			return mid, true, nil
		case e.blockIndex < h:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return 0, false, nil
}

// AnchoredBlocks returns the partition blocks DN block h anchored, excluding the DN's own.
func (l *LiteClientAdapter) AnchoredBlocks(ctx context.Context, h int64) ([]AnchoredBlock, error) {
	pos, found, err := l.findAnchorIndex(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("DN block %d anchor index: %w", h, err)
	}
	if !found {
		return nil, nil
	}
	end, err := l.anchorIndexEntryAt(ctx, pos)
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if pos > 0 {
		prev, err := l.anchorIndexEntryAt(ctx, pos-1)
		if err != nil {
			return nil, err
		}
		start = prev.source + 1
	}
	var out []AnchoredBlock
	for i := start; i <= end.source; i++ {
		recs, err := l.chainRange(ctx, dnAnchorPool, "main", i, 1)
		if err != nil {
			return nil, fmt.Errorf("DN block %d anchor %d: %w", h, i, err)
		}
		src, idx, err := anchorOf(recs[0])
		if err != nil {
			return nil, fmt.Errorf("DN block %d anchor %d: %w", h, i, err)
		}
		if strings.EqualFold(src, "acc://dn.acme") {
			continue // the DN's own block
		}
		out = append(out, AnchoredBlock{Source: src, Index: idx})
	}
	return out, nil
}

// anchorOf reads a partition anchor's source and minor block from an anchor-pool main-chain entry.
func anchorOf(rec map[string]interface{}) (string, int64, error) {
	v, _ := rec["value"].(map[string]interface{})
	msg, _ := v["message"].(map[string]interface{})
	txn, _ := msg["transaction"].(map[string]interface{})
	body, _ := txn["body"].(map[string]interface{})
	typ, _ := body["type"].(string)
	if typ != "blockValidatorAnchor" && typ != "directoryAnchor" {
		return "", 0, fmt.Errorf("the entry is a %q, not a partition anchor", typ)
	}
	src, _ := body["source"].(string)
	idx, ok := body["minorBlockIndex"].(float64)
	if src == "" || !ok || idx <= 0 {
		return "", 0, fmt.Errorf("the anchor names no source and minor block (%v/%v)", body["source"], body["minorBlockIndex"])
	}
	return src, int64(idx), nil
}
