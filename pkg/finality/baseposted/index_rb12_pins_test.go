// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// Note (i): the unindexable record is insert-only and cannot be deleted, so the reader prefers the digest: a block that has a digest is
// readable whatever an old record says.
func TestRB12UnindexableRecordIsIgnoredOnceTheBlockHasADigest(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	good := channelFrames("G", 1_790_100_000, 10, 1000, 1)
	vPutBlock(t, st, bp, 1010, []Frame{good[0]})
	// a block recorded as unreadable (by the code of an older roll) and later digested by a fixed one
	putRawBlock(t, st, 1015, map[string][]byte{ItemInbox: inboxRow(4097)})
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1500)
	if _, err := ixSearch(t, st, bp, 1000, 1_790_999_000); err == nil || !strings.Contains(err.Error(), "index_block_unindexable") {
		t.Fatalf("with the record alone the leg is told: %v", err)
	}
	// the digest of that block now exists (an empty digest is a valid digest of a block with no frames)
	h := shapeHash(1015, 0)
	dk := finality.CaptureKey{Chain: uint64(Chain), L1Block: 1015, L1Hash: h, Item: "idx/g1/bi/f"}
	d := &blockDigest{Block: 1015, Hash: h, Pins: pinsDigest(bp)}
	if err := finality.IndexPut(context.Background(), st, FamilyBaseInbox, dk, d.encode()); err != nil {
		t.Fatal(err)
	}
	if _, err := ixSearch(t, st, bp, 1000, 1_790_999_000); err != nil {
		t.Fatalf("a block with a digest is readable: the old record is ignored, got %v", err)
	}
}

// Every pin the bytes of the rows depend on is in the pins digest, and a digest written under other pins is the NAMED stale-pins state, never
// an index conflict.
func TestRB12PinsDigestCoversEveryPinTheRowsDependOnAndAStaleDigestIsNamed(t *testing.T) {
	_, bp := idxPins(t)
	base := pinsDigest(bp)
	for name, edit := range map[string]func(p *Pins){
		"SystemConfig":    func(p *Pins) { p.SystemConfig[0] ^= 1 },
		"impl hash set":   func(p *Pins) { p.SystemConfigImplHashes = map[[32]byte]bool{{1}: true} },
		"L1ChainID":       func(p *Pins) { p.L1ChainID++ },
		"SeqWindowSize":   func(p *Pins) { p.SeqWindowSize++ },
		"ChainID":         func(p *Pins) { p.ChainID++ },
		"L2GenesisTime":   func(p *Pins) { p.L2GenesisTime++ },
		"L2BlockTime":     func(p *Pins) { p.L2BlockTime++ },
		"MaxRLPBytesPerC": func(p *Pins) { p.MaxRLPBytesPerChannel++ },
	} {
		p := *bp
		edit(&p)
		if pinsDigest(&p) == base {
			t.Errorf("a change of %s does not change the pins digest", name)
		}
	}
	st := NewMemStore()
	good := channelFrames("G", 1_790_100_000, 10, 1000, 1)
	vPutBlock(t, st, bp, 1010, []Frame{good[0]})
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1500)
	rolled := *bp
	rolled.SystemConfig[0] ^= 1 // the SystemConfig pin rolled: the batcher filter, hence the digest bytes, would differ
	_, err := NewIndexer(st, &rolled, 0, IndexConfig{ReconcileEvery: 1}).Step(context.Background(), 1500)
	se, ok := finality.AsNamed(err)
	if !ok || se.Code != "index_inconsistent" || se.Fields["reason"] != finality.IndexPinsChanged {
		t.Fatalf("a pins roll over stored digests is index_inconsistent{pins_changed}, got %v", err)
	}
	if IsIndexConflict(err) {
		t.Fatal("never an index conflict")
	}
}
