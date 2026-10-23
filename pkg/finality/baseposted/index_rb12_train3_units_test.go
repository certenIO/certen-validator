// Copyright 2026 Certen Protocol

package baseposted

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-FIX: unit tests of the pure decisions added by the fixes.

// The reader's batcher rule is the verifier's: on every shape of SystemConfig proof, the transaction the reader calls foreign is exactly
// the one verifyChannel refuses as batcher_sender_mismatch, and a block whose proof the verifier refuses by another name is one the
// reader cannot establish (so it filters nothing and the verifier names the fault).
func TestRB12F19TheReadersBatcherRuleIsTheVerifiersRule(t *testing.T) {
	rowsOf := func(s *synth) (hdr, sys []byte) {
		var sw finality.Writer
		sw.LPList(s.body.Nodes)
		return s.body.L1Spine[0], sw.Bytes()
	}
	// the batcher signs, and is the batcher the SystemConfig records
	s := makeSynth(t, synthOpts{calldata: true, nFrames: 1})
	hdr, sys := rowsOf(s)
	if _, err := s.verify(); err != nil {
		t.Fatalf("the fixture must verify: %v", err)
	}
	addr, ok := batcherFromRows(s.bp, hdr, sys)
	if !ok || addr != [20]byte(crypto.PubkeyToAddress(testKey("batcher").PublicKey)) {
		t.Fatalf("the rows prove the batcher %x ok=%v", addr, ok)
	}
	flt := &senderFilter{want: addr, signer: mustSigner(s.bp)}
	if flt.foreign(s.body.Frames[0].TxRaw) {
		t.Fatal("the batcher's own transaction is not foreign")
	}
	// somebody else signs: the verifier refuses by batcher_sender_mismatch and the reader skips it
	s2 := makeSynth(t, synthOpts{calldata: true, nFrames: 1, batcher: testKey("other"), chainBatch: testKey("batcher")})
	hdr2, sys2 := rowsOf(s2)
	_, err := s2.verify()
	wantCode(t, err, CodeBatcherSender, nil)
	addr2, ok2 := batcherFromRows(s2.bp, hdr2, sys2)
	f2 := &senderFilter{want: addr2, signer: mustSigner(s2.bp)}
	if !ok2 || !f2.foreign(s2.body.Frames[0].TxRaw) {
		t.Fatalf("a transaction the verifier refuses as batcher_sender_mismatch must be foreign to the reader (ok=%v)", ok2)
	}
	// a batcherHash with a non-zero byte above the address, an unpinned or absent implementation: the verifier names the fault, the reader
	// cannot establish the batcher and filters nothing
	for _, o := range []synthOpts{
		{calldata: true, nFrames: 1, dirtyBatcherHash: true, dirtyIndex: 3, dirtyValue: 1},
		{calldata: true, nFrames: 1, omitImpl: true},
	} {
		s3 := makeSynth(t, o)
		h3, y3 := rowsOf(s3)
		if _, err := s3.verify(); err == nil {
			t.Fatalf("the verifier must refuse %+v", o)
		}
		if _, ok := batcherFromRows(s3.bp, h3, y3); ok {
			t.Errorf("the reader must not establish a batcher the verifier refuses: %+v", o)
		}
	}
	// garbage rows establish nothing
	if _, ok := batcherFromRows(s.bp, make([]byte, 600), make([]byte, 3000)); ok {
		t.Error("garbage rows establish no batcher")
	}
	if (*senderFilter)(nil).foreign(s.body.Frames[0].TxRaw) {
		t.Error("no filter filters nothing")
	}
}

func TestRB12EntryCodecCarriesTheFirstFrameAndRefusesAnEmptyChannel(t *testing.T) {
	good := &chanEntry{Status: entryDecoded, ID: [16]byte{1}, FirstBlock: 5, FirstTx: 2, FirstFrame: 3, NFrames: 4, TMin: 10, TMax: 20,
		Txs: []entryTx{{Block: 5, Index: 2, Blobs: 1}}, Runs: []covRun{{First: 10, Count: 6, Epoch: 4}}}
	got, err := decodeEntry(good.encode())
	if err != nil || got.FirstFrame != 3 {
		t.Fatalf("the first frame position round-trips: %+v %v", got, err)
	}
	for name, edit := range map[string]func(e chanEntry) chanEntry{
		"no transactions": func(e chanEntry) chanEntry { e.Txs = nil; return e },
		"no frames":       func(e chanEntry) chanEntry { e.NFrames = 0; return e },
		"more transactions than frames": func(e chanEntry) chanEntry {
			e.NFrames = 1
			e.Txs = append(append([]entryTx(nil), e.Txs...), entryTx{Block: 6, Index: 1})
			return e
		},
	} {
		e := edit(*good)
		if _, err := decodeEntry(e.encode()); err == nil {
			t.Errorf("%s: a checksum-valid entry that cannot describe a channel is corruption", name)
		}
	}
	a, b := *good, *good
	b.FirstFrame = 4
	if !firstLess(&a, &b) || firstLess(&b, &a) {
		t.Error("the first frame position is the last key of the order between channels")
	}
}

func mustSigner(bp *Pins) types.Signer {
	return types.LatestSignerForChainID(new(big.Int).SetUint64(bp.L1ChainID))
}
