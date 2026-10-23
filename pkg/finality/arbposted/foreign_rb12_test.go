// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-INDEX-B, the reference reader: a captured record the Bridge does not hold (the orphan twin of a reorged batch, an event a provider
// invented) must not shadow the batch the Bridge holds. This test uses only what the base commit has, so it fails there by assertion: the
// reference reader serves the first candidate in (N, L1 block) order that holds the message, and the verifier then refuses its accumulator for
// ever. The authorization (capture.AuthorizeBatch) skips a record a verified proof contradicts.
func TestRB12ArbReferenceReaderDoesNotServeARecordTheBridgeDoesNotHold(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "finality_arb_posted1", "raw", "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	arb, err := loadArbPins(pins)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := capture.NewMemStore()
	tx := legacyTx(7)
	payload := payloadOf(seg(segL2Message, signedTxMsg(tx)))
	blobs := encodeBlobs(payload)

	mkRecord := func(blockHashTag byte, beforeTag byte) (capture.BatchRecord, capture.Key) {
		hdr, _ := rlp.EncodeToBytes(&types.Header{Number: big.NewInt(1000), Time: 1_790_000_000, Root: common.Hash{blockHashTag}, Difficulty: big.NewInt(0), BaseFee: big.NewInt(7)})
		hash := crypto.Keccak256Hash(hdr)
		rec := capture.BatchRecord{N: 900, BeforeAcc: common.Hash{beforeTag}, DelayedAcc: common.Hash{2}, Header40: [5]uint64{1_790_000_000 - 86400, 1_790_000_000 + 768, 0, 0, 0},
			DataLocation: capture.LocBlob, L1Block: 1000, L1Hash: hash, VersionedHashes: [][32]byte{{1}}}
		rec.AfterAcc = Accumulator(rec.BeforeAcc, rec.DataHash(nil), rec.DelayedAcc)
		key := capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: 1000, L1Hash: hash}
		put := func(item string, b []byte) {
			if err := store.Put(ctx, capture.Key{Chain: key.Chain, L1Block: key.L1Block, L1Hash: key.L1Hash, Item: item}, b); err != nil {
				t.Fatal(err)
			}
		}
		put(capture.ItemHeader, hdr)
		put(capture.ItemBatch(900), rec.Encode())
		put(capture.ItemBlob(900, 0), capture.BlobRecord{Raw: blobs[0]}.Encode())
		return rec, key
	}
	recA, _ := mkRecord(1, 1)
	recB, _ := mkRecord(2, 2)
	// the Bridge holds the record that sorts SECOND at the same height
	held, foreign := recA, recB
	if string(recA.L1Hash[:]) < string(recB.L1Hash[:]) {
		held, foreign = recB, recA
	}
	st := newSynthState(t, map[uint64]common.Hash{900: held.AfterAcc}, nil)
	phdr, _ := rlp.EncodeToBytes(&types.Header{Number: big.NewInt(1010), Time: 1_790_000_200, Root: st.root, Difficulty: big.NewInt(0), BaseFee: big.NewInt(7)})
	pkey := capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: 1010, L1Hash: crypto.Keccak256Hash(phdr)}
	if err := store.Put(ctx, capture.Key{Chain: pkey.Chain, L1Block: pkey.L1Block, L1Hash: pkey.L1Hash, Item: capture.ItemHeader}, phdr); err != nil {
		t.Fatal(err)
	}
	pr := capture.ProofRecord{Kind: capture.ProofBatchAcc, Index: 900, ProofBlock: 1010, ProofBlockHash: pkey.L1Hash, Nodes: st.nodes}
	if err := store.Put(ctx, capture.Key{Chain: pkey.Chain, L1Block: pkey.L1Block, L1Hash: pkey.L1Hash, Item: capture.ItemProof(900)}, pr.Encode()); err != nil {
		t.Fatal(err)
	}

	b := &Builder{Store: store, Pins: pins}
	batches, err := capture.LoadBatches(ctx, store, finality.ChainArbitrumSepolia)
	if err != nil || len(batches) != 2 || batches[0].L1Hash != foreign.L1Hash {
		t.Fatalf("the world is not the one the test needs: %d batches, first %x, foreign %x (%v)", len(batches), batches[0].L1Hash[:4], foreign.L1Hash[:4], err)
	}
	loc, err := b.locate(ctx, batches, finality.HeaderFields{Number: 5, Timestamp: 1_790_000_010}, [][]byte{tx}, arb)
	if err != nil || loc == nil {
		t.Fatalf("locate: %v %v", loc, err)
	}
	if loc.rec.L1Hash != held.L1Hash {
		t.Fatalf("the reference reader serves the record %x that the Bridge does not hold, not the record %x it holds", loc.rec.L1Hash[:4], held.L1Hash[:4])
	}
}
