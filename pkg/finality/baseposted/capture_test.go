// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

const pinnedSetup = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"

func TestKZGSetupIsTheHashCheckedCeremonyFileAndBlobProofsRoundTrip(t *testing.T) {
	if _, err := kzgsetup.Load("00" + pinnedSetup[2:]); err == nil {
		t.Fatal("a pin that is not the embedded file's hash must be refused")
	}
	raw, err := os.ReadFile(filepath.Join("kzgsetup", "trusted_setup_4096.json"))
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(raw); common.Bytes2Hex(h[:]) != pinnedSetup {
		t.Fatalf("the embedded setup hashes to %x", h)
	}
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encodeBlob([]byte("a frame of a channel"))
	if err != nil {
		t.Fatal(err)
	}
	com, err := kz.Commit(blob)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := kz.Prove(blob, com)
	if err != nil {
		t.Fatal(err)
	}
	if err := kz.VerifyBlob(blob, com, pr); err != nil {
		t.Fatalf("a proof computed for the blob must verify: %v", err)
	}
	bad := append([]byte(nil), blob...)
	bad[40] ^= 1
	if err := kz.VerifyBlob(bad, com, pr); err == nil {
		t.Fatal("a changed blob must not verify")
	}
	pr2 := pr
	pr2[3] ^= 1
	if err := kz.VerifyBlob(blob, com, pr2); err == nil {
		t.Fatal("a changed proof must not verify")
	}
}

// fakeL1 serves one synthetic block that holds a blob transaction to the inbox and answers proofs from a fixed table.
type fakeL1 struct {
	blk       L1BlockData
	proofAsks int
	failProof bool
}

func (f *fakeL1) Head(context.Context) (uint64, error) { return f.blk.Number, nil }
func (f *fakeL1) Block(_ context.Context, n uint64) (L1BlockData, error) {
	if n != f.blk.Number {
		return L1BlockData{Number: n}, nil
	}
	return f.blk, nil
}
func (f *fakeL1) Proof(_ context.Context, addr [20]byte, slots [][32]byte, block uint64) (StateProof, error) {
	f.proofAsks++
	if f.failProof {
		return StateProof{}, errors.New("historical state is not available")
	}
	sp := StateProof{Nodes: [][]byte{[]byte("node-" + common.Bytes2Hex(addr[:2]))}, Values: map[[32]byte][32]byte{}}
	if len(slots) > 0 {
		var v [32]byte
		copy(v[12:], testImpl[:])
		sp.Values[eip1967ImplSlot] = v
	}
	return sp, nil
}

type fakeBeacon struct{ blobs [][]byte }

func (f fakeBeacon) Blobs(context.Context, uint64) ([][]byte, error) { return f.blobs, nil }

func blobBlock(t *testing.T, kz *kzgsetup.Context, number uint64, data []byte) (L1BlockData, []byte) {
	t.Helper()
	blob, err := encodeBlob(append([]byte{0}, MarshalFrame(Frame{ID: [16]byte{1}, Number: 0, Data: data, IsLast: true})...))
	if err != nil {
		t.Fatal(err)
	}
	com, err := kz.Commit(blob)
	if err != nil {
		t.Fatal(err)
	}
	vh := sha256.Sum256(com[:])
	vh[0] = 0x01
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	tx, err := types.SignNewTx(testKey("batcher"), signer, &types.BlobTx{ChainID: uint256.NewInt(11155111), Nonce: 1, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(10), Gas: 21000,
		To: testInbox, BlobFeeCap: uint256.NewInt(1), BlobHashes: []common.Hash{vh}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	other := userTx(7)
	raws := [][]byte{other, raw}
	root := ethproof.TrieRoot(raws)
	h := &types.Header{Number: new(big.Int).SetUint64(number), TxHash: root, Root: common.Hash{9}, ParentHash: common.Hash{8}, Time: 1655733600 + 12*5000,
		Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
	hdr, _ := rlp.EncodeToBytes(h)
	var otherTo [20]byte
	return L1BlockData{Number: number, Hash: [32]byte(crypto.Keccak256Hash(hdr)), HeaderRLP: hdr, Timestamp: h.Time, TxRaw: raws,
		TxTo: [][20]byte{otherTo, testInbox}, TxHasTo: []bool{true, true}, TxBlobHash: [][][32]byte{nil, {vh}}}, blob
}

func TestCapturerStoresTheBatchInboxBlockAndIsInsertOnly(t *testing.T) {
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blk, blob := blobBlock(t, kz, 1000, []byte("frame data"))
	l1 := &fakeL1{blk: blk}
	store := NewMemStore()
	var recorded []*finality.StateError
	c := &Capturer{Chain: 84532, Pins: newPins(), L1: l1, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: store, GenesisTime: 1655733600, SlotSeconds: 12,
		Record: func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }}
	ok, err := c.CaptureBlock(context.Background(), 1000)
	if err != nil || !ok {
		t.Fatalf("capture: %v %v", ok, err)
	}
	ctx := context.Background()
	k := CaptureKey{Chain: 84532, L1Block: 1000, L1Hash: blk.Hash}
	for _, item := range []string{ItemHeader, ItemInbox, ItemSysCfg, ItemTx(1), ItemTxNodes(1), ItemBlob(1, 0)} {
		k.Item = item
		if _, ok, _ := store.Get(ctx, k); !ok {
			t.Errorf("row %s missing", item)
		}
	}
	k.Item = ItemTx(0)
	if _, ok, _ := store.Get(ctx, k); ok {
		t.Error("a transaction that is not to the inbox must not be captured")
	}
	// the stored blob row carries a commitment and proof that verify
	k.Item = ItemBlob(1, 0)
	row, _, _ := store.Get(ctx, k)
	r := finality.NewReader(row, finality.DefaultLimits())
	raw, _ := r.LP("blob", BlobSize)
	com, _ := r.Fixed("c", 48)
	pr, _ := r.Fixed("p", 48)
	if err := kz.VerifyBlob(raw, [48]byte(com), [48]byte(pr)); err != nil {
		t.Fatalf("captured proof: %v", err)
	}
	// insert-only: the same bytes are a no-op, different bytes are refused
	if err := store.Put(ctx, k, row); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, k, append(row[:len(row):len(row)], 0)); !errors.Is(err, ErrCaptureConflict) {
		t.Fatalf("a rewrite must be refused, got %v", err)
	}
	// a block without inbox transactions captures nothing
	if ok, err := c.CaptureBlock(ctx, 999); ok || err != nil {
		t.Fatalf("empty block: %v %v", ok, err)
	}
	if len(recorded) != 0 {
		t.Fatalf("unexpected states %v", recorded)
	}
}

func TestCapturerNamesAProofWindowMissAndStoresNothing(t *testing.T) {
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blk, blob := blobBlock(t, kz, 1000, []byte("frame data"))
	store := NewMemStore()
	var recorded []*finality.StateError
	c := &Capturer{Chain: 84532, Pins: newPins(), L1: &fakeL1{blk: blk, failProof: true}, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: store, GenesisTime: 1655733600, SlotSeconds: 12,
		Record: func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }}
	if ok, err := c.CaptureBlock(context.Background(), 1000); ok || err == nil {
		t.Fatalf("a missed proof window must fail the capture: %v %v", ok, err)
	}
	if len(recorded) != 1 || recorded[0].Code != "batcher_state_unavailable" {
		t.Fatalf("recorded %v", recorded)
	}
	if ks, _ := finality.CaptureKeysOfItem(context.Background(), store, 84532, ItemHeader); len(ks) != 0 {
		t.Fatal("a failed capture must store nothing")
	}
	// a blob the beacon does not serve is l1_blob_unavailable
	recorded = nil
	c = &Capturer{Chain: 84532, Pins: newPins(), L1: &fakeL1{blk: blk}, Beacon: fakeBeacon{blobs: [][]byte{make([]byte, BlobSize)}}, Store: NewMemStore(), GenesisTime: 1655733600, SlotSeconds: 12,
		Record: func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }}
	if ok, err := c.CaptureBlock(context.Background(), 1000); ok || err == nil {
		t.Fatalf("a missing blob must fail the capture: %v %v", ok, err)
	}
	if len(recorded) != 1 || recorded[0].Code != "l1_blob_unavailable" {
		t.Fatalf("recorded %v", recorded)
	}
}

func TestBuilderPendingWhenNoCapturedChannelCoversTheBlockAndPostDenimIsNamed(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{Pins: pins, Store: NewMemStore()}
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	ad, pend, err := b.Build(context.Background(), &ethproof.Settlement{Header: s.l2Raw}, 0, finality.LevelL1Posted)
	if err != nil || ad != nil || pend == nil || pend.Reason != "l1_posted_unproven" || pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelL1Posted {
		t.Fatalf("%v %v %v", ad, pend, err)
	}
	// finalized is the sibling prover's level: "not mine" is (nil, nil, nil), never a refusal the upgrader would keep as the status
	if ad, pend, err := b.Build(context.Background(), &ethproof.Settlement{Header: s.l2Raw}, 0, finality.LevelFinalized); ad != nil || pend != nil || err != nil {
		t.Fatalf("this prover builds l1_posted only and is silent for any other level: %v %v %v", ad, pend, err)
	}
	if _, _, err := b.Build(context.Background(), &ethproof.Settlement{Header: s.l2Raw}, finality.LevelSet(0).With(finality.LevelL1Posted), finality.LevelL1Posted); err == nil {
		t.Fatal("a level already present is never rebuilt")
	}
	post := makeSynth(t, synthOpts{compression: "zlib", calldata: true, batchTs: 1792605600})
	_, _, err = b.Build(context.Background(), &ethproof.Settlement{Header: post.l2Raw}, 0, finality.LevelL1Posted)
	wantCode(t, err, CodeBatchFormat, map[string]string{"type": "post_denim"})
}
