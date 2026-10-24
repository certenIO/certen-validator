// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

const secretURL = "https://rpc.example.org/v2/0123456789abcdef0123456789abcdef"

// ---- a fake parent chain ----------------------------------------------------------------------------------------------

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

type fakeState struct {
	root      common.Hash
	acct      *trie.Trie
	bridge    *trie.Trie
	impl      common.Address
	bridgeKey []byte
}

func trimmed(w [32]byte) []byte {
	i := 0
	for i < 32 && w[i] == 0 {
		i++
	}
	b, _ := rlp.EncodeToBytes(w[i:])
	return b
}

// newFakeState builds a Bridge account whose storage holds slots, behind an implementation account.
func newFakeState(t *testing.T, bridge [20]byte, slots map[[32]byte][32]byte) *fakeState {
	t.Helper()
	impl := common.HexToAddress("0xed26e46f38957763f83f2c45f6fb6702cfebc7d8")
	st := trie.NewEmpty(nil)
	all := map[[32]byte][32]byte{}
	for k, v := range slots {
		all[k] = v
	}
	var iv [32]byte
	copy(iv[12:], impl[:])
	all[[32]byte(ImplSlot)] = iv
	for k, v := range all {
		if err := st.Update(crypto.Keccak256(k[:]), trimmed(v)); err != nil {
			t.Fatal(err)
		}
	}
	at := trie.NewEmpty(nil)
	mk := func(root common.Hash, code string) []byte {
		b, err := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), root, crypto.Keccak256([]byte(code))})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := at.Update(crypto.Keccak256(bridge[:]), mk(st.Hash(), "bridge-proxy")); err != nil {
		t.Fatal(err)
	}
	if err := at.Update(crypto.Keccak256(impl[:]), mk(crypto.Keccak256Hash(nil), "bridge-impl")); err != nil {
		t.Fatal(err)
	}
	return &fakeState{root: at.Hash(), acct: at, bridge: st, impl: impl, bridgeKey: crypto.Keccak256(bridge[:])}
}

func (s *fakeState) prove(addr [20]byte, slots [][32]byte) *Proof {
	var ac collector
	if err := s.acct.Prove(crypto.Keccak256(addr[:]), &ac); err != nil {
		panic(err)
	}
	p := &Proof{Address: addr, AccountProof: ac.nodes}
	for _, k := range slots {
		var sc collector
		if err := s.bridge.Prove(crypto.Keccak256(k[:]), &sc); err != nil {
			panic(err)
		}
		v, _ := s.bridge.Get(crypto.Keccak256(k[:]))
		var w [32]byte
		var raw []byte
		_ = rlp.DecodeBytes(v, &raw)
		copy(w[32-len(raw):], raw)
		p.Slots = append(p.Slots, SlotProof{Key: k, Value: w, Proof: sc.nodes})
	}
	return p
}

func synthHeader(number, ts uint64, stateRoot common.Hash, salt string) Header {
	items := []any{
		bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 20), stateRoot.Bytes(),
		bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x55}, 32), make([]byte, 256), uint64(0), number, uint64(30000000),
		uint64(1), ts, []byte(salt), bytes.Repeat([]byte{0x66}, 32), make([]byte, 8),
	}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return Header{Number: number, Timestamp: ts, Hash: crypto.Keccak256Hash(raw), RLP: raw}
}

type fakeL1 struct {
	head      uint64
	headers   map[uint64]Header
	logs      []Log
	txs       map[[32]byte]Tx
	state     *fakeState
	window    uint64 // eth_getProof is served for blocks >= head-window
	proofErr  error
	proofCall int
	failAt    map[uint64]bool // blocks whose state the provider does not serve (yet)
}

func (f *fakeL1) HeadNumber(context.Context) (uint64, error) { return f.head, nil }
func (f *fakeL1) Header(_ context.Context, n uint64) (Header, error) {
	h, ok := f.headers[n]
	if !ok {
		return Header{}, &ProviderErrors{Op: "eth_getBlockByNumber", Failures: []ProviderFailure{{Provider: "fake", Err: "no such block"}}}
	}
	return h, nil
}
func (f *fakeL1) Logs(_ context.Context, addr [20]byte, t0 [32]byte, t1 *[32]byte, from, to uint64) ([]Log, error) {
	var out []Log
	for _, l := range f.logs {
		if l.Address == addr && l.Topics[0] == t0 && l.BlockNumber >= from && l.BlockNumber <= to {
			if t1 != nil && l.Topics[1] != *t1 {
				continue
			}
			out = append(out, l)
		}
	}
	return out, nil
}
func (f *fakeL1) TxByHash(_ context.Context, h [32]byte) (Tx, error) {
	t, ok := f.txs[h]
	if !ok {
		return Tx{}, errors.New("no such transaction")
	}
	return t, nil
}
func (f *fakeL1) GetProof(_ context.Context, addr [20]byte, slots [][32]byte, n uint64, accept func(*Proof) error) (*Proof, error) {
	f.proofCall++
	if f.proofErr != nil {
		return nil, f.proofErr
	}
	if f.failAt[n] {
		return nil, &ProviderErrors{Op: "eth_getProof", Failures: []ProviderFailure{{Provider: "fake", Err: "state of the block is not available yet"}}}
	}
	if n+f.window < f.head {
		return nil, &ProviderErrors{Op: "eth_getProof", Failures: []ProviderFailure{{Provider: "fake", Err: "distance to target block exceeds maximum proof window"}}}
	}
	p := f.state.prove(addr, slots)
	if accept != nil {
		if err := accept(p); err != nil {
			return nil, &ProviderErrors{Op: "eth_getProof", Failures: []ProviderFailure{{Provider: "fake", Err: err.Error()}}}
		}
	}
	return p, nil
}

type fakeBeacon struct {
	blobs map[[32]byte]Sidecar
	err   error
	calls int
}

func (b *fakeBeacon) Sidecars(_ context.Context, slot uint64, wanted [][32]byte) (map[[32]byte]Sidecar, error) {
	b.calls++
	if b.err != nil {
		return nil, b.err
	}
	out := map[[32]byte]Sidecar{}
	for _, w := range wanted {
		sc, ok := b.blobs[w]
		if !ok {
			return nil, &BeaconError{Slot: slot, Status: 200, Err: "blob missing"}
		}
		out[w] = sc
	}
	return out, nil
}

func u256(v uint64) [32]byte {
	var w [32]byte
	binary.BigEndian.PutUint64(w[24:], v)
	return w
}

// scenario is one synthetic batch event in a fake chain.
type scenario struct {
	l1     *fakeL1
	beacon *fakeBeacon
	rec    BatchRecord
	accs   map[uint64][32]byte
}

// newScenario builds a chain whose head is 1000 with the batch event of batch 77 at block 995. loc is the data location.
func newScenario(t *testing.T, loc uint8, nBlobs int) *scenario {
	t.Helper()
	sc := &scenario{beacon: &fakeBeacon{blobs: map[[32]byte]Sidecar{}}, accs: map[uint64][32]byte{}}
	rec := BatchRecord{N: 77, Header40: [5]uint64{1000, 2000, 3000, 4000, 5}, DataLocation: loc, L1Block: 995}
	rec.BeforeAcc = crypto.Keccak256Hash([]byte("before"))
	rec.DelayedAcc = crypto.Keccak256Hash([]byte("delayed"))
	var data []byte
	var input []byte
	switch loc {
	case LocBlob:
		for j := 0; j < nBlobs; j++ {
			var c [48]byte
			copy(c[:], bytes.Repeat([]byte{byte(0xa0 + j)}, 48))
			vh := VersionedHash(c)
			rec.VersionedHashes = append(rec.VersionedHashes, vh)
			sc.beacon.blobs[vh] = Sidecar{Blob: bytes.Repeat([]byte{byte(j + 1)}, BlobBytes), Commitment: c, Proof: [48]byte{byte(j)}}
		}
	case LocTxInput:
		data = []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
		seq := u256(77)
		input = append([]byte{0x8f, 0x11, 0x1f, 0x3c}, seq[:]...)
		off := u256(0x80)
		input = append(input, off[:]...)
		after := u256(5)
		input = append(input, after[:]...)
		input = append(input, make([]byte, 32)...)
		ln := u256(uint64(len(data)))
		input = append(input, ln[:]...)
		input = append(input, data...)
		input = append(input, make([]byte, 32-len(data)%32)...)
	}
	dh := rec.DataHash(data)
	rec.AfterAcc = crypto.Keccak256Hash(rec.BeforeAcc[:], dh[:], rec.DelayedAcc[:])
	sc.accs[77] = rec.AfterAcc
	slots := map[[32]byte][32]byte{ArraySlot(SequencerAccSlot, 77): rec.AfterAcc, ArraySlot(DelayedAccSlot, 4): crypto.Keccak256Hash([]byte("d4")), ArraySlot(DelayedAccSlot, 5): crypto.Keccak256Hash([]byte("d5"))}
	st := newFakeState(t, BridgeAddr, slots)
	l1 := &fakeL1{head: 1000, headers: map[uint64]Header{}, txs: map[[32]byte]Tx{}, state: st, window: 100}
	for n := uint64(990); n <= 1000; n++ {
		l1.headers[n] = synthHeader(n, 1700000000+n*12, st.root, "")
	}
	rec.L1Hash = l1.headers[995].Hash
	rec.TxHash = crypto.Keccak256Hash([]byte("batch tx"))
	rec.TxIndex = 3
	tx := Tx{Hash: rec.TxHash, BlockHash: rec.L1Hash, BlockNumber: 995, Index: 3, Raw: []byte{0x03, 0xc0}, Input: input, BlobVersionedHashes: rec.VersionedHashes}
	rec.TxRaw = tx.Raw
	l1.txs[rec.TxHash] = tx
	l1.logs = append(l1.logs, eventLog(rec))
	sc.l1, sc.rec = l1, rec
	return sc
}

func eventLog(r BatchRecord) Log {
	var data []byte
	data = append(data, r.DelayedAcc[:]...)
	a := u256(r.Header40[4])
	data = append(data, a[:]...)
	for i := 0; i < 4; i++ {
		w := u256(r.Header40[i])
		data = append(data, w[:]...)
	}
	l := u256(uint64(r.DataLocation))
	data = append(data, l[:]...)
	return Log{Address: SequencerInboxAddr, Topics: [][32]byte{[32]byte(TopicBatchDelivered), u256(r.N), r.BeforeAcc, r.AfterAcc}, Data: data,
		BlockNumber: r.L1Block, BlockHash: r.L1Hash, TxHash: r.TxHash, TxIndex: r.TxIndex}
}

func newCapturer(sc *scenario, store CaptureStore) *Capturer {
	return NewCapturer(store, sc.l1, sc.beacon, Config{StartBack: 20, BlobGiveUpTicks: 2, UnavailableEvery: 2})
}

func allRows(t *testing.T, s CaptureStore, from, to uint64) []Row {
	t.Helper()
	var out []Row
	for n := from; n <= to; n++ {
		rows, err := s.ListByBlock(context.Background(), ChainArbitrumSepolia, n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rows...)
	}
	return out
}

func stores(t *testing.T) map[string]CaptureStore {
	d, err := NewDirStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]CaptureStore{"mem": NewMemStore(), "dir": d}
}

// ---- tests ----------------------------------------------------------------------------------------------------------

func TestStoresAreInsertOnlyAndAgree(t *testing.T) {
	for name, s := range stores(t) {
		k := Key{Chain: 1, L1Block: 5, L1Hash: [32]byte{9}, Item: "batch/3"}
		if err := s.Put(context.Background(), k, []byte("a")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := s.Put(context.Background(), k, []byte("a")); err != nil {
			t.Fatalf("%s: identical bytes must be a no-op: %v", name, err)
		}
		if err := s.Put(context.Background(), k, []byte("b")); !errors.Is(err, ErrExists) {
			t.Fatalf("%s: different bytes under one key: %v", name, err)
		}
		k2 := k
		k2.L1Hash = [32]byte{8}
		if err := s.Put(context.Background(), k2, []byte("b")); err != nil {
			t.Fatalf("%s: a reorg row (same height, other hash) must insert: %v", name, err)
		}
		if err := s.Put(context.Background(), Key{Chain: 1, L1Block: 5, L1Hash: [32]byte{9}, Item: "Bad Item"}, nil); err == nil {
			t.Fatalf("%s: a bad item name was accepted", name)
		}
		rows, _ := s.ListByBlock(context.Background(), 1, 5)
		if len(rows) != 2 || rows[0].L1Hash != [32]byte{8} {
			t.Fatalf("%s: List = %+v", name, rows)
		}
		ks, _ := s.ListByRange(context.Background(), 1, 0, finality.MaxCaptureBlock, "batch/")
		if len(ks) != 2 {
			t.Fatalf("%s: Keys = %v", name, ks)
		}
		got, ok, _ := s.Get(context.Background(), k)
		if !ok || string(got) != "a" {
			t.Fatalf("%s: Get = %q %v", name, got, ok)
		}
		if _, ok, _ := s.Get(context.Background(), Key{Chain: 1, L1Block: 6, Item: "x"}); ok {
			t.Fatalf("%s: absent row found", name)
		}
	}
}

func TestDirStoreSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewDirStore(dir)
	k := Key{Chain: 421614, L1Block: 12, L1Hash: [32]byte{1}, Item: "blob/3/0"}
	if err := a.Put(context.Background(), k, []byte("x")); err != nil {
		t.Fatal(err)
	}
	b, _ := NewDirStore(dir)
	got, ok, err := b.Get(context.Background(), k)
	if err != nil || !ok || string(got) != "x" {
		t.Fatalf("after reopen: %q %v %v", got, ok, err)
	}
	if err := b.Put(context.Background(), k, []byte("y")); !errors.Is(err, ErrExists) {
		t.Fatalf("a reopened store lost insert-only: %v", err)
	}
}

func TestCaptureOfABlobBatchStoresEverythingTheVerifierNeeds(t *testing.T) {
	for name, store := range stores(t) {
		sc := newScenario(t, LocBlob, 2)
		c := newCapturer(sc, store)
		rep, err := c.Tick(context.Background())
		if err != nil || len(rep.Errors) != 0 {
			t.Fatalf("%s: %v %v", name, err, rep.Errors)
		}
		if len(rep.NewBatches) != 1 || rep.NewBatches[0] != 77 || rep.BlobsStored != 2 || len(rep.Proofs) != 1 || rep.ProofBlock != 1000 {
			t.Fatalf("%s: report %+v", name, rep)
		}
		bk := Key{Chain: ChainArbitrumSepolia, L1Block: 995, L1Hash: sc.rec.L1Hash, Item: ItemBatch(77)}
		b, ok, _ := store.Get(context.Background(), bk)
		if !ok {
			t.Fatalf("%s: batch row missing", name)
		}
		rec, err := DecodeBatchRecord(b)
		if err != nil || rec.N != 77 || rec.Header40 != sc.rec.Header40 || rec.AfterAcc != sc.rec.AfterAcc || !rec.ConsistentAcc(nil) || len(rec.VersionedHashes) != 2 {
			t.Fatalf("%s: batch record %+v %v", name, rec, err)
		}
		blobs, err := LoadBlobs(context.Background(), store, ChainArbitrumSepolia, rec)
		if err != nil || len(blobs) != 2 || VersionedHash(blobs[1].Commitment) != rec.VersionedHashes[1] {
			t.Fatalf("%s: blobs %d %v", name, len(blobs), err)
		}
		pr, err := LoadProofs(context.Background(), store, ChainArbitrumSepolia, 77)
		if err != nil || len(pr) != 1 {
			t.Fatalf("%s: proofs %v %v", name, pr, err)
		}
		// the stored nodes verify, from scratch, under the state root of the stored proof-block header
		hb, ok, _ := store.Get(context.Background(), Key{Chain: ChainArbitrumSepolia, L1Block: 1000, L1Hash: pr[0].ProofBlockHash, Item: ItemHeader})
		if !ok {
			t.Fatalf("%s: proof block header row missing", name)
		}
		hf, _ := finality.ReadHeader(hb)
		acct, err := ethproof.VerifyAccount(common.Hash(hf.StateRoot), BridgeAddr, pr[0].Nodes)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ethproof.VerifySlot(acct.StorageRoot, common.Hash(ArraySlot(SequencerAccSlot, 77)), pr[0].Nodes)
		if err != nil || [32]byte(v) != rec.AfterAcc {
			t.Fatalf("%s: the stored nodes prove %x, want afterAcc: %v", name, v, err)
		}
		iv, err := ethproof.VerifySlot(acct.StorageRoot, ImplSlot, pr[0].Nodes)
		if err != nil || common.BytesToAddress(iv[:]) != sc.l1.state.impl || pr[0].Implementation != [20]byte(sc.l1.state.impl) {
			t.Fatalf("%s: implementation slot %x %v", name, iv, err)
		}
		if _, err := ethproof.VerifyAccount(common.Hash(hf.StateRoot), sc.l1.state.impl, pr[0].Nodes); err != nil {
			t.Fatalf("%s: implementation account proof missing from the nodes: %v", name, err)
		}
		// a second tick adds no batch, no blob, no proof; the cursor advances
		rep2, err := c.Tick(context.Background())
		if err != nil || len(rep2.NewBatches) != 0 || rep2.BlobsStored != 0 || len(rep2.Proofs) != 0 || len(rep2.Errors) != 0 {
			t.Fatalf("%s: second tick %+v %v", name, rep2, err)
		}
	}
}

func TestACapturerThatRestartsFinishesWhatTheLastRunLeftOpen(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
	sc.l1.proofErr = errors.New("down")
	c := newCapturer(sc, store)
	if _, err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows, _ := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "blob/"); len(rows) != 0 {
		t.Fatal("blob rows without a beacon answer")
	}
	sc.beacon.err, sc.l1.proofErr = nil, nil
	c2 := newCapturer(sc, store) // a new process over the same store
	rep, err := c2.Tick(context.Background())
	if err != nil || rep.BlobsStored != 1 || len(rep.Proofs) != 1 {
		t.Fatalf("after restart: %+v %v", rep, err)
	}
}

func TestAReorgGivesASecondRowAtTheSameHeight(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	c := newCapturer(sc, store)
	if _, err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// block 995 is replaced: another hash, the same batch event in it
	h2 := synthHeader(995, 1700000000+995*12, sc.l1.state.root, "reorg")
	sc.l1.headers[995] = h2
	rec2 := sc.rec
	rec2.L1Hash = h2.Hash
	sc.l1.logs = []Log{eventLog(rec2)}
	tx := sc.l1.txs[sc.rec.TxHash]
	tx.BlockHash = h2.Hash
	sc.l1.txs[sc.rec.TxHash] = tx
	rep, err := c.Tick(context.Background())
	if err != nil || len(rep.NewBatches) != 1 {
		t.Fatalf("reorg tick: %+v %v", rep, err)
	}
	rows, _ := store.ListByBlock(context.Background(), ChainArbitrumSepolia, 995)
	hashes := map[[32]byte]bool{}
	for _, r := range rows {
		if r.Item == ItemBatch(77) {
			hashes[r.L1Hash] = true
		}
	}
	if len(hashes) != 2 {
		t.Fatalf("batch rows at height 995 under %d hashes, want 2", len(hashes))
	}
}

func TestAProofWindowMissIsRecordedWithRedactedProvidersAndRetried(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.l1.proofErr = &ProviderErrors{Op: "eth_getProof", Failures: []ProviderFailure{{Provider: "rpc.example.org", Err: "historical state not available at " + secretURL}}}
	c := newCapturer(sc, store)
	rep, err := c.Tick(context.Background())
	if err != nil || len(rep.Proofs) != 0 || len(rep.Unavailable) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	var found *UnavailableRecord
	for _, r := range allRows(t, store, 990, 1000) {
		if r.Item == ItemUnavailable(77) {
			u, err := DecodeUnavailableRecord(r.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			found = &u
			if r.L1Block != 1000 {
				t.Fatalf("keyed at %d, want the head", r.L1Block)
			}
		}
	}
	if found == nil || found.N != 77 || found.EventBlock != 995 || found.Head != 1000 || len(found.Providers) == 0 {
		t.Fatalf("unavailable record: %+v", found)
	}
	assertNoSecret(t, store, rep)
	// the window opens: the same batch is proven at the next tick
	sc.l1.proofErr = nil
	rep, err = c.Tick(context.Background())
	if err != nil || len(rep.Proofs) != 1 {
		t.Fatalf("retry: %+v %v", rep, err)
	}
}

func assertNoSecret(t *testing.T, s CaptureStore, rep Report) {
	t.Helper()
	for _, r := range allRows(t, s, 980, 1010) {
		if bytes.Contains(r.Bytes, []byte("0123456789abcdef0123456789abcdef")) {
			t.Fatalf("row %s holds the provider secret", r.CaptureKey)
		}
	}
	for _, e := range rep.Errors {
		if strings.Contains(e, "0123456789abcdef0123456789abcdef") {
			t.Fatalf("report error holds the provider secret: %q", e)
		}
	}
}

func TestABlobFailureNeverLeaksAndIsRecordedOnceAfterTheGiveUpCount(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.beacon.err = &BeaconError{Slot: 9, Status: 503, Err: "upstream " + secretURL}
	c := newCapturer(sc, store) // BlobGiveUpTicks 2
	var last Report
	for i := 0; i < 4; i++ {
		var err error
		if last, err = c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, store, last)
	}
	ks, _ := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "blobunavailable/")
	if len(ks) != 1 {
		t.Fatalf("blob unavailability rows: %d, want exactly 1", len(ks))
	}
	b, _, _ := store.Get(context.Background(), ks[0])
	u, err := DecodeBlobUnavailableRecord(b)
	if err != nil || u.N != 77 || u.HTTPStatus != 503 || u.BeaconSlot != (1700000000+995*12-BeaconGenesisTime)/12 || len(u.VersionedHashes) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	sc.beacon.err = nil
	rep, _ := c.Tick(context.Background())
	if rep.BlobsStored != 1 {
		t.Fatalf("the blobs were not stored once the beacon answered: %+v", rep)
	}
}

func TestACalldataBatchStoresItsInputAndAnEventBatchItsData(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocTxInput, 0)
	c := newCapturer(sc, store)
	rep, err := c.Tick(context.Background())
	if err != nil || len(rep.NewBatches) != 1 || len(rep.Errors) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	b, ok, _ := store.Get(context.Background(), Key{Chain: ChainArbitrumSepolia, L1Block: 995, L1Hash: sc.rec.L1Hash, Item: ItemCalldata(77)})
	if !ok {
		t.Fatal("calldata row missing")
	}
	data, err := ExtractTxInputData(b)
	if err != nil || !bytes.Equal(data, []byte{0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}) {
		t.Fatalf("extracted %x %v", data, err)
	}
	for _, bad := range [][]byte{nil, b[:40], append(append([]byte{}, b[:36]...), bytes.Repeat([]byte{0xff}, 32)...)} {
		if _, err := ExtractTxInputData(bad); err == nil {
			t.Fatalf("a malformed input %x was extracted", bad)
		}
	}
}

func TestAnAccumulatorTheCaptureCannotReproduceIsNotStored(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	lg := sc.l1.logs[0]
	lg.Topics[3] = crypto.Keccak256Hash([]byte("not the accumulator"))
	sc.l1.logs[0] = lg
	c := newCapturer(sc, store)
	rep, err := c.Tick(context.Background())
	if err != nil || len(rep.NewBatches) != 0 || len(rep.Errors) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if ks, _ := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "batch/"); len(ks) != 0 {
		t.Fatal("a batch whose accumulator does not reproduce was stored")
	}
	if cur, ok, _ := cursorBlock(context.Background(), store, ChainArbitrumSepolia); ok && cur >= 995 {
		t.Fatalf("the cursor advanced to %d past an uncaptured event", cur)
	}
}

func TestADelayedProofIsCapturedWhenWantedAndOnlyForKAtLeastOne(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	c := newCapturer(sc, store)
	if err := c.WantDelayed(0); err == nil {
		t.Fatal("k = 0 has no k-1")
	}
	if err := c.WantDelayed(5); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks, _ := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "delayedproof/")
	if len(ks) != 1 || ks[0].Item != "delayedproof/5" {
		t.Fatalf("delayed proof rows %v", ks)
	}
	b, _, _ := store.Get(context.Background(), ks[0])
	pr, err := DecodeProofRecord(b)
	if err != nil || pr.Kind != ProofDelayedAcc || pr.Index != 5 {
		t.Fatalf("%+v %v", pr, err)
	}
	hb, _, _ := store.Get(context.Background(), Key{Chain: ChainArbitrumSepolia, L1Block: pr.ProofBlock, L1Hash: pr.ProofBlockHash, Item: ItemHeader})
	hf, _ := finality.ReadHeader(hb)
	acct, err := ethproof.VerifyAccount(common.Hash(hf.StateRoot), BridgeAddr, pr.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []uint64{5, 4} {
		if _, err := ethproof.VerifySlot(acct.StorageRoot, common.Hash(ArraySlot(DelayedAccSlot, k)), pr.Nodes); err != nil {
			t.Fatalf("slot %d: %v", k, err)
		}
	}
	if pr.ValueN != [32]byte(crypto.Keccak256Hash([]byte("d5"))) || pr.ValuePrev != [32]byte(crypto.Keccak256Hash([]byte("d4"))) {
		t.Fatal("hint values wrong")
	}
}

func TestAProofThatDoesNotVerifyUnderTheHeaderIsRefused(t *testing.T) {
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	other := newFakeState(t, BridgeAddr, map[[32]byte][32]byte{ArraySlot(SequencerAccSlot, 77): crypto.Keccak256Hash([]byte("forged"))})
	sc.l1.state = other // the headers commit to the honest root, the provider proves another state
	c := newCapturer(sc, store)
	rep, err := c.Tick(context.Background())
	if err != nil || len(rep.Proofs) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if ks, _ := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "proof/"); len(ks) != 0 {
		t.Fatal("a proof that fails against the header's state root was stored")
	}
}

func TestRecordsRoundTripAndRefuseMalformedBytes(t *testing.T) {
	br := BatchRecord{N: 9, Header40: [5]uint64{1, 2, 3, 4, 5}, DataLocation: 3, L1Block: 7, TxIndex: 2, TxRaw: []byte{1, 2, 3}, VersionedHashes: [][32]byte{{1}, {2}}}
	pr := ProofRecord{Kind: ProofBatchAcc, Index: 9, ProofBlock: 3, Nodes: [][]byte{{3}, {1}, {2}, {1}}}
	un := UnavailableRecord{N: 9, EventBlock: 7, Head: 8, Providers: []string{"a: x"}}
	bu := BlobUnavailableRecord{N: 9, L1Block: 7, BeaconSlot: 4, HTTPStatus: 404, VersionedHashes: [][32]byte{{5}}, Err: "e"}
	for name, enc := range map[string][]byte{"batch": br.Encode(), "proof": pr.Encode(), "unavail": un.Encode(), "blobunavail": bu.Encode()} {
		dec := map[string]func([]byte) error{
			"batch":       func(b []byte) error { _, e := DecodeBatchRecord(b); return e },
			"proof":       func(b []byte) error { _, e := DecodeProofRecord(b); return e },
			"unavail":     func(b []byte) error { _, e := DecodeUnavailableRecord(b); return e },
			"blobunavail": func(b []byte) error { _, e := DecodeBlobUnavailableRecord(b); return e },
		}[name]
		if err := dec(enc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := dec(enc[:len(enc)-1]); err == nil {
			t.Fatalf("%s: a truncated record decoded", name)
		}
		if err := dec(append(append([]byte{}, enc...), 0)); err == nil {
			t.Fatalf("%s: trailing byte accepted", name)
		}
	}
	got, _ := DecodeProofRecord(pr.Encode())
	if len(got.Nodes) != 3 || bytes.Compare(crypto.Keccak256(got.Nodes[0]), crypto.Keccak256(got.Nodes[1])) >= 0 {
		t.Fatalf("nodes are not the deduplicated ascending set: %d", len(got.Nodes))
	}
	if _, err := DecodeBlobRecord(make([]byte, 5)); err == nil {
		t.Fatal("a short blob row decoded")
	}
	if got := FindBatchContaining([]BatchRecord{br, {N: 10, Header40: [5]uint64{100, 200}}}, 150); len(got) != 1 || got[0].N != 10 {
		t.Fatalf("FindBatchContaining = %+v", got)
	}
	_ = fmt.Sprint
}

func TestArraySlotMatchesTheSolidityLayout(t *testing.T) {
	// keccak256(w(7)) + 3, computed independently
	base := new(big.Int).SetBytes(crypto.Keccak256(append(make([]byte, 31), 7)))
	base.Add(base, big.NewInt(3))
	var want [32]byte
	base.FillBytes(want[:])
	if ArraySlot(7, 3) != want {
		t.Fatal("ArraySlot differs from keccak256(w(7)) + 3")
	}
}
