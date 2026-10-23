// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX F19: the capture keeps every transaction sent TO the batch inbox, whoever sent it, so the first candidate channel of a
// leg can be junk. Both readers (and the index writer) derive channels only from frames of transactions the block's own SystemConfig
// proof names as the batcher's. The fixtures below are real: signed transactions, a header with a state root, and the SystemConfig
// account/slot/implementation proof nodes under it (the rows the capturer writes).

type f19Tx struct {
	key    *ecdsa.PrivateKey
	frames []Frame
	blob   bool // carried in a blob (the transaction row plus one blob row per frame payload)
}

type f19World struct {
	t       testing.TB
	bp      *Pins
	st      finality.CaptureStore
	honest  *ecdsa.PrivateKey
	junk    *ecdsa.PrivateKey
	signer  types.Signer
	root    common.Hash
	nodes   [][]byte
	nonce   uint64
	headers map[uint64]common.Hash
}

func newF19(t testing.TB, st finality.CaptureStore) *f19World {
	t.Helper()
	bp := newPins()
	w := &f19World{t: t, bp: bp, st: st, honest: testKey("batcher"), junk: testKey("junk"), headers: map[uint64]common.Hash{}}
	w.signer = types.LatestSignerForChainID(new(big.Int).SetUint64(bp.L1ChainID))
	batcherHash := common.BytesToHash(crypto.PubkeyToAddress(w.honest.PublicKey).Bytes())
	stt := trie.NewEmpty(nil)
	bv, _ := rlp.EncodeToBytes(bytes.TrimLeft(batcherHash[:], "\x00"))
	iv, _ := rlp.EncodeToBytes(bytes.TrimLeft(common.LeftPadBytes(testImpl.Bytes(), 32), "\x00"))
	stt.Update(crypto.Keccak256(batcherHashSlot[:]), bv)
	stt.Update(crypto.Keccak256(eip1967ImplSlot[:]), iv)
	acc := trie.NewEmpty(nil)
	sc, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: stt.Hash(), CodeHash: crypto.Keccak256([]byte("proxy"))})
	im, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: types.EmptyRootHash, CodeHash: testImplCode[:]})
	acc.Update(crypto.Keccak256(testSysConfig[:]), sc)
	acc.Update(crypto.Keccak256(testImpl[:]), im)
	w.root = acc.Hash()
	collect := func(tr *trie.Trie, key []byte) {
		var ns proofSink
		if err := tr.Prove(key, &ns); err != nil {
			t.Fatal(err)
		}
		w.nodes = append(w.nodes, ns.nodes...)
	}
	collect(acc, crypto.Keccak256(testSysConfig[:]))
	collect(acc, crypto.Keccak256(testImpl[:]))
	collect(stt, crypto.Keccak256(batcherHashSlot[:]))
	collect(stt, crypto.Keccak256(eip1967ImplSlot[:]))
	return w
}

func (w *f19World) signed(key *ecdsa.PrivateKey, data []byte, blob bool, nBlobs int) []byte {
	w.t.Helper()
	w.nonce++
	to := common.Address(w.bp.BatchInbox)
	var tx *types.Transaction
	var err error
	if blob {
		hashes := make([]common.Hash, nBlobs)
		for i := range hashes {
			hashes[i] = common.Hash{1, byte(w.nonce), byte(i)}
		}
		tx, err = types.SignNewTx(key, w.signer, &types.BlobTx{ChainID: uint256.NewInt(w.bp.L1ChainID), Nonce: w.nonce, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2),
			Gas: 21000, To: to, BlobFeeCap: uint256.NewInt(1), BlobHashes: hashes})
	} else {
		tx, err = types.SignNewTx(key, w.signer, &types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(w.bp.L1ChainID), Nonce: w.nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
			Gas: 21000, To: &to, Data: data})
	}
	if err != nil {
		w.t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		w.t.Fatal(err)
	}
	return raw
}

// putBlock writes the rows of captured block number as the capturer does and returns its hash. recorded is the batcher the block's
// SystemConfig proof names (nil: a garbage SystemConfig row, a block whose batcher the captured rows cannot establish).
func (w *f19World) putBlock(number uint64, recorded *ecdsa.PrivateKey, txs ...f19Tx) [32]byte {
	w.t.Helper()
	hdr := &types.Header{Number: new(big.Int).SetUint64(number), Root: w.root, ParentHash: common.Hash{byte(number), 1}, Time: 1790000000 + number, Difficulty: big.NewInt(0),
		UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
	if recorded == nil {
		hdr.Root = common.Hash{9, byte(number)}
	}
	raw, _ := rlp.EncodeToBytes(hdr)
	hash := [32]byte(crypto.Keccak256Hash(raw))
	put := func(item string, b []byte) {
		if err := w.st.Put(context.Background(), finality.CaptureKey{Chain: uint64(Chain), L1Block: number, L1Hash: hash, Item: item}, b); err != nil {
			w.t.Fatal(err)
		}
	}
	var iw finality.Writer
	iw.Count(len(txs))
	for i, tx := range txs {
		iw.U32(uint32(i))
		payload := payloadOf(tx.frames...)
		put(ItemTx(uint32(i)), w.signed(tx.key, payload, tx.blob, len(tx.frames)))
		var nw finality.Writer
		nw.LPList([][]byte{{1, 2, 3}})
		put(ItemTxNodes(uint32(i)), nw.Bytes())
		if tx.blob {
			for j, f := range tx.frames {
				blob, err := encodeBlob(payloadOf(f))
				if err != nil {
					w.t.Fatal(err)
				}
				var bw finality.Writer
				bw.LP(blob)
				bw.Fixed(make([]byte, 48))
				bw.Fixed(make([]byte, 48))
				put(ItemBlob(uint32(i), j), bw.Bytes())
			}
		}
	}
	put(ItemInbox, iw.Bytes())
	put(ItemHeader, raw)
	var sw finality.Writer
	if recorded != nil {
		sw.LPList(w.nodes)
	} else {
		sw.LPList([][]byte{make([]byte, 100)})
	}
	put(ItemSysCfg, sw.Bytes())
	return hash
}

func (w *f19World) builder(indexed bool, origin uint64, st finality.CaptureStore) *Builder {
	b := &Builder{Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}}
	if indexed {
		b.Index = NewIndexReader(st, w.bp, 0)
	}
	return b
}

func (w *f19World) search(indexed bool, origin, ts uint64, st finality.CaptureStore) (searched, error) {
	return w.builder(indexed, origin, st).search(context.Background(), w.bp, finality.HeaderFields{Number: 5, Timestamp: ts}, nil)
}

func entryIDs(t testing.TB, st finality.CaptureStore) map[[16]byte]bool {
	t.Helper()
	out := map[[16]byte]bool{}
	for k := range indexRows(t, st) {
		if n, ok := parseEntryName(1, k); ok {
			out[n.ID] = true
		}
	}
	return out
}

func foreignCount(t testing.TB) float64 {
	v, _ := vGather(t, "certen_finality_capture_foreign_txs_total")
	return v
}

// ---- tests ----

func TestRB12F19AJunkChannelFirstByPositionDoesNotHideTheHonestLeg(t *testing.T) {
	metrics.RegisterMetrics()
	for _, sameBlock := range []bool{false, true} {
		name := "junk block earlier"
		if sameBlock {
			name = "junk transaction earlier in the same block"
		}
		t.Run(name, func(t *testing.T) {
			st := NewMemStore()
			w := newF19(t, st)
			E := uint64(1000)
			H := channelFrames("honest", 1_790_100_000, 30, E, 1)
			J := channelFrames("junk", 1_790_100_000, 30, E, 1) // the same L2 timestamps: it holds T too
			if sameBlock {
				w.putBlock(1020, w.honest, f19Tx{key: w.junk, frames: J}, f19Tx{key: w.honest, frames: H})
			} else {
				w.putBlock(1010, w.honest, f19Tx{key: w.junk, frames: J})
				w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: H})
			}
			before := foreignCount(t)
			stepAll(t, NewIndexer(st, w.bp, 0, IndexConfig{}), 1200)
			T := uint64(1_790_100_030)
			ids := entryIDs(t, st)
			if !ids[chanLabelID("honest")] || ids[chanLabelID("junk")] || len(ids) != 1 {
				t.Fatalf("the index makes entries of the batcher's channels only: %v", ids)
			}
			for _, indexed := range []bool{false, true} {
				sr, err := w.search(indexed, E, T, st)
				if err != nil || sr.ch == nil || sr.ch.ID != chanLabelID("honest") {
					t.Errorf("indexed=%v: the honest leg must be served despite the junk channel that holds the same T first: ch=%v err=%v", indexed, sr.ch, err)
				}
			}
			if foreignCount(t) <= before {
				t.Errorf("a skipped non-batcher transaction is counted (certen_finality_capture_foreign_txs_total)")
			}
		})
	}
}

func TestRB12F19BJunkReusingTheHonestChannelIdOrCopyingItsFramesDoesNotBreakTheChannel(t *testing.T) {
	for _, mode := range []string{"reuses the id", "copies the frames"} {
		t.Run(mode, func(t *testing.T) {
			st := NewMemStore()
			w := newF19(t, st)
			E := uint64(1000)
			H := channelFrames("honest", 1_790_100_000, 30, E, 2)
			junk := []Frame{{ID: H[0].ID, Number: 0, Data: []byte("not the channel"), IsLast: true}}
			if mode == "copies the frames" {
				junk = []Frame{H[0], H[1]}
			}
			w.putBlock(1010, w.honest, f19Tx{key: w.junk, frames: junk})
			w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: H[:1]})
			w.putBlock(1022, w.honest, f19Tx{key: w.honest, frames: H[1:]})
			stepAll(t, NewIndexer(st, w.bp, 0, IndexConfig{}), 1200)
			T := uint64(1_790_100_030)
			for _, indexed := range []bool{false, true} {
				sr, err := w.search(indexed, E, T, st)
				if err != nil || sr.ch == nil || sr.ch.ID != H[0].ID || len(sr.frameTxs) != 2 {
					t.Errorf("indexed=%v: the channel is the batcher's two frames, got ch=%v txs=%d err=%v", indexed, sr.ch, len(sr.frameTxs), err)
				}
			}
		})
	}
}

func TestRB12F19CAForeignBlobTransactionIsNeverReadBeyondItsRow(t *testing.T) {
	st := &hideStore{CaptureStore: NewMemStore()}
	w := newF19(t, st)
	E := uint64(1000)
	H := channelFrames("honest", 1_790_100_000, 30, E, 1)
	J := channelFrames("junk", 1_790_100_000, 30, E, 1)
	w.putBlock(1010, w.honest, f19Tx{key: w.junk, frames: J, blob: true})
	w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: H})
	stepAll(t, NewIndexer(st, w.bp, 0, IndexConfig{}), 1200)
	if _, err := w.search(false, E, 1_790_100_030, st); err != nil {
		t.Fatal(err)
	}
	if st.reads["blob"] != 0 {
		t.Fatalf("the blob rows of a transaction the batcher did not send were read %d times (131 KB each): a non-batcher transaction costs its row and nothing else", st.reads["blob"])
	}
}

func TestRB12F19DCandidateSelectionIteratesUntilACandidateAssembles(t *testing.T) {
	st := &hideStore{CaptureStore: NewMemStore(), hidden: map[finality.CaptureKey]bool{}}
	w := newF19(t, st)
	E := uint64(1000)
	A := channelFrames("A", 1_790_100_000, 30, E, 1) // first by position
	B := channelFrames("B", 1_790_100_000, 30, E, 1)
	hashA := w.putBlock(1010, w.honest, f19Tx{key: w.honest, frames: A})
	w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: B})
	stepAll(t, NewIndexer(st, w.bp, 0, IndexConfig{}), 1200)
	T := uint64(1_790_100_030)
	if sr, err := w.search(true, E, T, st); err != nil || sr.ch == nil || sr.ch.ID != chanLabelID("A") {
		t.Fatalf("both assemble: the first by position wins: %v %v", sr.ch, err)
	}
	// A's transaction row is lost: A does not assemble, B does, and the leg is served by B
	st.hidden[finality.CaptureKey{Chain: uint64(Chain), L1Block: 1010, L1Hash: hashA, Item: ItemTx(0)}] = true
	sr, err := w.search(true, E, T, st)
	if err != nil || sr.ch == nil || sr.ch.ID != chanLabelID("B") {
		t.Fatalf("a candidate that does not assemble must not stop the search: ch=%v err=%v", sr.ch, err)
	}
	// every candidate fails: the first failure is the named answer
	st.hidden[finality.CaptureKey{Chain: uint64(Chain), L1Block: 1020, L1Hash: w.headersHash(1020, st), Item: ItemTx(0)}] = true
	_, err = w.search(true, E, T, st)
	if se, ok := finality.AsNamed(err); !ok || se.Code != "index_inconsistent" || se.Fields["reason"] != finality.IndexRowMissing {
		t.Fatalf("when no candidate assembles the answer is the first named failure, got %v", err)
	}
}

// headersHash is the hash of the captured block number (the only hash it was stored under).
func (w *f19World) headersHash(number uint64, st finality.CaptureStore) [32]byte {
	ks, err := st.ListByRange(context.Background(), uint64(Chain), number, number, ItemHeader)
	if err != nil || len(ks) != 1 {
		w.t.Fatalf("block %d: %v %v", number, ks, err)
	}
	return ks[0].L1Hash
}

// A block whose captured rows cannot establish the batcher is not filtered: its frames stay candidates and the verifier names whatever is
// wrong with the SystemConfig proof (nothing is hidden, nothing is invented).
func TestRB12F19EABlockWhoseBatcherCannotBeEstablishedKeepsItsFrames(t *testing.T) {
	st := NewMemStore()
	w := newF19(t, st)
	E := uint64(1000)
	H := channelFrames("honest", 1_790_100_000, 30, E, 1)
	w.putBlock(1020, nil, f19Tx{key: w.junk, frames: H})
	stepAll(t, NewIndexer(st, w.bp, 0, IndexConfig{}), 1200)
	for _, indexed := range []bool{false, true} {
		sr, err := w.search(indexed, E, 1_790_100_030, st)
		if err != nil || sr.ch == nil {
			t.Errorf("indexed=%v: an unestablished batcher filters nothing: %v %v", indexed, sr.ch, err)
		}
	}
	if v, ok := vGather(t, "certen_finality_capture_batcher_unestablished_total"); !ok || v == 0 {
		t.Errorf("a block whose batcher the rows cannot establish is counted: %v %v", v, ok)
	}
}

// ---- INT-1: the index path consults the durable gap records exactly as the window reader does ----

func TestRB12INT1AnOpenGapInTheWindowIsTheSameStateFromTheIndexedPath(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg+40, gcLeg+120, "state_proof_unavailable")
	s, l2 := rbLeg(t, gcLeg)
	bw := rbBuilder(t, st, l2)
	_, pendW, errW := bw.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	bp, err := ParsePins(bw.Pins)
	if err != nil {
		t.Fatal(err)
	}
	stepAll(t, NewIndexer(st, bp, 0, IndexConfig{}), rbFirstBlock+5*299+200)
	bi := rbBuilder(t, st, l2)
	bi.Index = NewIndexReader(st, bp, 0)
	_, pendI, errI := bi.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	sw, okW := finality.AsNamed(errW)
	si, okI := finality.AsNamed(errI)
	if pendW != nil || pendI != nil || !okW || !okI || sw.Code != "l1_capture_gap" || si.Code != "l1_capture_gap" {
		t.Fatalf("want l1_capture_gap on both paths: window %v %v index %v %v", pendW, errW, pendI, errI)
	}
	if !bytes.Equal(sw.Canonical(), si.Canonical()) {
		t.Fatalf("the two paths must give the same state bytes:\n window %s\n index  %s", sw.Canonical(), si.Canonical())
	}
	if si.Fields["from"] != uint64(gcLeg+40) || si.Fields["to"] != uint64(gcLeg+120) || si.Fields["gap_state"] != "open" {
		t.Fatalf("%v", si)
	}
}

// ---- the registry: one l1_capture_gap entry, and every emitter's output validates against it ----

type regSpec struct {
	Required            []string            `json:"required"`
	Optional            []string            `json:"optional"`
	Enums               map[string][]string `json:"enums"`
	ConditionalRequired []struct {
		When     map[string]string `json:"when"`
		Required []string          `json:"required"`
	} `json:"conditional_required"`
}

// regConforms is the registry's rule (pkg/finality state_test.go conforms): required, conditional, closed enums, no unregistered field.
func regConforms(t testing.TB, code string, fields map[string]any) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		States map[string]regSpec `json:"states"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	spec, ok := r.States[code]
	if !ok {
		return code + " is not registered"
	}
	allowed := map[string]bool{}
	required := append([]string(nil), spec.Required...)
	for _, c := range spec.ConditionalRequired {
		hit := true
		for k, v := range c.When {
			if toString(fields[k]) != v {
				hit = false
			}
		}
		if hit {
			required = append(required, c.Required...)
		}
	}
	for _, f := range required {
		allowed[f] = true
		if _, has := fields[f]; !has {
			return code + " lacks required field " + f
		}
	}
	for f, set := range spec.Enums {
		if v, has := fields[f]; has {
			found := false
			for _, m := range set {
				found = found || m == toString(v)
			}
			if !found {
				return code + " field " + f + " = " + toString(v) + " is not in its closed set"
			}
		}
	}
	for _, f := range spec.Optional {
		allowed[f] = true
	}
	for f := range fields {
		if !allowed[f] {
			return code + " carries unregistered field " + f
		}
	}
	return ""
}

func toString(v any) string { return strings.TrimSpace(strings.Trim(jsonOf(v), `"`)) }

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRB12L1CaptureGapIsOneRegistryEntryAndEveryEmittersOutputValidates(t *testing.T) {
	// the record-backed states, one per gap state
	for _, gs := range []finality.GapState{finality.GapOpen, finality.GapUnavailableProven, finality.GapRetentionExpired} {
		st := gapState([]finality.GapRange{{From: 5, To: 9, State: gs}}, 1, 100, true)
		if msg := regConforms(t, st.Code, st.Fields); msg != "" {
			t.Errorf("gap record state %s: %s", gs, msg)
		}
	}
	// the index inference: a channel missing between two captured channels of later and earlier L2 time
	stor := NewMemStore()
	w := newF19(t, stor)
	E := uint64(1000)
	w.putBlock(1010, w.honest, f19Tx{key: w.honest, frames: channelFrames("A", 1_790_100_000, 30, E, 1)})
	w.putBlock(1020, w.honest, f19Tx{key: w.honest, frames: channelFrames("C", 1_790_100_200, 30, E, 1)})
	w.putBlock(1400, w.honest, f19Tx{key: w.honest, frames: channelFrames("D", 1_790_100_400, 30, E, 1)})
	stepAll(t, NewIndexer(stor, w.bp, 0, IndexConfig{}), 1500)
	_, err := w.search(true, E, 1_790_100_100, stor)
	se, ok := finality.AsNamed(err)
	if !ok || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != finality.GapStateUnrecorded {
		t.Fatalf("want the inferred l1_capture_gap{gap_state: unrecorded}, got %v", err)
	}
	if msg := regConforms(t, se.Code, se.Fields); msg != "" {
		t.Errorf("the inferred state: %s", msg)
	}
	// a state of either producer that lacks its own shape does not conform
	if msg := regConforms(t, "l1_capture_gap", map[string]any{"chain": uint64(84532), "gap_state": "unrecorded", "from": uint64(1)}); msg == "" {
		t.Error("an unrecorded gap without its interval must not conform")
	}
	if msg := regConforms(t, "l1_capture_gap", map[string]any{"chain": uint64(84532), "gap_state": "open", "from_l1": uint64(1)}); msg == "" {
		t.Error("a recorded gap without its record fields must not conform")
	}
}
