// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

// RB12-CAPTURE-GAP, production proof, offline. testdata/gap_replay holds REAL provider answers recorded read-only on 2026-10-23 for three
// Sepolia blocks that lie inside the three outage holes of the Base capture (one per hole: 11976075, 11976414, 11976724; each holds a Base
// batch-inbox transaction with its blobs), and the scan table of the real hash and inbox-transaction count of every block of the three
// holes. The capturer below runs the production decoders (JSONRPCSource, BeaconHTTP, the KZG setup) against a server that replays those
// answers verbatim; nothing in a recorded answer was made up or edited.

type replayCall struct {
	Kind   string          `json:"kind"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Path   string          `json:"path"`
	Status int             `json:"status"`
	File   string          `json:"file"`
}

type replayScanBlock struct {
	N     uint64 `json:"n"`
	Hash  string `json:"hash"`
	Inbox int    `json:"inbox"`
	Blobs int    `json:"blobs"`
}

type replayHole struct {
	After  uint64            `json:"after"`
	Before uint64            `json:"before"`
	Blocks []replayScanBlock `json:"blocks"`
}

type replaySet struct {
	dir      string
	Calls    []replayCall `json:"calls"`
	Featured []uint64
	Holes    []replayHole
}

func gunzipFile(t testing.TB, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadReplay(t testing.TB) *replaySet {
	t.Helper()
	dir := filepath.Join("testdata", "gap_replay")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	rs := &replaySet{dir: dir}
	var m struct {
		Calls  []replayCall `json:"calls"`
		Blocks []struct {
			Number uint64 `json:"number"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	rs.Calls = m.Calls
	for _, b := range m.Blocks {
		rs.Featured = append(rs.Featured, b.Number)
	}
	if err := json.Unmarshal(gunzipFile(t, filepath.Join(dir, "scan.json.gz")), &rs.Holes); err != nil {
		t.Fatal(err)
	}
	return rs
}

func canonJSON(t testing.TB, raw []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// server replays the recorded answers; a request that was not recorded is a failure of the test (the capturer asked for something the
// recording does not hold).
func (rs *replaySet) server(t testing.TB) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	var unrecorded []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			want := canonJSON(t, req.Params)
			for _, c := range rs.Calls {
				if c.Kind == "rpc" && c.Method == req.Method && canonJSON(t, c.Params) == want {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(gunzipFile(t, filepath.Join(rs.dir, c.File)))
					return
				}
			}
			mu.Lock()
			unrecorded = append(unrecorded, req.Method+" "+want)
			mu.Unlock()
			http.Error(w, "unrecorded request", 500)
			return
		}
		for _, c := range rs.Calls {
			if c.Kind == "beacon" && c.Path == r.URL.Path {
				if c.Status != 200 {
					w.WriteHeader(c.Status)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(gunzipFile(t, filepath.Join(rs.dir, c.File)))
				return
			}
		}
		mu.Lock()
		unrecorded = append(unrecorded, "GET "+r.URL.Path)
		mu.Unlock()
		http.Error(w, "unrecorded request", 500)
	}))
	t.Cleanup(func() {
		srv.Close()
		mu.Lock()
		defer mu.Unlock()
		if len(unrecorded) > 0 {
			t.Errorf("the capturer asked for answers the recording does not hold: %v", unrecorded)
		}
	})
	return srv
}

func replayPins(t testing.TB) *Pins {
	t.Helper()
	fp, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := ParsePins(fp)
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

func (rs *replaySet) capturer(t testing.TB, srv *httptest.Server, store CaptureStore) *Capturer {
	t.Helper()
	src := &JSONRPCSource{BlockURLs: []string{srv.URL}, ProofURLs: []string{srv.URL}}
	return &Capturer{Chain: uint64(Chain), Pins: replayPins(t), L1: src, Beacon: &BeaconHTTP{Bases: []string{srv.URL}}, Store: store, GenesisTime: SepoliaBeaconGenesis, SlotSeconds: 12}
}

// verifyCapturedBlock checks the rows of one captured block against the block's own header with the verifier's primitives: the header hashes
// to the recorded block hash, the transaction proof opens to the recorded transaction under the header's transaction root, every blob row
// passes its KZG proof and matches the transaction's versioned hash, and the SystemConfig proof opens (under the header's state root) to a
// batcher that is the signer of the inbox transaction, behind a pinned implementation.
func verifyCapturedBlock(t testing.TB, store CaptureStore, bp *Pins, n uint64, wantHash [32]byte) {
	t.Helper()
	ctx := context.Background()
	ks, err := store.ListByRange(ctx, uint64(Chain), n, n, "")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]byte{}
	var hash [32]byte
	for _, k := range ks {
		if k.Item == "runtime/cursor" || len(k.Item) >= 3 && k.Item[:3] == "gap" {
			continue
		}
		b, _, _ := store.Get(ctx, k)
		rows[k.Item] = b
		hash = k.L1Hash
	}
	if hash != wantHash {
		t.Fatalf("block %d: rows are keyed under %x, the provider's block hash is %x", n, hash, wantHash)
	}
	h, err := finality.ReadHeader(rows[ItemHeader])
	if err != nil {
		t.Fatalf("block %d: %v", n, err)
	}
	if h.Hash != wantHash || h.Number != n || [32]byte(crypto.Keccak256Hash(rows[ItemHeader])) != wantHash {
		t.Fatalf("block %d: the header row does not hash to the block hash", n)
	}
	r := finality.NewReader(rows[ItemInbox], finality.DefaultLimits())
	cnt, err := r.Count("inbox", 1<<16, 4)
	if err != nil || cnt == 0 {
		t.Fatalf("block %d: inbox row: %v %d", n, err, cnt)
	}
	kz, err := kzgsetup.Load(bp.KZGSetupSHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	var senders [][20]byte
	for i := 0; i < cnt; i++ {
		idx, _ := r.U32("idx")
		var tx types.Transaction
		if err := tx.UnmarshalBinary(rows[ItemTx(idx)]); err != nil {
			t.Fatalf("block %d tx %d: %v", n, idx, err)
		}
		if tx.To() == nil || *tx.To() != common.Address(bp.BatchInbox) {
			t.Fatalf("block %d tx %d is not to the batch inbox", n, idx)
		}
		// the transaction opens under the header's transaction root
		nr := finality.NewReader(rows[ItemTxNodes(idx)], finality.DefaultLimits())
		nodes, err := nr.LPList("nodes", 1<<12, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		db := newNodeDB(nodes)
		key, _ := rlp.EncodeToBytes(uint64(idx))
		v, ok := db.value(h.TransactionRoot, key)
		if !ok || !bytes.Equal(v, rows[ItemTx(idx)]) {
			t.Fatalf("block %d tx %d: the stored proof does not open to the stored transaction under the header's transaction root", n, idx)
		}
		from, err := types.Sender(signer, &tx)
		if err != nil {
			t.Fatal(err)
		}
		senders = append(senders, from)
		for j, vh := range tx.BlobHashes() {
			br := finality.NewReader(rows[ItemBlob(idx, j)], finality.DefaultLimits())
			raw, _ := br.LP("blob", BlobSize)
			com, _ := br.Fixed("c", 48)
			pr, _ := br.Fixed("p", 48)
			if err := kz.VerifyBlob(raw, [48]byte(com), [48]byte(pr)); err != nil {
				t.Fatalf("block %d tx %d blob %d: KZG proof: %v", n, idx, j, err)
			}
			want := sha256Sum(com)
			want[0] = 0x01
			if common.Hash(want) != vh {
				t.Fatalf("block %d tx %d blob %d: the commitment does not hash to the transaction's versioned hash", n, idx, j)
			}
		}
	}
	// SystemConfig: account, batcherHash and the implementation, exactly as the verifier proves them
	sr := finality.NewReader(rows[ItemSysCfg], finality.DefaultLimits())
	nodes, err := sr.LPList("syscfg", 1<<12, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	batcher, err := systemConfigAt(newNodeDB(nodes), bp, h.StateRoot, n)
	if err != nil {
		t.Fatalf("block %d: the stored SystemConfig proof is refused by the verifier's own check: %v", n, err)
	}
	for _, s := range senders {
		if s != batcher {
			t.Fatalf("block %d: the inbox transaction is signed by %x but SystemConfig.batcherHash at the block is %x", n, s, batcher)
		}
	}
}

func TestRB12ReplayTheRecordedBlocksOfTheThreeHolesCaptureWithTheProductionCodeAndTheirRowsVerify(t *testing.T) {
	rs := loadReplay(t)
	if len(rs.Featured) != 3 {
		t.Fatalf("featured blocks %v", rs.Featured)
	}
	bp := replayPins(t)
	srv := rs.server(t)
	for i, n := range rs.Featured {
		hole := rs.Holes[i]
		if n <= hole.After || n >= hole.Before {
			t.Fatalf("featured block %d is not inside hole %d (%d,%d)", n, i+1, hole.After, hole.Before)
		}
		store := NewMemStore()
		c := rs.capturer(t, srv, store)
		ok, err := c.CaptureBlock(context.Background(), n)
		if err != nil || !ok {
			t.Fatalf("block %d: %v %v", n, ok, err)
		}
		var want [32]byte
		for _, b := range hole.Blocks {
			if b.N == n {
				copy(want[:], common.FromHex(b.Hash))
			}
		}
		verifyCapturedBlock(t, store, bp, n, want)
		// and a second capture (what a backfill after a live capture, or another validator, does) writes the same rows
		if ok, err := c.CaptureBlock(context.Background(), n); err != nil || !ok {
			t.Fatalf("block %d again: %v %v", n, ok, err)
		}
	}
}

// replayHoleCapturer is the BlockCapturer of the offline replay of the whole holes: the three recorded blocks are captured by the
// production capturer; a block the recorded scan found without inbox transactions is scanned empty; every other inbox block is a named
// failure, because the recording does not hold its provider answers (the live run behind the rb12live tag has them from the providers).
type replayHoleCapturer struct {
	rs    *replaySet
	real  BlockCapturer
	byNum map[uint64]replayScanBlock
}

func (c *replayHoleCapturer) CaptureBlockHash(ctx context.Context, n uint64) ([32]byte, bool, error) {
	for _, f := range c.rs.Featured {
		if f == n {
			return c.real.CaptureBlockHash(ctx, n)
		}
	}
	b, ok := c.byNum[n]
	if !ok {
		return [32]byte{}, false, errors.New("block outside the recorded holes")
	}
	var h [32]byte
	copy(h[:], common.FromHex(b.Hash))
	if b.Inbox == 0 {
		return h, false, nil
	}
	return h, false, &CaptureFailure{Block: n, State: finality.NewState("batcher_state_unavailable", "l1_block", n),
		Err: errors.New("offline replay: the provider answers for this inbox block were not recorded")}
}

// The gap lifecycle over the real hole shapes: the store as production has it (an inbox block every 5-19 blocks, the three runs missing)
// answers "pending" for a leg in a hole; the audit records the three runs; the leg is then the named gap state; the backfill closes every
// block it has the recorded answers for and leaves the rest OPEN under their class.
func TestRB12ReplayTheThreeHolesGapRecordedCoverageNamedBackfillFillsWhatTheRecordingHolds(t *testing.T) {
	rs := loadReplay(t)
	ctx := context.Background()
	st := rbShapedStore(t, rs)

	// 1. before: the cursor says covered, no row says otherwise: a leg whose batch lies in hole 1 is "not posted yet" (the live defect)
	s, l2 := rbLeg(t, 11976000)
	_, pend, err := rbBuilder(t, st, l2).Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("before the audit the leg is pending (the misleading state): pend=%v err=%v", pend, err)
	}

	// 2. the audit records exactly the three runs (228, 72 and 384 blocks)
	found, err := finality.AuditSpacing(ctx, st, uint64(Chain), ItemInbox, 0, finality.MaxCaptureBlock, 40)
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]uint64
	var blocks uint64
	for _, g := range found {
		got = append(got, [2]uint64{g.From, g.To})
		blocks += g.Blocks()
	}
	want := [][2]uint64{{11975927, 11976154}, {11976374, 11976445}, {11976621, 11977004}}
	if fmt.Sprint(got) != fmt.Sprint(want) || blocks != 684 {
		t.Fatalf("audit %v (%d blocks), want %v (684)", got, blocks, want)
	}

	// 3. the leg is now the named gap state, naming the part of the gap inside its window
	_, pend, err = rbBuilder(t, st, l2).Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	se, named := finality.AsNamed(err)
	if pend != nil || !named || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" || se.Fields["from"] != uint64(11976000) ||
		se.Fields["blocks"] != uint64(611) || se.Fields["ranges"] != uint64(3) {
		t.Fatalf("want l1_capture_gap over the 611 blocks of the three runs that lie inside the leg's window [11976000, 11979600], got pend=%v err=%v", pend, err)
	}

	// 4. the backfill
	srv := rs.server(t)
	realCap := CapturerOf(rs.capturer(t, srv, st))
	hc := &replayHoleCapturer{rs: rs, real: realCap, byNum: map[uint64]replayScanBlock{}}
	var unrecordedInbox []uint64
	for _, h := range rs.Holes {
		for _, b := range h.Blocks {
			hc.byNum[b.N] = b
			if b.Inbox > 0 && b.N != rs.Featured[0] && b.N != rs.Featured[1] && b.N != rs.Featured[2] {
				unrecordedInbox = append(unrecordedInbox, b.N)
			}
		}
	}
	sort.Slice(unrecordedInbox, func(i, j int) bool { return unrecordedInbox[i] < unrecordedInbox[j] })
	if len(unrecordedInbox) != 77 {
		t.Fatalf("the holes hold 80 inbox blocks; 3 are recorded, so 77 are not: %d", len(unrecordedInbox))
	}
	now, _ := bfClock()
	bf := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: hc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	for i := 0; i < 200; i++ {
		rep, err := bf.Step(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Attempted == 0 {
			break
		}
	}
	open, _ := finality.GapsIn(ctx, st, uint64(Chain), 0, finality.MaxCaptureBlock)
	var openBlocks []uint64
	for _, g := range open {
		if g.State != finality.GapOpen {
			t.Fatalf("no block is ended by a state-proof failure: %v", g)
		}
		for n := g.From; n <= g.To; n++ {
			openBlocks = append(openBlocks, n)
		}
	}
	if fmt.Sprint(openBlocks) != fmt.Sprint(unrecordedInbox) {
		t.Fatalf("after the backfill exactly the 77 unrecorded inbox blocks are open\n got %v\nwant %v", openBlocks, unrecordedInbox)
	}
	// the three recorded blocks were captured for real: rows keyed under their real hashes that verify
	bp := replayPins(t)
	for i, n := range rs.Featured {
		var h [32]byte
		for _, b := range rs.Holes[i].Blocks {
			if b.N == n {
				copy(h[:], common.FromHex(b.Hash))
			}
		}
		verifyCapturedBlock(t, st, bp, n, h)
	}
	// 5. the leg is still the gap state (the unrecorded inbox blocks of its window are open), now with exactly those blocks
	_, _, err = rbBuilder(t, st, l2).Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	se, named = finality.AsNamed(err)
	var inWindow []uint64
	for _, n := range unrecordedInbox {
		if n >= 11976000 {
			inWindow = append(inWindow, n)
		}
	}
	if !named || se.Code != "l1_capture_gap" || se.Fields["blocks"] != uint64(len(inWindow)) || se.Fields["from"] != inWindow[0] {
		t.Fatalf("want l1_capture_gap over the %d open blocks of the window starting at %d, got %v", len(inWindow), inWindow[0], err)
	}
	// 6. when the rest are filled (here: scanned by a capturer that has them), the leg is covered again: pending for what it is
	for _, n := range unrecordedInbox {
		var h [32]byte
		copy(h[:], common.FromHex(hc.byNum[n].Hash))
		if err := finality.RecordGapFill(ctx, st, uint64(Chain), n, h, true); err != nil {
			t.Fatal(err)
		}
	}
	_, pend, err = rbBuilder(t, st, l2).Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("every gap block closed: the leg is covered and pending: pend=%v err=%v", pend, err)
	}
}

// rbShapedStore is the capture store as production holds it on 2026-10-23: one inbox block every 5-19 blocks from 11958043 to 11977349
// except the three holes, cursor rows from 11958067 to 11977356. Rows of blocks before the window of the test legs are the inbox item alone
// (the builder never reads them); rows from 11975900 on are complete (header, inbox, transaction, blob, SystemConfig proof).
func rbShapedStore(t *testing.T, rs *replaySet) CaptureStore {
	t.Helper()
	st := NewMemStore()
	ctx := context.Background()
	inHole := func(n uint64) bool {
		for _, h := range rs.Holes {
			if n > h.After && n < h.Before {
				return true
			}
		}
		return false
	}
	var blocks []uint64
	step := []uint64{12, 12, 11, 13, 12, 7, 12, 16, 12, 12}
	n, i := uint64(11958043), 0
	for n <= 11977349 {
		if !inHole(n) {
			blocks = append(blocks, n)
		}
		n += step[i%len(step)]
		i++
	}
	for _, h := range rs.Holes { // the captured rows on both sides of each hole, as production has them
		blocks = append(blocks, h.After, h.Before)
	}
	seen := map[uint64]bool{}
	for _, b := range blocks {
		if seen[b] {
			continue
		}
		seen[b] = true
		var hash [32]byte
		hash[0], hash[1], hash[2] = 0x5a, byte(b>>16), byte(b>>8)
		hash[3] = byte(b)
		k := func(item string) CaptureKey {
			return CaptureKey{Chain: uint64(Chain), L1Block: b, L1Hash: hash, Item: item}
		}
		var w finality.Writer
		w.Count(1)
		w.U32(0)
		if b < 11975900 {
			if err := st.Put(ctx, k(ItemInbox), w.Bytes()); err != nil {
				t.Fatal(err)
			}
			continue
		}
		tx := types.NewTx(&types.BlobTx{ChainID: uint256.NewInt(11155111), Nonce: b, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2), Gas: 21000,
			To: common.Address{1}, BlobFeeCap: uint256.NewInt(1), BlobHashes: []common.Hash{{1}}, V: uint256.NewInt(0), R: uint256.NewInt(1), S: uint256.NewInt(1)})
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		blob := make([]byte, BlobSize)
		crand.Read(blob)
		var bw finality.Writer
		bw.LP(blob)
		bw.Fixed(make([]byte, 48))
		bw.Fixed(make([]byte, 48))
		for item, data := range map[string][]byte{ItemInbox: w.Bytes(), ItemTx(0): raw, ItemBlob(0, 0): bw.Bytes(), ItemHeader: make([]byte, 600), ItemSysCfg: make([]byte, 3000)} {
			if err := st.Put(ctx, k(item), data); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, blk := range []uint64{11958067, 11977356} {
		var v [8]byte
		v[7], v[6], v[5], v[4], v[3], v[2] = byte(blk), byte(blk>>8), byte(blk>>16), byte(blk>>24), byte(blk>>32), byte(blk>>40)
		if err := st.Put(ctx, CaptureKey{Chain: uint64(Chain), L1Block: blk, Item: "runtime/cursor"}, v[:]); err != nil {
			t.Fatal(err)
		}
	}
	return st
}
