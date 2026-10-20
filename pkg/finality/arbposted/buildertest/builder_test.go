// Copyright 2026 Certen Protocol

// Package buildertest exercises the attest half of the l1_posted build (arbposted.Builder) against the recorded live vector:
// the capture rows are rebuilt from the vector's own evidence, the providers are fakes, and the assembled container must be
// byte-identical to the recorded one. Every pending and unavailable state is checked against its registered fields.
package buildertest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

const raw = "../testdata/finality_arb_posted1/raw/"

type fixture struct {
	ev      arbposted.Evidence
	evBytes []byte
	pins    *finality.Pins
	pinsRaw []byte
	ref     finality.BlockRef
	txs     [][]byte
	store   *capture.MemStore
	batch   capture.BatchRecord
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(raw, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{evBytes: read(t, "evidence.bin"), pinsRaw: read(t, "pins.json")}
	c, err := finality.DecodeContainer(f.evBytes, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if f.ev, err = arbposted.Decode(c.Body, arbposted.DefaultBounds()); err != nil {
		t.Fatal(err)
	}
	if f.pins, err = finality.ParsePinsOverride(f.pinsRaw); err != nil {
		t.Fatal(err)
	}
	var leg struct {
		Number    string   `json:"number"`
		Hash      string   `json:"hash"`
		HeaderRLP string   `json:"header_rlp"`
		Txs       []string `json:"txs"`
	}
	if err := json.Unmarshal(read(t, "leg.json"), &leg); err != nil {
		t.Fatal(err)
	}
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	f.ref = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: num, HeaderRLP: unhex(t, leg.HeaderRLP)}
	copy(f.ref.Hash[:], unhex(t, leg.Hash))
	for _, x := range leg.Txs {
		f.txs = append(f.txs, unhex(t, x))
	}
	// the capture rows the Capturer would have stored for this batch
	f.store = capture.NewMemStore()
	e := f.ev
	f.batch = capture.BatchRecord{N: e.BatchSeq, BeforeAcc: e.BeforeAcc, DelayedAcc: e.DelayedAcc, Header40: e.Header40, DataLocation: capture.LocBlob,
		L1Block: 1000, L1Hash: crypto.Keccak256Hash([]byte("event block")), VersionedHashes: e.VersionedHashes}
	f.batch.AfterAcc = arbposted.Accumulator(e.BeforeAcc, arbposted.DataHash(e), e.DelayedAcc)
	put := func(k capture.Key, b []byte) {
		if err := f.store.Put(k, b); err != nil {
			t.Fatal(err)
		}
	}
	key := func(block uint64, hash [32]byte, item string) capture.Key {
		return capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: block, L1Hash: hash, Item: item}
	}
	put(key(f.batch.L1Block, f.batch.L1Hash, capture.ItemBatch(e.BatchSeq)), f.batch.Encode())
	for j, bl := range e.Blobs {
		put(key(f.batch.L1Block, f.batch.L1Hash, capture.ItemBlob(e.BatchSeq, j)), capture.BlobRecord{Raw: bl.Raw, Commitment: bl.Commitment, Proof: bl.Proof}.Encode())
	}
	f.putProof(t, e.StateBlock)
	return f
}

func (f *fixture) putProof(t *testing.T, block uint64) {
	t.Helper()
	p := capture.ProofRecord{Kind: capture.ProofBatchAcc, Index: f.ev.BatchSeq, ProofBlock: block, ProofBlockHash: crypto.Keccak256Hash([]byte("proof block")), Nodes: f.ev.Nodes}
	if err := f.store.Put(capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: block, L1Hash: p.ProofBlockHash, Item: capture.ItemProof(f.ev.BatchSeq)}, p.Encode()); err != nil {
		t.Fatal(err)
	}
}

// without returns a store holding every row of f's except those drop selects.
func (f *fixture) without(t *testing.T, drop func(capture.Key) bool) *capture.MemStore {
	t.Helper()
	out := capture.NewMemStore()
	keys, err := f.store.Keys(finality.ChainArbitrumSepolia, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if drop(k) {
			continue
		}
		b, ok, err := f.store.Get(k)
		if err != nil || !ok {
			t.Fatal(err)
		}
		if err := out.Put(k, b); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

type l2 struct {
	txs [][]byte
	err error
}

func (l *l2) BlockTxs(context.Context, [32]byte) ([][]byte, error) { return l.txs, l.err }

type l1 struct {
	lc     ethl1.LC
	lcErr  error
	spine  [][]byte
	hdrErr error
}

func (l *l1) LightClient(context.Context) (ethl1.LC, error) { return l.lc, l.lcErr }
func (l *l1) HeaderRLP(_ context.Context, n uint64) ([]byte, error) {
	if l.hdrErr != nil {
		return nil, l.hdrErr
	}
	for _, h := range l.spine {
		if hd, err := finality.ReadHeader(h); err == nil && hd.Number == n {
			return h, nil
		}
	}
	return nil, errors.New("no such header")
}
func (l *l1) HeaderRLPByHash(_ context.Context, h [32]byte) ([]byte, error) {
	if l.hdrErr != nil {
		return nil, l.hdrErr
	}
	for _, r := range l.spine {
		if crypto.Keccak256Hash(r) == h {
			return r, nil
		}
	}
	return nil, errors.New("no such header")
}

func (f *fixture) builder() *arbposted.Builder {
	return &arbposted.Builder{Store: f.store, L2: &l2{txs: f.txs}, L1: &l1{lc: f.ev.LC, spine: f.ev.L1Spine}, Pins: f.pins}
}

func state(err error) string {
	if s, ok := finality.AsNamed(err); ok {
		return string(s.Canonical())
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func pend(p *finality.PendingState) string {
	if p == nil {
		return ""
	}
	return string(p.State().Canonical())
}

func TestTheBuilderAssemblesExactlyTheRecordedEvidenceFromTheCaptureRows(t *testing.T) {
	f := load(t)
	add, p, err := f.builder().BuildFor(context.Background(), f.ref)
	if err != nil || p != nil {
		t.Fatalf("build: %v %s", err, pend(p))
	}
	if add.Level != finality.LevelL1Posted || add.Chain != finality.ChainArbitrumSepolia || add.Kind != arbposted.KindName {
		t.Fatalf("addendum %+v", add)
	}
	if !bytes.Equal(add.Evidence, f.evBytes) {
		t.Fatalf("the assembled container (%d B) differs from the recorded one (%d B)", len(add.Evidence), len(f.evBytes))
	}
	// a second level 2 addendum is refused by name
	want := string(finality.NewState(finality.CodeLevelAlreadyPresent, "chain", finality.ChainArbitrumSepolia, "level", finality.LevelL1Posted).Canonical())
	if _, _, err := f.builder().Build(context.Background(), nil, finality.LevelSetOf(finality.LevelL1Posted), finality.LevelL1Posted); state(err) != want {
		t.Fatalf("level already present: %s", state(err))
	}
}

func TestPendingAndUnavailableStatesAreNamedWithTheirFields(t *testing.T) {
	ctx := context.Background()
	f := load(t)
	hdr, err := finality.ReadHeader(f.ref.HeaderRLP)
	if err != nil {
		t.Fatal(err)
	}
	top, err := finality.ReadHeader(f.ev.L1Spine[0])
	if err != nil {
		t.Fatal(err)
	}

	// no batch holds the block yet
	g := load(t)
	g.store = capture.NewMemStore()
	_, p, err := g.builder().BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != arbposted.PendingAwaitingBatchPost || p.Judged["l2_block"] != hdr.Number || p.Judged["latest_captured_batch"] != uint64(0) || p.ETA.IsZero() {
		t.Fatalf("no batch: %v %s", err, pend(p))
	}

	// the batch is captured but no near-head proof was
	g = load(t)
	g.store = f.without(t, func(k capture.Key) bool { return strings.HasPrefix(k.Item, "proof/") })
	_, p, err = g.builder().BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != arbposted.PendingProofWindowUnavailable || p.Judged["l1_block"] != f.batch.L1Block {
		t.Fatalf("no proof: %v %s", err, pend(p))
	}

	// the finalized head is below the proof block
	g = load(t)
	g.store = f.without(t, func(k capture.Key) bool { return strings.HasPrefix(k.Item, "proof/") })
	g.putProof(t, top.Number+5)
	_, p, err = g.builder().BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != arbposted.PendingAwaitingL1Finality || p.Judged["l1_block"] != top.Number+5 || p.Judged["finalized_exec_number"] != top.Number || p.ETA.IsZero() {
		t.Fatalf("finality wait: %v %s", err, pend(p))
	}

	// the light-client source is down: a named pending carrying redacted text, never a weaker level
	g = load(t)
	b := g.builder()
	b.L1 = &l1{lcErr: errors.New("Get https://user:secret@lodestar.example/x?apikey=abc123: refused"), spine: g.ev.L1Spine}
	_, p, err = b.BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != "finality_lc_unavailable" || strings.Contains(pend(p), "secret") || strings.Contains(pend(p), "abc123") {
		t.Fatalf("lc down: %v %s", err, pend(p))
	}
	// an L1 header source that is down
	g = load(t)
	b = g.builder()
	b.L1 = &l1{lc: g.ev.LC, hdrErr: errors.New("boom"), spine: g.ev.L1Spine}
	_, p, err = b.BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != "l1_state_unavailable" {
		t.Fatalf("l1 headers down: %v %s", err, pend(p))
	}

	// the L2 block cannot be read
	g = load(t)
	b = g.builder()
	b.L2 = &l2{err: errors.New("down")}
	if _, _, err := b.BuildFor(ctx, g.ref); state(err) != string(finality.NewState("l2_header_unavailable", "block", hdr.Number).Canonical()) {
		t.Fatalf("l2 down: %s", state(err))
	}
	// the served transactions are not the header's
	b = g.builder()
	b.L2 = &l2{txs: g.txs[:len(g.txs)-1]}
	if _, _, err := b.BuildFor(ctx, g.ref); !strings.Contains(state(err), `"reason":"block_txs_root_mismatch"`) {
		t.Fatalf("txs: %s", state(err))
	}
	// a blob row is missing
	g = load(t)
	g.store = f.without(t, func(k capture.Key) bool { return k.Item == capture.ItemBlob(f.ev.BatchSeq, 1) })
	if _, _, err := g.builder().BuildFor(ctx, g.ref); !strings.Contains(state(err), `"code":"l1_blob_unavailable"`) {
		t.Fatalf("blob: %s", state(err))
	}
	// a block at or before the BoLD genesis
	g = load(t)
	b = g.builder()
	pj := map[string]any{}
	if err := json.Unmarshal(g.pinsRaw, &pj); err != nil {
		t.Fatal(err)
	}
	pj["arb_sepolia"].(map[string]any)["bold_genesis_l2_block"] = float64(hdr.Number)
	raw2, _ := json.Marshal(pj)
	if b.Pins, err = finality.ParsePinsOverride(raw2); err != nil {
		t.Fatalf("pins variant: %v", err)
	}
	if _, _, err := b.BuildFor(ctx, g.ref); !strings.Contains(state(err), `"code":"pre_bold_block"`) {
		t.Fatalf("pre-bold: %s", state(err))
	}
}
