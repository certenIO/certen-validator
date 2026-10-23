// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// RB12-SEPOLIA-SPINE through the real insert-only table: the recorded gloas_period leg (2192 spine headers of the real Sepolia chain) is built
// by provers that each live one attempt (a new process every time) behind a provider that fails every fifth request. Only the rows in
// proof_finality_capture carry the progress from one to the next.

type spineReplay struct {
	final []byte
	links map[uint64][]byte
}

func (r *spineReplay) Name() string                                   { return "replay" }
func (r *spineReplay) FinalityUpdate(context.Context) ([]byte, error) { return r.final, nil }
func (r *spineReplay) HeadSlot(context.Context) (uint64, error)       { return 1, nil }
func (r *spineReplay) Bootstrap(context.Context, [32]byte) ([]byte, error) {
	return r.links[1378], nil
}
func (r *spineReplay) Updates(_ context.Context, start uint64, count int) ([][]byte, error) {
	var out [][]byte
	for i := 0; i < count; i++ {
		out = append(out, r.links[start+uint64(i)+1])
	}
	return out, nil
}

type flakyHeaders struct {
	mu     sync.Mutex
	byNum  map[uint64][]byte
	byHash map[[32]byte][]byte
	calls  int
	every  int // every n-th request fails
	first  int // the first n requests fail
}

func (f *flakyHeaders) HeaderByHash(_ context.Context, h [32]byte) ([]byte, error) {
	if b, ok := f.byHash[h]; ok {
		return b, nil
	}
	return nil, errors.New("unknown hash")
}

func (f *flakyHeaders) HeadersByNumber(_ context.Context, from, to uint64) ([][]byte, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n <= f.first || (f.every > 0 && n%f.every == 0) {
		return nil, &ethsepolia.SourceError{Failures: []ethsepolia.EndpointFailure{{Endpoint: "https://rpc.example", Op: "headers", Reason: "HTTP 503"}}}
	}
	var out [][]byte
	for k := from; k <= to; k++ {
		out = append(out, f.byNum[k])
	}
	return out, nil
}

func TestSepoliaSpineChunksResumeAcrossProcessesThroughTheRealCaptureTable(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join("..", "finality", "ethsepolia", "testdata", "finality_eth_sepolia2")
	rd := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var lj struct {
		Number    string `json:"number"`
		Hash      string `json:"hash"`
		HeaderRLP string `json:"header_rlp"`
	}
	if err := json.Unmarshal(rd("raw/gloas_period/leg.json"), &lj); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		out := make([]byte, 0, len(s)/2)
		for i := 2; i+1 < len(s); i += 2 {
			v, err := strconv.ParseUint(s[i:i+2], 16, 8)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, byte(v))
		}
		return out
	}
	num, _ := strconv.ParseUint(lj.Number, 10, 64)
	ref := finality.BlockRef{Chain: finality.ChainSepolia, Number: num, HeaderRLP: unhex(lj.HeaderRLP)}
	copy(ref.Hash[:], unhex(lj.Hash))
	ev := rd("raw/gloas_period/evidence.bin")
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := ethsepolia.DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384)
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64][]byte{}
	ents, _ := os.ReadDir(filepath.Join(dir, "raw", "links"))
	for _, e := range ents {
		p, _ := strconv.ParseUint(strings.TrimSuffix(e.Name(), ".ssz"), 10, 64)
		links[p] = rd("raw/links/" + e.Name())
	}
	hdrs := &flakyHeaders{byNum: map[uint64][]byte{}, byHash: map[[32]byte][]byte{}, every: 5, first: 1} // the top of the spine is never kept, so the very first request is always one that can fail
	for _, raw := range body.Spine {
		f, err := finality.ReadHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		hdrs.byNum[f.Number], hdrs.byHash[f.Hash] = raw, raw
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))

	var firstPending *finality.PendingState
	var evidence []byte
	attempts := 0
	for ; attempts < 200 && evidence == nil; attempts++ {
		// a new process each time: nothing but the table carries progress
		p := &ethsepolia.Prover{Source: &spineReplay{final: body.LC.FinalUpdate.SSZ, links: links}, Exec: hdrs, Pins: pins, Verifier: ethsepolia.New(),
			ExtraLinks: links, Store: store}
		add, pend, err := p.BuildLeg(ctx, ref)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempts+1, err)
		}
		if add != nil {
			evidence = add.Evidence
		} else if firstPending == nil {
			firstPending = pend
		}
	}
	// a new process after completion asks the provider for the top of the spine and nothing else: every other chunk is a row
	quiet := &flakyHeaders{byNum: hdrs.byNum, byHash: hdrs.byHash}
	again := &ethsepolia.Prover{Source: &spineReplay{final: body.LC.FinalUpdate.SSZ, links: links}, Exec: quiet, Pins: pins, Verifier: ethsepolia.New(), ExtraLinks: links, Store: store}
	if add, pend, err := again.BuildLeg(ctx, ref); err != nil || pend != nil || add == nil || !bytes.Equal(add.Evidence, ev) || quiet.calls != 1 {
		t.Fatalf("a new process after completion: evidence %v pending %v err %v, %d provider calls (want 1)", add != nil, pend, err, quiet.calls)
	}
	if !bytes.Equal(evidence, ev) {
		t.Fatalf("after %d attempts the evidence is not the recorded evidence (%d bytes)", attempts, len(evidence))
	}
	if firstPending == nil || firstPending.Reason != ethsepolia.PendingAwaitingSpine {
		t.Fatalf("the flaky provider never put an attempt into the progress state: %v", firstPending)
	}

	// the rows: the shape the production table holds and the shape check (pr/rb11-prod-shape-check.sh SP1) asserts
	spans := ethsepolia.PlanSpans(ref.Number, ref.Number+uint64(len(body.Spine))-2)
	kept := 0
	for _, sp := range spans {
		if sp.Stored {
			kept++
		}
	}
	var n, badHash, badItem, badPrefix, notBoundary int
	if err := testDB.QueryRow(`SELECT count(*), count(*) FILTER (WHERE octet_length(l1_hash) <> 32), count(*) FILTER (WHERE item !~ '^spine/n[0-9]+$'),
		count(*) FILTER (WHERE get_byte(bytes, 0) < 192), count(*) FILTER (WHERE item = 'spine/n40' AND l1_block % 40 <> 39)
		FROM proof_finality_capture WHERE chain = 11155111 AND item LIKE 'spine/%' AND l1_block BETWEEN $1 AND $2`, ref.Number, ref.Number+uint64(len(body.Spine))).
		Scan(&n, &badHash, &badItem, &badPrefix, &notBoundary); err != nil {
		t.Fatal(err)
	}
	if n < kept || badHash+badItem+badPrefix+notBoundary != 0 {
		t.Fatalf("%d spine rows (want at least %d); bad hash %d, item %d, list prefix %d, not on a window boundary %d", n, kept, badHash, badItem, badPrefix, notBoundary)
	}
	// a row is never rewritten: other bytes under a kept key are the conflict, identical bytes are not
	keys, err := store.ListByRange(ctx, finality.ChainSepolia, ref.Number, ref.Number+uint64(len(body.Spine)), "spine/")
	if err != nil || len(keys) < kept {
		t.Fatalf("%d keys, %v", len(keys), err)
	}
	b, ok, err := store.Get(ctx, keys[0])
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if err := store.Put(ctx, keys[0], b); err != nil {
		t.Fatalf("identical bytes: %v", err)
	}
	if err := store.Put(ctx, keys[0], append(append([]byte(nil), b...), 0)); !errors.Is(err, finality.ErrCaptureConflict) {
		t.Fatalf("other bytes: %v", err)
	}

	// the progress state is a builder status row like any other: it is stored and read back with its fields
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	st := finality.BuilderStatusOf(pid, finality.ChainSepolia, finality.LevelFinalized, finality.LevelIncluded, firstPending, nil, false, time.Now())
	if err := repo.UpsertStatus(ctx, st); err != nil {
		t.Fatal(err)
	}
	got, ok, err := repo.GetStatus(ctx, pid, finality.LevelFinalized)
	if err != nil || !ok || got.Class != finality.BuilderPending || !got.ETA.Equal(firstPending.ETA.UTC().Truncate(time.Second)) {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	var doc struct {
		Code   string            `json:"code"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(got.State, &doc); err != nil || doc.Code != finality.CodePending || doc.Fields["reason"] != "awaiting_spine" ||
		doc.Fields["have"] == "" || doc.Fields["need"] != strconv.Itoa(len(body.Spine)) || doc.Fields["next_attempt_at"] == "" {
		t.Fatalf("%s %v", got.State, err)
	}
}
