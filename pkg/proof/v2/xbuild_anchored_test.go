// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// A fake Directory behind the real JSON-RPC wire: it serves the continuous minor-root records of a synthetic chain (minor-root-range) and the
// receipt of the anchor(directory)-root chain that joins a previous root into a later record's height (the query), exactly the two calls the
// builder makes. refuse answers a link question with the refusal text (empty: serve it).
type fakeDirectory struct {
	t        *testing.T
	recs     []*api.MinorRootRecord
	roots    [][]byte // roots[0] is the root at the checkpoint, roots[i+1] the end of recs[i]
	blocks   []uint64
	heights  []uint64
	refuse   func(prev []byte, height uint64) string
	noRange  bool
	queried  [][2]string
	rangeAsk [][2]uint64
}

func newFakeDirectory(t *testing.T, start []byte, recs []*api.MinorRootRecord) *fakeDirectory {
	f := &fakeDirectory{t: t, recs: recs, roots: [][]byte{start}}
	for _, r := range recs {
		body := r.Anchor.Message.(*messaging.TransactionMessage).Transaction.Body.(*protocol.DirectoryAnchor)
		f.roots = append(f.roots, body.RootChainAnchor[:])
		f.blocks = append(f.blocks, body.MinorBlockIndex)
		f.heights = append(f.heights, body.RootChainIndex)
	}
	return f
}

func (f *fakeDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("bad request: %v", err)
		return
	}
	reply := func(result any, msg string) {
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if msg != "" {
			out["error"] = map[string]any{"code": -32000, "message": msg}
		} else {
			out["result"] = result
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	switch req.Method {
	case "minor-root-range":
		var p struct {
			Since uint64 `json:"since"`
			Until uint64 `json:"until"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			f.t.Errorf("minor-root-range params: %v", err)
		}
		f.rangeAsk = append(f.rangeAsk, [2]uint64{p.Since, p.Until})
		if f.noRange {
			reply(nil, "the minor-root range is not served")
			return
		}
		for i, b := range f.blocks {
			if b > p.Since {
				reply(f.recs[i], "")
				return
			}
		}
		reply(nil, "no anchor at or after "+strconv.FormatUint(p.Since, 10))
	case "query":
		var p struct {
			Scope string `json:"scope"`
			Query struct {
				QueryType      string `json:"queryType"`
				Name           string `json:"name"`
				Entry          string `json:"entry"`
				IncludeReceipt struct {
					ForHeight uint64 `json:"forHeight"`
				} `json:"includeReceipt"`
			} `json:"query"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			f.t.Errorf("query params: %v", err)
		}
		if p.Scope != "acc://dn.acme/anchors" || p.Query.QueryType != "chain" || p.Query.Name != "anchor(directory)-root" {
			f.t.Errorf("unexpected query %+v", p)
		}
		prev, _ := hex.DecodeString(p.Query.Entry)
		h := p.Query.IncludeReceipt.ForHeight
		f.queried = append(f.queried, [2]string{p.Query.Entry, strconv.FormatUint(h, 10)})
		if f.refuse != nil {
			if msg := f.refuse(prev, h); msg != "" {
				reply(nil, msg)
				return
			}
		}
		from := -1
		for i, root := range f.roots {
			if string(root) == string(prev) {
				from = i
			}
		}
		to := -1
		for i, hh := range f.heights {
			if hh == h {
				to = i + 1
			}
		}
		if from < 0 || to <= from {
			reply(nil, fmt.Sprintf("entry %x is not an entry of the chain at height %d", prev, h))
			return
		}
		link := &merkle.Receipt{Start: prev, Anchor: f.roots[to]}
		for k := from; k < to; k++ { // each synthetic record's root is h2(previous root, its single element)
			link.Entries = append(link.Entries, &merkle.ReceiptEntry{Right: true, Hash: f.recs[k].RootProof.Elements[0]})
		}
		reply(&api.ChainEntryRecord[api.Record]{Name: "anchor(directory)-root", Receipt: &api.Receipt{Receipt: *link}}, "")
	default:
		f.t.Errorf("unexpected method %s", req.Method)
		reply(nil, "unexpected method")
	}
}

func decodeRuns(t *testing.T, hexes []string) []*api.MinorRootRecord {
	t.Helper()
	var out []*api.MinorRootRecord
	for _, h := range hexes {
		raw, _ := hex.DecodeString(h)
		r := new(api.MinorRootRecord)
		if err := r.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func plain() xworld.ChainItem { return xworld.ChainItem{} }

// The builder's certification, against a Directory served over the real JSON-RPC wire, keeps the run of each applied update and the last,
// drops the run between them, joins each kept run to the previously verified root with a served link, and the document verifies from
// genesis with the very report of the continuous one. A hop whose previous root is not yet anchored at the height is emitted continuous; a
// link that cannot be had is certify_link_unavailable{prevRoot,height}, a range the Directory does not serve is
// certify_range_unavailable{since,until}.
func TestBuildAnchored(t *testing.T) {
	// a: applies the globals write; b: nothing (the dropped hop); c: applies another; then the closing run. All continuous as the Directory serves them.
	world := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{eff(false), plain(), eff(false)}, Final: xworld.ChainItem{}})
	sp, recs, _ := spineAt1(t, world)
	if len(recs) != 4 {
		t.Fatalf("%d served runs", len(recs))
	}
	wantReport, err := proofv2.Verify21FromGenesis(world.Evidence, world.Archive, world.Inputs, world.Pin)
	if err != nil {
		t.Fatal(err)
	}
	build := func(t *testing.T, f *fakeDirectory) (*proofv2.Evidence, []string, []string, error) {
		srv := httptest.NewServer(f)
		defer srv.Close()
		b := &proofv2.Builder{C: jsonrpc.NewClient(srv.URL)}
		_, runs, links, err := b.CertifyRuns(context.Background(), sp.Clone(), 300, true)
		if err != nil {
			return nil, nil, nil, err
		}
		ev := *world.Evidence
		ev.Certify, ev.Links = runs, links
		return &ev, runs, links, nil
	}

	t.Run("keeps the update-bearing runs and the last", func(t *testing.T) {
		ev, runs, links, err := build(t, newFakeDirectory(t, sp.RootChainAnchor[:], recs))
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) != 3 || len(links) != 3 {
			t.Fatalf("%d runs and %d links, want 3 and 3 (a, c and the last; b dropped)", len(runs), len(links))
		}
		kept := decodeRuns(t, runs)
		for i, r := range kept {
			if r.RootProof != nil {
				t.Fatalf("kept run %d still carries a root proof", i)
			}
		}
		dropped := decodeRuns(t, world.Evidence.Certify)[1]
		for i, r := range kept {
			if reflect.DeepEqual(r.Anchor, dropped.Anchor) {
				t.Fatalf("the dropped run b was kept as run %d", i)
			}
		}
		rep, err := proofv2.Verify21FromGenesis(ev, world.Archive, world.Inputs, world.Pin)
		if err != nil {
			t.Fatalf("the built document does not verify: %v", err)
		}
		if reportJSON(t, rep) != reportJSON(t, wantReport) {
			t.Fatalf("report differs from the continuous document's:\n%+v\n%+v", rep, wantReport)
		}
		// The dropped hop is spanned by one link (two steps); the others join adjacent roots (one step each).
		var steps []int
		for _, h := range links {
			raw, _ := hex.DecodeString(h)
			l := new(merkle.Receipt)
			if err := l.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			steps = append(steps, len(l.Entries))
		}
		if !reflect.DeepEqual(steps, []int{1, 2, 1}) {
			t.Fatalf("link steps %v, want [1 2 1]", steps)
		}
	})

	t.Run("a hop whose previous root is not yet anchored is emitted continuous", func(t *testing.T) {
		f := newFakeDirectory(t, sp.RootChainAnchor[:], recs)
		f.refuse = func(prev []byte, h uint64) string {
			if h == f.heights[2] { // run c: its previous kept root (a) is "not yet anchored" at c's height
				return "get chain receipt: cannot satisfy target height " + strconv.FormatUint(h, 10) + ": entry is anchored at height " + strconv.FormatUint(h+4, 10)
			}
			return ""
		}
		ev, runs, links, err := build(t, f)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) != 4 || len(links) != 2 {
			t.Fatalf("%d runs and %d links, want a (anchored), b and c (continuous), last (anchored): 4 and 2", len(runs), len(links))
		}
		kept := decodeRuns(t, runs)
		for i, wantProof := range []bool{false, true, true, false} {
			if (kept[i].RootProof != nil) != wantProof {
				t.Fatalf("run %d: root proof present %v, want %v", i, kept[i].RootProof != nil, wantProof)
			}
		}
		rep, err := proofv2.Verify21FromGenesis(ev, world.Archive, world.Inputs, world.Pin)
		if err != nil {
			t.Fatalf("the mixed document does not verify: %v", err)
		}
		if reportJSON(t, rep) != reportJSON(t, wantReport) {
			t.Fatal("report differs from the continuous document's")
		}
	})

	t.Run("a link that cannot be had is certify_link_unavailable", func(t *testing.T) {
		f := newFakeDirectory(t, sp.RootChainAnchor[:], recs)
		f.refuse = func([]byte, uint64) string { return "the node is down" }
		_, _, _, err := build(t, f)
		var cs *proofv2.CertifyState
		if !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyLinkUnavailable {
			t.Fatalf("got %v, want certify_link_unavailable", err)
		}
		wantFields := []string{hex.EncodeToString(sp.RootChainAnchor[:]), strconv.FormatUint(f.heights[0], 10)}
		if !reflect.DeepEqual(cs.Fields, wantFields) {
			t.Fatalf("fields %v, want %v", cs.Fields, wantFields)
		}
	})

	t.Run("a range the Directory does not serve is certify_range_unavailable", func(t *testing.T) {
		f := newFakeDirectory(t, sp.RootChainAnchor[:], recs)
		f.noRange = true
		_, _, _, err := build(t, f)
		var cs *proofv2.CertifyState
		if !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyRangeUnavailable {
			t.Fatalf("got %v, want certify_range_unavailable", err)
		}
		if want := []string{strconv.FormatUint(sp.LastMinorBlock, 10), "300"}; !reflect.DeepEqual(cs.Fields, want) {
			t.Fatalf("fields %v, want %v", cs.Fields, want)
		}
	})

	t.Run("evidence 2.0 keeps every run, continuous", func(t *testing.T) {
		f := newFakeDirectory(t, sp.RootChainAnchor[:], recs)
		srv := httptest.NewServer(f)
		defer srv.Close()
		b := &proofv2.Builder{C: jsonrpc.NewClient(srv.URL)}
		_, runs, links, err := b.CertifyRuns(context.Background(), sp.Clone(), 300, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(runs) != 4 || len(links) != 0 || len(f.queried) != 0 {
			t.Fatalf("%d runs, %d links, %d link queries; 2.0 keeps all four runs and asks for no link", len(runs), len(links), len(f.queried))
		}
	})
}

func reportJSON(t *testing.T, r *proofv2.Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// synthLinks serves the links of the synthetic chains of a world from their continuous records: a link from a root to the root at a height
// is the run of single elements between them. Both sequences (certify and the set check's hops) start at the same checkpoint root.
type synthLinks struct {
	start []byte
	seqs  [][]*api.MinorRootRecord
}

func (s synthLinks) Link(_ context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	for _, seq := range s.seqs {
		roots := [][]byte{s.start}
		var heights []uint64
		for _, r := range seq {
			body := r.Anchor.Message.(*messaging.TransactionMessage).Transaction.Body.(*protocol.DirectoryAnchor)
			roots = append(roots, body.RootChainAnchor[:])
			heights = append(heights, body.RootChainIndex)
		}
		from, to := -1, -1
		for i, root := range roots {
			if string(root) == string(prev[:]) {
				from = i
			}
		}
		for i, h := range heights {
			if h == height {
				to = i + 1
			}
		}
		if from < 0 || to <= from {
			continue
		}
		link := &merkle.Receipt{Start: prev[:], Anchor: roots[to]}
		for k := from; k < to; k++ {
			link.Entries = append(link.Entries, &merkle.ReceiptEntry{Right: true, Hash: seq[k].RootProof.Elements[0]})
		}
		return link, nil
	}
	return nil, fmt.Errorf("no link from %x at height %d", prev, height)
}

// AnchorEvidence selects by effect, not by the updates member (V-F routing note): a run that carries only an oracle write, which the walk
// does not apply, is dropped like a run without updates, and the set check's hops are anchored by the same rule, their links following the
// certify links in the document.
func TestAnchorEvidenceSelectsAppliedUpdatesAndAnchorsTheHops(t *testing.T) {
	world := buildChain(t, &xworld.Chain{
		Items: []xworld.ChainItem{orc(false), eff(false)}, Final: xworld.ChainItem{},
		Hops: []xworld.ChainItem{eff(false), plain()}})
	sp, certRecs, _ := spineAt1(t, world)
	want, err := proofv2.Verify21FromGenesis(world.Evidence, world.Archive, world.Inputs, world.Pin)
	if err != nil {
		t.Fatal(err)
	}
	src := synthLinks{start: sp.RootChainAnchor[:], seqs: [][]*api.MinorRootRecord{certRecs, decodeRuns(t, world.Evidence.Check.Hops)}}
	anchored, err := proofv2.AnchorEvidence(context.Background(), world.Evidence, world.Archive, world.Inputs, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(world.Evidence.Certify) != 3 || len(anchored.Certify) != 2 || len(world.Evidence.Check.Hops) != 2 || len(anchored.Check.Hops) != 2 || len(anchored.Links) != 4 {
		t.Fatalf("certify %d -> %d (want 3 -> 2: the oracle-only run is dropped), hops %d -> %d (want 2 -> 2), %d links (want 4)",
			len(world.Evidence.Certify), len(anchored.Certify), len(world.Evidence.Check.Hops), len(anchored.Check.Hops), len(anchored.Links))
	}
	got, err := proofv2.Verify21FromGenesis(anchored, world.Archive, world.Inputs, world.Pin)
	if err != nil {
		t.Fatalf("the anchored document does not verify: %v", err)
	}
	if reportJSON(t, got) != reportJSON(t, want) {
		t.Fatalf("the reports differ:\n%+v\n%+v", got, want)
	}
	// the continuous input is not changed, and an anchored document is refused as input
	if len(world.Evidence.Links) != 0 || len(world.Evidence.Certify) != 3 {
		t.Fatal("AnchorEvidence changed its input")
	}
	if _, err := proofv2.AnchorEvidence(context.Background(), anchored, world.Archive, world.Inputs, src); err == nil {
		t.Fatal("an already anchored document was anchored again")
	}
}
