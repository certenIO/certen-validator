// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// callsOf returns, for every function of the package's non-test sources, the names of the calls it makes to the given functions (a selector's
// last element, or a plain name).
func callsOf(t *testing.T, dirs []string, names ...string) map[string][]string {
	t.Helper()
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string][]string{}
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range af.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				owner := filepath.Base(f) + ":" + fd.Name.Name
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						switch fn := c.Fun.(type) {
						case *ast.SelectorExpr:
							if want[fn.Sel.Name] {
								out[owner] = append(out[owner], fn.Sel.Name)
							}
						case *ast.Ident:
							if want[fn.Name] {
								out[owner] = append(out[owner], fn.Name)
							}
						}
					}
					return true
				})
			}
		}
	}
	return out
}

// Neither LoadBatches (every batch row of the table) nor the reference locate (every batch of the leg's window decoded) is reachable from a
// production build when the index is on: the only call sites in the packages of the validator binary are in the else branch of
// `if b.Index != nil` in BuildFor, the operator switch CERTEN_FINALITY_ARB_INDEX=off.
func TestRB12ArbReferenceReaderIsReachableOnlyThroughTheOffSwitch(t *testing.T) {
	calls := callsOf(t, []string{".", "capture"}, "LoadBatches", "locate")
	for owner, names := range calls {
		if owner != "builder.go:BuildFor" {
			t.Errorf("%s calls %v: the reference reader must be reachable only from BuildFor's off branch", owner, names)
		}
	}
	if len(calls["builder.go:BuildFor"]) != 2 {
		t.Fatalf("BuildFor calls %v, want LoadBatches and locate exactly once each", calls["builder.go:BuildFor"])
	}
	// both calls sit in the else branch of `if b.Index != nil`
	af, err := parser.ParseFile(token.NewFileSet(), "builder.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var inElse, outside int
	for _, d := range af.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "BuildFor" {
			continue
		}
		count := func(n ast.Node) int {
			k := 0
			ast.Inspect(n, func(x ast.Node) bool {
				if c, ok := x.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && (s.Sel.Name == "LoadBatches" || s.Sel.Name == "locate") {
						k++
					}
				}
				return true
			})
			return k
		}
		total := count(fd.Body)
		for _, st := range fd.Body.List {
			if is, ok := st.(*ast.IfStmt); ok {
				if be, ok := is.Cond.(*ast.BinaryExpr); ok && be.Op == token.NEQ {
					if sel, ok := be.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Index" {
						if is.Else != nil {
							inElse = count(is.Else)
						}
						if count(is.Body) != 0 {
							t.Error("the index branch calls the reference reader")
						}
					}
				}
			}
		}
		outside = total - inElse
	}
	if inElse != 2 || outside != 0 {
		t.Fatalf("%d calls in the else branch of `if b.Index != nil`, %d elsewhere in BuildFor", inElse, outside)
	}
}

// readCounter counts the blob rows and the full-table batch listings a build performs.
type readCounter struct {
	finality.CaptureStore
	blobGets, wholeBatchLists atomic.Int64
}

func (c *readCounter) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if strings.HasPrefix(k.Item, "blob/") {
		c.blobGets.Add(1)
	}
	return c.CaptureStore.Get(ctx, k)
}

func (c *readCounter) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	if strings.HasPrefix(prefix, "batch") && from == 0 && to == finality.MaxCaptureBlock {
		c.wholeBatchLists.Add(1)
	}
	return c.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

// What the indexed reader reads for a leg: no blob row at all for a leg no batch holds (the reference decodes every batch of the window), and the
// blobs of the one batch it locates for a leg that is found; and it never lists the batch rows of the whole table.
func TestRB12ArbIndexedLookupReadsOnlyTheBlobsOfTheBatchItLocates(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	rc := &readCounter{CaptureStore: w.store}
	r, err := NewIndexReader(rc, w.pins, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{Store: rc, Pins: w.pins, Index: r}
	locate := func(ts uint64, txs [][]byte) {
		t.Helper()
		if _, _, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(txs), w.arb); err != nil {
			t.Fatal(err)
		}
	}
	locate(ixT0+300, legs["absent"])
	if n := rc.blobGets.Load(); n != 0 {
		t.Errorf("a leg no batch holds read %d blob rows", n)
	}
	locate(ixT0+300, legs["d1"])
	nBlobs := int64(len(w.recs[w.keys[203][0]].VersionedHashes))
	if n := rc.blobGets.Load(); n != nBlobs {
		t.Errorf("a leg in batch 203 read %d blob rows, the batch has %d", n, nBlobs)
	}
	if n := rc.wholeBatchLists.Load(); n != 0 {
		t.Errorf("the indexed lookup listed the batch rows of the whole table %d times", n)
	}
	// the reference, on the same store, lists the whole table and reads the blobs of every candidate
	rc.blobGets.Store(0)
	bb := &Builder{Store: rc, Pins: w.pins}
	batches, _ := capture.LoadBatches(context.Background(), rc, ixChain)
	if _, err := bb.locate(context.Background(), batches, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 300}, legs["absent"], w.arb); err != nil {
		t.Fatal(err)
	}
	if rc.blobGets.Load() < 10 || rc.wholeBatchLists.Load() != 1 {
		t.Errorf("the reference read %d blob rows and listed the table %d times: the comparison is vacuous", rc.blobGets.Load(), rc.wholeBatchLists.Load())
	}
}

// While the index is still catching up (the first backfill), an ask for a leg that no indexed batch holds reads no blob row at all - not those of
// the many batches that have no entry yet - and says so: the pending carries the positions the index is at.
func TestRB12ArbIndexMissDuringBackfillReadsNoBlobRowsAndSaysTheIndexIsBehind(t *testing.T) {
	w, legs := ixPopulation(t)
	w.cursor(w.low - 1)
	w.cursor(w.top + 1)
	ix := w.indexer(IndexConfig{BlocksPerStep: 3})
	if rep, err := ix.Step(context.Background(), w.top+1); err != nil || rep.StoppedByCap != "blocks" {
		t.Fatalf("the first step did not stop at its block bound: %+v %v", rep, err)
	}
	rc := &readCounter{CaptureStore: w.store}
	r, err := NewIndexReader(rc, w.pins, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{Store: rc, Pins: w.pins, Index: r}
	loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 300}, standardTxs(legs["absent"]), w.arb)
	if err != nil || loc != nil || pend == nil || pend.Judged["index_behind"] != true {
		t.Fatalf("loc=%v pend=%v err=%v", loc, pend, err)
	}
	if n := rc.blobGets.Load(); n != 0 {
		t.Fatalf("a miss during the backfill read %d blob rows of batches that have no entry yet", n)
	}
}
