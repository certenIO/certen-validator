// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr/isolationtest"
)

// RB12-LEGACY-191: the leg source serves the 191 legacy legs (stored execution proof without block_header_rlp) from the header
// pkg/finality/legacyhdr reconstructed and kept in the capture store, judges that row like any other evidence, and lists the legs the
// reconstruction has to serve. The component is the production legacy shape (finalitytest.ProductionLegacyExecutionProof: the live
// key set), the blocks are real captured blocks of the three chains.

type legacyFix struct {
	leg    leg
	comp   map[string]any
	parsed legacyhdr.Leg
	header []byte
}

// newLegacyLeg stores the proof row and its legacy bundle of a real settled leg.
func newLegacyLeg(t *testing.T, fixture string, mutate func(comp map[string]any)) legacyFix {
	t.Helper()
	l := newLeg(t, fixture)
	comp := finalitytest.ProductionLegacyExecutionProof(t, l.s)
	if mutate != nil {
		mutate(comp)
	}
	storeBundleAt(t, l.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(l.id, comp)), time.Now())
	raw, err := json.Marshal(comp)
	if err != nil {
		t.Fatal(err)
	}
	parsed, perr := legacyhdr.ParseLeg(l.id, "", raw)
	if perr != nil && mutate == nil {
		t.Fatal(perr)
	}
	return legacyFix{leg: l, comp: comp, parsed: parsed, header: append([]byte(nil), l.s.Included.Header...)}
}

func (f legacyFix) ref(t *testing.T, repo *FinalityAddendaRepository) finality.LegRef {
	t.Helper()
	ref, ok := listed(t, repo)[f.leg.id]
	if !ok {
		t.Fatalf("the legacy leg %s is not listed", f.leg.id)
	}
	return ref
}

func captureStore() *FinalityCaptureStore { return NewFinalityCaptureStore(NewClientFromDB(testDB)) }

var legacyFixtures = []struct{ name, fixture string }{
	{"base-sepolia", "base_sepolia_47368146"},
	{"ethereum-sepolia", "sepolia_11792612"},
	{"arbitrum-sepolia", "arbitrum_sepolia_315455204"},
}

func TestFinalityLegSourceServesALegacyLegFromItsReconstructedHeaderAsTheNewShapePathBuildsIt(t *testing.T) {
	ctx := context.Background()
	for _, c := range legacyFixtures {
		t.Run(c.name, func(t *testing.T) {
			store := finality.NewMemCaptureStore()
			repo := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(store)
			f := newLegacyLeg(t, c.fixture, nil)
			ref := f.ref(t, repo)

			// no row yet: the named state, judged at the chain and block the bundle names
			for what, err := range map[string]error{"LegSettlement": errOf(repo.LegSettlement(ctx, ref)), "LegRef": errOf(repo.LegRef(ctx, f.leg.id))} {
				n, ok := finality.AsNamed(err)
				if !ok || n.Code != finality.CodeIncludedUnavailable || n.Fields["reason"] != finality.IncludedNoBlockHeader ||
					n.Fields["chain"] != f.parsed.Chain || n.Fields["block"] != f.parsed.BlockNumber || n.Fields["proof_id"] != f.leg.id {
					t.Fatalf("%s without a row: %v", what, err)
				}
			}

			if err := store.Put(ctx, f.parsed.Key(), f.header); err != nil {
				t.Fatal(err)
			}
			got, err := repo.LegSettlement(ctx, ref)
			if err != nil {
				t.Fatalf("LegSettlement with the reconstructed header: %v", err)
			}
			if got.Chain != f.leg.s.Chain || got.Subject != f.leg.s.Subject || got.Unrecorded {
				t.Fatalf("settlement %+v, want chain %d subject %+v recorded", got, f.leg.s.Chain, f.leg.s.Subject)
			}
			// exactly the value the new-shape path holds for this block
			want, _ := json.Marshal(f.leg.s.Included)
			have, _ := json.Marshal(got.Included)
			if !bytes.Equal(want, have) {
				t.Fatal("the Settlement built from the legacy component and its reconstructed header is not the new-shape Settlement")
			}
			if _, _, err := got.Included.Verify(); err != nil {
				t.Fatal(err)
			}
			if r, err := repo.LegRef(ctx, f.leg.id); err != nil || r.Chain != f.parsed.Chain {
				t.Fatalf("LegRef = %+v %v", r, err)
			}
			// reads are repeatable and the row is not consumed
			if _, err := repo.LegSettlement(ctx, ref); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The production store: the row the loop writes into proof_finality_capture (migration 00028, insert-only) is the row the leg source
// reads. The key is the hash of the bytes, so a repeat is a no-op however often it runs (and on every validator).
func TestFinalityLegSourceReadsTheHeaderRowFromTheDatabaseCaptureStore(t *testing.T) {
	ctx := context.Background()
	store := captureStore()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(store)
	f := newLegacyLeg(t, "sepolia_11792612", nil)
	for i := 0; i < 2; i++ {
		if err := store.Put(ctx, f.parsed.Key(), f.header); err != nil {
			t.Fatalf("put %d: %v", i+1, err)
		}
	}
	if err := store.Put(ctx, f.parsed.Key(), append(append([]byte(nil), f.header...), 0)); err == nil {
		t.Fatal("other bytes under a stored header key were accepted")
	}
	got, err := repo.LegSettlement(ctx, f.ref(t, repo))
	if err != nil || !bytes.Equal(got.Included.Header, f.header) || got.Chain != 11155111 {
		t.Fatalf("settlement from the database row: %+v %v", got.Subject, err)
	}
}

func TestFinalityLegSourceWithoutAHeaderStoreKeepsTheOldNamedState(t *testing.T) {
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	f := newLegacyLeg(t, "base_sepolia_47368146", nil)
	err := errOf(repo.LegSettlement(context.Background(), f.ref(t, repo)))
	wantState(t, "LegSettlement", err, finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoBlockHeader))
	if n, _ := finality.AsNamed(err); n.Fields["block"] != nil || n.Fields["chain"] != nil {
		t.Fatalf("a repository without a header store reads the component further: %v", n)
	}
}

// The row is the store's, not evidence: a foreign, empty or inconsistent row never becomes a Settlement.
func TestFinalityLegSourceNeverTrustsAReconstructedHeaderRow(t *testing.T) {
	ctx := context.Background()
	other := newLeg(t, "arbitrum_sepolia_315455204")
	cases := []struct {
		name   string
		row    func(f legacyFix) []byte
		bundle func(comp map[string]any)
		check  string
	}{
		{"another block's header", func(f legacyFix) []byte { return other.s.Included.Header }, nil, legacyhdr.CheckHeaderHash},
		{"an empty row", func(f legacyFix) []byte { return []byte{} }, nil, legacyhdr.CheckHeaderSize},
		{"a flipped byte", func(f legacyFix) []byte {
			h := append([]byte(nil), f.header...)
			h[len(h)-1] ^= 1
			return h
		}, nil, legacyhdr.CheckHeaderHash},
		{"the right header but a stored receipts_root the block does not have", func(f legacyFix) []byte { return f.header },
			func(comp map[string]any) {
				r := comp["receipts_root"].(string)
				comp["receipts_root"] = r[:len(r)-1] + map[bool]string{true: "1", false: "0"}[strings.HasSuffix(r, "0")]
			}, legacyhdr.CheckStoredRoots},
		{"the right header but a stored block number the block does not have", func(f legacyFix) []byte { return f.header },
			func(comp map[string]any) { comp["block_number"] = comp["block_number"].(uint64) + 1 }, legacyhdr.CheckBlockNumber},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := finality.NewMemCaptureStore() // insert-only: every case needs a key of its own
			repo := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(store)
			f := newLegacyLeg(t, "base_sepolia_47368146", c.bundle)
			// the key is the one the (possibly altered) component names
			raw, _ := json.Marshal(f.comp)
			leg, err := legacyhdr.ParseLeg(f.leg.id, "", raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, leg.Key(), c.row(f)); err != nil {
				t.Fatal(err)
			}
			err = errOf(repo.LegSettlement(ctx, f.ref(t, repo)))
			n, ok := finality.AsNamed(err)
			if !ok || n.Code != finality.CodeIncludedInvalid || n.Fields["check"] != c.check || n.Fields["proof_id"] != f.leg.id {
				t.Fatalf("want finality_included_invalid{check=%s}, got %v", c.check, err)
			}
		})
	}
}

// A bundle that carries its header never consults the store, however the store is filled.
func TestFinalityLegSourceIgnoresTheHeaderStoreForABundleThatHasItsHeader(t *testing.T) {
	ctx := context.Background()
	store := finality.NewMemCaptureStore()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(store)
	l := newLeg(t, "base_sepolia_47368146")
	storeProductionBundle(t, l.id, l)
	raw, _ := json.Marshal(l.exec)
	parsed, err := legacyhdr.ParseLeg(l.id, "", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, parsed.Key(), []byte("not a header")); err != nil {
		t.Fatal(err)
	}
	ref := listed(t, repo)[l.id]
	got, err := repo.LegSettlement(ctx, ref)
	if err != nil || !bytes.Equal(got.Included.Header, l.s.Included.Header) {
		t.Fatalf("a bundle with its header was judged by the store: %v", err)
	}
}

// With a header store, a legacy component that cannot be read as a leg is named invalid (it can never be reconstructed); without
// one it keeps the quiet state it always had.
func TestFinalityLegSourceNamesALegacyComponentItCannotReadAsALeg(t *testing.T) {
	ctx := context.Background()
	withStore := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(finality.NewMemCaptureStore())
	plain := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	f := newLegacyLeg(t, "base_sepolia_47368146", func(comp map[string]any) { delete(comp, "block_hash") })
	err := errOf(withStore.LegSettlement(ctx, f.ref(t, withStore)))
	n, ok := finality.AsNamed(err)
	if !ok || n.Code != finality.CodeIncludedInvalid || !strings.Contains(fmt.Sprint(n.Fields["cause"]), "block_hash") {
		t.Fatalf("with a store: %v", err)
	}
	wantState(t, "without a store", errOf(plain.LegSettlement(ctx, f.ref(t, plain))), finality.CodeIncludedUnavailable, "reason", string(finality.IncludedNoBlockHeader))
}

func TestFinalityLegacyLegsListsOnlyTheLegacyLegsOfTheChain(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityAddendaRepository(NewClientFromDB(testDB)).WithLegacyHeaders(captureStore())
	baseLegacy := newLegacyLeg(t, "base_sepolia_47368146", nil)
	arbLegacy := newLegacyLeg(t, "arbitrum_sepolia_315455204", nil)
	broken := newLegacyLeg(t, "base_sepolia_47368146", func(comp map[string]any) { comp["tx_hash"] = "0x12" })
	withHeader := newLeg(t, "base_sepolia_47368146")
	storeProductionBundle(t, withHeader.id, withHeader)
	noComponent := newLeg(t, "base_sepolia_47368146")
	storeBundleAt(t, noComponent.id, finalitytest.Gzip(finalitytest.ProductionBundleJSON(noComponent.id, nil)), time.Now())

	collect := func(chain uint64, limit int) map[string]legacyhdr.Candidate {
		out := map[string]legacyhdr.Candidate{}
		after, pages := "", 0
		for {
			cands, next, err := repo.LegacyLegs(ctx, chain, after, limit)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cands {
				if _, dup := out[c.Leg.ProofID]; dup {
					t.Fatalf("%s listed twice", c.Leg.ProofID)
				}
				out[c.Leg.ProofID] = c
			}
			if pages++; pages > 10000 {
				t.Fatal("the cursor never ended")
			}
			if next == "" {
				return out
			}
			after = next
		}
	}
	for _, limit := range []int{1, 2, 7, 200} {
		base := collect(84532, limit)
		a, ok := base[baseLegacy.leg.id]
		if !ok || a.Err != nil || a.Leg.Chain != 84532 || a.Leg.BlockNumber != baseLegacy.parsed.BlockNumber || a.Leg.BlockHash != baseLegacy.parsed.BlockHash ||
			a.Leg.BundleID == "" || a.Leg.Tx == nil || a.Leg.Receipt == nil {
			t.Fatalf("limit %d: the base legacy leg is %+v ok %v", limit, a, ok)
		}
		if b, ok := base[broken.leg.id]; !ok || b.Err == nil {
			t.Fatalf("limit %d: an unreadable legacy component is not listed with its named state: %+v", limit, b)
		} else if n, named := finality.AsNamed(b.Err); !named || n.Code != finality.CodeIncludedInvalid || b.Leg.ProofID != broken.leg.id {
			t.Fatalf("limit %d: unreadable component state = %v", limit, b.Err)
		}
		for what, id := range map[string]string{"a leg on another chain": arbLegacy.leg.id, "a bundle with its header": withHeader.id, "a bundle without an execution proof": noComponent.id} {
			if _, listed := base[id]; listed {
				t.Fatalf("limit %d: %s is listed as a legacy leg of Base Sepolia", limit, what)
			}
		}
		arb := collect(421614, limit)
		if _, ok := arb[arbLegacy.leg.id]; !ok {
			t.Fatalf("limit %d: the Arbitrum legacy leg is not listed", limit)
		}
		if _, ok := arb[baseLegacy.leg.id]; ok {
			t.Fatalf("limit %d: a Base leg is listed for Arbitrum", limit)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := repo.LegacyLegs(cancelled, 84532, "", 10); err == nil {
		t.Fatal("a cancelled context listed legs")
	}
}

// The same isolation proof against the production store (PostgreSQL): legacy rows beside production rows on chains of their own
// (so the expectations are exact in a database the other tests share).
func TestLegacyRowsDoNotChangeWhatAnyProductionReaderSeesInTheDatabase(t *testing.T) {
	isolationtest.Check(t, captureStore(), isolationtest.Chains{L2A: 900000084, L2B: 900000421, L1: 900011155})
}
