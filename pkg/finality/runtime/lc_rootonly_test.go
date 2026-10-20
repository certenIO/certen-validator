// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// The recorded evidence of finality_eth_sepolia2 (real Lodestar objects of 2026-10-20) is the world the fake Lodestar replays: the
// EMBEDDED pins hold the root pin 1378 only, so the source must anchor at its block root and carry every period's best update.
const rootOnlySet = "../ethsepolia/testdata/finality_eth_sepolia2"

type rootOnlyWorld struct {
	final []byte
	links map[uint64][]byte
}

func loadRootOnlyWorld(t testing.TB) rootOnlyWorld {
	t.Helper()
	ev, err := os.ReadFile(filepath.Join(rootOnlySet, "raw", "gloas_latest", "evidence.bin"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := ethsepolia.DecodeBody(c.Body, finality.DefaultLimits(), 64, 16384)
	if err != nil {
		t.Fatal(err)
	}
	w := rootOnlyWorld{final: body.LC.FinalUpdate.SSZ, links: map[uint64][]byte{}}
	ents, err := os.ReadDir(filepath.Join(rootOnlySet, "raw", "links"))
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range ents {
		p, _ := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		if w.links[p], err = os.ReadFile(filepath.Join(rootOnlySet, "raw", "links", en.Name())); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// serve replays the world; paths receives every request path.
func (w rootOnlyWorld) serve(paths *[]string, mu *sync.Mutex) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*paths = append(*paths, r.URL.RequestURI())
		mu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "/light_client/bootstrap/"):
			rw.Write(w.links[1378])
		case strings.HasSuffix(r.URL.Path, "/light_client/finality_update"):
			rw.Write(w.final)
		case strings.HasSuffix(r.URL.Path, "/light_client/updates"):
			start, _ := strconv.ParseUint(r.URL.Query().Get("start_period"), 10, 64)
			count, _ := strconv.Atoi(r.URL.Query().Get("count"))
			var out bytes.Buffer
			for i := 0; i < count; i++ {
				u, ok := w.links[start+uint64(i)+1]
				if !ok {
					http.Error(rw, "no update", http.StatusNotFound)
					return
				}
				var n [8]byte
				binary.LittleEndian.PutUint64(n[:], uint64(len(u)+4))
				out.Write(n[:])
				out.Write([]byte{0, 0, 0, 0})
				out.Write(u)
			}
			rw.Write(out.Bytes())
		default:
			http.NotFound(rw, r)
		}
	}))
}

// Under the root-only embedded ledger the source anchors at the root pin (a kind-2 anchor: the bootstrap of the pinned checkpoint)
// and assembles the 13 links from period 1378 to the signature period; ethl1 accepts the result under the same pins.
func TestTheLCSourceWorksWithTheRootOnlyEmbeddedLedger(t *testing.T) {
	w := loadRootOnlyWorld(t)
	var paths []string
	var mu sync.Mutex
	srv := w.serve(&paths, &mu)
	defer srv.Close()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := (&LC{URLs: []string{srv.URL}, Pins: pins}).LC(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lc.AnchorKind != 2 || lc.AnchorPeriod != 1378 || len(lc.Links) != 13 {
		t.Fatalf("anchor kind %d period %d links %d", lc.AnchorKind, lc.AnchorPeriod, len(lc.Links))
	}
	e, _ := pins.Sepolia()
	h, err := ethl1.VerifyFinalizedHead(e.L1Pins(e.Anchors), lc)
	if err != nil {
		t.Fatalf("the source's evidence is refused under the embedded pins: %v", err)
	}
	if h.PeriodsCrossed != 13 {
		t.Fatalf("periods crossed %d", h.PeriodsCrossed)
	}
}

// When the final update lies more than max_links periods past the anchor the source asks for none of the links and returns the named
// ledger-incomplete pending with the exact periods; the next endpoint is not tried (it would say the same).
func TestTheLCSourceRefusesBeyondMaxLinksWithTheNamedPendingAndRequestsNoLink(t *testing.T) {
	w := loadRootOnlyWorld(t)
	var p1, p2 []string
	var mu sync.Mutex
	a, b := w.serve(&p1, &mu), w.serve(&p2, &mu)
	defer a.Close()
	defer b.Close()
	raw := bytes.Replace(finality.EmbeddedPinsBytes(), []byte(`"max_links": 64`), []byte(`"max_links": 12`), 1)
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&LC{URLs: []string{a.URL, b.URL}, Pins: pins}).LC(context.Background())
	n, ok := finality.AsNamed(err)
	if !ok || n.Code != finality.CodePending || n.Fields["reason"] != ethsepolia.PendingLedgerIncomplete {
		t.Fatalf("got %v", err)
	}
	for k, want := range map[string]any{"needed_period": uint64(1391), "anchor_period": uint64(1378), "links_needed": uint64(13), "max_links": uint64(12), "missing_period": uint64(1391)} {
		if n.Fields[k] != want {
			t.Errorf("%s = %v, want %v", k, n.Fields[k], want)
		}
	}
	for _, p := range p1 {
		if strings.Contains(p, "/updates") {
			t.Errorf("a link was requested beyond the bound: %s", p)
		}
	}
	if len(p2) != 0 {
		t.Errorf("the second endpoint was asked after a ledger-incomplete answer: %v", p2)
	}
	var le *LedgerIncompleteError
	if !asLedgerIncomplete(err, &le) || le.Pending.Reason != ethsepolia.PendingLedgerIncomplete {
		t.Errorf("the error is not a LedgerIncompleteError: %T", err)
	}
	_ = fmt.Sprint
}

func asLedgerIncomplete(err error, target **LedgerIncompleteError) bool {
	le, ok := err.(*LedgerIncompleteError)
	if ok {
		*target = le
	}
	return ok
}
