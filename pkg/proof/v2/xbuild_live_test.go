// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// The builder's anchored form on REAL data (RB9-F5 package F5-2). testdata/certify1-live/links.json holds the answers Kermit's served query
// (query acc://dn.acme/anchors {chain, name "anchor(directory)-root", entry <previous root>, includeReceipt {forHeight <RootChainIndex>}}) gave
// to cmd/proofv2linkprobe, with the question each answers; MANIFEST.sha256 pins the file. The tests replay it: no network.

const liveLinksDir = "testdata/certify1-live/"

type liveLink struct {
	Label       string `json:"label"`
	Prev        string `json:"prev"`
	Height      uint64 `json:"height"`
	Receipt     string `json:"receipt"`
	NotAnchored string `json:"notAnchored"`
}

type liveLinks struct {
	Endpoint string     `json:"endpoint"`
	Fixture  string     `json:"fixture"`
	Links    []liveLink `json:"links"`
}

func loadLiveLinks(t *testing.T) *liveLinks {
	t.Helper()
	raw, err := os.ReadFile(liveLinksDir + "links.json")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(liveLinksDir + "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); !strings.HasPrefix(strings.TrimSpace(string(pin)), got) {
		t.Fatalf("links.json hashes to %s, the manifest pins %s", got, strings.TrimSpace(string(pin)))
	}
	l := new(liveLinks)
	if err := json.Unmarshal(raw, l); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *liveLinks) find(t *testing.T, label string) (prev [32]byte, height uint64, r *merkle.Receipt) {
	t.Helper()
	for _, x := range l.Links {
		if x.Label != label {
			continue
		}
		b, err := hex.DecodeString(x.Prev)
		if err != nil || len(b) != 32 {
			t.Fatalf("%s: prev %q", label, x.Prev)
		}
		copy(prev[:], b)
		if x.Receipt == "" {
			t.Fatalf("%s: the recorded answer is a refusal: %s", label, x.NotAnchored)
		}
		r, err = decodeReceipt(x.Receipt)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return prev, x.Height, r
	}
	t.Fatalf("no recorded answer labelled %s", label)
	return
}

// replayLinks serves the recorded answers; a question that was not recorded is an error, never a guess.
type replayLinks struct{ l *liveLinks }

func (s replayLinks) Link(_ context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	p := hex.EncodeToString(prev[:])
	for _, x := range s.l.Links {
		if x.Prev == p && x.Height == height {
			if x.Receipt == "" {
				return nil, fmt.Errorf("%w: %s", ErrLinkNotAnchored, x.NotAnchored)
			}
			return decodeReceipt(x.Receipt)
		}
	}
	return nil, fmt.Errorf("no recorded answer for prev %s height %d", p, height)
}

// Kermit's recorded link responses are receipts of the question asked: each starts at the entry asked for (the genesis entry, a major
// block's closing root, the fixture's checkpoint), ends at the signed root chain anchor of the real certified anchor, validates, and is
// small; and the one asked from the checkpoint is accepted by AdvanceAnchored, on a spine walked from genesis, in place of the walk of every
// root chain entry in between.
func TestLinkMatchesLiveKermit(t *testing.T) {
	l := loadLiveLinks(t)
	r := loadReal21(t)
	if len(r.ev.Certify) != 1 {
		t.Fatalf("the fixture certifies in %d runs; this test expects the checkpoint to be one run before the certified anchor", len(r.ev.Certify))
	}
	height, root, err := RunAnchor(r.ev.Certify[0])
	if err != nil {
		t.Fatal(err)
	}
	asked := map[string][32]byte{"genesis": r.in.GenesisRootChainAnchor}
	for _, m := range []uint64{2, 250} {
		c, err := MajorRootChainAnchor(r.ar, m)
		if err != nil {
			t.Fatal(err)
		}
		asked[fmt.Sprintf("major-%d", m)] = c
	}
	for label, want := range asked {
		prev, h, link := l.find(t, label)
		if prev != want {
			t.Fatalf("%s: asked for %x, want %x", label, prev, want)
		}
		if h != height {
			t.Fatalf("%s: asked at height %d, the certified anchor's RootChainIndex is %d", label, h, height)
		}
		if !bytesEq(link.Start, want[:]) || !bytesEq(link.Anchor, root[:]) {
			t.Fatalf("%s: the receipt runs %x -> %x, want %x -> %x", label, link.Start, link.Anchor, want, root)
		}
		if !stepsPresent(link) || !link.Validate(nil) {
			t.Fatalf("%s: the receipt does not validate", label)
		}
		if b, _ := link.MarshalBinary(); len(b) == 0 || len(b) > 2048 || len(link.Entries) > 40 {
			t.Fatalf("%s: a link must be O(log n): %d bytes, %d steps", label, len(b), len(link.Entries))
		}
	}

	// The link from the fixture's checkpoint, in place of the root proof, advances a verifier standing at that checkpoint.
	at, err := spinesAt(r.ar, r.in, r.ev.Majors)
	if err != nil {
		t.Fatal(err)
	}
	prev, _, link := l.find(t, "fixture")
	sp := at[r.ev.Majors]
	if prev != sp.RootChainAnchor {
		t.Fatalf("the fixture's recorded question starts at %x, the checkpoint stands at %x", prev, sp.RootChainAnchor)
	}
	mr, err := decodeMinorRoot(r.ev.Certify[0])
	if err != nil {
		t.Fatal(err)
	}
	mr.RootProof = nil
	if err := sp.AdvanceAnchored(mr, link); err != nil {
		t.Fatal(err)
	}
	if sp.RootChainAnchor != root {
		t.Fatalf("the spine stands at %x, want %x", sp.RootChainAnchor, root)
	}
}

// The anchored form of a real evidence 2.1 document, built by AnchorEvidence from Kermit's recorded answers, verifies from genesis and gives
// the very report of the continuous document, and is smaller.
func TestAnchorEvidenceLiveKermit(t *testing.T) {
	r := loadReal21(t)
	want, err := Verify21FromGenesis(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := AnchorEvidence(context.Background(), r.ev, r.ar, r.in, replayLinks{loadLiveLinks(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchored.Links) == 0 {
		t.Fatal("the anchored document carries no link")
	}
	for i, h := range anchored.Certify {
		mr, err := decodeMinorRoot(h)
		if err != nil {
			t.Fatal(err)
		}
		if mr.RootProof != nil {
			t.Fatalf("certify run %d still carries a root proof", i)
		}
	}
	got, err := Verify21FromGenesis(anchored, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	if reportJSON(t, got) != reportJSON(t, want) {
		t.Fatalf("the anchored report differs from the continuous one:\n%+v\n%+v", got, want)
	}
	cont, _ := json.Marshal(r.ev)
	anch, _ := json.Marshal(anchored)
	if len(anch) >= len(cont) {
		t.Fatalf("the anchored document (%d bytes) is not smaller than the continuous one (%d)", len(anch), len(cont))
	}
	t.Logf("continuous %d bytes, anchored %d bytes", len(cont), len(anch))
}

// V-E A9: the height the builder asks links and receipts at is the anchor's RootChainIndex. It must equal the end of the served root proof
// (MerkleState.Count + len(Elements) - 1, what the builder used before it dropped the proof) on every live record, because the receipts the
// Directory serves at a ForHeight are root chain heights. Checked on every minor-root run of the live documents of this package.
func TestRootChainIndexIsTheRootProofEndOnEveryLiveFixture(t *testing.T) {
	docs := []string{"testdata/evidence_3cfb04cf.json.gz"}
	for _, pat := range []string{"testdata/xpartition3/real-*/evidence21.json.gz", "testdata/xpartition*/*.json.gz"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, m...)
	}
	seen := map[string]bool{}
	runs, evidence := 0, 0
	for _, d := range docs {
		if seen[d] {
			continue
		}
		seen[d] = true
		ev := new(Evidence)
		if err := json.Unmarshal(gunzip(t, d), ev); err != nil || len(ev.Certify) == 0 {
			continue // not an evidence document (a conformance case, an archive, a capture)
		}
		evidence++
		all := append(append([]string{}, ev.Certify...), ev.Check.Hops...)
		for i, h := range all {
			end, err := RunRootProofEnd(h)
			if err != nil {
				t.Fatalf("%s run %d: %v", d, i, err)
			}
			idx, _, err := RunAnchor(h)
			if err != nil {
				t.Fatalf("%s run %d: %v", d, i, err)
			}
			if end != idx {
				t.Fatalf("%s run %d: the root proof ends at height %d, the anchor's RootChainIndex is %d", d, i, end, idx)
			}
			runs++
		}
	}
	if evidence < 2 || runs < 3 {
		t.Fatalf("only %d runs of %d evidence documents were checked", runs, evidence)
	}
	t.Logf("%d live minor-root runs in %d evidence documents: RootChainIndex == root proof end", runs, evidence)
}

// reportJSON is a report as its JSON encoding: the two forms of a document give the same report when the encodings are equal (pointer
// members, such as the proven pages, differ by address).
func reportJSON(t *testing.T, r *Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
