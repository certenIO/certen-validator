// Copyright 2026 Certen Protocol

package entitlement

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

// RB3-F79: building entitlement evidence used to normalise the store's shared set - replacing its leaf
// slice - on every call, while other intents read the same set, and to rehash every leaf each time.

func TestEvidenceBuildDoesNotRewriteTheSharedSet(t *testing.T) {
	p := newPublisher(t)
	doc := p.doc(t, activeLeaf("acc://b.acme/data"), activeLeaf(principal), activeLeaf("acc://a.acme/data"))
	srv := serve(t, func() ([]byte, int) { return mustJSON(t, doc), 200 })
	s := storeFor(srv.URL, p.keys)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	before := s.set.Leaves
	s.mu.RUnlock()
	if s.BuildEvidence(principal) == nil {
		t.Fatal("expected evidence")
	}
	s.mu.RLock()
	after := s.set.Leaves
	s.mu.RUnlock()
	if len(before) == 0 || len(after) != len(before) || &after[0] != &before[0] {
		t.Fatal("building evidence rewrote the set every concurrent intent reads")
	}
}

// referenceProof is the inclusion path exactly as Set.BuildProof computed it before the index,
// over already-normalised leaves.
func referenceProof(leaves []Leaf, adiURL string) ([]ProofStep, Leaf, bool) {
	idx := -1
	for i, l := range leaves {
		if SameADI(l.ADIURL, adiURL) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, Leaf{}, false
	}
	level := make([][]byte, 0, len(leaves))
	for _, l := range leaves {
		h := l.Hash()
		level = append(level, h[:])
	}
	var steps []ProofStep
	pos := idx
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				if i == pos {
					pos = len(next) - 1
				}
				continue
			}
			if i == pos {
				steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[i+1]), Right: true})
				pos = len(next)
			} else if i+1 == pos {
				steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[i]), Right: false})
				pos = len(next)
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		level = next
	}
	return steps, leaves[idx], true
}

func TestProofIndexAgreesWithTheReferencePathOnEveryLeaf(t *testing.T) {
	rng := rand.New(rand.NewSource(79))
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 33, 100, 257} {
		leaves := make([]Leaf, 0, n+2)
		for i := 0; i < n; i++ {
			leaves = append(leaves, activeLeaf(fmt.Sprintf("acc://payer%05d.acme/data", rng.Intn(1_000_000))))
		}
		// A trailing slash is the same ADI to a lookup but a distinct key to Normalize.
		leaves = append(leaves, activeLeaf("acc://slash.acme/data"), activeLeaf("acc://slash.acme/data/"))
		set := Set{Leaves: leaves}
		root := set.Root() // normalises
		x := NewProofIndex(set.Leaves)
		if x.Root() != root {
			t.Fatalf("n=%d: index root %s, set root %s", n, x.Root(), root)
		}
		probes := append([]string{"acc://absent.acme/data", "", "acc://SLASH.acme/data/"}, func() []string {
			out := make([]string, 0, len(set.Leaves))
			for _, l := range set.Leaves {
				out = append(out, l.ADIURL)
			}
			return out
		}()...)
		for _, adi := range probes {
			wantSteps, wantLeaf, wantOK := referenceProof(set.Leaves, adi)
			gotSteps, gotLeaf, gotOK := x.Proof(adi)
			if gotOK != wantOK || gotLeaf != wantLeaf || fmt.Sprint(gotSteps) != fmt.Sprint(wantSteps) {
				t.Fatalf("n=%d adi=%q: index (%v %v %v) != reference (%v %v %v)", n, adi, gotOK, gotLeaf.ADIURL, gotSteps, wantOK, wantLeaf.ADIURL, wantSteps)
			}
			if gotOK {
				if err := verifyInclusion(gotLeaf, gotSteps, root); err != nil {
					t.Fatalf("n=%d adi=%q: the index's proof does not verify: %v", n, adi, err)
				}
			}
			if l, ok := x.Lookup(adi); ok != wantOK || ok && l != wantLeaf {
				t.Fatalf("n=%d adi=%q: lookup disagrees with the proof", n, adi)
			}
		}
	}
}
