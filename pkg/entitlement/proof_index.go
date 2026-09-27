// Copyright 2026 Certen Protocol

package entitlement

import (
	"encoding/hex"
	"strings"
)

// ProofIndex is a set's Merkle tree, built once: every level's hashes and each ADI's leaf position.
//
// Set.BuildProof normalised the set - replacing its leaf slice - and rehashed every leaf on each call.
// The store called it on the set every intent shares, so each evidence build wrote to a slice other
// intents were reading, and a lookup's answer for duplicate ADIs depended on whether one had run
// (RB3-F79). The index is built from a normalised copy and only ever read.
type ProofIndex struct {
	leaves []Leaf
	pos    map[string]int
	levels [][][]byte
}

// adiKey is the form SameADI compares ADIs in. Empty matches nothing.
func adiKey(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), "/")
}

// NewProofIndex builds the index over the leaves, normalised as the set's root is (Normalize), without
// touching the caller's slice.
func NewProofIndex(leaves []Leaf) *ProofIndex {
	s := Set{Leaves: append([]Leaf(nil), leaves...)}
	s.Normalize()
	x := &ProofIndex{leaves: s.Leaves, pos: make(map[string]int, len(s.Leaves))}
	for i, l := range s.Leaves {
		// The first leaf in canonical order answers for an ADI, as a scan in that order would.
		if k := adiKey(l.ADIURL); k != "" {
			if _, seen := x.pos[k]; !seen {
				x.pos[k] = i
			}
		}
	}
	if len(s.Leaves) == 0 {
		return x
	}
	level := make([][]byte, 0, len(s.Leaves))
	for _, l := range s.Leaves {
		h := l.Hash()
		level = append(level, append([]byte(nil), h[:]...))
	}
	x.levels = append(x.levels, level)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // an odd node promotes unchanged (RFC 6962)
				continue
			}
			next = append(next, interiorHash(level[i], level[i+1]))
		}
		x.levels = append(x.levels, next)
		level = next
	}
	return x
}

// Root is the Merkle root over the leaves, as Set.Root computes it; empty for no leaves.
func (x *ProofIndex) Root() string {
	if len(x.levels) == 0 {
		return ""
	}
	return hex.EncodeToString(x.levels[len(x.levels)-1][0])
}

// Lookup returns the leaf that answers for an ADI.
func (x *ProofIndex) Lookup(adiURL string) (Leaf, bool) {
	i, ok := x.pos[adiKey(adiURL)]
	if !ok {
		return Leaf{}, false
	}
	return x.leaves[i], true
}

// Proof returns the inclusion path for an ADI, or false if absent.
func (x *ProofIndex) Proof(adiURL string) ([]ProofStep, Leaf, bool) {
	idx, ok := x.pos[adiKey(adiURL)]
	if !ok {
		return nil, Leaf{}, false
	}
	var steps []ProofStep
	pos := idx
	for lv := 0; lv < len(x.levels)-1; lv++ {
		level := x.levels[lv]
		if pos%2 == 0 {
			if pos+1 < len(level) {
				steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[pos+1]), Right: true})
			} // else promoted: no sibling at this level
		} else {
			steps = append(steps, ProofStep{Hash: hex.EncodeToString(level[pos-1]), Right: false})
		}
		pos /= 2
	}
	return steps, x.leaves[idx], true
}
