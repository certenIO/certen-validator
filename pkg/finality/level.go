// Copyright 2026 Certen Protocol

// Package finality is the framework of PROOF_V2 S7: a settlement on a target chain is proven to staged levels, each
// level carrying its own evidence, and a proof is upgraded append-only as stronger evidence becomes buildable
// (docs/proof/PROOF_V2.md section 7; domain tag certen:finality:v1).
//
// What the package fixes, and what it leaves to the chain packages:
//
//   - Level orders the levels (included < l1_posted < finalized) and, beside it, the two typed non-levels a chain can
//     answer with instead: NotApplicable (the chain has no such level, with the reason) and Pending (the level reached
//     and the next one, with an ETA and the reason). Neither is ever reported as a level.
//   - Evidence is the CFE1 container (codec.go) one prover builds and one Kind verifies; its header names the leg
//     (chain, block number, block hash) it is about.
//   - A Prover (online, may use RPC) builds an addendum; Verify (pure, offline) dispatches on a registry of per-chain,
//     per-level Kinds that each chain package registers. Verify reports exactly the level its Kind proved and nothing more;
//     an unknown kind, an unsupported chain or a level the chain does not offer is a named state, never a weaker or
//     different answer.
//   - An Addendum is one append-only, hash-linked record of a level reached (l1_posted or finalized; included is derived and
//     never stored); VerifyChain checks a leg's whole chain of them against the leg binding D0, a pure function of the leg's
//     verified Settlement block (V2_SPEC_S7 section 2.6). The original proof's bytes are never touched.
//
// Nothing in this package feeds an attestation message, an outcome root or a govRoot input (docs: RB11-B PR text).
package finality

import "fmt"

// Level is a proven finality level. The zero value means nothing is proven and is never stored or reported as a level.
type Level uint8

const (
	// LevelNone is the absence of any proven level.
	LevelNone Level = 0
	// LevelIncluded: the settlement transaction and receipt are in a block whose header is in the proof (today's L6).
	LevelIncluded Level = 1
	// LevelL1Posted: the block's data is posted to the chain's L1 (Base Sepolia, Arbitrum Sepolia).
	LevelL1Posted Level = 2
	// LevelFinalized: the block is final under the chain's own consensus or rollup L1 contracts.
	LevelFinalized Level = 3
)

// Levels are the real levels in ascending order.
var Levels = []Level{LevelIncluded, LevelL1Posted, LevelFinalized}

// String is the level's published name; the zero value is "none".
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelIncluded:
		return "included"
	case LevelL1Posted:
		return "l1_posted"
	case LevelFinalized:
		return "finalized"
	}
	return fmt.Sprintf("invalid(%d)", uint8(l))
}

// Valid reports whether l is one of the three real levels.
func (l Level) Valid() bool { return l >= LevelIncluded && l <= LevelFinalized }

// Stored reports whether an addendum can carry l: only l1_posted (2) and finalized (3). Level 1 (included) is derived from
// the original proof's Settlement and is never stored, carried or hashed (V2_SPEC_S7 R1, section 2.1).
func (l Level) Stored() bool { return l == LevelL1Posted || l == LevelFinalized }

// LevelSet is a set of levels (the levels already present for a leg, in any order, R1).
type LevelSet uint8

// Has reports whether l is in the set.
func (s LevelSet) Has(l Level) bool { return l.Valid() && s&(1<<l) != 0 }

// With returns the set with l added.
func (s LevelSet) With(l Level) LevelSet {
	if !l.Valid() {
		return s
	}
	return s | 1<<l
}

// LevelSetOf builds a set.
func LevelSetOf(levels ...Level) LevelSet {
	var s LevelSet
	for _, l := range levels {
		s = s.With(l)
	}
	return s
}

// ParseStoredLevel is ParseLevel restricted to the levels an addendum carries (l1_posted, finalized).
func ParseStoredLevel(s string) (Level, error) {
	l, err := ParseLevel(s)
	if err != nil {
		return LevelNone, err
	}
	if !l.Stored() {
		return LevelNone, fmt.Errorf("level %q is derived and never stored (stored levels: l1_posted, finalized)", s)
	}
	return l, nil
}

// ParseLevel is the inverse of String for the three real levels.
func ParseLevel(s string) (Level, error) {
	for _, l := range Levels {
		if l.String() == s {
			return l, nil
		}
	}
	return LevelNone, fmt.Errorf("%q is not a finality level (included, l1_posted, finalized)", s)
}
