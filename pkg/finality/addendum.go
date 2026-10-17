// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Domain is the hash domain of every addendum (PROOF_V2 section 10.3: new evidence gets a new tag, never a reused one).
const Domain = "certen:finality:v1"

// Addendum is one record of the append-only chain by which a proof is upgraded. It is evidence ABOUT a proof, stored and
// served beside it: the proof's own bytes never change, and nothing here is an input of any attestation, outcome root or
// govRoot.
//
//	OwnHash = sha256( lp(Domain) || lp(originalProofDigest) || lp(PrevHash) || lp(be64(Seq)) || lp(Level) ||
//	                  lp(be64(Chain)) || lp(Kind) || lp(sha256(Evidence)) )
//
// where lp is a 4-byte big-endian length followed by the bytes, Level is its one-byte number (1 included, 2 l1_posted,
// 3 finalized) and the first addendum's PrevHash is 32 zero bytes. ProofID is the storage key (the stored proof the chain
// belongs to); it is deliberately not a hash input, because the original digest is what ties the chain to the proof.
type Addendum struct {
	ProofID  string
	Seq      uint64
	Level    Level
	Chain    uint64
	Kind     string
	Evidence []byte // the canonical encoding of an Evidence (evidence.go)
	PrevHash [32]byte
	OwnHash  [32]byte

	// OriginalDigest is the digest of the original proof this chain commits to. The store does not keep it (it is the
	// stored proof's own artifact hash); a portable document carries it beside each addendum so a verifier can recompute.
	OriginalDigest [32]byte
}

// ComputeHash is OwnHash for the given original proof digest.
func (a Addendum) ComputeHash(original [32]byte) [32]byte {
	evSum := sha256.Sum256(a.Evidence)
	var seq, chain [8]byte
	binary.BigEndian.PutUint64(seq[:], a.Seq)
	binary.BigEndian.PutUint64(chain[:], a.Chain)
	h := sha256.New()
	for _, f := range [][]byte{
		[]byte(Domain), original[:], a.PrevHash[:], seq[:], {byte(a.Level)}, chain[:], []byte(a.Kind), evSum[:],
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// NewAddendum builds the addendum that follows prev (nil for the first) for a proof whose original digest is original,
// on a chain. It refuses what VerifyChain would refuse: evidence that is not a decodable container, a level that does not
// strictly exceed prev's, or a chain that differs from prev's.
func NewAddendum(original [32]byte, proofID string, prev *Addendum, chain uint64, level Level, ev Evidence) (Addendum, error) {
	if proofID == "" {
		return Addendum{}, NewState(CodeAddendumMalformed, "field", "proofId", "reason", "empty")
	}
	if !level.Valid() {
		return Addendum{}, NewState(CodeAddendumMalformed, "field", "level", "reason", "not a level", "level", level)
	}
	enc, err := ev.Encode()
	if err != nil {
		return Addendum{}, err
	}
	a := Addendum{ProofID: proofID, Seq: 1, Level: level, Chain: chain, Kind: ev.Kind, Evidence: enc, OriginalDigest: original}
	if prev != nil {
		a.Seq, a.PrevHash = prev.Seq+1, prev.OwnHash
		if chain != prev.Chain {
			return Addendum{}, broken("chain", a.Seq, "chain", chain, "prev_chain", prev.Chain)
		}
		if level <= prev.Level {
			return Addendum{}, broken("level_not_monotone", a.Seq, "prev_level", prev.Level, "level", level)
		}
	}
	a.OwnHash = a.ComputeHash(original)
	return a, nil
}

// Top is the highest level in a chain (LevelNone for an empty chain). It trusts nothing: callers verify the chain first.
func Top(chain []Addendum) Level {
	top := LevelNone
	for _, a := range chain {
		if a.Level > top {
			top = a.Level
		}
	}
	return top
}

// ChainSubject is the settlement an addendum chain is about: the Subject of its first addendum's evidence.
func ChainSubject(chain []Addendum) (Subject, error) {
	if len(chain) == 0 {
		return Subject{}, NewState(CodeChainBroken, "check", "empty", "seq", 0)
	}
	ev, err := DecodeEvidence(chain[0].Evidence)
	if err != nil {
		return Subject{}, err
	}
	return ev.Subject, nil
}

func broken(check string, seq uint64, kv ...any) *State {
	return NewState(CodeChainBroken, append([]any{"check", check, "seq", seq}, kv...)...)
}

// VerifyChain checks one proof's whole addendum chain against the proof's original digest: the sequence starts at 1 and
// is contiguous, every PrevHash is the previous OwnHash (zeros for the first), every OwnHash is recomputed from the
// addendum's own fields and the original digest, every addendum belongs to one proof and one chain, levels strictly
// increase, every evidence container decodes with the addendum's kind, and all of them are about one Subject.
// An empty chain is valid (nothing has been proven beyond the proof itself). Any failure is a *State whose
// "check" field names what broke and "seq" where.
//
// VerifyChain does not judge the evidence itself: that is Verify's job, per addendum, and a caller needs both.
func VerifyChain(original [32]byte, chain []Addendum) error {
	var prev *Addendum
	var subject Subject
	for i := range chain {
		a := &chain[i]
		want := uint64(i + 1)
		if a.Seq != want {
			return broken("seq", a.Seq, "want", want)
		}
		if a.ProofID == "" || (prev != nil && a.ProofID != prev.ProofID) {
			return broken("proof_id", a.Seq, "proof_id", a.ProofID)
		}
		if !a.Level.Valid() {
			return broken("level_invalid", a.Seq, "level", a.Level)
		}
		if prev == nil {
			if a.PrevHash != [32]byte{} {
				return broken("prev_hash", a.Seq, "reason", "first addendum's prevHash is not 32 zero bytes")
			}
		} else {
			if a.PrevHash != prev.OwnHash {
				return broken("prev_hash", a.Seq, "reason", "does not equal the previous ownHash")
			}
			if a.Chain != prev.Chain {
				return broken("chain", a.Seq, "chain", a.Chain, "prev_chain", prev.Chain)
			}
		}
		if got := a.ComputeHash(original); got != a.OwnHash {
			return broken("own_hash", a.Seq, "reason", "ownHash is not the hash of the addendum's fields and the original digest")
		}
		if prev != nil && a.Level <= prev.Level {
			return broken("level_not_monotone", a.Seq, "prev_level", prev.Level, "level", a.Level)
		}
		ev, err := DecodeEvidence(a.Evidence)
		if err != nil {
			return broken("evidence", a.Seq, "cause", err.Error())
		}
		if ev.Kind != a.Kind {
			return broken("kind", a.Seq, "kind", a.Kind, "evidence_kind", ev.Kind)
		}
		if prev == nil {
			subject = ev.Subject
		} else if ev.Subject != subject {
			return broken("subject", a.Seq, "reason", "evidence is about another settlement than the first addendum's")
		}
		prev = a
	}
	return nil
}

// ---- JSON (the portable document's and the gateway's form) ----

type addendumJSON struct {
	ProofID        string `json:"proofId"`
	Seq            uint64 `json:"seq"`
	Level          string `json:"level"`
	Chain          uint64 `json:"chain"`
	Kind           string `json:"kind"`
	Evidence       string `json:"evidence"` // hex of the canonical Evidence encoding
	PrevHash       string `json:"prevHash"` // hex32
	OwnHash        string `json:"ownHash"`  // hex32
	OriginalDigest string `json:"originalDigest,omitempty"`
}

// MarshalJSON writes the addendum with hex byte strings and the level by name.
func (a Addendum) MarshalJSON() ([]byte, error) {
	j := addendumJSON{
		ProofID: a.ProofID, Seq: a.Seq, Level: a.Level.String(), Chain: a.Chain, Kind: a.Kind,
		Evidence: hex.EncodeToString(a.Evidence), PrevHash: hex.EncodeToString(a.PrevHash[:]), OwnHash: hex.EncodeToString(a.OwnHash[:]),
	}
	if a.OriginalDigest != [32]byte{} {
		j.OriginalDigest = hex.EncodeToString(a.OriginalDigest[:])
	}
	return json.Marshal(j)
}

// UnmarshalJSON reads MarshalJSON's form strictly: unknown fields, a level that is not a level, hashes that are not 32
// bytes of hex and evidence that is not hex are each refused by name.
func (a *Addendum) UnmarshalJSON(b []byte) error {
	var j addendumJSON
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return NewState(CodeAddendumMalformed, "field", "json", "reason", err.Error())
	}
	level, err := ParseLevel(j.Level)
	if err != nil {
		return NewState(CodeAddendumMalformed, "field", "level", "reason", err.Error())
	}
	ev, err := hex.DecodeString(j.Evidence)
	if err != nil {
		return NewState(CodeAddendumMalformed, "field", "evidence", "reason", err.Error())
	}
	out := Addendum{ProofID: j.ProofID, Seq: j.Seq, Level: level, Chain: j.Chain, Kind: j.Kind, Evidence: ev}
	for _, f := range []struct {
		name string
		src  string
		dst  *[32]byte
		opt  bool
	}{
		{"prevHash", j.PrevHash, &out.PrevHash, false},
		{"ownHash", j.OwnHash, &out.OwnHash, false},
		{"originalDigest", j.OriginalDigest, &out.OriginalDigest, true},
	} {
		if f.opt && f.src == "" {
			continue
		}
		raw, err := hex.DecodeString(f.src)
		if err != nil || len(raw) != 32 {
			return NewState(CodeAddendumMalformed, "field", f.name, "reason", fmt.Sprintf("not 32 bytes of hex (%q)", f.src))
		}
		copy(f.dst[:], raw)
	}
	*a = out
	return nil
}
