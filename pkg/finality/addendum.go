// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Domain is the hash domain of every addendum (PROOF_V2 section 10.3: new evidence gets a new tag, never a reused one). It
// appears in exactly one preimage, OwnHash.
const Domain = "certen:finality:v1"

// LegDomain is the domain of the leg binding D0 (V2_SPEC_S7 section 2.6).
const LegDomain = "certen:finality:d0/v1"

// Addendum is one record of the append-only chain by which a leg is upgraded. It is evidence ABOUT a proof, stored and
// served beside it: the proof's own bytes never change, and nothing here is an input of any attestation, outcome root or
// govRoot.
//
//	OwnHash = sha256( lp(Domain) || lp(D0) || lp(PrevHash) || lp(be64(Seq)) || lp(u8(Level)) || lp(be64(Chain)) ||
//	                  lp(Kind) || lp(sha256(Evidence)) )
//
// lp is a 4-byte big-endian length followed by the bytes; D0 is the leg binding (LegBinding), which a verifier recomputes
// from the Settlement it verified and never reads from the file; the first addendum's PrevHash is 32 zero bytes. Level is 2
// (l1_posted) or 3 (finalized): level 1 (included) is derived and never stored. ProofID is the storage key (the uuid of the
// proof_artifacts row, which carries exactly one leg) and is not hashed.
type Addendum struct {
	ProofID  [16]byte
	Seq      uint64
	Level    Level
	Chain    uint64
	Kind     string
	Evidence []byte // the CFE1 container (codec.go)
	PrevHash [32]byte
	OwnHash  [32]byte
}

func lp(f []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(f)))
	return append(out, f...)
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// LegBindingPreimage is lp("certen:finality:d0/v1") || lp(be64(chain)) || lp(be64(number)) || lp(blockHash): 85 bytes.
func LegBindingPreimage(chain, number uint64, blockHash [32]byte) []byte {
	var out []byte
	for _, f := range [][]byte{[]byte(LegDomain), be64(chain), be64(number), blockHash[:]} {
		out = append(out, lp(f)...)
	}
	return out
}

// LegBinding is D0: SHA-256 of LegBindingPreimage, a pure function of the three facts a verifier has already verified in S6
// (V2_SPEC_S7 2.6). It makes the chain a consistency check of the stored hashes against this leg's block; it is not
// authenticity and not completeness.
func LegBinding(chain, number uint64, blockHash [32]byte) [32]byte {
	return sha256.Sum256(LegBindingPreimage(chain, number, blockHash))
}

// LegBindingOf is LegBinding of a BlockRef.
func LegBindingOf(b BlockRef) [32]byte { return LegBinding(b.Chain, b.Number, b.Hash) }

// OwnHashPreimage is lp(Domain) || lp(d0) || lp(prevHash) || lp(be64 seq) || lp(u8 level) || lp(be64 chain) || lp(kind) ||
// lp(sha256(evidence)).
func OwnHashPreimage(d0 [32]byte, a Addendum) []byte {
	evSum := sha256.Sum256(a.Evidence)
	var out []byte
	for _, f := range [][]byte{
		[]byte(Domain), d0[:], a.PrevHash[:], be64(a.Seq), {byte(a.Level)}, be64(a.Chain), []byte(a.Kind), evSum[:],
	} {
		out = append(out, lp(f)...)
	}
	return out
}

// OwnHash is the addendum's chain hash under the leg binding d0 (V2_SPEC_S7 2.2).
func OwnHash(d0 [32]byte, a Addendum) [32]byte { return sha256.Sum256(OwnHashPreimage(d0, a)) }

// NewAddendum builds the addendum that follows `existing` (the leg's chain so far, possibly empty) for the leg bound by d0.
// It refuses what VerifyChain would refuse: a level that is not stored (finality_chain_broken kind), a (chain, level, kind)
// that is not a table row, a container whose header disagrees with the addendum's kind, chain or level, and a level the
// chain already holds (level_already_present).
func NewAddendum(d0 [32]byte, proofID [16]byte, existing []Addendum, chain uint64, level Level, kind string, evidence []byte) (Addendum, error) {
	seq := uint64(len(existing) + 1)
	a := Addendum{ProofID: proofID, Seq: seq, Level: level, Chain: chain, Kind: kind, Evidence: append([]byte(nil), evidence...)}
	if !IsRow(chain, level, kind) {
		return Addendum{}, ChainBroken(seq, CheckKind, "chain", chain, "level", level, "kind", kind)
	}
	for _, e := range existing {
		if e.Level == level {
			return Addendum{}, NewState(CodeLevelAlreadyPresent, "chain", chain, "level", level)
		}
	}
	c, err := DecodeContainer(evidence, DefaultLimits())
	if err != nil {
		return Addendum{}, err
	}
	if c.Header.Kind != kind || c.Header.Chain != chain || c.Header.Level != level {
		return Addendum{}, BlockMismatch("header", map[string]any{"kind": kind, "chain": chain, "level": level},
			map[string]any{"kind": c.Header.Kind, "chain": c.Header.Chain, "level": c.Header.Level})
	}
	if len(existing) > 0 {
		a.PrevHash = existing[len(existing)-1].OwnHash
	}
	a.OwnHash = OwnHash(d0, a)
	return a, nil
}

// Top is the highest stored level in a chain (LevelNone for an empty chain). It trusts nothing: callers verify first.
func Top(chain []Addendum) Level {
	top := LevelNone
	for _, a := range chain {
		if a.Level > top {
			top = a.Level
		}
	}
	return top
}

// LevelsOf is the set of levels a chain holds.
func LevelsOf(chain []Addendum) LevelSet {
	var s LevelSet
	for _, a := range chain {
		s = s.With(a.Level)
	}
	return s
}

// VerifyChain checks one leg's whole addendum chain against the leg binding d0 (V2_SPEC_S7 2.3). For i = 1..n, in this
// order: seq == i (seq_gap); prevHash == (i == 1 ? 0x00*32 : ownHash_{i-1}) (prev_hash); the recomputed ownHash equals the
// stored one (own_hash); the level equals no earlier level (level_duplicate; any order, R1); (chain, level, kind) is a
// table row (kind). The failure is finality_chain_broken{seq, check}. d0 is the CALLER's LegBinding of the verified
// Settlement: the addenda carry none, and a chain built under another d0 fails own_hash at seq 1. An empty chain is valid.
//
// VerifyChain does not judge the evidence itself: that is Verify's job, per addendum.
func VerifyChain(d0 [32]byte, adds []Addendum) error {
	var seen LevelSet
	var prev [32]byte
	for i := range adds {
		a := &adds[i]
		want := uint64(i + 1)
		if a.Seq != want {
			return ChainBroken(a.Seq, CheckSeqGap, "want", want)
		}
		if a.PrevHash != prev {
			return ChainBroken(a.Seq, CheckPrevHash)
		}
		if OwnHash(d0, *a) != a.OwnHash {
			return ChainBroken(a.Seq, CheckOwnHash)
		}
		if seen.Has(a.Level) {
			return ChainBroken(a.Seq, CheckLevelDuplicate, "level", a.Level)
		}
		if !IsRow(a.Chain, a.Level, a.Kind) {
			return ChainBroken(a.Seq, CheckKind, "chain", a.Chain, "level", a.Level, "kind", a.Kind)
		}
		seen = seen.With(a.Level)
		prev = a.OwnHash
	}
	return nil
}

// ---- proof ids ----

// ParseProofID reads a uuid in its canonical text form.
func ParseProofID(s string) ([16]byte, error) {
	var out [16]byte
	t := strings.ReplaceAll(s, "-", "")
	if len(s) != 36 || len(t) != 32 {
		return out, NewState(CodeAddendumMalformed, "field", "proofId", "reason", fmt.Sprintf("not a uuid (%q)", s))
	}
	raw, err := hex.DecodeString(t)
	if err != nil {
		return out, NewState(CodeAddendumMalformed, "field", "proofId", "reason", fmt.Sprintf("not a uuid (%q)", s))
	}
	copy(out[:], raw)
	return out, nil
}

// ProofIDString is the canonical lowercase uuid text (proof_artifacts.proof_id::text).
func ProofIDString(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---- JSON (the portable document's and the gateway's form, V2_SPEC_S7 2.5) ----

type addendumJSON struct {
	ProofID  string `json:"proofId"`
	Seq      uint64 `json:"seq"`
	Level    string `json:"level"`
	Chain    uint64 `json:"chain"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"` // hex of the CFE1 container
	PrevHash string `json:"prevHash"` // hex32
	OwnHash  string `json:"ownHash"`  // hex32
}

// MarshalJSON writes the addendum with hex byte strings and the level by name ("l1_posted" | "finalized").
func (a Addendum) MarshalJSON() ([]byte, error) {
	return json.Marshal(addendumJSON{
		ProofID: ProofIDString(a.ProofID), Seq: a.Seq, Level: a.Level.String(), Chain: a.Chain, Kind: a.Kind,
		Evidence: hex.EncodeToString(a.Evidence), PrevHash: hex.EncodeToString(a.PrevHash[:]), OwnHash: hex.EncodeToString(a.OwnHash[:]),
	})
}

// UnmarshalJSON reads MarshalJSON's form strictly: unknown fields, a level that is not l1_posted or finalized ("included" is
// derived and never stored), hashes that are not 32 bytes of hex and evidence that is not hex are each refused by name.
func (a *Addendum) UnmarshalJSON(b []byte) error {
	var j addendumJSON
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return NewState(CodeAddendumMalformed, "field", "json", "reason", err.Error())
	}
	level, err := ParseStoredLevel(j.Level)
	if err != nil {
		return NewState(CodeAddendumMalformed, "field", "level", "reason", err.Error())
	}
	id, err := ParseProofID(j.ProofID)
	if err != nil {
		return err
	}
	ev, err := hex.DecodeString(j.Evidence)
	if err != nil {
		return NewState(CodeAddendumMalformed, "field", "evidence", "reason", err.Error())
	}
	out := Addendum{ProofID: id, Seq: j.Seq, Level: level, Chain: j.Chain, Kind: j.Kind, Evidence: ev}
	for _, f := range []struct {
		name string
		src  string
		dst  *[32]byte
	}{{"prevHash", j.PrevHash, &out.PrevHash}, {"ownHash", j.OwnHash, &out.OwnHash}} {
		raw, err := hex.DecodeString(f.src)
		if err != nil || len(raw) != 32 {
			return NewState(CodeAddendumMalformed, "field", f.name, "reason", fmt.Sprintf("not 32 bytes of hex (%q)", f.src))
		}
		copy(f.dst[:], raw)
	}
	*a = out
	return nil
}

// SectionFormat is the format string of the portable document's `finality` member.
const SectionFormat = "certen-finality-addenda/1"

// CarriedLeg is the `leg` member of the finality section: the block the addenda claim to be about.
type CarriedLeg struct {
	Chain       uint64 `json:"chain"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash"` // hex32
}

// Ref is the carried leg as a BlockRef (no header).
func (c CarriedLeg) Ref() (BlockRef, error) {
	raw, err := hex.DecodeString(c.BlockHash)
	if err != nil || len(raw) != 32 {
		return BlockRef{}, NewState(CodeAddendumMalformed, "field", "leg.blockHash", "reason", fmt.Sprintf("not 32 bytes of hex (%q)", c.BlockHash))
	}
	var h [32]byte
	copy(h[:], raw)
	return BlockRef{Chain: c.Chain, Number: c.BlockNumber, Hash: h}, nil
}

// CarriedLegOf renders a BlockRef as the carried form.
func CarriedLegOf(b BlockRef) CarriedLeg {
	return CarriedLeg{Chain: b.Chain, BlockNumber: b.Number, BlockHash: hex.EncodeToString(b.Hash[:])}
}

// Section is the value of a portable document's `finality` member (V2_SPEC_S7 2.5).
type Section struct {
	Format  string     `json:"format"`
	Leg     CarriedLeg `json:"leg"`
	Addenda []Addendum `json:"addenda"`
}

// NewSection builds the member for a leg's chain.
func NewSection(leg BlockRef, chain []Addendum) Section {
	return Section{Format: SectionFormat, Leg: CarriedLegOf(leg), Addenda: append([]Addendum{}, chain...)}
}

// ParseSection reads the member strictly (unknown fields and a wrong format are refused by name).
func ParseSection(raw []byte) (Section, error) {
	var s Section
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Section{}, NewState(CodeAddendumMalformed, "field", "finality", "reason", err.Error())
	}
	if s.Format != SectionFormat {
		return Section{}, NewState(CodeAddendumMalformed, "field", "format", "reason", fmt.Sprintf("want %q, got %q", SectionFormat, s.Format))
	}
	return s, nil
}

// CheckLegChain is the chain-level judgement of one leg without judging any evidence: the leg's chain must be a row of the
// table (finality_chain_unsupported), the carried leg must equal the verified Settlement block b FIRST (a difference is
// finality_chain_broken{seq:0, check:"leg_binding", want:<b>, got:<carried>} and nothing else is judged), and then VerifyChain
// runs under D0 = LegBinding of b. D0 is never read from the addenda.
func CheckLegChain(b BlockRef, carried BlockRef, adds []Addendum) error {
	if !ChainSupported(b.Chain) {
		return ChainUnsupported(b.Chain)
	}
	if carried.Chain != b.Chain || carried.Number != b.Number || carried.Hash != b.Hash {
		return ChainBroken(0, CheckLegBinding, "want", b.Triple(), "got", carried.Triple())
	}
	return VerifyChain(LegBindingOf(b), adds)
}
