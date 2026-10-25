// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

// ParseProofID reads a uuid in its ONE canonical text form: 8-4-4-4-12 lower-case hex digits separated by dashes (36
// characters). Anything else (no dashes, upper case, braces, a urn prefix, a wrong dash position) is refused as
// finality_addendum_malformed{field:"proofId", reason:"not_canonical_uuid"}, so a Go and a TypeScript verifier accept exactly
// the same set of proof ids.
func ParseProofID(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 36 {
		return out, AddendumMalformed("proofId", AddendumNotUUID)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return out, AddendumMalformed("proofId", AddendumNotUUID)
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return out, AddendumMalformed("proofId", AddendumNotUUID)
			}
		}
	}
	raw, err := hex.DecodeString(s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36])
	if err != nil {
		return out, AddendumMalformed("proofId", AddendumNotUUID)
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

// UnmarshalJSON-side strict reading shared by Addendum, Section and the carried leg. A Go and a TypeScript verifier must accept
// the same documents, and encoding/json is lenient in ways JSON.parse is not (case-insensitive keys, a repeated key silently
// taking the last value, null leaving a zero value, hex of either case), so a document is read in four fixed steps:
//
//  1. the whole text is valid JSON (json.Valid; trailing data is invalid)             -> not_json
//  2. an object whose keys are EXACTLY the schema's keys (case-sensitive), none twice  -> unknown_key{key}, duplicate_key{key},
//     in document order, decided on the decoded key (a key spelled with a unicode escape is the key it decodes to)
//  3. every schema key is present                                                      -> missing_key{key}, in schema order
//  4. members are decoded in SCHEMA order and the first failure is reported            -> bad_value, level_not_stored,
//     unknown_level, not_lowercase_hex, not_32_bytes, wrong_format
//
// The state is always finality_addendum_malformed{field, reason[, key][, index]}: field names the member, or the object for a
// key refusal. Hex is lower case only; an integer is a JSON integer that fits uint64; null is never a value.

func strictObject(raw []byte, field string, keys []string, optional ...string) (map[string]json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, AddendumMalformed(field, AddendumNotJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if d, ok := tok.(json.Delim); err != nil || !ok || d != '{' {
		return nil, AddendumMalformed(field, AddendumNotJSON)
	}
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, AddendumMalformed(field, AddendumNotJSON)
		}
		k, _ := kt.(string)
		if !allowed[k] {
			return nil, AddendumMalformed(field, AddendumUnknownKey, "key", k)
		}
		if _, dup := out[k]; dup {
			return nil, AddendumMalformed(field, AddendumDuplicateKey, "key", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, AddendumMalformed(field, AddendumNotJSON)
		}
		out[k] = v
	}
	for _, k := range keys {
		if _, ok := out[k]; !ok {
			return nil, AddendumMalformed(field, AddendumMissingKey, "key", k)
		}
	}
	return out, nil
}

func strictString(raw json.RawMessage, field string) (string, error) {
	var s string
	if string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &s) != nil {
		return "", AddendumMalformed(field, AddendumBadValue)
	}
	return s, nil
}

func strictUint(raw json.RawMessage, field string) (uint64, error) {
	var u uint64
	if string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &u) != nil {
		return 0, AddendumMalformed(field, AddendumBadValue)
	}
	return u, nil
}

// strictHex decodes lower-case hex; want >= 0 also fixes the decoded length.
func strictHex(s, field string, want int) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, AddendumMalformed(field, AddendumNotLowerHex)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, AddendumMalformed(field, AddendumNotLowerHex)
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, AddendumMalformed(field, AddendumNotLowerHex)
	}
	if want >= 0 && len(b) != want {
		return nil, AddendumMalformed(field, AddendumNot32Bytes)
	}
	return b, nil
}

func strictHex32(raw json.RawMessage, field string) ([32]byte, error) {
	var out [32]byte
	s, err := strictString(raw, field)
	if err != nil {
		return out, err
	}
	b, err := strictHex(s, field, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

var addendumKeys = []string{"proofId", "seq", "level", "chain", "kind", "evidence", "prevHash", "ownHash"}

// UnmarshalJSON reads MarshalJSON's form strictly (rules above): a key that is not exactly one of the eight, a repeated or
// missing key, a level that is not "l1_posted" or "finalized" ("included" is derived and never stored), hex that is not lower
// case, hashes that are not 32 bytes and a proof id that is not a canonical lower-case uuid are each refused by name.
func (a *Addendum) UnmarshalJSON(b []byte) error {
	m, err := strictObject(b, "addendum", addendumKeys)
	if err != nil {
		return err
	}
	var out Addendum
	idStr, err := strictString(m["proofId"], "proofId")
	if err != nil {
		return err
	}
	if out.ProofID, err = ParseProofID(idStr); err != nil {
		return err
	}
	if out.Seq, err = strictUint(m["seq"], "seq"); err != nil {
		return err
	}
	levelStr, err := strictString(m["level"], "level")
	if err != nil {
		return err
	}
	level, perr := ParseLevel(levelStr)
	switch {
	case perr != nil:
		return AddendumMalformed("level", AddendumUnknownLevel)
	case !level.Stored():
		return AddendumMalformed("level", AddendumLevelNotStored)
	}
	out.Level = level
	if out.Chain, err = strictUint(m["chain"], "chain"); err != nil {
		return err
	}
	if out.Kind, err = strictString(m["kind"], "kind"); err != nil {
		return err
	}
	evStr, err := strictString(m["evidence"], "evidence")
	if err != nil {
		return err
	}
	if out.Evidence, err = strictHex(evStr, "evidence", -1); err != nil {
		return err
	}
	if out.PrevHash, err = strictHex32(m["prevHash"], "prevHash"); err != nil {
		return err
	}
	if out.OwnHash, err = strictHex32(m["ownHash"], "ownHash"); err != nil {
		return err
	}
	*a = out
	return nil
}

// SectionFormat is the format string of the portable document's `finality` member.
const SectionFormat = "certen-finality-addenda/1"

// MaxLegHeaderBytes bounds the carried settlement header (a few hundred bytes today) before it is hashed.
const MaxLegHeaderBytes = 16 << 10

// CarriedLeg is the `leg` member of the finality section: the block the addenda claim to be about. HeaderRLP is OPTIONAL: the lower-case
// hex of the settlement block's header RLP, bound by keccak256(header) == blockHash and by the block number read positionally from the
// header == blockNumber (V2_SPEC_S7 5.1 item 8), so a holder of the section alone can recompute D0 and judge the addenda against that
// block. It proves the block, not the settlement transaction (R12-OUTCOME-TX; a composer that has no header omits the member).
type CarriedLeg struct {
	Chain       uint64 `json:"chain"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`           // hex32
	HeaderRLP   string `json:"headerRlp,omitempty"` // hex, optional
}

// Ref is the carried leg as a BlockRef. blockHash is 32 bytes of lower-case hex. When the leg carries its header, the header is bound
// here: keccak256(header) must equal blockHash and its block number (read positionally) must equal blockNumber, else
// finality_chain_broken{seq: 0, check: leg_binding, want, got} naming the differing member in both maps; the BlockRef then holds the
// header. A header that is not a readable block header is the named malformed state of ReadHeader. Without a header the BlockRef has none.
func (c CarriedLeg) Ref() (BlockRef, error) {
	raw, err := strictHex(c.BlockHash, "leg.blockHash", 32)
	if err != nil {
		return BlockRef{}, err
	}
	var h [32]byte
	copy(h[:], raw)
	ref := BlockRef{Chain: c.Chain, Number: c.BlockNumber, Hash: h}
	if c.HeaderRLP == "" {
		return ref, nil
	}
	hdr, err := strictHex(c.HeaderRLP, "leg.headerRlp", -1)
	if err != nil {
		return BlockRef{}, err
	}
	if len(hdr) == 0 || len(hdr) > MaxLegHeaderBytes {
		return BlockRef{}, AddendumMalformed("leg.headerRlp", AddendumBadValue)
	}
	f, err := ReadHeader(hdr)
	if err != nil {
		return BlockRef{}, err
	}
	if f.Hash != h {
		return BlockRef{}, ChainBroken(0, CheckLegBinding, "want", map[string]any{"blockHash": f.Hash}, "got", map[string]any{"blockHash": h})
	}
	if f.Number != c.BlockNumber {
		return BlockRef{}, ChainBroken(0, CheckLegBinding, "want", map[string]any{"blockNumber": f.Number}, "got", map[string]any{"blockNumber": c.BlockNumber})
	}
	ref.HeaderRLP = hdr
	return ref, nil
}

// CarriedLegOf renders a BlockRef as the carried form, without its header (the member a composer without the header emits).
func CarriedLegOf(b BlockRef) CarriedLeg {
	return CarriedLeg{Chain: b.Chain, BlockNumber: b.Number, BlockHash: hex.EncodeToString(b.Hash[:])}
}

// CarriedLegWithHeaderOf renders a BlockRef as the carried form WITH its header when it holds one (b.HeaderRLP non-empty).
func CarriedLegWithHeaderOf(b BlockRef) CarriedLeg {
	c := CarriedLegOf(b)
	if len(b.HeaderRLP) > 0 {
		c.HeaderRLP = hex.EncodeToString(b.HeaderRLP)
	}
	return c
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

// NewSectionWithHeader is NewSection with the leg's header carried when the leg holds one (leg.HeaderRLP non-empty).
func NewSectionWithHeader(leg BlockRef, chain []Addendum) Section {
	s := NewSection(leg, chain)
	s.Leg = CarriedLegWithHeaderOf(leg)
	return s
}

var (
	sectionKeys = []string{"format", "leg", "addenda"}
	legKeys     = []string{"chain", "blockNumber", "blockHash"}
)

// ParseSection reads the member strictly by the rules above: the format string must be SectionFormat (wrong_format), the leg
// has exactly chain, blockNumber and blockHash, and every addendum is read by Addendum.UnmarshalJSON (a refusal there carries
// the element's index). Members are judged in schema order: format, leg, addenda.
func ParseSection(raw []byte) (Section, error) {
	m, err := strictObject(raw, "finality", sectionKeys)
	if err != nil {
		return Section{}, err
	}
	format, err := strictString(m["format"], "format")
	if err != nil {
		return Section{}, err
	}
	if format != SectionFormat {
		return Section{}, AddendumMalformed("format", AddendumWrongFormat)
	}
	lm, err := strictObject(m["leg"], "leg", legKeys, "headerRlp") // headerRlp is the one optional member
	if err != nil {
		return Section{}, err
	}
	var s Section
	s.Format = format
	if s.Leg.Chain, err = strictUint(lm["chain"], "leg.chain"); err != nil {
		return Section{}, err
	}
	if s.Leg.BlockNumber, err = strictUint(lm["blockNumber"], "leg.blockNumber"); err != nil {
		return Section{}, err
	}
	hash, err := strictHex32(lm["blockHash"], "leg.blockHash")
	if err != nil {
		return Section{}, err
	}
	s.Leg.BlockHash = hex.EncodeToString(hash[:])
	if rawHeader, has := lm["headerRlp"]; has {
		hs, err := strictString(rawHeader, "leg.headerRlp")
		if err != nil {
			return Section{}, err
		}
		hb, err := strictHex(hs, "leg.headerRlp", -1)
		if err != nil {
			return Section{}, err
		}
		if len(hb) == 0 || len(hb) > MaxLegHeaderBytes {
			return Section{}, AddendumMalformed("leg.headerRlp", AddendumBadValue)
		}
		s.Leg.HeaderRLP = hs
	}
	var list []json.RawMessage
	if string(bytes.TrimSpace(m["addenda"])) == "null" || json.Unmarshal(m["addenda"], &list) != nil {
		return Section{}, AddendumMalformed("addenda", AddendumBadValue)
	}
	s.Addenda = make([]Addendum, 0, len(list))
	for i, el := range list {
		var a Addendum
		if err := a.UnmarshalJSON(el); err != nil {
			if st, ok := AsNamed(err); ok {
				st.Fields["index"] = uint64(i)
			}
			return Section{}, err
		}
		s.Addenda = append(s.Addenda, a)
	}
	return s, nil
}

// UnmarshalJSON makes every decoding path of a Section the strict one (ParseSection).
func (s *Section) UnmarshalJSON(b []byte) error {
	v, err := ParseSection(b)
	if err != nil {
		return err
	}
	*s = v
	return nil
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
