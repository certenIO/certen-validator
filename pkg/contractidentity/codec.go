// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"regexp"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// This file is the strict codec of the CIE1 evidence container (V2_SPEC_S8.md r3.1, Freeze inventory item 1). It is built on the
// pkg/finality Writer and Reader primitives (u8/u32/u64, fixed bytes, lp(), counts, the trailing-byte check) and adds only the CIE1
// grammar and the translation of the reader's refusals into the contract_identity_ states of the registry.
//
//	Container = "CIE1"(4) || STR kind("contract-identity/v1") || u64 chain || u64 leg.number || B32 leg.hash || LIST<Code> codes
//	            || Part settle || Part attest || NODES
//	Code      = B20 address || LP runtime              ascending by address, unique
//	Part      = u8 tag || ( tag 1: captured body (settle: empty; attest: Proof_attest) | tag 2: Stated )
//	Stated    = STR "contract_identity_unproven" || STR reason || u64 judgedBlock || B32 judgedHash || LIST<ProviderFailure> || STR detail
//	Proof_attest = u8 link || LP headerV || LP headerVParent || [link 1: LIST<LP> hopHeaders] || [link 2: LIST<LP> spine]
//	               || u32 txIndex || LP txLeaf || LP receiptLeaf || LIST<LP> blockTxs
//	NODES     = LIST<LP> strictly ascending by keccak256(node), unique
//
// Decode is strict (a short field, a count above its bound, an unordered code or node set, a trailing byte are named refusals) and
// encode(decode(x)) == x for every x it accepts. The unreferenced-node rule of step 22b is a VERIFIER rule: Decode checks order and
// uniqueness only, so the codec goldens (whose nodes are arbitrary bytes) stay valid.

const (
	// Magic opens every container.
	Magic = "CIE1"
	// Kind is the only container kind of this format.
	Kind = "contract-identity/v1"
	// StatedState is the only state a Stated part may carry.
	StatedState = "contract_identity_unproven"
)

// Part tags (item 1b).
type PartTag uint8

const (
	TagCaptured PartTag = 1
	TagStated   PartTag = 2
)

// Attestation header links (item 1a, Proof_attest).
const (
	LinkSameBlock uint8 = 0
	LinkHops      uint8 = 1
	LinkSpine     uint8 = 2
)

// BlockRef is a block named by number and hash.
type BlockRef struct {
	Number uint64
	Hash   [32]byte
}

// Code is the runtime code of one contract, shared by both parts.
type Code struct {
	Address [20]byte
	Runtime []byte
}

// ProviderFailure is one provider's failure to serve a proof (bounded, redacted text).
type ProviderFailure struct {
	Host  string
	Error string
}

// Stated is a part the builder could not capture: informational, bounded, never judged as evidence. The verifier turns it into the
// unproven state of its reason and can never raise a status above unproven because of it.
type Stated struct {
	State       string // StatedState
	Reason      string // [a-z0-9_]{1,64}
	JudgedBlock uint64
	JudgedHash  [32]byte
	Failures    []ProviderFailure
	Detail      string
}

// AttestProof is the captured attestation part (Proof_attest): the headers that link the attestation block to the settlement block, the
// attestation transaction and receipt leaves, and every transaction of the attestation block (rule IB).
type AttestProof struct {
	Link          uint8
	HeaderV       []byte
	HeaderVParent []byte
	HopHeaders    [][]byte // link 1 only, ascending by number
	Spine         [][]byte // link 2 only, descending
	TxIndex       uint32
	TxLeaf        []byte
	ReceiptLeaf   []byte
	BlockTxs      [][]byte // EVERY transaction of the attestation block in index order (typed wire encoding)
}

// Part is the settle or the attest part: captured (Tag 1; Attest is nil for settle and set for attest) or Stated (Tag 2).
type Part struct {
	Tag    PartTag
	Stated *Stated
	Attest *AttestProof
}

// Container is a decoded CIE1 evidence container.
type Container struct {
	Chain  uint64
	Leg    BlockRef
	Codes  []Code
	Settle Part
	Attest Part
	Nodes  [][]byte
}

var statedReasonRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

func asciiNoNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 || c > 0x7f {
			return false
		}
	}
	return true
}

// ---- decoding ----

type decoder struct {
	r     *finality.Reader
	total int
}

func (d *decoder) off() int { return d.total - d.r.Left() }

func u64Field(v any) uint64 {
	if x, ok := v.(uint64); ok {
		return x
	}
	return 0
}

func baseOf(part string) string {
	for i := 0; i < len(part); i++ {
		if part[i] == '.' {
			return part[:i]
		}
	}
	return part
}

// conv translates a pkg/finality reader refusal into the registry state of this format. tooLargePart, when not empty, replaces the part
// of an evidence_too_large (the Stated strings are bounded under part "failures").
func (d *decoder) conv(err error, tooLargePart string) error {
	fs, ok := err.(*finality.StateError)
	if !ok {
		return err
	}
	switch fs.Code {
	case finality.CodeEvidenceTooLarge:
		part, _ := fs.Fields["part"].(string)
		if tooLargePart != "" {
			part = tooLargePart
		}
		return TooLarge(part, u64Field(fs.Fields["count"]), u64Field(fs.Fields["limit"]))
	case finality.CodeEvidenceMalformed:
		part, _ := fs.Fields["part"].(string)
		reason, _ := fs.Fields["reason"].(finality.EvidenceReason)
		got, want := int(u64Field(fs.Fields["got_len"])), int(u64Field(fs.Fields["want_len"]))
		switch reason {
		case finality.ReasonTruncated, finality.ReasonLengthExceedsRemaining, finality.ReasonCountExceedsRemaining:
			return Malformed(baseOf(part), MalformedTruncated, d.off(), got, want)
		case finality.ReasonTrailingBytes:
			return Malformed(baseOf(part), MalformedTrailingBytes, d.off(), got, want)
		}
	}
	// The primitives used here raise only the refusals above; anything else is a change in pkg/finality that this codec must be re-read for.
	return Malformed(PartContainer, MalformedTruncated, d.off(), d.total-d.off(), 0)
}

func (d *decoder) u8(part string) (uint8, error) {
	v, err := d.r.U8(part)
	if err != nil {
		return 0, d.conv(err, "")
	}
	return v, nil
}

func (d *decoder) u32(part string) (uint32, error) {
	v, err := d.r.U32(part)
	if err != nil {
		return 0, d.conv(err, "")
	}
	return v, nil
}

func (d *decoder) u64(part string) (uint64, error) {
	v, err := d.r.U64(part)
	if err != nil {
		return 0, d.conv(err, "")
	}
	return v, nil
}

func (d *decoder) fixed(part string, n int) ([]byte, error) {
	v, err := d.r.Fixed(part, n)
	if err != nil {
		return nil, d.conv(err, "")
	}
	return v, nil
}

func (d *decoder) b32(part string) (b [32]byte, err error) {
	v, err := d.fixed(part, 32)
	if err != nil {
		return b, err
	}
	copy(b[:], v)
	return b, nil
}

func (d *decoder) lp(part string, max int) ([]byte, error) {
	v, err := d.r.LP(part, max)
	if err != nil {
		return nil, d.conv(err, "")
	}
	return v, nil
}

func (d *decoder) count(part string, limit int) (int, error) {
	n, err := d.r.Count(part, limit, 0)
	if err != nil {
		return 0, d.conv(err, "")
	}
	return n, nil
}

// str reads an ASCII string with no NUL of at most max bytes. A string above max is evidence_too_large under tooLargePart; one with a
// NUL or a byte above 0x7f is string_not_ascii of part (index = the offset after the string).
func (d *decoder) str(part, tooLargePart string, max int) (string, error) {
	v, err := d.r.LP(part, max)
	if err != nil {
		return "", d.conv(err, tooLargePart)
	}
	if !asciiNoNUL(v) {
		return "", Malformed(part, MalformedStringNotAscii, d.off(), 0, 0)
	}
	return string(v), nil
}

// Decode parses a container strictly under lim. Every refusal is a *StateError of the registry.
func Decode(raw []byte, lim Limits) (*Container, error) {
	if len(raw) > lim.MaxContainerBytes {
		return nil, TooLarge(PartContainer, uint64(len(raw)), uint64(lim.MaxContainerBytes))
	}
	d := &decoder{r: finality.NewReader(raw, finality.Limits{MaxStringBytes: lim.MaxText}), total: len(raw)}
	magic, err := d.fixed(PartMagic, 4)
	if err != nil {
		return nil, err
	}
	if string(magic) != Magic {
		return nil, Malformed(PartMagic, MalformedBadMagic, 0, 0, 0)
	}
	kind, err := d.str(PartKind, "", lim.MaxKindBytes)
	if err != nil {
		return nil, err
	}
	if kind != Kind {
		return nil, Unrecognised(kind)
	}
	c := &Container{}
	if c.Chain, err = d.u64(PartContainer); err != nil {
		return nil, err
	}
	if c.Leg.Number, err = d.u64(PartContainer); err != nil {
		return nil, err
	}
	if c.Leg.Hash, err = d.b32(PartContainer); err != nil {
		return nil, err
	}
	// codes: ascending by address, unique
	nc, err := d.count(PartCodes, lim.MaxCodes)
	if err != nil {
		return nil, err
	}
	c.Codes = make([]Code, 0, nc)
	for i := 0; i < nc; i++ {
		a, err := d.fixed(PartCodes, 20)
		if err != nil {
			return nil, err
		}
		var code Code
		copy(code.Address[:], a)
		if i > 0 {
			switch cmp := bytes.Compare(c.Codes[i-1].Address[:], code.Address[:]); {
			case cmp == 0:
				return nil, Malformed(PartCodes, MalformedCodesDuplicate, i, 0, 0)
			case cmp > 0:
				return nil, Malformed(PartCodes, MalformedCodesNotAscending, i, 0, 0)
			}
		}
		if code.Runtime, err = d.lp(PartCodes, lim.MaxCodeBytes); err != nil {
			return nil, err
		}
		c.Codes = append(c.Codes, code)
	}
	if c.Settle, err = d.part(PartSettle, lim); err != nil {
		return nil, err
	}
	if c.Attest, err = d.part(PartAttest, lim); err != nil {
		return nil, err
	}
	// nodes: ascending by keccak256, unique
	nn, err := d.count(PartNodes, lim.MaxNodes)
	if err != nil {
		return nil, err
	}
	c.Nodes = make([][]byte, 0, nn)
	var prev [32]byte
	for i := 0; i < nn; i++ {
		n, err := d.lp(PartNodes, lim.MaxNodeBytes)
		if err != nil {
			return nil, err
		}
		h := crypto.Keccak256Hash(n)
		if i > 0 {
			switch cmp := bytes.Compare(prev[:], h[:]); {
			case cmp == 0:
				return nil, Malformed(PartNodes, MalformedNodesDuplicate, i, 0, 0)
			case cmp > 0:
				return nil, Malformed(PartNodes, MalformedNodesNotAscending, i, 0, 0)
			}
		}
		prev = h
		c.Nodes = append(c.Nodes, n)
	}
	if err := d.r.End(PartContainer); err != nil {
		return nil, d.conv(err, "")
	}
	return c, nil
}

func (d *decoder) part(part string, lim Limits) (Part, error) {
	tag, err := d.u8(part)
	if err != nil {
		return Part{}, err
	}
	switch PartTag(tag) {
	case TagStated:
		s, err := d.stated(part, lim)
		if err != nil {
			return Part{}, err
		}
		return Part{Tag: TagStated, Stated: s}, nil
	case TagCaptured:
		if part == PartSettle {
			return Part{Tag: TagCaptured}, nil
		}
		a, err := d.attest(lim)
		if err != nil {
			return Part{}, err
		}
		return Part{Tag: TagCaptured, Attest: a}, nil
	}
	return Part{}, Malformed(part, MalformedUnknownPartTag, d.off(), 0, 0)
}

func (d *decoder) stated(part string, lim Limits) (*Stated, error) {
	s := &Stated{}
	var err error
	if s.State, err = d.str(part, PartFailures, lim.MaxText); err != nil {
		return nil, err
	}
	if s.State != StatedState {
		return nil, Malformed(part, MalformedBadStatedState, d.off(), 0, 0)
	}
	if s.Reason, err = d.str(part, PartFailures, lim.MaxText); err != nil {
		return nil, err
	}
	if !statedReasonRe.MatchString(s.Reason) {
		return nil, Malformed(part, MalformedBadStatedReason, d.off(), 0, 0)
	}
	if s.JudgedBlock, err = d.u64(part); err != nil {
		return nil, err
	}
	if s.JudgedHash, err = d.b32(part); err != nil {
		return nil, err
	}
	nf, err := d.count(PartFailures, lim.MaxFailures)
	if err != nil {
		return nil, err
	}
	s.Failures = make([]ProviderFailure, 0, nf)
	for i := 0; i < nf; i++ {
		var f ProviderFailure
		if f.Host, err = d.str(part, PartFailures, lim.MaxText); err != nil {
			return nil, err
		}
		if f.Error, err = d.str(part, PartFailures, lim.MaxText); err != nil {
			return nil, err
		}
		s.Failures = append(s.Failures, f)
	}
	if s.Detail, err = d.str(part, PartFailures, lim.MaxText); err != nil {
		return nil, err
	}
	return s, nil
}

func (d *decoder) attest(lim Limits) (*AttestProof, error) {
	a := &AttestProof{}
	var err error
	if a.Link, err = d.u8(PartAttest); err != nil {
		return nil, err
	}
	if a.Link > LinkSpine {
		return nil, Malformed(PartAttest, MalformedUnknownLink, d.off(), 0, 0)
	}
	if a.HeaderV, err = d.lp(PartAttest, lim.MaxHeaderBytes); err != nil {
		return nil, err
	}
	if a.HeaderVParent, err = d.lp(PartAttest, lim.MaxHeaderBytes); err != nil {
		return nil, err
	}
	switch a.Link {
	case LinkHops:
		if a.HopHeaders, err = d.headers(PartHopHeaders, lim.MaxAttestHops, lim.MaxHeaderBytes); err != nil {
			return nil, err
		}
	case LinkSpine:
		if a.Spine, err = d.headers(PartSpine, lim.MaxAttestSpine, lim.MaxHeaderBytes); err != nil {
			return nil, err
		}
	}
	if a.TxIndex, err = d.u32(PartAttest); err != nil {
		return nil, err
	}
	if a.TxLeaf, err = d.lp(PartAttest, lim.MaxLeafBytes); err != nil {
		return nil, err
	}
	if a.ReceiptLeaf, err = d.lp(PartAttest, lim.MaxLeafBytes); err != nil {
		return nil, err
	}
	nt, err := d.count(PartBlockTxs, lim.MaxBlockTxs)
	if err != nil {
		return nil, err
	}
	a.BlockTxs = make([][]byte, 0, nt)
	total := 0
	for i := 0; i < nt; i++ {
		t, err := d.lp(PartBlockTxs, lim.MaxBlockTxsBytes)
		if err != nil {
			return nil, err
		}
		total += len(t)
		if total > lim.MaxBlockTxsBytes {
			return nil, TooLarge(PartBlockTxs, uint64(total), uint64(lim.MaxBlockTxsBytes))
		}
		a.BlockTxs = append(a.BlockTxs, t)
	}
	return a, nil
}

func (d *decoder) headers(part string, limit, maxBytes int) ([][]byte, error) {
	n, err := d.count(part, limit)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		h, err := d.lp(part, maxBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// CheckStatedReasons is the verifier rule of step 1c(b) / 15 [r3.2:E-f]: a Stated part whose reason is not one of the six builder reasons
// (Item 4, 'Stated reason (builders)') is evidence_malformed{part,reason:unknown_stated_reason}. Decode checks the syntax only, so that
// encode(decode(x)) == x holds for every accepted container; the closed list is applied here, like nodes_unreferenced. The first such
// part (settle, then attest) is reported; nil when every Stated reason is a builder reason.
func (c *Container) CheckStatedReasons() *StateError {
	for _, p := range []struct {
		part string
		p    Part
	}{{PartSettle, c.Settle}, {PartAttest, c.Attest}} {
		if p.p.Tag == TagStated && p.p.Stated != nil && !Check("stated_reason_builders", p.p.Stated.Reason) {
			return Malformed(p.part, MalformedUnknownStatedReason, 0, 0, 0)
		}
	}
	return nil
}

// ---- encoding ----

// Encode is the canonical encoding of c. It refuses, with the same named states Decode raises, a container that Decode would refuse: an
// unordered or duplicate code or node set, a Stated part with a bad state or reason, a bound exceeded, a link that disagrees with the
// hop and spine lists. A container that Encode returns therefore always decodes under lim to an equal container.
func Encode(c *Container, lim Limits) ([]byte, error) {
	if c == nil {
		return nil, Malformed(PartContainer, MalformedTruncated, 0, 0, 0)
	}
	if err := c.validate(lim); err != nil {
		return nil, err
	}
	out := EncodeUnvalidated(c)
	if len(out) > lim.MaxContainerBytes {
		return nil, TooLarge(PartContainer, uint64(len(out)), uint64(lim.MaxContainerBytes))
	}
	return out, nil
}

// EncodeUnvalidated writes the grammar with no validation at all. It exists to build the hostile containers of the published vector sets
// (unordered nodes, a bound exceeded, a bad tag) and the fuzz seeds; a verifier or a capture must never call it, and
// TestEncodeUnvalidatedIsOnlyForVectors keeps that claim: every container it writes that Encode refuses, Decode refuses too.
func EncodeUnvalidated(c *Container) []byte {
	var w finality.Writer
	w.Fixed([]byte(Magic))
	w.STR(Kind)
	w.U64(c.Chain)
	w.U64(c.Leg.Number)
	w.B32(c.Leg.Hash)
	w.Count(len(c.Codes))
	for _, code := range c.Codes {
		w.Fixed(code.Address[:])
		w.LP(code.Runtime)
	}
	putPart(&w, c.Settle, false)
	putPart(&w, c.Attest, true)
	w.LPList(c.Nodes)
	return w.Bytes()
}

func putPart(w *finality.Writer, p Part, isAttest bool) {
	w.U8(uint8(p.Tag))
	switch p.Tag {
	case TagStated:
		s := p.Stated
		if s == nil {
			s = &Stated{}
		}
		w.STR(s.State)
		w.STR(s.Reason)
		w.U64(s.JudgedBlock)
		w.B32(s.JudgedHash)
		w.Count(len(s.Failures))
		for _, f := range s.Failures {
			w.STR(f.Host)
			w.STR(f.Error)
		}
		w.STR(s.Detail)
	case TagCaptured:
		if !isAttest || p.Attest == nil {
			return
		}
		a := p.Attest
		w.U8(a.Link)
		w.LP(a.HeaderV)
		w.LP(a.HeaderVParent)
		switch a.Link {
		case LinkHops:
			w.LPList(a.HopHeaders)
		case LinkSpine:
			w.LPList(a.Spine)
		}
		w.U32(a.TxIndex)
		w.LP(a.TxLeaf)
		w.LP(a.ReceiptLeaf)
		w.LPList(a.BlockTxs)
	}
}

func (c *Container) validate(lim Limits) error {
	if len(c.Codes) > lim.MaxCodes {
		return TooLarge(PartCodes, uint64(len(c.Codes)), uint64(lim.MaxCodes))
	}
	for i, code := range c.Codes {
		if len(code.Runtime) > lim.MaxCodeBytes {
			return TooLarge(PartCodes, uint64(len(code.Runtime)), uint64(lim.MaxCodeBytes))
		}
		if i > 0 {
			switch cmp := bytes.Compare(c.Codes[i-1].Address[:], code.Address[:]); {
			case cmp == 0:
				return Malformed(PartCodes, MalformedCodesDuplicate, i, 0, 0)
			case cmp > 0:
				return Malformed(PartCodes, MalformedCodesNotAscending, i, 0, 0)
			}
		}
	}
	if err := validatePart(PartSettle, c.Settle, lim); err != nil {
		return err
	}
	if err := validatePart(PartAttest, c.Attest, lim); err != nil {
		return err
	}
	if len(c.Nodes) > lim.MaxNodes {
		return TooLarge(PartNodes, uint64(len(c.Nodes)), uint64(lim.MaxNodes))
	}
	var prev [32]byte
	for i, n := range c.Nodes {
		if len(n) > lim.MaxNodeBytes {
			return TooLarge(PartNodes, uint64(len(n)), uint64(lim.MaxNodeBytes))
		}
		h := crypto.Keccak256Hash(n)
		if i > 0 {
			switch cmp := bytes.Compare(prev[:], h[:]); {
			case cmp == 0:
				return Malformed(PartNodes, MalformedNodesDuplicate, i, 0, 0)
			case cmp > 0:
				return Malformed(PartNodes, MalformedNodesNotAscending, i, 0, 0)
			}
		}
		prev = h
	}
	return nil
}

func validatePart(part string, p Part, lim Limits) error {
	switch p.Tag {
	case TagStated:
		if p.Stated == nil || p.Attest != nil {
			return Malformed(part, MalformedUnknownPartTag, 0, 0, 0)
		}
		return validateStated(part, p.Stated, lim)
	case TagCaptured:
		if p.Stated != nil || (part == PartSettle) != (p.Attest == nil) {
			return Malformed(part, MalformedUnknownPartTag, 0, 0, 0)
		}
		if p.Attest != nil {
			return validateAttest(p.Attest, lim)
		}
		return nil
	}
	return Malformed(part, MalformedUnknownPartTag, 0, 0, 0)
}

func checkStr(part, s string, lim Limits) error {
	if len(s) > lim.MaxText {
		return TooLarge(PartFailures, uint64(len(s)), uint64(lim.MaxText))
	}
	if !asciiNoNUL([]byte(s)) {
		return Malformed(part, MalformedStringNotAscii, 0, 0, 0)
	}
	return nil
}

func validateStated(part string, s *Stated, lim Limits) error {
	if err := checkStr(part, s.State, lim); err != nil {
		return err
	}
	if s.State != StatedState {
		return Malformed(part, MalformedBadStatedState, 0, 0, 0)
	}
	if err := checkStr(part, s.Reason, lim); err != nil {
		return err
	}
	if !statedReasonRe.MatchString(s.Reason) {
		return Malformed(part, MalformedBadStatedReason, 0, 0, 0)
	}
	if len(s.Failures) > lim.MaxFailures {
		return TooLarge(PartFailures, uint64(len(s.Failures)), uint64(lim.MaxFailures))
	}
	for _, f := range s.Failures {
		if err := checkStr(part, f.Host, lim); err != nil {
			return err
		}
		if err := checkStr(part, f.Error, lim); err != nil {
			return err
		}
	}
	return checkStr(part, s.Detail, lim)
}

func validateAttest(a *AttestProof, lim Limits) error {
	if a.Link > LinkSpine {
		return Malformed(PartAttest, MalformedUnknownLink, 0, 0, 0)
	}
	if (a.Link != LinkHops && len(a.HopHeaders) != 0) || (a.Link != LinkSpine && len(a.Spine) != 0) {
		return Malformed(PartAttest, MalformedUnknownLink, 0, 0, 0)
	}
	for _, h := range [][]byte{a.HeaderV, a.HeaderVParent} {
		if len(h) > lim.MaxHeaderBytes {
			return TooLarge(PartAttest, uint64(len(h)), uint64(lim.MaxHeaderBytes))
		}
	}
	if len(a.HopHeaders) > lim.MaxAttestHops {
		return TooLarge(PartHopHeaders, uint64(len(a.HopHeaders)), uint64(lim.MaxAttestHops))
	}
	for _, h := range a.HopHeaders {
		if len(h) > lim.MaxHeaderBytes {
			return TooLarge(PartHopHeaders, uint64(len(h)), uint64(lim.MaxHeaderBytes))
		}
	}
	if len(a.Spine) > lim.MaxAttestSpine {
		return TooLarge(PartSpine, uint64(len(a.Spine)), uint64(lim.MaxAttestSpine))
	}
	for _, h := range a.Spine {
		if len(h) > lim.MaxHeaderBytes {
			return TooLarge(PartSpine, uint64(len(h)), uint64(lim.MaxHeaderBytes))
		}
	}
	for _, l := range [][]byte{a.TxLeaf, a.ReceiptLeaf} {
		if len(l) > lim.MaxLeafBytes {
			return TooLarge(PartAttest, uint64(len(l)), uint64(lim.MaxLeafBytes))
		}
	}
	if len(a.BlockTxs) > lim.MaxBlockTxs {
		return TooLarge(PartBlockTxs, uint64(len(a.BlockTxs)), uint64(lim.MaxBlockTxs))
	}
	total := 0
	for _, t := range a.BlockTxs {
		if len(t) > lim.MaxBlockTxsBytes {
			return TooLarge(PartBlockTxs, uint64(len(t)), uint64(lim.MaxBlockTxsBytes))
		}
		total += len(t)
	}
	if total > lim.MaxBlockTxsBytes {
		return TooLarge(PartBlockTxs, uint64(total), uint64(lim.MaxBlockTxsBytes))
	}
	return nil
}
