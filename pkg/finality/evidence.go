// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/binary"
	"fmt"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// EvidenceVersion is the container version this package writes and reads. A reader refuses any other
// (finality_evidence_unrecognised): a future layout is a new version, never a reinterpretation of this one.
const EvidenceVersion uint32 = 1

// Subject is the settlement a piece of evidence is about: the block (number and hash) that holds the transaction, and the
// transaction. Every addendum of one chain carries the same Subject.
type Subject struct {
	BlockNumber uint64
	BlockHash   [32]byte
	TxHash      [32]byte
}

// Settlement is what a prover is asked to upgrade and a verifier is asked to judge evidence against: the settlement's
// chain and Subject, and (provers only) the L6 evidence already held for it. Verify never reads Included: the evidence
// carries everything a verifier needs.
type Settlement struct {
	Chain uint64
	Subject
	// Included is today's L6 evidence for the settlement: the block header and the transaction and receipt MPT proofs.
	// It is the input of the included level; a prover of a higher level may also read it.
	Included *ethproof.Settlement
}

// Evidence is the versioned container a prover returns and a verifier consumes.
//
// Canonical encoding (every field in order; "lp" is a 4-byte big-endian length followed by the bytes):
//
//	be32(Version) || lp(Kind) || be64(Subject.BlockNumber) || Subject.BlockHash(32) || Subject.TxHash(32) || lp(Body)
//
// Body is the kind's own payload; its encoding is the chain package's, versioned by Kind.
type Evidence struct {
	Version uint32
	Kind    string
	Subject Subject
	Body    []byte
}

// NewEvidence builds version-1 evidence about s.
func NewEvidence(kind string, s Settlement, body []byte) Evidence {
	return Evidence{Version: EvidenceVersion, Kind: kind, Subject: s.Subject, Body: body}
}

// kindOK reports whether kind is a printable lowercase identifier: [a-z0-9._/-], 1..64 bytes, starting with a letter.
func kindOK(kind string) bool {
	if n := len(kind); n == 0 || n > 64 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		c := kind[i]
		switch {
		case c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '_' || c == '/' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// Encode is the canonical encoding. It refuses an unrecognised version or a malformed kind.
func (e Evidence) Encode() ([]byte, error) {
	if e.Version != EvidenceVersion {
		return nil, NewState(CodeEvidenceUnrecognised, "version", e.Version, "want", EvidenceVersion)
	}
	if !kindOK(e.Kind) {
		return nil, NewState(CodeEvidenceMalformed, "part", "kind", "reason", "not [a-z][a-z0-9._/-]{0,63}", "kind", e.Kind)
	}
	out := make([]byte, 0, 4+4+len(e.Kind)+8+64+4+len(e.Body))
	out = binary.BigEndian.AppendUint32(out, e.Version)
	out = appendLP(out, []byte(e.Kind))
	out = binary.BigEndian.AppendUint64(out, e.Subject.BlockNumber)
	out = append(out, e.Subject.BlockHash[:]...)
	out = append(out, e.Subject.TxHash[:]...)
	out = appendLP(out, e.Body)
	return out, nil
}

// DecodeEvidence parses the canonical encoding strictly: a wrong version, a malformed kind, a short or long field or
// trailing bytes are each a named refusal, and DecodeEvidence(b).Encode() equals b for every b it accepts.
func DecodeEvidence(b []byte) (Evidence, error) {
	r := reader{b: b}
	var e Evidence
	v, ok := r.u32()
	if !ok {
		return e, malformed("version", "truncated", len(b), 4)
	}
	if v != EvidenceVersion {
		return e, NewState(CodeEvidenceUnrecognised, "version", v, "want", EvidenceVersion)
	}
	e.Version = v
	kind, ok := r.lp()
	if !ok {
		return e, malformed("kind", "truncated", r.left(), 0)
	}
	if !kindOK(string(kind)) {
		return e, NewState(CodeEvidenceMalformed, "part", "kind", "reason", "not [a-z][a-z0-9._/-]{0,63}")
	}
	e.Kind = string(kind)
	n, ok := r.u64()
	if !ok {
		return e, malformed("subject.blockNumber", "truncated", r.left(), 8)
	}
	e.Subject.BlockNumber = n
	if !r.fixed(e.Subject.BlockHash[:]) {
		return e, malformed("subject.blockHash", "truncated", r.left(), 32)
	}
	if !r.fixed(e.Subject.TxHash[:]) {
		return e, malformed("subject.txHash", "truncated", r.left(), 32)
	}
	body, ok := r.lp()
	if !ok {
		return e, malformed("body", "truncated", r.left(), 0)
	}
	e.Body = append([]byte(nil), body...)
	if r.left() != 0 {
		return e, malformed("end", "trailing bytes", r.left(), 0)
	}
	return e, nil
}

func malformed(part, reason string, got, want int) *State {
	return NewState(CodeEvidenceMalformed, "part", part, "reason", reason, "got_len", got, "want_len", want)
}

func appendLP(out, b []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) left() int { return len(r.b) - r.off }

func (r *reader) u32() (uint32, bool) {
	if r.left() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *reader) u64() (uint64, bool) {
	if r.left() < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v, true
}

func (r *reader) fixed(dst []byte) bool {
	if r.left() < len(dst) {
		return false
	}
	copy(dst, r.b[r.off:r.off+len(dst)])
	r.off += len(dst)
	return true
}

// lp reads a 4-byte length and that many bytes. The length is checked against what remains before anything is sliced.
func (r *reader) lp() ([]byte, bool) {
	n, ok := r.u32()
	if !ok || uint64(n) > uint64(r.left()) {
		return nil, false
	}
	out := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return out, true
}

// String is a short rendering for logs.
func (s Subject) String() string {
	return fmt.Sprintf("block %d %x tx %x", s.BlockNumber, s.BlockHash[:4], s.TxHash[:4])
}
