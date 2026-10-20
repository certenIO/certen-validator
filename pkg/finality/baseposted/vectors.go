// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
)

// SetName is the published vector set of this kind.
const SetName = "finality_base_posted1"

// Splice replaces evidence[Offset:Offset+Delete] with Insert (a hex string): the whole difference between a case and the base
// evidence it names, so the set stores the real evidence once.
type Splice struct {
	Offset uint64 `json:"offset"`
	Delete uint64 `json:"delete"`
	Insert string `json:"insert"`
}

// Case is one vector: the pins file, the leg (the L2 block header), the evidence (a base file plus an optional splice) and the
// expected canonical verdict.
type Case struct {
	Format      string          `json:"format"`
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Pins        string          `json:"pins"`
	Leg         string          `json:"leg"`
	Base        string          `json:"evidence"`
	Splice      *Splice         `json:"splice,omitempty"`
	Expect      json.RawMessage `json:"expect"`
}

// Leg is the leg block of a case: the L2 header that is Settlement.Header.
type Leg struct {
	Chain  string `json:"chain"`
	Number string `json:"number"`
	Hash   string `json:"hash"`
	Header string `json:"header"`
}

// Expect is the expected verdict: result "ok" with the canonical verdict fields, or "state" with the code and canonical fields.
type Expect struct {
	Result string          `json:"result"`
	Code   string          `json:"code,omitempty"`
	Fields json.RawMessage `json:"fields"`
}

// Diff is the minimal splice that turns base into mut.
func Diff(base, mut []byte) *Splice {
	if bytes.Equal(base, mut) {
		return nil
	}
	p := 0
	for p < len(base) && p < len(mut) && base[p] == mut[p] {
		p++
	}
	s := 0
	for s < len(base)-p && s < len(mut)-p && base[len(base)-1-s] == mut[len(mut)-1-s] {
		s++
	}
	return &Splice{Offset: uint64(p), Delete: uint64(len(base) - p - s), Insert: "0x" + hex.EncodeToString(mut[p:len(mut)-s])}
}

// Apply returns base with the splice applied.
func (s *Splice) Apply(base []byte) ([]byte, error) {
	if s == nil {
		return append([]byte(nil), base...), nil
	}
	ins, err := hex.DecodeString(strings.TrimPrefix(s.Insert, "0x"))
	if err != nil {
		return nil, err
	}
	if s.Offset+s.Delete > uint64(len(base)) {
		return nil, fmt.Errorf("splice beyond the evidence")
	}
	out := append([]byte(nil), base[:s.Offset]...)
	out = append(out, ins...)
	return append(out, base[s.Offset+s.Delete:]...), nil
}

// CanonicalVerdict renders a verification outcome exactly as the expected verdicts are written: for a state
// {"code":...,"fields":{...}}; for a verdict {"fields":{...},"result":"ok"} (sorted keys, integers as decimal strings, bytes as
// 0x hex), so the Go and TypeScript verifiers compare bytes.
func CanonicalVerdict(v finality.Verdict, err error) []byte {
	if err != nil {
		if se, ok := finality.AsNamed(err); ok {
			return se.Canonical()
		}
		return finality.NewState("go_error", "text", err.Error()).Canonical()
	}
	c := finality.NewState("ok")
	c.Fields = v.Fields
	var m struct {
		Fields json.RawMessage `json:"fields"`
	}
	_ = json.Unmarshal(c.Canonical(), &m)
	return []byte(`{"fields":` + string(m.Fields) + `,"result":"ok"}`)
}

// ExpectBytes renders an Expect in the canonical form CanonicalVerdict produces.
func ExpectBytes(e Expect) []byte {
	var cf bytes.Buffer
	if err := json.Compact(&cf, e.Fields); err == nil {
		e.Fields = cf.Bytes()
	}
	if e.Result == "ok" {
		return []byte(`{"fields":` + string(e.Fields) + `,"result":"ok"}`)
	}
	return []byte(`{"code":` + strconv.Quote(e.Code) + `,"fields":` + string(e.Fields) + `}`)
}

// ReadFile reads a set member.
func ReadFile(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
}

// Run executes a case against a set directory and returns the canonical outcome.
func (c Case) Run(dir string) ([]byte, error) {
	pinsRaw, err := ReadFile(dir, c.Pins)
	if err != nil {
		return nil, err
	}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		return CanonicalVerdict(finality.Verdict{}, err), nil
	}
	legRaw, err := ReadFile(dir, c.Leg)
	if err != nil {
		return nil, err
	}
	var leg Leg
	if err := json.Unmarshal(legRaw, &leg); err != nil {
		return nil, err
	}
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	hdr, _ := hex.DecodeString(strings.TrimPrefix(leg.Header, "0x"))
	h, _ := hex.DecodeString(strings.TrimPrefix(leg.Hash, "0x"))
	var hash [32]byte
	copy(hash[:], h)
	base, err := ReadFile(dir, c.Base)
	if err != nil {
		return nil, err
	}
	ev, err := c.Splice.Apply(base)
	if err != nil {
		return nil, err
	}
	v, verr := Kind{}.Verify(pins, finality.BlockRef{Chain: uint64(Chain), Number: num, Hash: hash, HeaderRLP: hdr}, ev)
	return CanonicalVerdict(v, verr), nil
}

// FileSHA256 is the hex SHA-256 of bytes.
func FileSHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
