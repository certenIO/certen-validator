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

// PublishedSetPinSupply is what the harness adds to the pins files of the published sets finality_base_posted1 (and the pins of
// the synthetic world of finality_base_posted2), which predate two base_sepolia pins: the Granite activation time and the
// post-Granite channel timeout (V2_SPEC_S7 5.4 O4, [r2:D2FIX]). Those sets are never edited, and the verifier has no default for a
// missing pin (it refuses the pins file, finality_pins_corrupt{key:base_sepolia.granite_time}); so the harness supplies the
// published values explicitly. Base Sepolia's real values: granite_time 1723478400 (superchain-registry sepolia/superchain.toml) and
// op-node params.ChannelTimeoutGranite 50. Every live frame of set 1 lies within 50 L1 blocks of its channel's first frame, so the
// set's expected bytes are unchanged. A TypeScript consumer of sets 1 and 2 supplies the same two numbers the same way.
var PublishedSetPinSupply = map[string]uint64{"granite_time": 1723478400, "channel_timeout_granite": 50}

// SupplyBaseSepoliaPins returns the pins file with the given base_sepolia keys added where the file lacks them (a key the file
// has is never overwritten), in the canonical form ParsePinsOverride reads. A file without a base_sepolia section is returned as is.
func SupplyBaseSepoliaPins(pinsRaw []byte, supply map[string]uint64) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(pinsRaw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	sec, ok := m["base_sepolia"].(map[string]any)
	if !ok {
		return pinsRaw, nil
	}
	for k, v := range supply {
		if _, has := sec[k]; !has {
			sec[k] = json.Number(strconv.FormatUint(v, 10))
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Run executes a case against a set directory and returns the canonical outcome; the pins file is read exactly as the set gives it.
func (c Case) Run(dir string) ([]byte, error) { return c.run(dir, nil) }

// RunSupplied is Run for a published set that predates some base_sepolia pins: the harness supplies them (PublishedSetPinSupply).
func (c Case) RunSupplied(dir string, supply map[string]uint64) ([]byte, error) {
	return c.run(dir, supply)
}

func (c Case) run(dir string, supply map[string]uint64) ([]byte, error) {
	if supply == nil {
		return c.RunEdited(dir, nil)
	}
	return c.RunEdited(dir, func(raw []byte) ([]byte, error) { return SupplyBaseSepoliaPins(raw, supply) })
}

// RunEdited is Run with the case's pins file passed through edit first (nil: as it is): a published set judged under pins that gained a
// key after the set was published (the harness never edits the set's files).
func (c Case) RunEdited(dir string, edit func(pinsRaw []byte) ([]byte, error)) ([]byte, error) {
	pinsRaw, err := ReadFile(dir, c.Pins)
	if err != nil {
		return nil, err
	}
	if edit != nil {
		if pinsRaw, err = edit(pinsRaw); err != nil {
			return nil, err
		}
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
