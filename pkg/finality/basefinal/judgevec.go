// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// JudgeCase is a vector for the part of 5.5 that follows the L1 head: an L1 block A (the header values a covered spine would
// have given), the evidence parts that are not the LC (game proxy, game code, output-root index, L2 spine, proof nodes), the leg
// and the pins. The state root is a SYNTHETIC world's, so a judge case covers every rule of O2-O6 that no live Base game can reach
// (a blacklisted game, a pause, a different template, a fast path ...); the LC and the spine are covered by the live cases. A
// TypeScript verifier runs the same inputs through its equivalent of Judge and must give the same canonical verdict.
type JudgeCase struct {
	Format          string          `json:"format"`
	ID              string          `json:"id"`
	Description     string          `json:"description"`
	Pins            string          `json:"pins"`
	A               JudgeA          `json:"a"`
	Leg             Leg             `json:"leg"`
	GameProxy       string          `json:"game_proxy"`
	GameCode        string          `json:"game_code"`
	OutputRootIndex string          `json:"output_root_index"`
	L2Spine         []string        `json:"l2_spine"`
	Nodes           []string        `json:"nodes"`
	Expect          json.RawMessage `json:"expect"`
}

// JudgeA is the covered L1 block the judgement is "as of".
type JudgeA struct {
	Number    string `json:"number"`
	Hash      string `json:"hash"`
	StateRoot string `json:"state_root"`
	Timestamp string `json:"timestamp"`
}

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

// unhx is the lenient reader JudgeCase.Run used before TSB-2 (it dropped hex errors); Run now loads through loadHex and nothing calls this.
func unhx(s string) []byte {
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return b
}

// NewJudgeCase serialises a synthetic world and its expected canonical verdict.
func NewJudgeCase(id, desc, pins string, o *SynthOut, expect []byte) JudgeCase {
	c := JudgeCase{Format: "certen-finality-judge-vectors/1", ID: id, Description: desc, Pins: pins,
		A:         JudgeA{Number: strconv.FormatUint(o.A.Number, 10), Hash: hx(o.A.Hash[:]), StateRoot: hx(o.A.StateRoot[:]), Timestamp: strconv.FormatUint(o.A.Timestamp, 10)},
		Leg:       Leg{Chain: strconv.FormatUint(o.Leg.Chain, 10), Number: strconv.FormatUint(o.Leg.Number, 10), Hash: hx(o.Leg.Hash[:]), Header: hx(o.Leg.HeaderRLP)},
		GameProxy: hx(o.Body.GameProxy[:]), GameCode: hx(o.Body.GameCode), OutputRootIndex: strconv.FormatUint(uint64(o.Body.OutputRootIndex), 10), Expect: expect}
	for _, h := range o.Body.L2Spine {
		c.L2Spine = append(c.L2Spine, hx(h))
	}
	for _, n := range o.Body.Nodes {
		c.Nodes = append(c.Nodes, hx(n))
	}
	return c
}

// JudgeLoadError is a world that cannot be loaded: a number that is not a decimal of its width, or a byte string that is not
// lower-case hex of an even number of digits (and, for the fixed-size fields, of the right length). It names the field and the value;
// Run returns it instead of judging a different world than the one the file describes.
type JudgeLoadError struct {
	Field string
	Value string
	Want  string
}

func (e *JudgeLoadError) Error() string {
	return fmt.Sprintf("judge case load error: field %s: value %q is not %s", e.Field, e.Value, e.Want)
}

// loadDecimal reads a decimal of at most bits bits: digits only (no sign, no space, no prefix, no underscore), within range.
func loadDecimal(field, s string, bits int) (uint64, error) {
	want := "a decimal uint" + strconv.Itoa(bits)
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &JudgeLoadError{Field: field, Value: s, Want: want}
		}
	}
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, &JudgeLoadError{Field: field, Value: s, Want: want}
	}
	return v, nil
}

// loadHex reads lower-case hex with an optional 0x prefix; size >= 0 fixes the byte length.
func loadHex(field, s string, size int) ([]byte, error) {
	want := "lower-case hex"
	if size >= 0 {
		want += " of " + strconv.Itoa(size) + " bytes"
	}
	h := strings.TrimPrefix(s, "0x")
	for i := 0; i < len(h); i++ {
		if c := h[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, &JudgeLoadError{Field: field, Value: s, Want: want}
		}
	}
	b, err := hex.DecodeString(h)
	if err != nil || (size >= 0 && len(b) != size) {
		return nil, &JudgeLoadError{Field: field, Value: s, Want: want}
	}
	return b, nil
}

// judgeWorld is the loaded form of a JudgeCase.
type judgeWorld struct {
	a    ethl1.L1Block
	body Body
	leg  finality.BlockRef
}

// load reads every number and byte string of the case strictly: nothing is coerced to zero, clamped or cut at a bad digit.
func (c JudgeCase) load() (*judgeWorld, error) {
	w := &judgeWorld{}
	num, err := loadDecimal("a.number", c.A.Number, 64)
	if err != nil {
		return nil, err
	}
	ts, err := loadDecimal("a.timestamp", c.A.Timestamp, 64)
	if err != nil {
		return nil, err
	}
	w.a = ethl1.L1Block{Number: num, Timestamp: ts}
	for _, f := range []struct {
		field string
		s     string
		size  int
		dst   []byte
	}{{"a.hash", c.A.Hash, 32, w.a.Hash[:]}, {"a.state_root", c.A.StateRoot, 32, w.a.StateRoot[:]}} {
		b, err := loadHex(f.field, f.s, f.size)
		if err != nil {
			return nil, err
		}
		copy(f.dst, b)
	}
	idx, err := loadDecimal("output_root_index", c.OutputRootIndex, 32)
	if err != nil {
		return nil, err
	}
	w.body = Body{StateBlock: num, OutputRootIndex: uint32(idx)}
	proxy, err := loadHex("game_proxy", c.GameProxy, 20)
	if err != nil {
		return nil, err
	}
	copy(w.body.GameProxy[:], proxy)
	if w.body.GameCode, err = loadHex("game_code", c.GameCode, -1); err != nil {
		return nil, err
	}
	for i, h := range c.L2Spine {
		b, err := loadHex(fmt.Sprintf("l2_spine[%d]", i), h, -1)
		if err != nil {
			return nil, err
		}
		w.body.L2Spine = append(w.body.L2Spine, b)
	}
	for i, n := range c.Nodes {
		b, err := loadHex(fmt.Sprintf("nodes[%d]", i), n, -1)
		if err != nil {
			return nil, err
		}
		w.body.Nodes = append(w.body.Nodes, b)
	}
	if _, err := loadDecimal("leg.chain", c.Leg.Chain, 64); err != nil {
		return nil, err
	}
	if _, err := loadDecimal("leg.number", c.Leg.Number, 64); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		field string
		s     string
		size  int
	}{{"leg.hash", c.Leg.Hash, 32}, {"leg.header", c.Leg.Header, -1}} {
		if _, err := loadHex(f.field, f.s, f.size); err != nil {
			return nil, err
		}
	}
	w.leg = c.Leg.BlockRef(noopHelper{})
	return w, nil
}

// Run judges the case against a set directory and returns the canonical outcome. A world that cannot be loaded is a *JudgeLoadError.
func (c JudgeCase) Run(dir string) ([]byte, error) {
	pinsRaw, err := ReadFile(dir, c.Pins)
	if err != nil {
		return nil, err
	}
	w, err := c.load()
	if err != nil {
		return nil, err
	}
	fp, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		return CanonicalVerdict(finality.Verdict{}, err), nil
	}
	bp, err := ParsePins(fp)
	if err != nil {
		return CanonicalVerdict(finality.Verdict{}, err), nil
	}
	f, jerr := Judge(bp, w.a, w.body, w.leg, ethl1.FinalizedHead{})
	return CanonicalVerdict(finality.Verdict{Fields: f}, jerr), nil
}

type noopHelper struct{}

func (noopHelper) Helper() {}

var _ = crypto.Keccak256
