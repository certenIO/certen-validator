// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/hex"
	"encoding/json"
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

// Run judges the case against a set directory and returns the canonical outcome.
func (c JudgeCase) Run(dir string) ([]byte, error) {
	pinsRaw, err := ReadFile(dir, c.Pins)
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
	num, _ := strconv.ParseUint(c.A.Number, 10, 64)
	ts, _ := strconv.ParseUint(c.A.Timestamp, 10, 64)
	a := ethl1.L1Block{Number: num, Timestamp: ts}
	copy(a.Hash[:], unhx(c.A.Hash))
	copy(a.StateRoot[:], unhx(c.A.StateRoot))
	idx, _ := strconv.ParseUint(c.OutputRootIndex, 10, 32)
	body := Body{StateBlock: num, GameCode: unhx(c.GameCode), OutputRootIndex: uint32(idx)}
	copy(body.GameProxy[:], unhx(c.GameProxy))
	for _, h := range c.L2Spine {
		body.L2Spine = append(body.L2Spine, unhx(h))
	}
	for _, n := range c.Nodes {
		body.Nodes = append(body.Nodes, unhx(n))
	}
	leg := c.Leg.BlockRef(noopHelper{})
	f, jerr := Judge(bp, a, body, leg, ethl1.FinalizedHead{})
	return CanonicalVerdict(finality.Verdict{Fields: f}, jerr), nil
}

type noopHelper struct{}

func (noopHelper) Helper() {}

var _ = crypto.Keccak256
