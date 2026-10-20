// Copyright 2026 Certen Protocol

// Package basefinal is the base-sepolia/finalized/v1 kind of V2_SPEC_S7 (section 5.5): an AggregateVerifier game (type 621)
// replayed through AnchorStateRegistry.isGameClaimValid from L1 storage proofs at a finalized L1 block A, an output root
// recomputed from an L2 header, and an L2 header spine down to the leg's block. Verify is pure (no I/O, no clock, no
// randomness). The builder (build.go, capture.go, live.go) is the online half: it captures proofs near the L1 head, waits for
// the L1 finalized head to cover A, assembles the container and calls Verify before returning it.
package basefinal

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The names this kind judges under.
const (
	KindName = "base-sepolia/finalized/v1"
	Chain    = finality.ChainBaseSepolia
)

// The roles of impl_pins and proxy_pins rows (V2_SPEC_S7 section 4.2).
const (
	RoleGameImpl       = "game_impl"
	RoleASRImpl        = "asr_impl"
	RolePortalImpl     = "portal_impl"
	RoleSysCfgImpl     = "syscfg_impl"
	RoleDGFImpl        = "dgf_impl"
	RoleSuperchainImpl = "superchain_impl"
	RoleOPProxy        = "op_proxy"
	RoleSuperchainPrx  = "superchain_proxy"
	LayoutAggregateV1  = "aggregate_v1"
)

// ImplRow is one impl_pins row (append-only: codeHash -> role and the decoded immutables the predicates need).
type ImplRow struct {
	Role string
	// game_impl
	GameType      uint32
	Version       string
	Impl          [20]byte
	CWIA          string
	NIntermediate int
	ArgsLen       int
	IntervalPairs [][2]uint64 // {total blocks of the game, intermediate interval}
	SlowDelay     uint64
	FastDelay     uint64
	// game_impl: the AnchorStateRegistry (and, when pinned, the DisputeGameFactory) the pinned build is made for
	ASR [20]byte
	DGF [20]byte
	// asr_impl
	FinalityDelaySeconds *uint64
}

// GameLayout is the game_layout row: the clone template (V2_SPEC_S7 5.5 O3, B30 Q2) and the game slots.
type GameLayout struct {
	CloneHead   []byte // 54 bytes
	CloneMid    []byte // 9 bytes
	CloneTail   []byte // 13 bytes
	ArgsBaseLen int    // 0x88
	ArgsPerRoot int    // 0x20
}

// Pins are the base_sepolia pieces of finality-pins.json this kind reads. Keys other kinds add (batch inbox, channel and KZG
// values) are ignored here.
type Pins struct {
	ChainID      uint64
	L1ChainID    uint64
	Portal       [20]byte
	SystemConfig [20]byte
	MaxL2Headers int
	Impl         map[[32]byte]ImplRow
	Proxy        map[[32]byte]string
	Layouts      map[string]GameLayout
}

type rawRow struct {
	Role          string      `json:"role"`
	GameType      *uint32     `json:"game_type"`
	Version       string      `json:"version"`
	ImplAddr      string      `json:"impl"`
	CWIA          string      `json:"cwia"`
	NIntermediate int         `json:"n_intermediate"`
	ArgsLen       int         `json:"args_len"`
	IntervalPairs [][2]uint64 `json:"interval_pairs"`
	SlowDelay     uint64      `json:"slow_finalization_delay"`
	FastDelay     uint64      `json:"fast_finalization_delay"`
	FinalityDelay *uint64     `json:"finality_delay_seconds"`
	ASRAddr       string      `json:"asr"`
	DGFAddr       string      `json:"dgf"`
}

type rawLayout struct {
	CloneHead   string `json:"clone_head"`
	CloneMid    string `json:"clone_mid"`
	CloneTail   string `json:"clone_tail"`
	ArgsBaseLen int    `json:"args_base_len"`
	ArgsPerRoot int    `json:"args_per_root"`
}

type rawBase struct {
	ChainID      uint64                     `json:"chain_id"`
	L1ChainID    uint64                     `json:"l1_chain_id"`
	Portal       string                     `json:"portal"`
	SystemConfig string                     `json:"system_config"`
	MaxL2Headers int                        `json:"max_l2_headers"`
	ImplPins     map[string]json.RawMessage `json:"impl_pins"`
	ProxyPins    map[string]json.RawMessage `json:"proxy_pins"`
	GameLayout   map[string]rawLayout       `json:"game_layout"`
}

// The game args the judge and the builder index: the fixed part up to the parent address at [116,136), and one 32-byte root per
// intermediate root. A layout that cannot hold them is refused when the pins are read.
const (
	minArgsBaseLen = 136
	minArgsPerRoot = 32
)

func unhex(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil && len(b) == n
}

// ParsePins reads the base_sepolia section of the framework pins. An absent section is finality_pin_unknown; a malformed one is
// finality_pins_corrupt{bad_value, key}. A game_impl row that does not carry everything the predicates of 5.5 need is treated
// as ABSENT (the rule of V2_SPEC_S7 4.2 for every game_impl row): it is not an error of the file, the implementation then
// stays contract_identity_unproven.
func ParsePins(p *finality.Pins) (*Pins, error) {
	var raw json.RawMessage
	if p != nil {
		raw = p.Sections["base_sepolia"]
	}
	if len(raw) == 0 {
		return nil, finality.NewState(finality.CodePinUnknown, "chain", uint64(Chain), "kind", "base_sepolia")
	}
	var r rawBase
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia")
	}
	bad := func(key string) error { return finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia."+key) }
	out := &Pins{ChainID: r.ChainID, L1ChainID: r.L1ChainID, MaxL2Headers: r.MaxL2Headers,
		Impl: map[[32]byte]ImplRow{}, Proxy: map[[32]byte]string{}, Layouts: map[string]GameLayout{}}
	if r.ChainID != uint64(Chain) {
		return nil, bad("chain_id")
	}
	if r.L1ChainID != ethl1.SepoliaChainID {
		return nil, bad("l1_chain_id")
	}
	if b, ok := unhex(r.Portal, 20); ok {
		copy(out.Portal[:], b)
	} else {
		return nil, bad("portal")
	}
	if b, ok := unhex(r.SystemConfig, 20); ok {
		copy(out.SystemConfig[:], b)
	} else {
		return nil, bad("system_config")
	}
	if r.MaxL2Headers <= 0 {
		return nil, bad("max_l2_headers")
	}
	for k, row := range r.ImplPins {
		h, ok := unhex(k, 32)
		if !ok || [32]byte(h) == ([32]byte{}) { // no deployed code hashes to zero: an absent account would look pinned
			return nil, bad("impl_pins")
		}
		var rr rawRow
		if err := json.Unmarshal(row, &rr); err != nil || rr.Role == "" {
			return nil, bad("impl_pins")
		}
		ir := ImplRow{Role: rr.Role, Version: rr.Version, CWIA: rr.CWIA, NIntermediate: rr.NIntermediate, ArgsLen: rr.ArgsLen,
			IntervalPairs: rr.IntervalPairs, SlowDelay: rr.SlowDelay, FastDelay: rr.FastDelay, FinalityDelaySeconds: rr.FinalityDelay}
		if rr.GameType != nil {
			ir.GameType = *rr.GameType
		}
		if a, ok := unhex(rr.ImplAddr, 20); ok {
			copy(ir.Impl[:], a)
		}
		if a, ok := unhex(rr.ASRAddr, 20); ok {
			copy(ir.ASR[:], a)
		}
		if a, ok := unhex(rr.DGFAddr, 20); ok {
			copy(ir.DGF[:], a)
		}
		out.Impl[[32]byte(h)] = ir
	}
	for k, row := range r.ProxyPins {
		h, ok := unhex(k, 32)
		if !ok || [32]byte(h) == ([32]byte{}) {
			return nil, bad("proxy_pins")
		}
		var rr rawRow
		if err := json.Unmarshal(row, &rr); err != nil || rr.Role == "" {
			return nil, bad("proxy_pins")
		}
		out.Proxy[[32]byte(h)] = rr.Role
	}
	for name, l := range r.GameLayout {
		head, ok1 := hexBytes(l.CloneHead)
		mid, ok2 := hexBytes(l.CloneMid)
		tail, ok3 := hexBytes(l.CloneTail)
		if !ok1 || !ok2 || !ok3 || l.ArgsBaseLen < minArgsBaseLen || l.ArgsPerRoot < minArgsPerRoot {
			return nil, bad("game_layout")
		}
		out.Layouts[name] = GameLayout{CloneHead: head, CloneMid: mid, CloneTail: tail, ArgsBaseLen: l.ArgsBaseLen, ArgsPerRoot: l.ArgsPerRoot}
	}
	return out, nil
}

func hexBytes(s string) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil
}

// Complete reports whether a game_impl row carries every decoded immutable, the CWIA layout and the interval semantics the
// predicates of 5.5 need (V2_SPEC_S7 4.2 rule: an incomplete row is treated as absent).
func (r ImplRow) Complete(layouts map[string]GameLayout) bool {
	if r.Role != RoleGameImpl || r.GameType == 0 || r.Version == "" || r.Impl == [20]byte{} || r.ASR == [20]byte{} || r.NIntermediate <= 0 || len(r.IntervalPairs) == 0 || r.SlowDelay == 0 || r.FastDelay == 0 {
		return false
	}
	l, ok := layouts[r.CWIA]
	if !ok || r.ArgsLen != l.ArgsBaseLen+l.ArgsPerRoot*r.NIntermediate {
		return false
	}
	for _, p := range r.IntervalPairs {
		if p[0] == 0 || p[1] == 0 || p[0]%p[1] != 0 {
			return false
		}
	}
	return true
}

// ethl1Pins converts the framework's Sepolia section into the L1 head verifier's pins.
func ethl1Pins(e *finality.EthSepoliaPins) ethl1.Pins {
	var p ethl1.Pins
	p.Network.ChainID = e.ChainID
	gvr, _ := unhex(e.GenesisValidatorsRoot, 32)
	copy(p.Network.GenesisValidatorsRoot[:], gvr)
	for _, f := range e.Forks {
		fk := ethl1.Fork{Name: f.Name, Epoch: f.Epoch}
		v, _ := unhex(f.Version, 4)
		copy(fk.Version[:], v)
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				fk.Layout = ethl1.LayoutElectra
			case "gloas":
				fk.Layout = ethl1.LayoutGloas
			}
		}
		p.Network.Forks = append(p.Network.Forks, fk)
	}
	for _, a := range e.Anchors {
		an := ethl1.Anchor{Period: a.Period, WSPEpochs: a.WspEpochs}
		cr, _ := unhex(a.CommitteeRoot, 32)
		copy(an.CommitteeRoot[:], cr)
		if a.BlockRoot != "" {
			br, _ := unhex(a.BlockRoot, 32)
			var b32 [32]byte
			copy(b32[:], br)
			an.BlockRoot = &b32
		}
		p.Anchors = append(p.Anchors, an)
	}
	p.MinParticipants, p.MaxLinks, p.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return p
}

// EthL1Pins is the L1 head verifier's view of the framework pins (used by the builder and the vector generator).
func EthL1Pins(p *finality.Pins) ethl1.Pins {
	e, err := p.Sepolia()
	if err != nil {
		return ethl1.Pins{}
	}
	return ethl1Pins(e)
}

// stateOf adapts an L1 head fault to the framework's StateError with the same code and fields.
func stateOf(err error) error {
	if f, ok := err.(*ethl1.Fault); ok {
		s := finality.NewState(f.Code)
		for k, v := range f.Fields {
			s.Fields[k] = v
		}
		return s
	}
	return err
}

// sortedImplHashes is the deterministic order of the impl_pins rows (used by the pins writer and tests).
func sortedImplHashes(m map[[32]byte]ImplRow) [][32]byte {
	out := make([][32]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out
}
