// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// PinsFormat is the format string of the pins file (V2_SPEC_S7 section 4.1).
const PinsFormat = "certen-finality-pins/1"

// PinsSHA256 is the SHA-256 of the embedded pins file. A verifier refuses to start (finality_pins_corrupt) if the embedded
// bytes hash otherwise; CI job finality-pins-sync compares this constant and the file across the three repositories.
const PinsSHA256 = "507d72b3499fd094f3e14e0ed585edba90c7a7a4c6235c7ccd98d04db7329cca"

//go:embed pins/finality-pins.json
var embeddedPins []byte

// EmbeddedPinsBytes returns a copy of the embedded pins file.
func EmbeddedPinsBytes() []byte { return append([]byte(nil), embeddedPins...) }

// PinsSource values (the report's pins_source).
const PinsSourceEmbedded = "embedded"

// ForkPin is one row of the Sepolia fork table; Layout is nil for the forks no evidence object can belong to.
type ForkPin struct {
	Name    string  `json:"name"`
	Epoch   uint64  `json:"epoch"`
	Version string  `json:"version"`
	Layout  *string `json:"layout"`
}

// AnchorPin is one entry of the Sepolia ledger (4.3): a configured weak-subjectivity pin, not evidence about any block.
type AnchorPin struct {
	Period        uint64   `json:"period"`
	CommitteeRoot string   `json:"committee_root"`
	BlockRoot     string   `json:"block_root,omitempty"`
	WspEpochs     uint64   `json:"wsp_epochs"`
	LinkSHA256    string   `json:"link_sha256"`
	DerivedBy     []string `json:"derived_by"`
}

// EthSepoliaPins is the Sepolia network section of 4.2.
type EthSepoliaPins struct {
	ChainID               uint64      `json:"chain_id"`
	GenesisValidatorsRoot string      `json:"genesis_validators_root"`
	GenesisTime           uint64      `json:"genesis_time"`
	Forks                 []ForkPin   `json:"forks"`
	Spec                  string      `json:"spec"`
	SyncCommitteeSize     int         `json:"sync_committee_size"`
	MinParticipants       int         `json:"min_participants"`
	EpochsPerPeriod       uint64      `json:"epochs_per_period"`
	MaxLinks              int         `json:"max_links"`
	MaxSpineHeaders       int         `json:"max_spine_headers"`
	Anchors               []AnchorPin `json:"anchors"`
}

// OnchainCommitment is the optional on-chain commitment of the file hash (D3).
type OnchainCommitment struct {
	Chain uint64 `json:"chain"`
	Tx    string `json:"tx"`
	Block uint64 `json:"block"`
}

// Pins are the parsed trust inputs of S7 (the pins file). They are configuration, never evidence: a pin proves nothing about
// any block by itself. The other chains' sections (base_sepolia, arb_sepolia, adiri) are accepted when present and kept raw
// for their own packages (RB11-D..F); the loader accepts an absent section and refuses an unknown top-level key.
type Pins struct {
	Format            string
	PublishedUTC      string
	OnchainCommitment *OnchainCommitment
	EthSepolia        *EthSepoliaPins
	Sections          map[string]json.RawMessage // base_sepolia, arb_sepolia, adiri: raw, parsed by their chain packages

	sum    [32]byte
	source string
}

type pinsFile struct {
	Format            string             `json:"format"`
	PublishedUTC      string             `json:"published_utc"`
	OnchainCommitment *OnchainCommitment `json:"onchain_commitment"`
	EthSepolia        *EthSepoliaPins    `json:"eth_sepolia"`
	BaseSepolia       json.RawMessage    `json:"base_sepolia"`
	ArbSepolia        json.RawMessage    `json:"arb_sepolia"`
	Adiri             json.RawMessage    `json:"adiri"`
}

// SHA256 is the hash of the raw bytes this Pins was loaded from.
func (p *Pins) SHA256() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.sum
}

// Identity returns (pins_sha256 hex, pins_source) for a report. A nil Pins is ("", "none").
func (p *Pins) Identity() (string, string) {
	if p == nil {
		return "", "none"
	}
	return hex.EncodeToString(p.sum[:]), p.source
}

// LoadPins hash-checks raw against want and parses it. A mismatch, or a file that does not parse, is
// finality_pins_corrupt: a verifier given such a file refuses to start.
func LoadPins(raw []byte, want [32]byte) (*Pins, error) {
	got := sha256.Sum256(raw)
	if got != want {
		return nil, PinsCorrupt("sha256 mismatch", "want_sha256", want, "got_sha256", got)
	}
	return parsePins(raw, got, PinsSourceEmbedded)
}

// ParsePinsOverride parses a pins file handed to the verifier (--pins) with no expected hash; the report states
// pins_source = override:<sha256>.
func ParsePinsOverride(raw []byte) (*Pins, error) {
	sum := sha256.Sum256(raw)
	return parsePins(raw, sum, "override:"+hex.EncodeToString(sum[:]))
}

// EmbeddedPins loads the embedded pins file against the PinsSHA256 constant.
func EmbeddedPins() (*Pins, error) {
	want, err := hex.DecodeString(PinsSHA256)
	if err != nil || len(want) != 32 {
		return nil, PinsCorrupt("PinsSHA256 constant is not 32 bytes of hex")
	}
	return LoadPins(embeddedPins, [32]byte(want))
}

func parsePins(raw []byte, sum [32]byte, source string) (*Pins, error) {
	if !utf8.Valid(raw) {
		return nil, PinsCorrupt("not UTF-8")
	}
	if bytes.ContainsRune(raw, '\r') {
		return nil, PinsCorrupt("contains CR: the file is LF only")
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, PinsCorrupt("starts with a byte order mark")
	}
	if err := checkSortedKeys(raw); err != nil {
		return nil, PinsCorrupt(err.Error())
	}
	var f pinsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, PinsCorrupt("does not parse: " + err.Error())
	}
	if f.Format != PinsFormat {
		return nil, PinsCorrupt(fmt.Sprintf("format is %q, want %q", f.Format, PinsFormat))
	}
	if f.PublishedUTC == "" {
		return nil, PinsCorrupt("published_utc is empty")
	}
	p := &Pins{Format: f.Format, PublishedUTC: f.PublishedUTC, OnchainCommitment: f.OnchainCommitment, EthSepolia: f.EthSepolia, sum: sum, source: source}
	for name, r := range map[string]json.RawMessage{"base_sepolia": f.BaseSepolia, "arb_sepolia": f.ArbSepolia, "adiri": f.Adiri} {
		if len(r) > 0 && string(r) != "null" {
			if p.Sections == nil {
				p.Sections = map[string]json.RawMessage{}
			}
			p.Sections[name] = r
		}
	}
	if p.EthSepolia != nil {
		if err := p.EthSepolia.validate(); err != nil {
			return nil, PinsCorrupt("eth_sepolia: " + err.Error())
		}
	}
	return p, nil
}

func hexN(s string, n int, prefixed bool) bool {
	if prefixed {
		if !strings.HasPrefix(s, "0x") {
			return false
		}
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && s == strings.ToLower(s)
}

func (e *EthSepoliaPins) validate() error {
	if e.ChainID != ChainSepolia {
		return fmt.Errorf("chain_id is %d, want %d", e.ChainID, ChainSepolia)
	}
	if !hexN(e.GenesisValidatorsRoot, 32, true) {
		return fmt.Errorf("genesis_validators_root is not 0x + 32 bytes of lowercase hex")
	}
	if e.SyncCommitteeSize <= 0 || e.MinParticipants <= 0 || e.MinParticipants*3 < e.SyncCommitteeSize*2 || e.MinParticipants > e.SyncCommitteeSize {
		return fmt.Errorf("min_participants %d of sync_committee_size %d is not a two-thirds floor", e.MinParticipants, e.SyncCommitteeSize)
	}
	if e.EpochsPerPeriod == 0 || e.MaxLinks <= 0 || e.MaxSpineHeaders <= 0 {
		return fmt.Errorf("epochs_per_period, max_links and max_spine_headers must be positive")
	}
	if len(e.Forks) == 0 {
		return fmt.Errorf("the fork table is empty")
	}
	for i, f := range e.Forks {
		if f.Name == "" || !hexN(f.Version, 4, true) {
			return fmt.Errorf("fork %d (%q): name empty or version not 0x + 4 bytes", i, f.Name)
		}
		if i > 0 && f.Epoch <= e.Forks[i-1].Epoch {
			return fmt.Errorf("fork %q epoch %d does not ascend", f.Name, f.Epoch)
		}
		if f.Layout != nil && *f.Layout != "electra" && *f.Layout != "gloas" {
			return fmt.Errorf("fork %q layout %q is not null, electra or gloas", f.Name, *f.Layout)
		}
	}
	if e.Forks[0].Epoch != 0 {
		return fmt.Errorf("the first fork must start at epoch 0")
	}
	for i, a := range e.Anchors {
		if !hexN(a.CommitteeRoot, 32, true) || (a.BlockRoot != "" && !hexN(a.BlockRoot, 32, true)) || !hexN(a.LinkSHA256, 32, false) {
			return fmt.Errorf("anchor %d (period %d): a root or hash is malformed", i, a.Period)
		}
		if i > 0 && a.Period <= e.Anchors[i-1].Period {
			return fmt.Errorf("anchor periods must ascend (%d after %d)", a.Period, e.Anchors[i-1].Period)
		}
		if a.WspEpochs == 0 || len(a.DerivedBy) == 0 {
			return fmt.Errorf("anchor %d (period %d): wsp_epochs and derived_by are required", i, a.Period)
		}
	}
	return nil
}

// Sepolia returns the Sepolia network section, or finality_pin_unknown when the file has none.
func (p *Pins) Sepolia() (*EthSepoliaPins, error) {
	if p == nil || p.EthSepolia == nil {
		return nil, NewState(CodePinUnknown, "chain", ChainSepolia, "kind", "eth_sepolia")
	}
	return p.EthSepolia, nil
}

// AnchorFor is the ledger entry chosen for a proof: the latest entry with period <= sigPeriod. An empty ledger, or no entry at
// or below sigPeriod, is finality_pin_unknown{period} (correct until the ledger is filled by RB11-C).
func (e *EthSepoliaPins) AnchorFor(sigPeriod uint64) (AnchorPin, error) {
	var best *AnchorPin
	for i := range e.Anchors {
		if e.Anchors[i].Period <= sigPeriod {
			best = &e.Anchors[i]
		}
	}
	if best == nil {
		return AnchorPin{}, NewState(CodePinUnknown, "chain", ChainSepolia, "kind", "eth_sepolia", "period", sigPeriod)
	}
	return *best, nil
}

// checkSortedKeys requires every object's keys to be strictly ascending (no duplicates) and a single JSON document.
func checkSortedKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			var keys []string
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				keys = append(keys, k)
				if err := walk(); err != nil {
					return err
				}
			}
			if !sort.SliceIsSorted(keys, func(i, j int) bool { return keys[i] < keys[j] }) {
				return fmt.Errorf("object keys are not sorted: %v", keys)
			}
			for i := 1; i < len(keys); i++ {
				if keys[i] == keys[i-1] {
					return fmt.Errorf("duplicate key %q", keys[i])
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token() // closing delimiter
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("data after the JSON document")
	}
	return nil
}
