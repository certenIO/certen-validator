// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// PinsFormat is the format string of the pins file (V2_SPEC_S7 section 4.1).
const PinsFormat = "certen-finality-pins/1"

// PinsSHA256 is the SHA-256 of the embedded pins file. A verifier refuses to start (finality_pins_corrupt) if the embedded
// bytes hash otherwise; CI job finality-pins-sync compares this constant and the file across the three repositories
// (.github/workflows/finality-pins-sync.yml here; the comparison is scripts/finality-pins-sync.mjs of certen-contracts, which publishes the file).
const PinsSHA256 = "fdba733e7fc4206d96d73c87352834c51801ee8fe0af76d60654cb461fbd5440"

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
	ChainID               uint64 `json:"chain_id"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisTime           uint64 `json:"genesis_time"`
	// KZGSetupSHA256 is the LEGACY location of the KZG setup pin (pins files published with finality_arb_posted1). The embedded file
	// carries the pin only in `shared`; read it through Pins.KZGSetupPin, never from this field.
	KZGSetupSHA256    string      `json:"kzg_setup_sha256"`
	Forks             []ForkPin   `json:"forks"`
	Spec              string      `json:"spec"`
	SyncCommitteeSize int         `json:"sync_committee_size"`
	MinParticipants   int         `json:"min_participants"`
	EpochsPerPeriod   uint64      `json:"epochs_per_period"`
	MaxLinks          int         `json:"max_links"`
	MaxSpineHeaders   int         `json:"max_spine_headers"`
	Anchors           []AnchorPin `json:"anchors"`
}

// SharedPins is the top-level `shared` section of the pins file: values more than one chain kind reads, held once so the kinds
// cannot diverge (RB11-INT1, decision F13b). Unknown keys inside it are refused like everywhere else.
type SharedPins struct {
	// KZGSetupSHA256 is the SHA-256 (64 lower-case hex, no prefix) of the EIP-4844 trusted setup file the blob kinds load: the
	// consensus-specs v1.7.0-beta.4 trusted_setup_4096.json, verified byte for byte (V2_SPEC_S7 11 item 9).
	KZGSetupSHA256 string `json:"kzg_setup_sha256"`
}

// KZGSetupSharedKey is the pins key a missing, malformed or conflicting KZG setup pin is reported under.
const KZGSetupSharedKey = "shared.kzg_setup_sha256"

// KZGSetupPin returns the pinned SHA-256 of the KZG ceremony setup and the pins key it was read from.
//
// The pin lives in the `shared` section (the embedded file carries it nowhere else). Pins files published before that section
// existed carry a copy in the chain section of the kind that used it (finality_base_posted1: base_sepolia.kzg_setup_sha256;
// finality_arb_posted1: eth_sepolia.kzg_setup_sha256) and a published vector set is never edited, so legacyKey/legacyValue name that
// copy. It is read when the file has no `shared` section; when the file has both and they differ the file is
// finality_pins_corrupt (never "the shared one wins"); when it has neither the pin is missing: finality_pins_corrupt{bad_value}
// under KZGSetupSharedKey.
func (p *Pins) KZGSetupPin(legacyKey, legacyValue string) (value, key string, err error) {
	if p == nil {
		return "", KZGSetupSharedKey, NewState(CodePinUnknown, "kind", "kzg_setup_sha256")
	}
	if p.Shared != nil {
		if legacyValue != "" && legacyValue != p.Shared.KZGSetupSHA256 {
			return "", legacyKey, PinsCorrupt(PinsBadValue, "key", legacyKey)
		}
		return p.Shared.KZGSetupSHA256, KZGSetupSharedKey, nil
	}
	if legacyValue != "" {
		return legacyValue, legacyKey, nil
	}
	return "", KZGSetupSharedKey, PinsCorrupt(PinsBadValue, "key", KZGSetupSharedKey)
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
	Shared            *SharedPins                // pins more than one chain kind reads (the KZG ceremony setup)

	sum    [32]byte
	source string
	raw    []byte // the bytes this Pins was parsed from (Extend compares non-ledger content against them)
}

type pinsFile struct {
	Format            string             `json:"format"`
	PublishedUTC      string             `json:"published_utc"`
	OnchainCommitment *OnchainCommitment `json:"onchain_commitment"`
	EthSepolia        *EthSepoliaPins    `json:"eth_sepolia"`
	BaseSepolia       json.RawMessage    `json:"base_sepolia"`
	ArbSepolia        json.RawMessage    `json:"arb_sepolia"`
	Adiri             json.RawMessage    `json:"adiri"`
	Shared            *SharedPins        `json:"shared"`
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
		return nil, PinsCorrupt(PinsSHA256Mismatch, "want_sha256", want, "got_sha256", got)
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
		return nil, PinsCorrupt(PinsSHA256ConstantMalformed)
	}
	return LoadPins(embeddedPins, [32]byte(want))
}

func parsePins(raw []byte, sum [32]byte, source string) (*Pins, error) {
	if !utf8.Valid(raw) {
		return nil, PinsCorrupt(PinsNotUTF8)
	}
	if bytes.ContainsRune(raw, '\r') {
		return nil, PinsCorrupt(PinsContainsCR)
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, PinsCorrupt(PinsByteOrderMark)
	}
	if !json.Valid(raw) {
		return nil, PinsCorrupt(PinsNotJSON)
	}
	if reason, key := walkKeys(json.NewDecoder(bytes.NewReader(raw)), reflect.TypeOf(pinsFile{})); reason != "" {
		if key != "" {
			return nil, PinsCorrupt(reason, "key", key)
		}
		return nil, PinsCorrupt(reason)
	}
	var f pinsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, PinsCorrupt(PinsBadValue)
	}
	if f.Format != PinsFormat {
		return nil, PinsCorrupt(PinsWrongFormat)
	}
	if f.PublishedUTC == "" {
		return nil, PinsCorrupt(PinsPublishedUTCEmpty)
	}
	p := &Pins{Format: f.Format, PublishedUTC: f.PublishedUTC, OnchainCommitment: f.OnchainCommitment, EthSepolia: f.EthSepolia, Shared: f.Shared, sum: sum, source: source, raw: append([]byte(nil), raw...)}
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
			return nil, err
		}
	}
	if p.Shared != nil && !hexN(p.Shared.KZGSetupSHA256, 32, false) {
		return nil, PinsCorrupt(PinsBadValue, "key", KZGSetupSharedKey)
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

// SepoliaSpecPin is the consensus specification the light-client objects and the fork layouts of the L1 head verifier follow, and
// SepoliaGenesisTime the genesis time of the Sepolia beacon chain (V2_SPEC_S7 4.2): the eth_sepolia section must carry exactly these.
const (
	SepoliaSpecPin     = "consensus-specs v1.7.0-beta.4 aa16bb4c"
	SepoliaGenesisTime = 1655733600
	// MaxLinksBound is the V2_SPEC_S7 8.2 bound on max_links (64 links, about 72 days of ledger staleness): a pin above it is refused,
	// so the link count of an evidence container cannot be made to size anything beyond what the specification allows.
	MaxLinksBound = 64
)

// MinWspEpochs is the smallest valid wsp_epochs of a ledger anchor: V2_SPEC_S7 5.2 step 3 (r2:F10) makes the window rule vacuous
// for wsp_epochs >= 256 (one period), and "a ledger entry with wsp_epochs < 256 is invalid".
const MinWspEpochs = 256

// validate enforces the invariants the Sepolia verifier relies on, each with its own reason (and the index of the offending
// fork or anchor), in this order: the chain id and genesis root; the bounds (present and positive, in the order
// sync_committee_size, min_participants, epochs_per_period, max_links, max_spine_headers) and the two-thirds participation
// floor; the fork table (non-empty, first fork at epoch 0, epochs strictly ascending, layouts null/electra/gloas); the ledger
// (roots and hashes well formed, periods unique and ascending, wsp_epochs >= 256, derived_by non-empty).
func (e *EthSepoliaPins) validate() error {
	if e.ChainID != ChainSepolia {
		return PinsCorrupt(PinsChainIDMismatch)
	}
	if !hexN(e.GenesisValidatorsRoot, 32, true) {
		return PinsCorrupt(PinsGenesisRootMalformed)
	}
	if e.KZGSetupSHA256 != "" && !hexN(e.KZGSetupSHA256, 32, false) {
		return PinsCorrupt(PinsBadValue, "key", "kzg_setup_sha256")
	}
	for _, b := range []struct {
		key string
		ok  bool
	}{
		{"sync_committee_size", e.SyncCommitteeSize > 0}, {"min_participants", e.MinParticipants > 0},
		{"epochs_per_period", e.EpochsPerPeriod > 0}, {"max_links", e.MaxLinks > 0}, {"max_spine_headers", e.MaxSpineHeaders > 0},
	} {
		if !b.ok {
			return PinsCorrupt(PinsBoundMissing, "key", b.key)
		}
	}
	// What the L1 head verifier runs on is not configurable: a pin that says otherwise would describe a network and a spec the
	// verifier does not judge under, so it is refused by name instead of being parsed and ignored.
	for _, v := range []struct {
		key string
		ok  bool
	}{
		{"sync_committee_size", e.SyncCommitteeSize == ethl1.SyncCommitteeSize}, {"epochs_per_period", e.EpochsPerPeriod == ethl1.EpochsPerPeriod},
		{"spec", e.Spec == SepoliaSpecPin}, {"genesis_time", e.GenesisTime == SepoliaGenesisTime}, {"max_links", e.MaxLinks <= MaxLinksBound},
	} {
		if !v.ok {
			return PinsCorrupt(PinsBadValue, "key", v.key)
		}
	}
	if e.MinParticipants*3 < e.SyncCommitteeSize*2 || e.MinParticipants > e.SyncCommitteeSize {
		return PinsCorrupt(PinsParticipationFloor)
	}
	if len(e.Forks) == 0 {
		return PinsCorrupt(PinsForksEmpty)
	}
	if e.Forks[0].Epoch != 0 {
		return PinsCorrupt(PinsFirstForkNotEpochZero)
	}
	for i, f := range e.Forks {
		if f.Name == "" || !hexN(f.Version, 4, true) {
			return PinsCorrupt(PinsForkMalformed, "index", uint64(i))
		}
		if i > 0 && f.Epoch <= e.Forks[i-1].Epoch {
			return PinsCorrupt(PinsForkEpochNotAscending, "index", uint64(i))
		}
		if f.Layout != nil && *f.Layout != "electra" && *f.Layout != "gloas" {
			return PinsCorrupt(PinsForkLayoutUnknown, "index", uint64(i))
		}
	}
	for i, a := range e.Anchors {
		idx := uint64(i)
		if !hexN(a.CommitteeRoot, 32, true) || (a.BlockRoot != "" && !hexN(a.BlockRoot, 32, true)) || !hexN(a.LinkSHA256, 32, false) {
			return PinsCorrupt(PinsAnchorMalformed, "index", idx)
		}
		if i > 0 && a.Period == e.Anchors[i-1].Period {
			return PinsCorrupt(PinsAnchorPeriodDuplicate, "index", idx)
		}
		if i > 0 && a.Period < e.Anchors[i-1].Period {
			return PinsCorrupt(PinsAnchorPeriodNotAscending, "index", idx)
		}
		if a.WspEpochs < MinWspEpochs {
			return PinsCorrupt(PinsAnchorWspBelow256, "index", idx)
		}
		if len(a.DerivedBy) == 0 {
			return PinsCorrupt(PinsAnchorDerivedByEmpty, "index", idx)
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

// walkKeys reads one JSON value from dec and returns the FIRST structural violation in document order, as a pins reason and the
// offending key: inside every object a key smaller than its predecessor is keys_unsorted{key}, a key equal to it
// duplicate_key{key} (sorted keys make a duplicate adjacent), and, where t is a struct type, a key that is not EXACTLY (case-
// sensitively) one of its json names is unknown_key{key}. Where t is nil, or not a struct (the raw sections of the other
// chains), only the order and duplicate rules apply, plus one more (RB12-OPS-A1, F4/N1): a key that differs from an earlier key of
// the same object only in letter case (the code hash keys of logic_pins, 0xAB.. and 0xab.., are the same hash) is duplicate_key{key}
// wherever it stands, because the decoders of the chain sections match names and hex digits without regard to case and two spellings
// of one name would otherwise be merged in the order of a Go map. The first such key in document order is the one named, so the answer
// is a function of the bytes of the file. The text has already passed json.Valid, so a token error is not_json.
func walkKeys(dec *json.Decoder, t reflect.Type) (PinsReason, string) {
	for t != nil && t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return PinsNotJSON, ""
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return "", ""
	}
	switch d {
	case '{':
		prev, first := "", true
		var spelled map[string]string // case-folded key -> the spelling seen first; objects that are not structs only
		if t == nil || t.Kind() != reflect.Struct {
			spelled = map[string]string{}
		}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return PinsNotJSON, ""
			}
			k, _ := kt.(string)
			if spelled != nil {
				f := foldKey(k)
				if was, seen := spelled[f]; !seen {
					spelled[f] = k
				} else if was != k {
					return PinsDuplicateKey, k
				}
			}
			if !first {
				if k < prev {
					return PinsKeysUnsorted, k
				}
				if k == prev {
					return PinsDuplicateKey, k
				}
			}
			first, prev = false, k
			var ft reflect.Type
			if t != nil && t.Kind() == reflect.Struct {
				if ft = jsonFieldType(t, k); ft == nil {
					return PinsUnknownKey, k
				}
			}
			if r, key := walkKeys(dec, ft); r != "" {
				return r, key
			}
		}
	case '[':
		var et reflect.Type
		if t != nil && t.Kind() == reflect.Slice {
			et = t.Elem()
		}
		for dec.More() {
			if r, key := walkKeys(dec, et); r != "" {
				return r, key
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return PinsNotJSON, ""
	}
	return "", ""
}

// jsonFieldType is the type of the struct field whose json name is exactly name, or nil.
func jsonFieldType(t reflect.Type, name string) reflect.Type {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		n := strings.Split(f.Tag.Get("json"), ",")[0]
		if n == "" {
			n = f.Name
		}
		if n != "-" && n == name {
			return f.Type
		}
	}
	return nil
}

// foldKey maps every rune of s to the smallest rune of its Unicode simple-folding orbit, so foldKey(a) == foldKey(b) exactly when
// strings.EqualFold(a, b): the equivalence encoding/json uses to match an object key to a field name.
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		return m
	}, s)
}
