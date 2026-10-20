// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestThePinsConstantEqualsTheHashOfTheEmbeddedBytes(t *testing.T) {
	sum := sha256.Sum256(EmbeddedPinsBytes())
	if hex.EncodeToString(sum[:]) != PinsSHA256 {
		t.Fatalf("PinsSHA256 %s, the embedded file hashes to %x", PinsSHA256, sum)
	}
	onDisk, err := os.ReadFile("pins/finality-pins.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, EmbeddedPinsBytes()) {
		t.Fatal("the embedded bytes are not the file on disk")
	}
	if bytes.ContainsRune(onDisk, '\r') {
		t.Fatal("the pins file must be LF only")
	}
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if h, src := p.Identity(); h != PinsSHA256 || src != "embedded" {
		t.Fatalf("identity %s %s", h, src)
	}
}

// The embedded file carries the Sepolia network section and the raw sections of the chain packages (adiri, base_sepolia, ...); the Sepolia fields are checked here, each chain package checks its own section.
func TestTheInitialPinsHoldExactlyTheSepoliaNetworkSectionOfSection42(t *testing.T) {
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != PinsFormat || p.OnchainCommitment != nil || !onlyChainSections(p.Sections) {
		t.Fatalf("%+v", p)
	}
	e, err := p.Sepolia()
	if err != nil {
		t.Fatal(err)
	}
	if e.ChainID != 11155111 || e.GenesisValidatorsRoot != "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078" ||
		e.GenesisTime != 1655733600 || e.Spec != "consensus-specs v1.7.0-beta.4 aa16bb4c" || e.SyncCommitteeSize != 512 ||
		e.MinParticipants != 342 || e.EpochsPerPeriod != 256 || e.MaxLinks != 64 || e.MaxSpineHeaders != 16384 || len(e.Anchors) != 0 {
		t.Fatalf("%+v", e)
	}
	type row struct {
		name    string
		epoch   uint64
		version string
		layout  string // "" = null
	}
	want := []row{{"genesis", 0, "0x90000069", ""}, {"altair", 50, "0x90000070", ""}, {"bellatrix", 100, "0x90000071", ""},
		{"capella", 56832, "0x90000072", ""}, {"deneb", 132608, "0x90000073", ""}, {"electra", 222464, "0x90000074", "electra"},
		{"fulu", 272640, "0x90000075", "electra"}, {"gloas", 353024, "0x90000076", "gloas"}}
	if len(e.Forks) != len(want) {
		t.Fatalf("%d forks", len(e.Forks))
	}
	for i, w := range want {
		f := e.Forks[i]
		layout := ""
		if f.Layout != nil {
			layout = *f.Layout
		}
		if f.Name != w.name || f.Epoch != w.epoch || f.Version != w.version || layout != w.layout {
			t.Errorf("fork %d: %+v want %+v", i, f, w)
		}
	}
	// an empty ledger is finality_pin_unknown, correct until RB11-C fills it
	if _, err := e.AnchorFor(1000); err == nil || stateOf(t, err).Code != CodePinUnknown {
		t.Fatalf("an empty ledger gave an anchor: %v", err)
	}
	// The KZG setup hash is a pin since it was compared with the Ethereum ceremony output at the pinned tag (V2_SPEC_S7 11.9:
	// the raw sha256 of presets/mainnet/trusted_setups/trusted_setup_4096.json at consensus-specs v1.7.0-beta.4 equals it,
	// verified by RB11-D2 and again by RB11-E2). RB11-INT1: it lives ONCE, in the top-level `shared` section; neither chain
	// section of the embedded file carries a copy.
	const kzg = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"
	if bytes.Count(EmbeddedPinsBytes(), []byte("kzg_setup_sha256")) != 1 || bytes.Count(EmbeddedPinsBytes(), []byte(kzg)) != 1 {
		t.Fatal("the verified KZG setup hash must be pinned exactly once")
	}
	if p.Shared == nil || p.Shared.KZGSetupSHA256 != kzg || e.KZGSetupSHA256 != "" {
		t.Fatalf("the KZG pin is not (only) in the shared section: %+v / %q", p.Shared, e.KZGSetupSHA256)
	}
	if v, k, err := p.KZGSetupPin("base_sepolia.kzg_setup_sha256", ""); err != nil || v != kzg || k != KZGSetupSharedKey {
		t.Fatalf("%q %q %v", v, k, err)
	}
}

func TestLoadPinsRefusesAHashMismatchAndEveryMalformedFile(t *testing.T) {
	good := EmbeddedPinsBytes()
	want := sha256.Sum256(good)
	if _, err := LoadPins(good, want); err != nil {
		t.Fatal(err)
	}
	wrong := want
	wrong[0] ^= 1
	if _, err := LoadPins(good, wrong); err == nil || stateOf(t, err).Code != CodePinsCorrupt {
		t.Fatalf("a hash mismatch loaded: %v", err)
	}
	edit := func(f func(string) string) []byte { return []byte(f(string(good))) }
	cases := map[string][]byte{
		"CRLF":              edit(func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }),
		"unknown top level": edit(func(s string) string { return strings.Replace(s, `"format"`, `"zzz": 1, "format"`, 1) }),
		"keys unsorted": edit(func(s string) string {
			return strings.Replace(s, `"format": "certen-finality-pins/1",`, `"format": "certen-finality-pins/1", "aaa": 0,`, 1)
		}),
		"wrong format": edit(func(s string) string {
			return strings.Replace(s, "certen-finality-pins/1", "certen-finality-pins/2", 1)
		}),
		"not UTF-8":         append(append([]byte(nil), good...), 0xff),
		"unknown inner key": edit(func(s string) string { return strings.Replace(s, `"anchors": []`, `"anchors": [], "extra": 1`, 1) }),
		"bad genesis root":  edit(func(s string) string { return strings.Replace(s, "0xd8ea17", "0xD8ea17", 1) }),
		"layout":            edit(func(s string) string { return strings.Replace(s, `"layout": "gloas"`, `"layout": "fulu"`, 1) }),
		"trailing data":     append(append([]byte(nil), good...), []byte("{}")...),
		"duplicate key": edit(func(s string) string {
			return strings.Replace(s, `"format": "certen-finality-pins/1",`, `"format": "certen-finality-pins/1", "format": "certen-finality-pins/1",`, 1)
		}),
	}
	for name, raw := range cases {
		if _, err := LoadPins(raw, sha256.Sum256(raw)); err == nil || stateOf(t, err).Code != CodePinsCorrupt {
			t.Errorf("%s: loaded or wrong state: %v", name, err)
		}
	}
}

func TestLoadPinsAcceptsAnAbsentSectionAndKeepsOtherChainsSectionsRaw(t *testing.T) {
	only := []byte(`{
  "format": "certen-finality-pins/1",
  "onchain_commitment": null,
  "published_utc": "2026-10-20T02:35:00Z"
}
`)
	p, err := ParsePinsOverride(only)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Sepolia(); err == nil || stateOf(t, err).Code != CodePinUnknown {
		t.Fatalf("an absent Sepolia section was not finality_pin_unknown: %v", err)
	}
	if h, src := p.Identity(); !strings.HasPrefix(src, "override:") || h != strings.TrimPrefix(src, "override:") {
		t.Fatalf("%s %s", h, src)
	}
	withBase := []byte(`{
  "base_sepolia": {"chain_id": 84532},
  "format": "certen-finality-pins/1",
  "published_utc": "2026-10-20T02:35:00Z"
}
`)
	q, err := ParsePinsOverride(withBase)
	if err != nil || len(q.Sections["base_sepolia"]) == 0 {
		t.Fatalf("%v %v", err, q)
	}
}

// onlyChainSections: besides the Sepolia network section, the file may carry the raw sections of the chain packages
// (adiri from RB11-F1; base_sepolia and arb_sepolia are added by their own work packages). Any other key is a defect.
func onlyChainSections(s map[string]json.RawMessage) bool {
	for k := range s {
		if k != "adiri" && k != "base_sepolia" && k != "arb_sepolia" {
			return false
		}
	}
	return true
}

// RB11-INT1 (F13b): the KZG setup pin is read through Pins.KZGSetupPin. Published pins files (the vector sets finality_base_posted1
// and finality_arb_posted1) carry it in a chain section; the embedded file carries it in `shared`.
func TestKZGSetupPinIsReadFromTheSharedSectionOrTheLegacyCopyAndRefusesAConflict(t *testing.T) {
	const kzg = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"
	other := strings.Repeat("22", 32)
	mk := func(shared string) *Pins {
		raw := `{"format": "certen-finality-pins/1", "onchain_commitment": null, "published_utc": "2026-10-20T02:35:00Z"` + shared + "}\n"
		p, err := ParsePinsOverride([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		return p
	}
	shared := mk(`, "shared": {"kzg_setup_sha256": "` + kzg + `"}`)
	none := mk("")
	const legacy = "base_sepolia.kzg_setup_sha256"
	for name, c := range map[string]struct {
		p                  *Pins
		legacy             string
		wantVal, wantKey   string
		wantCode, wantKey2 string
	}{
		"shared only":                 {shared, "", kzg, KZGSetupSharedKey, "", ""},
		"shared and equal legacy":     {shared, kzg, kzg, KZGSetupSharedKey, "", ""},
		"legacy only":                 {none, kzg, kzg, legacy, "", ""},
		"legacy only, another value":  {none, other, other, legacy, "", ""},
		"shared and different legacy": {shared, other, "", legacy, CodePinsCorrupt, legacy},
		"neither":                     {none, "", "", KZGSetupSharedKey, CodePinsCorrupt, KZGSetupSharedKey},
		"no pins at all":              {nil, kzg, "", KZGSetupSharedKey, CodePinUnknown, ""},
	} {
		v, k, err := c.p.KZGSetupPin(legacy, c.legacy)
		if c.wantCode == "" {
			if err != nil || v != c.wantVal || k != c.wantKey {
				t.Errorf("%s: %q %q %v", name, v, k, err)
			}
			continue
		}
		if err == nil || stateOf(t, err).Code != c.wantCode || v != "" || k != c.wantKey {
			t.Errorf("%s: %q %q %v", name, v, k, err)
		}
		if c.wantKey2 != "" {
			if got := stateOf(t, err).Fields["key"]; got != c.wantKey2 {
				t.Errorf("%s: the report names key %q, want %q", name, got, c.wantKey2)
			}
		}
	}
	// the shared section is strict: its value must be 64 lower-case hex, and it has no other key
	for name, raw := range map[string]string{
		"uppercase":   `, "shared": {"kzg_setup_sha256": "` + strings.ToUpper(kzg) + `"}`,
		"0x prefixed": `, "shared": {"kzg_setup_sha256": "0x` + kzg + `"}`,
		"short":       `, "shared": {"kzg_setup_sha256": "abcd"}`,
		"empty":       `, "shared": {"kzg_setup_sha256": ""}`,
		"absent":      `, "shared": {}`,
		"unknown key": `, "shared": {"kzg_setup_sha256": "` + kzg + `", "zzz": 1}`,
		"unsorted":    `, "shared": {"zzz": 1, "kzg_setup_sha256": "` + kzg + `"}`,
	} {
		full := `{"format": "certen-finality-pins/1", "onchain_commitment": null, "published_utc": "2026-10-20T02:35:00Z"` + raw + "}\n"
		if _, err := ParsePinsOverride([]byte(full)); err == nil || stateOf(t, err).Code != CodePinsCorrupt {
			t.Errorf("shared section %s loaded or gave the wrong state: %v", name, err)
		}
	}
}
