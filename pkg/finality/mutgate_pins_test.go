// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// RB11-GATE-A, pins: the structural and boundary rules of the pins loader that the embedded file and the existing malformed-file
// table do not reach. A document is the embedded pins file decoded, changed in one member and re-encoded (the encoder sorts map
// keys, which the pins file requires), so every refusal below is about exactly that one member.

func pinsMutated(t *testing.T, mutate func(m map[string]any)) ([]byte, error) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(EmbeddedPinsBytes()))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	mutate(doc)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, perr := ParsePinsOverride(raw)
	return raw, perr
}

func ethSection(m map[string]any) map[string]any { return m["eth_sepolia"].(map[string]any) }

func TestPinsBoundsOfOneAreValidAndTheParticipationFloorIsExact(t *testing.T) {
	keys := []string{"sync_committee_size", "min_participants", "epochs_per_period", "max_links", "max_spine_headers"}
	// the committee size, epochs per period and the participation floor are what the L1 head verifier runs on (512, 256, 342): they
	// are accepted at those values only; the two DoS bounds are valid down to their smallest positive value
	_, err := pinsMutated(t, func(m map[string]any) {
		ethSection(m)["sync_committee_size"] = json.Number("512")
		ethSection(m)["min_participants"] = json.Number("342")
		ethSection(m)["epochs_per_period"] = json.Number("256")
		ethSection(m)["max_links"] = json.Number("1")
		ethSection(m)["max_spine_headers"] = json.Number("1")
	})
	if err != nil {
		t.Fatalf("the two DoS bounds at their smallest positive value (1) must be accepted: %v", err)
	}
	for _, k := range keys {
		_, err := pinsMutated(t, func(m map[string]any) { ethSection(m)[k] = json.Number("0") })
		wantNamed(t, err, CodePinsCorrupt, "reason", PinsBoundMissing, "key", k)
	}
	floor := func(min string) error {
		_, err := pinsMutated(t, func(m map[string]any) {
			ethSection(m)["min_participants"] = json.Number(min)
		})
		return err
	}
	if err := floor("342"); err != nil { // 3*342 >= 2*512: the smallest count that is two thirds
		t.Fatalf("the smallest two-thirds count is the floor and is valid: %v", err)
	}
	if err := floor("512"); err != nil {
		t.Fatalf("min_participants == sync_committee_size is valid: %v", err)
	}
	wantNamed(t, floor("341"), CodePinsCorrupt, "reason", PinsParticipationFloor)
	wantNamed(t, floor("513"), CodePinsCorrupt, "reason", PinsParticipationFloor)
}

func TestPinsForkAndAnchorOrderingAndShapeAreEnforcedAtEveryIndex(t *testing.T) {
	_, err := pinsMutated(t, func(m map[string]any) {
		f := ethSection(m)["forks"].([]any)
		if len(f) < 2 {
			t.Fatal("the embedded pins hold at least two forks")
		}
		f[1].(map[string]any)["epoch"] = json.Number("0")
	})
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsForkEpochNotAscending, "index", 1)
	anchor := func(period string) map[string]any {
		return map[string]any{
			"period": json.Number(period), "committee_root": "0x" + strings.Repeat("11", 32), "block_root": "0x" + strings.Repeat("22", 32),
			"wsp_epochs": json.Number("256"), "link_sha256": strings.Repeat("33", 32), "derived_by": []any{"a"},
		}
	}
	setAnchors := func(as ...map[string]any) func(m map[string]any) {
		return func(m map[string]any) {
			l := make([]any, len(as))
			for i := range as {
				l[i] = as[i]
			}
			ethSection(m)["anchors"] = l
		}
	}
	if _, err := pinsMutated(t, setAnchors(anchor("5"), anchor("6"))); err != nil {
		t.Fatalf("a well formed ascending ledger: %v", err)
	}
	_, err = pinsMutated(t, setAnchors(anchor("5"), anchor("5")))
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsAnchorPeriodDuplicate, "index", 1)
	_, err = pinsMutated(t, setAnchors(anchor("5"), anchor("4")))
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsAnchorPeriodNotAscending, "index", 1)
	noBlockRoot := anchor("5")
	delete(noBlockRoot, "block_root")
	if _, err := pinsMutated(t, setAnchors(noBlockRoot)); err != nil {
		t.Fatalf("an absent block_root is valid: %v", err)
	}
	for name, mut := range map[string]func(a map[string]any){
		"block_root unprefixed":  func(a map[string]any) { a["block_root"] = strings.Repeat("22", 32) },
		"block_root short":       func(a map[string]any) { a["block_root"] = "0x22" },
		"committee_root short":   func(a map[string]any) { a["committee_root"] = "0x22" },
		"link_sha256 prefixed":   func(a map[string]any) { a["link_sha256"] = "0x" + strings.Repeat("33", 32) },
		"link_sha256 upper case": func(a map[string]any) { a["link_sha256"] = strings.Repeat("AB", 32) },
		"link_sha256 not hex":    func(a map[string]any) { a["link_sha256"] = strings.Repeat("zz", 32) },
	} {
		a := anchor("5")
		mut(a)
		_, err := pinsMutated(t, setAnchors(a))
		if st, ok := AsNamed(err); !ok || st.Fields["reason"] != PinsAnchorMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
	belowFloor := anchor("5")
	belowFloor["wsp_epochs"] = json.Number("255")
	_, err = pinsMutated(t, setAnchors(belowFloor))
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsAnchorWspBelow256)
	noDerived := anchor("5")
	noDerived["derived_by"] = []any{}
	_, err = pinsMutated(t, setAnchors(noDerived))
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsAnchorDerivedByEmpty)
	_, err = pinsMutated(t, func(m map[string]any) { ethSection(m)["genesis_validators_root"] = strings.Repeat("11", 32) })
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsGenesisRootMalformed)
}

func TestAnchorForPicksTheLatestEntryAtOrBelowThePeriod(t *testing.T) {
	e := &EthSepoliaPins{Anchors: []AnchorPin{{Period: 10, WspEpochs: 1}, {Period: 20, WspEpochs: 2}, {Period: 30, WspEpochs: 3}}}
	for _, c := range []struct {
		period uint64
		want   uint64 // WspEpochs of the chosen anchor, 0 = finality_pin_unknown
	}{{9, 0}, {10, 1}, {19, 1}, {20, 2}, {29, 2}, {30, 3}, {1 << 40, 3}} {
		a, err := e.AnchorFor(c.period)
		if c.want == 0 {
			wantNamed(t, err, CodePinUnknown, "period", c.period)
			continue
		}
		if err != nil || a.WspEpochs != c.want {
			t.Errorf("period %d: %+v %v", c.period, a, err)
		}
	}
	_, err := (&EthSepoliaPins{}).AnchorFor(5)
	wantNamed(t, err, CodePinUnknown)
}

func TestPinsParserRefusesWhatItCannotReadByNameAndKeepsRawSectionsExactly(t *testing.T) {
	good := EmbeddedPinsBytes()
	bad := bytes.Replace(good, []byte(`"published_utc": "`), []byte("\"published_utc\": \"\xff"), 1)
	if bytes.Equal(bad, good) {
		t.Fatal("the embedded pins file has no published_utc member in the expected spelling")
	}
	_, err := ParsePinsOverride(bad)
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsNotUTF8)
	_, err = pinsMutated(t, func(m map[string]any) { m["format"] = json.Number("5") })
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsBadValue)
	_, err = pinsMutated(t, func(m map[string]any) { m[""] = json.Number("1") })
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsUnknownKey)
	raw, _ := pinsMutated(t, func(m map[string]any) {
		delete(m, "adiri")
		m["arb_sepolia"] = nil
		m["base_sepolia"] = json.Number("7")
	})
	p, err := ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := p.Sections["adiri"]; has {
		t.Error("an absent section was recorded")
	}
	if _, has := p.Sections["arb_sepolia"]; has {
		t.Error("a null section was recorded")
	}
	if string(p.Sections["base_sepolia"]) != "7" {
		t.Errorf("a one byte section: %q", p.Sections["base_sepolia"])
	}
	raw, _ = pinsMutated(t, func(m map[string]any) {
		m["adiri"] = map[string]any{"": json.Number("1")}
		delete(m, "base_sepolia")
		delete(m, "arb_sepolia")
	})
	p, err = ParsePinsOverride(raw)
	if err != nil || string(p.Sections["adiri"]) != `{"":1}` {
		t.Fatalf("an empty first key inside a raw section: %v %q", err, p.Sections["adiri"])
	}
	if (*Pins)(nil).SHA256() != [32]byte{} {
		t.Fatal("a nil Pins hashes to zero")
	}
	if h, src := (*Pins)(nil).Identity(); h != "" || src != "none" {
		t.Fatalf("%q %q", h, src)
	}
}

// A genesis root whose first two characters are not "0x" is refused even when what follows them is 64 hex digits: stripping
// "a prefix" without checking it would accept it.
func TestPinsHexPrefixIsCheckedNotJustStripped(t *testing.T) {
	_, err := pinsMutated(t, func(m map[string]any) { ethSection(m)["genesis_validators_root"] = "zz" + strings.Repeat("11", 32) })
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsGenesisRootMalformed)
	_, err = pinsMutated(t, func(m map[string]any) { ethSection(m)["genesis_validators_root"] = "0X" + strings.Repeat("11", 32) })
	wantNamed(t, err, CodePinsCorrupt, "reason", PinsGenesisRootMalformed)
	if _, err := pinsMutated(t, func(m map[string]any) { ethSection(m)["genesis_validators_root"] = "0x" + strings.Repeat("11", 32) }); err != nil {
		t.Fatalf("the prefixed form is valid: %v", err)
	}
}
