// Copyright 2026 Certen Protocol

package adiri_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, the Adiri genesis link: the embedded 290-header file is hash-pinned by genesis_link_sha256 and runs from
// genesis_hash (block 1) to epoch0_final_state, checked once at load; every way of breaking either is a named pins refusal.

func gateAdiriPinsFile(t *testing.T, mutate func(sec map[string]any)) *finality.Pins {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if mutate == nil {
		delete(doc, "adiri")
	} else {
		mutate(doc["adiri"].(map[string]any))
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatalf("the pins file itself must load: %v", err)
	}
	return p
}

func TestTheEmbeddedGenesisLinkIsTheHashPinnedOneAndLinksGenesisToEpochZero(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if err := adiri.CheckEmbeddedGenesisLink(pins); err != nil {
		t.Fatalf("the embedded link fails its own load check: %v", err)
	}
	link := adiri.EmbeddedGenesisLink()
	if len(link) != 176758 {
		t.Fatalf("%d bytes, the annex says 176,758", len(link))
	}
	onDisk, err := os.ReadFile(filepath.Join("testdata", "pins", "genesis_link_1_290.bin"))
	if err != nil || !bytes.Equal(onDisk, link) {
		t.Fatalf("the embedded link differs from the file beside the pins: %v", err)
	}
	link[0] ^= 0xff // the accessor returns a copy
	if bytes.Equal(link, adiri.EmbeddedGenesisLink()) {
		t.Fatal("EmbeddedGenesisLink exposes its backing array")
	}
	par, err := adiri.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	n, err := adiri.VerifyGenesisLink(adiri.EmbeddedGenesisLink(), par.GenesisLinkSHA, par.GenesisHash, par.Epoch0FinalState)
	if err != nil || n != 290 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestACorruptedOrMissingGenesisLinkIsRefusedByNameAtLoad(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	good := adiri.EmbeddedGenesisLink()
	flipped := append([]byte(nil), good...)
	flipped[1000] ^= 1
	for name, file := range map[string][]byte{
		"absent": nil, "empty": {}, "truncated": good[:len(good)-1], "one bit flipped": flipped, "extended": append(append([]byte(nil), good...), 0xc0),
	} {
		gateNamed(t, adiri.CheckGenesisLink(file, pins), finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", "adiri.genesis_link_sha256")
		_ = name
	}
	// the right file under pins that name another genesis, another tip or another tip number: the hash matches, the chain does not
	otherGenesis := gateAdiriPinsFile(t, func(s map[string]any) { s["genesis_hash"] = "0x" + strings.Repeat("11", 32) })
	gateNamed(t, adiri.CheckGenesisLink(good, otherGenesis), finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", "adiri.genesis_link")
	otherTip := gateAdiriPinsFile(t, func(s map[string]any) { s["epoch0_final_state"].(map[string]any)["number"] = json.Number("289") })
	gateNamed(t, adiri.CheckGenesisLink(good, otherTip), finality.CodePinsCorrupt, "key", "adiri.genesis_link")
	otherTipHash := gateAdiriPinsFile(t, func(s map[string]any) {
		s["epoch0_final_state"].(map[string]any)["hash"] = "0x" + strings.Repeat("22", 32)
	})
	gateNamed(t, adiri.CheckGenesisLink(good, otherTipHash), finality.CodePinsCorrupt, "key", "adiri.genesis_link")
	// a file that the pins hash-pin but that is not a header chain: empty, not RLP, or a hostile declared length (never a panic)
	for name, file := range map[string][]byte{
		"empty pinned": {}, "not rlp": []byte("not a header chain"), "hostile length": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"one header only": good[:headerLen(t, good)],
	} {
		sum := sha256.Sum256(file)
		p := gateAdiriPinsFile(t, func(s map[string]any) { s["genesis_link_sha256"] = hex.EncodeToString(sum[:]) })
		if err := adiri.CheckGenesisLink(file, p); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			gateNamed(t, err, finality.CodePinsCorrupt, "key", "adiri.genesis_link")
		}
	}
	// no adiri section at all is the pin-unknown state, not a pass
	gateNamed(t, adiri.CheckGenesisLink(good, gateAdiriPinsFile(t, nil)), finality.CodePinUnknown)
	gateNamed(t, adiri.CheckGenesisLink(good, nil), finality.CodePinUnknown)
}

func headerLen(t *testing.T, file []byte) int {
	t.Helper()
	hs, err := adiri.SplitHeaders(file)
	if err != nil || len(hs) != 290 {
		t.Fatalf("%d %v", len(hs), err)
	}
	return len(hs[0])
}

func TestSplitHeadersRefusesWhatIsNotAConcatenationOfRLPLists(t *testing.T) {
	for name, file := range map[string][]byte{
		"a string": {0x80}, "truncated list": {0xc8, 0x01}, "hostile 8 byte length": {0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"overflowing length": {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "list then junk": {0xc0, 0x80},
	} {
		if hs, err := adiri.SplitHeaders(file); err == nil {
			t.Errorf("%s: %d headers", name, len(hs))
		}
	}
	hs, err := adiri.SplitHeaders([]byte{0xc0, 0xc1, 0x01})
	if err != nil || len(hs) != 2 || len(hs[0]) != 1 || len(hs[1]) != 2 {
		t.Fatalf("%v %v", hs, err)
	}
	if hs, err := adiri.SplitHeaders(nil); err != nil || len(hs) != 0 {
		t.Fatalf("%v %v", hs, err)
	}
}
