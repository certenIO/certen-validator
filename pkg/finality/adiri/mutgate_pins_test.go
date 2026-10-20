// Copyright 2026 Certen Protocol

package adiri_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, adiri pins: the bounds ParsePins enforces on the adiri section and the reasons it names, each by changing exactly
// one member of the embedded section.

func gateAdiriPins(t *testing.T, mutate func(sec map[string]any)) (*adiri.Params, error) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	mutate(doc["adiri"].(map[string]any))
	raw, err := json.Marshal(doc) // sorted keys, as the pins file requires
	if err != nil {
		t.Fatal(err)
	}
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatalf("the pins file itself must load: %v", err)
	}
	return adiri.ParsePins(p)
}

func TestAdiriPinsBoundsAreExactAndEachRefusalNamesItsKey(t *testing.T) {
	if par, err := gateAdiriPins(t, func(map[string]any) {}); err != nil || par.ChainID != 2017 || len(par.GenesisCommittee) != 5 {
		t.Fatalf("the embedded section: %v", err)
	}
	// the smallest valid positive bounds
	par, err := gateAdiriPins(t, func(s map[string]any) { s["min_committee_size"], s["max_headers"] = json.Number("1"), json.Number("1") })
	if err != nil || par.MinCommittee != 1 || par.MaxHeaders != 1 {
		t.Fatalf("bounds of 1 are valid: %v", err)
	}
	refused := func(name, key string, mutate func(s map[string]any)) {
		t.Helper()
		_, err := gateAdiriPins(t, mutate)
		gateNamed(t, err, finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", key)
		_ = name
	}
	refused("chain id 0", "adiri.chain_id", func(s map[string]any) { s["chain_id"] = json.Number("0") })
	refused("min committee 0", "adiri.min_committee_size", func(s map[string]any) { s["min_committee_size"] = json.Number("0") })
	refused("max headers 0", "adiri.max_headers", func(s map[string]any) { s["max_headers"] = json.Number("0") })
	refused("link 63", "adiri.genesis_link_sha256", func(s map[string]any) { s["genesis_link_sha256"] = strings.Repeat("a", 63) })
	refused("link 65", "adiri.genesis_link_sha256", func(s map[string]any) { s["genesis_link_sha256"] = strings.Repeat("a", 65) })
	refused("hash short", "adiri.genesis_hash", func(s map[string]any) { s["genesis_hash"] = "0x12" })
	refused("hash one char", "adiri.genesis_hash", func(s map[string]any) { s["genesis_hash"] = "0" })
	refused("hash empty", "adiri.genesis_hash", func(s map[string]any) { s["genesis_hash"] = "" })
	refused("hash no prefix", "adiri.genesis_hash", func(s map[string]any) { s["genesis_hash"] = "zz" + strings.Repeat("11", 32) })
	refused("epoch0 hash", "adiri.epoch0_final_state.hash", func(s map[string]any) { s["epoch0_final_state"].(map[string]any)["hash"] = "0x12" })
	refused("codehash", "adiri.eip2935.runtime_codehash", func(s map[string]any) { s["eip2935"].(map[string]any)["runtime_codehash"] = "0x12" })
	refused("address 19", "adiri.eip2935.address", func(s map[string]any) { s["eip2935"].(map[string]any)["address"] = "0x" + strings.Repeat("11", 19) })
	refused("address bare 0x", "adiri.eip2935.address", func(s map[string]any) { s["eip2935"].(map[string]any)["address"] = "0x" })
	refused("committee empty", "adiri.genesis_committee", func(s map[string]any) { s["genesis_committee"] = []any{} })
	refused("committee 256", "adiri.genesis_committee", func(s map[string]any) {
		l := make([]any, 256)
		for i := range l {
			l[i] = strings.Repeat("11", adiri.KeyBytes)
		}
		s["genesis_committee"] = l
	})
	// 255 keys are accepted; a short key names its index
	l := make([]any, 255)
	for i := range l {
		l[i] = strings.Repeat("11", adiri.KeyBytes)
	}
	if par, err := gateAdiriPins(t, func(s map[string]any) { s["genesis_committee"] = l }); err != nil || len(par.GenesisCommittee) != 255 {
		t.Fatalf("255 genesis keys: %v", err)
	}
	_, err = gateAdiriPins(t, func(s map[string]any) {
		s["genesis_committee"] = []any{strings.Repeat("11", adiri.KeyBytes), strings.Repeat("11", adiri.KeyBytes-1)}
	})
	gateNamed(t, err, finality.CodePinsCorrupt, "key", "adiri.genesis_committee", "index", 1)
}

func TestAdiriPinsDecodeErrorsAreNamedByKind(t *testing.T) {
	_, err := gateAdiriPins(t, func(s map[string]any) { s["surprise"] = json.Number("1") })
	gateNamed(t, err, finality.CodePinsCorrupt, "reason", finality.PinsUnknownKey, "key", "adiri.surprise")
	_, err = gateAdiriPins(t, func(s map[string]any) { s["chain_id"] = "2017" })
	gateNamed(t, err, finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", "adiri.chain_id")
	_, err = gateAdiriPins(t, func(s map[string]any) { s["max_headers"] = "many" })
	gateNamed(t, err, finality.CodePinsCorrupt, "reason", finality.PinsBadValue, "key", "adiri.max_headers")
	if _, err := adiri.ParsePins(nil); err == nil {
		t.Fatal("no pins")
	} else {
		gateNamed(t, err, finality.CodePinUnknown, "chain", 2017)
	}
}
