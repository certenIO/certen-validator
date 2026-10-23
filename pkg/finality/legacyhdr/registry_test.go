// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

type spec struct {
	Required            []string            `json:"required"`
	Optional            []string            `json:"optional"`
	Enums               map[string][]string `json:"enums"`
	ConditionalRequired []struct {
		When     map[string]string `json:"when"`
		Required []string          `json:"required"`
	} `json:"conditional_required"`
}

func loadSpecs(t *testing.T) map[string]spec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		States map[string]spec `json:"states"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r.States
}

// conforms checks a state against the registry the way the conformance tests of pkg/finality do: the code is registered, every field is
// one the registry lists (required, optional or conditionally required), every required field and every conditionally required one is
// present, and a field with a closed set carries a member of it.
func conforms(specs map[string]spec, st *finality.StateError) error {
	sp, ok := specs[st.Code]
	if !ok {
		return fmt.Errorf("%s is not in the registry", st.Code)
	}
	known := map[string]bool{}
	for _, f := range append(append([]string(nil), sp.Required...), sp.Optional...) {
		known[f] = true
	}
	for _, c := range sp.ConditionalRequired {
		for _, f := range c.Required {
			known[f] = true
		}
	}
	for f := range st.Fields {
		if !known[f] {
			return fmt.Errorf("%s carries the field %q the registry does not list", st.Code, f)
		}
	}
	for _, f := range sp.Required {
		if _, ok := st.Fields[f]; !ok {
			return fmt.Errorf("%s lacks the required field %q", st.Code, f)
		}
	}
	for _, c := range sp.ConditionalRequired {
		match := true
		for k, v := range c.When {
			if fmt.Sprint(st.Fields[k]) != v {
				match = false
			}
		}
		if !match {
			continue
		}
		for _, f := range c.Required {
			if _, ok := st.Fields[f]; !ok {
				return fmt.Errorf("%s with %v lacks the conditionally required field %q", st.Code, c.When, f)
			}
		}
	}
	for f, set := range sp.Enums {
		v, ok := st.Fields[f]
		if !ok {
			continue
		}
		in := false
		for _, s := range set {
			if s == fmt.Sprint(v) {
				in = true
			}
		}
		if !in {
			return fmt.Errorf("%s: %s=%v is not in the closed set %v", st.Code, f, v, set)
		}
	}
	return nil
}

// Every state this package emits conforms, including the conditionally required fields: a refusal that names a check carries the
// proof, the chain and the block it was judged at, and legacy_header_unserved carries the counts.
func TestEveryStateTheLegacyHeaderPackageEmitsConformsToTheRegistry(t *testing.T) {
	specs := loadSpecs(t)
	base := legacyOf(t, "base_sepolia_47368146")
	other := legacyOf(t, "arbitrum_sepolia_315455204")
	junk := []byte{0xc2, 0x01, 0x02}
	flip := func(h common.Hash) common.Hash { h[31] ^= 1; return h }
	var emitted []*finality.StateError
	add := func(err error) {
		t.Helper()
		st, ok := finality.AsNamed(err)
		if !ok {
			t.Fatalf("not a named state: %v", err)
		}
		emitted = append(emitted, st)
	}
	// every check of Leg.Verify
	mut := func(f func(l *Leg)) Leg { l := base.leg; f(&l); return l }
	for _, c := range []struct {
		leg    Leg
		header []byte
	}{
		{base.leg, nil},
		{base.leg, other.header},
		{mut(func(l *Leg) { l.BlockHash = crypto.Keccak256Hash(junk) }), junk},
		{mut(func(l *Leg) { l.BlockNumber++ }), base.header},
		{mut(func(l *Leg) { l.TransactionsRoot = flip(l.TransactionsRoot) }), base.header},
		{mut(func(l *Leg) { l.ReceiptsRoot = flip(l.ReceiptsRoot) }), base.header},
		{mut(func(l *Leg) { l.TxHash = flip(l.TxHash) }), base.header},
	} {
		add(c.leg.Verify(c.header))
	}
	// the store conflict of Judge
	out := Judge(context.Background(), base.leg, flakyStore{finality.NewMemCaptureStore(), nil, fmt.Errorf("%w: raced", finality.ErrCaptureConflict)}, &stubSource{hdr: base.header}, nil)
	emitted = append(emitted, out.Named)
	// the unserved state, and the states the leg source and ParseLeg raise
	emitted = append(emitted, (&Unserved{Chain: 84532, Hash: base.leg.BlockHash, Asked: 3, NotServed: 1, Unreachable: 1, WrongBlock: 1}).State(base.leg))
	emitted = append(emitted, finality.IncludedUnavailable(finality.IncludedNoBlockHeader, "proof_id", testProof),
		finality.IncludedUnavailable(finality.IncludedNoBlockHeader, "proof_id", testProof, "chain", base.leg.Chain, "block", base.leg.BlockNumber))
	_, err := ParseLeg(testProof, testBundle, json.RawMessage(`{"chain_id":"84532"}`))
	add(err)

	seen := map[string]bool{}
	for _, st := range emitted {
		if err := conforms(specs, st); err != nil {
			t.Errorf("%v: %v", st, err)
		}
		seen[fmt.Sprint(st.Fields["check"])] = true
	}
	var got []string
	for k := range seen {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"<nil>", CheckBlockNumber, CheckHeaderHash, CheckHeaderParse, CheckHeaderSize, CheckInclusion, CheckStoreConflict, CheckStoredRoots}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the emitters exercised the checks %v, want every check %v", got, want)
	}
}

// The validator itself refuses what it should (otherwise the test above proves nothing).
func TestRegistryValidatorRefusesAStateMissingItsConditionalFields(t *testing.T) {
	specs := loadSpecs(t)
	for name, st := range map[string]*finality.StateError{
		"a check without the block":       finality.NewState(finality.CodeIncludedInvalid, "proof_id", testProof, "check", CheckHeaderHash, "chain", uint64(1), "cause", "x"),
		"a check without the chain":       finality.NewState(finality.CodeIncludedInvalid, "proof_id", testProof, "check", CheckInclusion, "block", uint64(1), "cause", "x"),
		"an unknown check":                finality.NewState(finality.CodeIncludedInvalid, "proof_id", testProof, "check", "nope", "chain", uint64(1), "block", uint64(1), "cause", "x"),
		"unserved without counts":         finality.IncludedUnavailable(finality.IncludedLegacyHeaderUnserved, "proof_id", testProof, "chain", uint64(1), "block", uint64(1)),
		"unserved without the block":      finality.IncludedUnavailable(finality.IncludedLegacyHeaderUnserved, "proof_id", testProof, "chain", uint64(1), "asked", 1, "not_served", 1, "unreachable", 0, "wrong_block", 0, "oversized", 0),
		"an unlisted field":               finality.NewState(finality.CodeIncludedInvalid, "proof_id", testProof, "cause", "x", "provider", "https://x"),
		"a reason outside the closed set": finality.IncludedUnavailable(finality.IncludedReason("nope"), "proof_id", testProof),
	} {
		if err := conforms(specs, st); err == nil {
			t.Errorf("%s was accepted: %v", name, st)
		}
	}
}
