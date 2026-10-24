// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The manifest_history route (step 21c without a Registry9) needs "ALL of the following at pre AND at post": every condition is also tried with
// the fault at the PRE station only (s8_2c_3 carries the faults at both stations). The base is VS8-154 of s8_2c_3.
func TestC2HistoryConditionsHoldAtBothStations(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &author2c{t, f}
	var base ci.Vector
	for _, v := range a.vectors3() {
		if v.ID == "VS8-154" {
			base = v
		}
	}
	if base.ID == "" {
		t.Fatal("VS8-154 is not in the set")
	}
	anchor := hexAddr(f.spec.Roles.Anchor)
	used := common.HexToHash(f.spec.Attestation.Blob[13])
	pick := world.WorldPKCs(11155111)[10]
	if pick == used {
		pick = world.WorldPKCs(11155111)[11]
	}
	m2 := hexAddr(f.spec.Context.Registry9.Members[2].Address)
	keySlot := ci.DynDataSlot(ci.MemberSlot(ci.MappingSlotAt(ci.KeyAddress(m2), 12), 2), 0)
	pre := func(slot, w common.Hash) ci.Mutation { return world.SetStorage(world.StationPre, anchor, slot, w) }
	word := func(n int64) common.Hash { return common.BigToHash(big.NewInt(n)) }
	cases := []struct {
		name, part, reason string
		mut                ci.Mutation
	}{
		{"the set root differs at pre", "registry_link", "no_registry_in_file", pre(ci.SlotIndex(17), word(0xabc))},
		{"the threshold differs at pre", "registry_keys", "threshold_mismatch", pre(ci.SlotIndex(15), word(3))},
		{"the authorized count differs at pre", "registry_keys", "pkc_count_mismatch", pre(ci.SlotIndex(5), word(30))},
		{"a listed commitment is 0 at pre", "registry_keys", "pkc_set_mismatch", pre(ci.MappingSlotAt(ci.KeyBytes32(pick), 4), common.Hash{})},
		{"a key differs at pre", "registry_keys", "keys_digest_mismatch", pre(keySlot, word(0x5a5a))},
	}
	wj := worldJSON(t, f)
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := ci.Vector{ID: fmt.Sprintf("VS8-154.pre%d", i), Base: "H0", Mutations: append(append([]ci.Mutation(nil), base.Mutations...), c.mut)}
			in, err := world.Builder{Manifest: f.m}.Build(wj, v, nil)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := f.build2c(nil).Verify(in.Ctx, in.Container, in.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			var found *ci.OpenEntry
			for _, o := range rep.OpenEntries() {
				o := o
				if o.Part == ci.JudgedRegistryLink {
					found = &o
				}
			}
			if found == nil || found.State.Fields["part"] != c.part || found.State.Fields["reason"] != c.reason {
				t.Fatalf("registry_link open entries %v, want not_checked{%s,%s}", rep.OpenEntries(), c.part, c.reason)
			}
			if rep.Headline.Kind == ci.HeadlineVerified {
				t.Fatal("verified with a fault at the pre station")
			}
			if c.reason == "keys_digest_mismatch" && found.State.Fields["want"] == found.State.Fields["got"] {
				t.Fatalf("want equals got: %v", found.State.Fields)
			}
		})
	}
}
