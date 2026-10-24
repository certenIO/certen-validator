// Copyright 2026 Certen Protocol

// Package capturetest holds test support shared by the packages that judge the evidence of a captured leg.
package capturetest

import (
	"bytes"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// Enrich fills the settlement station with unrelated storage, so that a read of a wrong or missing slot visits other trie nodes than the
// plan reads (in the minimal world several slots share the one root node and a dropped read is invisible).
// It is meant for a world.Spec before world.Derive. The step 22b exactness test of every verifier should run on such a world too: in the
// minimal H0 world the storage tries are so small that a dropped read of an absent slot visits the same nodes as the others.
func Enrich(sp *world.Spec) {
	for _, name := range []string{world.StationSettle, world.StationPre, world.StationPost} {
		EnrichStation(sp, sp.Stations[name])
	}
}

func EnrichStation(sp *world.Spec, st *world.Station) {
	put := func(addr string, slot, val common.Hash) {
		for k, a := range st.Accounts {
			if strings.EqualFold(k, addr) {
				if a.Storage == nil {
					a.Storage = map[string]string{}
				}
				a.Storage[slot.Hex()] = val.Hex()
				return
			}
		}
		st.Accounts[addr] = &world.AcctSpec{Storage: map[string]string{slot.Hex(): val.Hex()}}
	}
	one := common.BigToHash(big.NewInt(1))
	for i := byte(1); i <= 7; i++ {
		noise := common.BytesToHash(bytes.Repeat([]byte{i * 17}, 32))
		put(sp.Roles.History, ci.SlotIndex(uint64(i)*911), noise)
		put(sp.Roles.Factory, ci.MappingSlotAt(ci.KeyAddress(common.BytesToAddress(noise[:20])), 2), one)
		put(sp.Roles.Factory, ci.MappingSlotAt(ci.KeyBytes32(noise), 3), noise)
		put(sp.Roles.Account, ci.MappingSlotAt(ci.KeyBytes4([4]byte{i, i, i, i}), 8), noise)
		put(sp.Roles.Account, ci.PageSlot(10, noise, uint64(i)), one)
		put(sp.Roles.Anchor, ci.MappingSlotAt(ci.KeyBytes32(noise), 4), one)
		put(sp.Roles.Anchor, ci.MappingSlotAt(ci.KeyBytes32(noise), 1), noise)
	}
	book := common.HexToHash(sp.Settlement.AuthorityBook)
	put(sp.Roles.Account, ci.PageSlot(10, book, sp.Settlement.AuthorityPage), one)
	// the stored page level is the level the world logs (ROOT = 4, the governing default of page 1): step 14 judges the computed level against the
	// logged one, so a different stored level would make the rich world a world in which the leg is (correctly) unproven
	put(sp.Roles.Account, ci.PageSlot(9, book, sp.Settlement.AuthorityPage), common.BigToHash(big.NewInt(4)))
	for _, l := range sp.Settlement.Legs {
		if d := common.FromHex(l.Data); len(d) >= 4 {
			put(sp.Roles.Account, ci.MappingSlotAt(ci.KeyBytes4([4]byte(d[:4])), 8), common.BigToHash(big.NewInt(2)))
		}
	}
}
