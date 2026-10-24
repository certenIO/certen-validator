// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// worldPKCCount is the number of authorized commitments the honest world stores (29 = C(7,5)+C(7,6)+C(7,7), the live anchors' count).
const worldPKCCount = 29

// WorldPKCs are the authorized pubkey commitments the world's anchor stores for a chain, ascending as bytes32: the pkcList of an honest
// setRootHistory row (step 21c). A vector sets them in attestation.pkc_list so that the read plan also reads their flags (rows A06) at both
// attestation stations.
func WorldPKCs(chain uint64) []common.Hash {
	seed := fmt.Sprintf("%s|%d", SeedLabel, chain)
	out := make([]common.Hash, worldPKCCount)
	for j := range out {
		out[j] = seeded(seed, "pkc", j)
	}
	sort.Slice(out, func(a, b int) bool { return bytes.Compare(out[a][:], out[b][:]) < 0 })
	return out
}

func (d *derived) pkcListIDs() ([]common.Hash, error) {
	var out []common.Hash
	for i, s := range d.sp.Attestation.PKCList {
		h, err := parseHash(strings.ToLower(s))
		if err != nil {
			return nil, fmt.Errorf("attestation.pkc_list[%d]: %w", i, err)
		}
		out = append(out, h)
	}
	return out, nil
}

// pkcListReads reads authorizedPubkeyCommitments[c] (row A06) for every commitment of attestation.pkc_list at an attestation station; the
// settlement station does not read them (A06 is "not read" at N).
func (p *planner) pkcListReads(st string, ids planIDs) {
	if st == StationSettle {
		return
	}
	for _, c := range ids.pkcList {
		p.slot(st, ids.A, ci.MappingSlotAt(ci.KeyBytes32(c), 4))
	}
}
