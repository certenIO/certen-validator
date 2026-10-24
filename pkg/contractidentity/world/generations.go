// Copyright 2026 Certen Protocol

package world

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// WORLD-FIX (RB12-GOVERIFY-2a, additive): the live runtime bytes of three UNPINNED generations of the manifest `generations` table, so that
// the vectors VS8-046 (V7, catalogued), VS8-047 (V7, observed) and VS8-070 (anchor V8.1 behind the account pointer) are expressible. Each file
// is the code a live chain serves (`eth_getCode`), unmasked, whose keccak256 is the codeHash of the generations evidence row and whose masked
// keccak256 (the row's own references) is the row's maskedKeccak; generations_test.go checks both. testdata/code/README.md lists the source.

// Generation runtime files (testdata/code/<name>.runtime.hex).
const (
	GenV7Catalogued  = "v7_catalogued_base"
	GenV7Observed    = "v7_observed_sepolia"
	GenAnchorV8_1    = "anchor_v8_1_sepolia"
	genRuntimeSuffix = ".runtime.hex"
)

// GenerationRuntime is the runtime code of an unpinned generation.
func GenerationRuntime(name string) ([]byte, error) { return readHexFile(name + genRuntimeSuffix) }

// pointedAccount makes the read plan read the account the settlement account's pointer (slot 2) names when it is not the manifest anchor and
// the world carries its code: the verifier then identifies a pinned:false anchor generation behind the pointer (step 9). For every world whose
// pointer is the anchor (H0 and all its other mutations) it reads nothing: the H0 container hashes are unchanged.
func (d *derived) pointedAccount(p *planner, ids planIDs, w common.Hash) {
	ptr := common.BytesToAddress(w[12:])
	if p.err != nil || ptr == (common.Address{}) || ptr == ids.A {
		return
	}
	for _, c := range d.sp.Carry {
		if strings.EqualFold(c, ptr.Hex()) {
			p.account(StationSettle, ptr)
			return
		}
	}
}
