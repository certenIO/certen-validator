package contracts

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// govRoot v4 (docs/proof/G1_CROSS_PARTITION.md D4/D7, rules v15): the per-intent commitment over the proof v2 levels when the
// proof is evidence 2.1, whose governing pages live on more than one partition. The same ten slots in the same order as v3,
// under its own root domain. Five slots (L1-L4, G0) commit exactly the facts v3 commits, in exactly v3's bytes, so they are
// v3's slot functions unchanged; the root domain differs, so no v4 root can be taken for a v3 one over the same slots. The G1
// slot commits what 2.1 adds - each page's partition, block and roles, and the proven vote records - under its own tag, and the G2
// slot commits the v4 G1 slot under its own (certen:g2:v4).
//
// v3 is untouched and keeps its golden tests.

// GovRootV4Domain is the 32-byte, zero-padded domain of govRoot v4.
const GovRootV4Domain = "certen:govroot:v4"

// GovRootV4TagG1 is the G1 slot's tag under v4. It is new: certen:g1:v3 commits different bytes.
const GovRootV4TagG1 = "certen:g1:v4"

// GovRootV4TagG2 is the G2 slot's tag under v4. G2 commits the v4 G1 slot, so it is a different commitment from certen:g2:v3, which commits
// the v3 one; it was hashed under the v3 tag until the unreleased v4 was finalised (RB9-VB).
const GovRootV4TagG2 = "certen:g2:v4"

// GovRootV4G2 is the G2 slot: sha256(CanonicalG2JSONV2) ‖ the v4 G1 slot, under its own tag.
func GovRootV4G2(g2Sha256, g1Slot [32]byte) [32]byte {
	return GovRootV3SlotHash(GovRootV4TagG2, v3cat(g2Sha256[:], g1Slot[:]))
}

// GovRootV4G1 is the G1 slot: sha256(CanonicalG1JSONV2) ‖ pagesRoot (v4: with partition, block and roles) ‖ votesRoot.
func GovRootV4G1(g1Sha256, pagesRoot, votesRoot [32]byte) [32]byte {
	return GovRootV3SlotHash(GovRootV4TagG1, v3cat(g1Sha256[:], pagesRoot[:], votesRoot[:]))
}

// ComputeAccumulateGovRootV4 is keccak256(bytes32("certen:govroot:v4") || the ten slots), every slot required. The slots travel
// in AccumulateGovRootInputs in v2's order, as for v3.
func ComputeAccumulateGovRootV4(inp AccumulateGovRootInputs) ([32]byte, error) {
	var zero [32]byte
	// A fixed order, so the refusal names the same first missing slot on every validator.
	slots := []struct {
		name string
		v    [32]byte
	}{
		{"L1", inp.L1AccountHash}, {"L2", inp.L2BPTRoot}, {"L3", inp.L3BlockHash}, {"L4", inp.L4ConsensusProofH},
		{"G0", inp.G0CanonicalHash}, {"G1", inp.G1CanonicalHash}, {"G2", inp.G2CanonicalHash},
		{"key page", inp.KeypageURLHash}, {"key book", inp.KeybookURLHash}, {"operation id", inp.OperationID},
	}
	var domain [32]byte
	copy(domain[:], GovRootV4Domain)
	pre := make([]byte, 0, 32*11)
	pre = append(pre, domain[:]...)
	for _, s := range slots {
		if s.v == zero {
			return zero, fmt.Errorf("govRoot v4: the %s slot is required", s.name)
		}
		pre = append(pre, s.v[:]...)
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256(pre))
	return out, nil
}
