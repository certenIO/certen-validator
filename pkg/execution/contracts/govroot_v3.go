package contracts

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// govRoot v3 (docs/proof/GOVROOT_V3.md, RB6 switch): the per-intent commitment over the proof v2 levels. The same ten
// slots in the same order as v2, under its own domain; the L1-L4 and G0-G2 slots commit the facts proof v2 verifies
// (the certified Directory block and root, the partition anchor, the proven pages, the spine-derived validator set)
// instead of the lite client's hashes. Each slot is keccak256(tag || ":" || payload), every payload field fixed-width
// (bytes32 or uint64 big-endian) or sha256 of a canonical encoding.
//
// v2 is untouched and keeps its golden tests; it remains the record of what was signed before activation.

// GovRootV3Domain is the 32-byte, zero-padded domain of govRoot v3.
const GovRootV3Domain = "certen:govroot:v3"

// The govRoot v3 slot tags. None is used anywhere else: v2 already uses certen:g{0,1,2}:v2 for different bytes.
const (
	GovRootV3TagL1 = "certen:l1:v3"
	GovRootV3TagL2 = "certen:l2:v3"
	GovRootV3TagL3 = "certen:l3:v3"
	GovRootV3TagL4 = "certen:l4gov:v3"
	GovRootV3TagG0 = "certen:g0:v3"
	GovRootV3TagG1 = "certen:g1:v3"
	GovRootV3TagG2 = "certen:g2:v3"
)

// GovRootV3SlotHash is keccak256(tag || ":" || payload).
func GovRootV3SlotHash(tag string, payload []byte) [32]byte {
	pre := make([]byte, 0, len(tag)+1+len(payload))
	pre = append(pre, tag...)
	pre = append(pre, ':')
	pre = append(pre, payload...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(pre))
	return out
}

func v3u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func v3cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// GovRootV3L1 is the L1 slot: txHash ‖ partitionAnchorTxHash ‖ uint64(anchorBlock).
func GovRootV3L1(txHash, anchorTxHash [32]byte, anchorBlock uint64) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagL1, v3cat(txHash[:], anchorTxHash[:], v3u64(anchorBlock)))
}

// GovRootV3L2 is the L2 slot: certifiedRootChainAnchor ‖ uint64(certifiedDirectoryBlock).
func GovRootV3L2(certifiedRoot [32]byte, certifiedBlock uint64) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagL2, v3cat(certifiedRoot[:], v3u64(certifiedBlock)))
}

// GovRootV3L3 is the L3 slot: partitionStateTreeAnchor ‖ uint64(anchorBlock).
func GovRootV3L3(anchorStateRoot [32]byte, anchorBlock uint64) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagL3, v3cat(anchorStateRoot[:], v3u64(anchorBlock)))
}

// GovRootV3L4 is the L4 slot: accumulateSetRoot ‖ incarnation ‖ uint64(certifiedDirectoryBlock).
func GovRootV3L4(accumulateSetRoot, incarnation [32]byte, certifiedBlock uint64) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagL4, v3cat(accumulateSetRoot[:], incarnation[:], v3u64(certifiedBlock)))
}

// GovRootV3G0 is the G0 slot: sha256(CanonicalG0JSONV2) ‖ txHash ‖ certifiedRootChainAnchor.
func GovRootV3G0(g0Sha256, txHash, certifiedRoot [32]byte) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagG0, v3cat(g0Sha256[:], txHash[:], certifiedRoot[:]))
}

// GovRootV3G1 is the G1 slot: sha256(CanonicalG1JSONV2) ‖ pagesRoot.
func GovRootV3G1(g1Sha256, pagesRoot [32]byte) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagG1, v3cat(g1Sha256[:], pagesRoot[:]))
}

// GovRootV3G2 is the G2 slot: sha256(CanonicalG2JSONV2) ‖ the G1 slot.
func GovRootV3G2(g2Sha256, g1Slot [32]byte) [32]byte {
	return GovRootV3SlotHash(GovRootV3TagG2, v3cat(g2Sha256[:], g1Slot[:]))
}

// ComputeAccumulateGovRootV3 is keccak256(bytes32("certen:govroot:v3") || the ten slots), every slot required. The
// slots travel in AccumulateGovRootInputs in v2's order; under v3 the L1-L4 fields hold the L1-L4 v3 slots, and the
// G0-G2 fields the G0-G2 v3 slots.
func ComputeAccumulateGovRootV3(inp AccumulateGovRootInputs) ([32]byte, error) {
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
	copy(domain[:], GovRootV3Domain)
	pre := make([]byte, 0, 32*11)
	pre = append(pre, domain[:]...)
	for _, s := range slots {
		if s.v == zero {
			return zero, fmt.Errorf("govRoot v3: the %s slot is required", s.name)
		}
		pre = append(pre, s.v[:]...)
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256(pre))
	return out, nil
}
