package contracts

import (
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// govRoot v2 (RB5-F19 / D3): the per-intent commitment CERTEN's quorum certifies. Same ten slots and byte layout as
// v1 (ComputeAccumulateGovRoot), under its own domain, with two differences that make it certifiable by independent
// builders:
//
//   - the G0/G1/G2 slots hash the canonical HASHED form (pkg/proof CanonicalG{0,1,2}JSONV2), which contains only
//     execution-fixed facts, under "certen:g0:v2" / "certen:g1:v2" / "certen:g2:v2";
//   - nothing is silently zero: every slot is required, and a failure is an error (v1's setters leave a slot zero on
//     a marshal error, indistinguishable from an absent layer).
//
// v1 is untouched and keeps its golden tests; it remains the record of what the retired per-intent signature signed.

// GovRootV2Domain is the 32-byte, zero-padded domain of govRoot v2.
const GovRootV2Domain = "certen:govroot:v2"

// GovernanceHashV2 hashes one level's canonical JSON: keccak256("certen:g<level>:v2" || ":" || sha256(json)).
func GovernanceHashV2(level int, canonicalJSON []byte) ([32]byte, error) {
	if level < 0 || level > 2 {
		return [32]byte{}, fmt.Errorf("govRoot v2: governance level %d does not exist", level)
	}
	if len(canonicalJSON) == 0 {
		return [32]byte{}, fmt.Errorf("govRoot v2: G%d is required", level)
	}
	inner := sha256.Sum256(canonicalJSON)
	pre := append([]byte(fmt.Sprintf("certen:g%d:v2:", level)), inner[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(pre))
	return out, nil
}

// ComputeAccumulateGovRootV2 is keccak256(bytes32("certen:govroot:v2") || the ten slots), every slot required.
func ComputeAccumulateGovRootV2(inp AccumulateGovRootInputs) ([32]byte, error) {
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
	for _, s := range slots {
		if s.v == zero {
			return zero, fmt.Errorf("govRoot v2: the %s slot is required", s.name)
		}
	}
	var domain [32]byte
	copy(domain[:], GovRootV2Domain)
	pre := make([]byte, 0, 32*11)
	pre = append(pre, domain[:]...)
	for _, s := range [][32]byte{inp.L1AccountHash, inp.L2BPTRoot, inp.L3BlockHash, inp.L4ConsensusProofH,
		inp.G0CanonicalHash, inp.G1CanonicalHash, inp.G2CanonicalHash, inp.KeypageURLHash, inp.KeybookURLHash, inp.OperationID} {
		pre = append(pre, s[:]...)
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256(pre))
	return out, nil
}
