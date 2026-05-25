// V6.1 A+++ derivation helpers — primitive-based so neither pkg/consensus nor
// pkg/execution creates an import cycle when calling them.
//
// Caller pulls fields out of (intent, proof) and hands them to these helpers
// as plain strings / bytes / ints. The helpers return 32-byte cryptographic
// commitments. Both BFT signing and EVM submission use IDENTICAL helpers,
// so as long as both extract the same fields from the same proof object the
// resulting messageHash is byte-identical.
//
// Cycle safety: this file imports ONLY standard library + go-ethereum.
// No pkg/intent or pkg/proof imports — keeps pkg/execution/contracts at
// the bottom of the import graph.
package contracts

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Primitive derivations — caller extracts primitives, helpers hash them.
// =============================================================================

// DeriveAdiURLHashFromString returns keccak256(adiURL). Empty URL → keccak256("").
func DeriveAdiURLHashFromString(adiURL string) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte(adiURL)))
	return out
}

// DeriveOperationCommitmentFromFields matches generateCommitmentHash from
// ethereum_contracts.go — keccak256("certen:op:v1_<intentID>_<height>_<tx>").
// Deterministic from intent + proof identifiers, no BLS-sig dependency.
func DeriveOperationCommitmentFromFields(intentID string, blockHeight uint64, txHash string) [32]byte {
	preimage := fmt.Sprintf("certen:op:v1_%s_%d_%s", intentID, blockHeight, txHash)
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte(preimage)))
	return out
}

// DeriveCrossChainCommitmentFromBPT extracts the first 32 bytes of the BPT
// root. Zero hash if BPT root is shorter than 32 bytes or empty.
func DeriveCrossChainCommitmentFromBPT(bptRoot []byte) [32]byte {
	var out [32]byte
	if len(bptRoot) >= 32 {
		copy(out[:], bptRoot[:32])
	}
	return out
}

// DeriveExecutionCommitmentFromCrossChainJSON matches extractExecutionCommitment
// priority 1 from ethereum_contracts.go: read
// CrossChainData.legs[0].executionPayload.executionCommitment (the value the
// user actually signed). Returns zero [32]byte if not present — caller is
// responsible for handling that as "intent malformed."
//
// The pre-V6.1 fallback (computing from legs[0].chainID/target/value/data)
// is intentionally NOT replicated here. For BFT signing we only sign what
// the user signed; if the user didn't sign an executionCommitment, we don't
// fabricate one.
func DeriveExecutionCommitmentFromCrossChainJSON(crossChainData []byte) [32]byte {
	var out [32]byte
	if len(crossChainData) == 0 {
		return out
	}
	var userSignedCC struct {
		Legs []struct {
			ExecutionPayload *struct {
				ExecutionCommitment string `json:"executionCommitment"`
			} `json:"executionPayload,omitempty"`
		} `json:"legs"`
	}
	if err := json.Unmarshal(crossChainData, &userSignedCC); err != nil {
		return out
	}
	if len(userSignedCC.Legs) == 0 || userSignedCC.Legs[0].ExecutionPayload == nil {
		return out
	}
	commitHex := strings.TrimPrefix(userSignedCC.Legs[0].ExecutionPayload.ExecutionCommitment, "0x")
	commitBytes := common.FromHex(commitHex)
	if len(commitBytes) != 32 {
		return out
	}
	copy(out[:], commitBytes)
	return out
}

// DeriveOperationIDBytes32FromString reduces the intent's OperationID() hex
// string to a 32-byte value. If it's NOT 32 bytes of hex (some intents use
// shorter IDs), falls back to keccak256(opID) — both sides agree because
// both call this helper.
func DeriveOperationIDBytes32FromString(opID string) [32]byte {
	var out [32]byte
	if opID == "" {
		return out
	}
	hexStr := strings.TrimPrefix(opID, "0x")
	if b, err := hex.DecodeString(hexStr); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out
	}
	copy(out[:], crypto.Keccak256([]byte(opID)))
	return out
}

// =============================================================================
// govRoot inputs — primitive form.
// =============================================================================

// AccumulateGovRootInputsBuilder is a small struct that bundles the raw
// fields a caller has on hand. Each Set* method canonicalizes one input.
// When all inputs are set (or skipped), Build() returns the
// AccumulateGovRootInputs struct ready for ComputeAccumulateGovRoot.
//
// Why a builder rather than 10 positional args: governance inputs are
// optional (G2 may be absent; URLs may be empty). The builder lets callers
// skip what they don't have and produce identical zero-hashes on both sides.
type AccumulateGovRootInputsBuilder struct {
	out AccumulateGovRootInputs
}

func NewAccumulateGovRootInputsBuilder() *AccumulateGovRootInputsBuilder {
	return &AccumulateGovRootInputsBuilder{}
}

func (b *AccumulateGovRootInputsBuilder) SetL1AccountHash(h []byte) *AccumulateGovRootInputsBuilder {
	if len(h) >= 32 {
		copy(b.out.L1AccountHash[:], h[:32])
	}
	return b
}

func (b *AccumulateGovRootInputsBuilder) SetL2BPTRoot(h []byte) *AccumulateGovRootInputsBuilder {
	if len(h) >= 32 {
		copy(b.out.L2BPTRoot[:], h[:32])
	}
	return b
}

func (b *AccumulateGovRootInputsBuilder) SetL3BlockHash(h []byte) *AccumulateGovRootInputsBuilder {
	if len(h) >= 32 {
		copy(b.out.L3BlockHash[:], h[:32])
	}
	return b
}

// SetL4ConsensusProofFromJSON canonicalizes a consensus-proof object via
// json.Marshal (deterministic for our types) and hashes it under
// "certen:l4:v1".
func (b *AccumulateGovRootInputsBuilder) SetL4ConsensusProofFromJSON(v interface{}) *AccumulateGovRootInputsBuilder {
	if v == nil {
		return b
	}
	bytes, err := json.Marshal(v)
	if err != nil {
		return b
	}
	b.out.L4ConsensusProofH = HashL4ConsensusProof(bytes)
	return b
}

// SetG0FromJSON canonicalizes a G0Result via json.Marshal and hashes it
// under "certen:g0:v1". Nil v leaves the slot zero.
func (b *AccumulateGovRootInputsBuilder) SetG0FromJSON(v interface{}) *AccumulateGovRootInputsBuilder {
	if v == nil {
		return b
	}
	bytes, err := CanonicalJSONMarshal(v)
	if err != nil {
		return b
	}
	b.out.G0CanonicalHash = CanonicalHashGovernance("certen:g0:v1", bytes)
	return b
}

// SetG1FromJSON — same as SetG0FromJSON but under "certen:g1:v1".
func (b *AccumulateGovRootInputsBuilder) SetG1FromJSON(v interface{}) *AccumulateGovRootInputsBuilder {
	if v == nil {
		return b
	}
	bytes, err := CanonicalJSONMarshal(v)
	if err != nil {
		return b
	}
	b.out.G1CanonicalHash = CanonicalHashGovernance("certen:g1:v1", bytes)
	return b
}

// SetG2FromJSON — same as SetG0FromJSON but under "certen:g2:v1".
func (b *AccumulateGovRootInputsBuilder) SetG2FromJSON(v interface{}) *AccumulateGovRootInputsBuilder {
	if v == nil {
		return b
	}
	bytes, err := CanonicalJSONMarshal(v)
	if err != nil {
		return b
	}
	b.out.G2CanonicalHash = CanonicalHashGovernance("certen:g2:v1", bytes)
	return b
}

func (b *AccumulateGovRootInputsBuilder) SetKeypageURL(url string) *AccumulateGovRootInputsBuilder {
	b.out.KeypageURLHash = HashURLString(url)
	return b
}

func (b *AccumulateGovRootInputsBuilder) SetKeybookURL(url string) *AccumulateGovRootInputsBuilder {
	b.out.KeybookURLHash = HashURLString(url)
	return b
}

func (b *AccumulateGovRootInputsBuilder) SetOperationIDBytes32(opID [32]byte) *AccumulateGovRootInputsBuilder {
	b.out.OperationID = opID
	return b
}

func (b *AccumulateGovRootInputsBuilder) Build() AccumulateGovRootInputs {
	return b.out
}
