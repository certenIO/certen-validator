// V6.1 A+++ binding primitives. PURE functions — no certen-internal imports —
// so this file can be referenced from BOTH the BFT signing path
// (pkg/consensus/bft_integration.go) and the EVM submission path
// (pkg/execution/ethereum_contracts.go) without creating an import cycle.
//
// CRITICAL INVARIANT: every byte produced here is recomputed on-chain inside
// CertenAnchorV6_1.sol. If you change a domain tag, slot order, or encoding,
// you MUST update both sides and bump the version suffix in the domain tag.
//
// Domain tags in use:
//   "certen:bls:v1:pre"     — pre-execution BLS messageHash (Phase 3/4 sign,
//                              Phase 6 EVM-side ZK verify)
//   "certen:bls:v1:post"    — post-execution BLS messageHash (Phase 8 sign)
//   "certen:bundleid:v1.1"  — V6.1 bundleId (anchorId) derivation
//   "certen:govroot:v1.1"   — A+++ Accumulate governance root
//   "certen:g0:v1"          — G0 canonical hash
//   "certen:g1:v1"          — G1 canonical hash
//   "certen:g2:v1"          — G2 canonical hash
//   "certen:l4:v1"          — L4 consensus proof canonical hash
//
// Version suffixes are intentional — bumping any of them invalidates every
// existing aggregate signature derived under the old domain, which is the
// correct behavior on a hash-encoding upgrade.
package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// EVM messageHash (pre-exec) — 6 fields, keccak256 over 192 bytes.
// Mirror of CertenAnchorV6_1.sol::_verifyBLSProof.
// =============================================================================

// ComputeEvmMessageHashV6_1_Pre is the V6.1 A++ pre-execution messageHash.
// Validators sign this; the V6.1 anchor recomputes it during verification.
//
// Wire format (abi.encode == 32-byte slots, no length-or-type ambiguity):
//   keccak256(abi.encode(
//     bytes32("certen:bls:v1:pre"),   // domain — different from Phase 8 ":post"
//     uint256(chainId),                // cross-chain replay defeat
//     anchorId,                        // bytes32 — V6.1 commitment+opID bundleId
//     executionCommitment,             // bytes32 — explicit value-moving binding
//     operationID,                     // bytes32 — 4-blob intent hash on Accumulate
//     validatorSetRoot                 // bytes32 — quorum-snapshot binding
//   ))
//
// Total preimage: 192 bytes (6 × 32).
func ComputeEvmMessageHashV6_1_Pre(
	chainID int64,
	anchorId, executionCommitment, operationID, validatorSetRoot [32]byte,
) [32]byte {
	return computeEvmMessageHashV6_1(
		[]byte("certen:bls:v1:pre"),
		chainID, anchorId, executionCommitment, operationID, validatorSetRoot,
	)
}

// ComputeEvmMessageHashV6_1_Post is the V6.1 A+++ post-execution messageHash
// for Phase 8 attestations. Domain tag differs from pre so a pre-exec sig
// can never satisfy a post-exec gate (and vice versa). executionResultRoot
// replaces executionCommitment to bind the actual execution outcome.
func ComputeEvmMessageHashV6_1_Post(
	chainID int64,
	anchorId, executionResultRoot, operationID, validatorSetRoot [32]byte,
) [32]byte {
	return computeEvmMessageHashV6_1(
		[]byte("certen:bls:v1:post"),
		chainID, anchorId, executionResultRoot, operationID, validatorSetRoot,
	)
}

func computeEvmMessageHashV6_1(
	domainTag []byte,
	chainID int64,
	anchorId, payloadCommitment, operationID, validatorSetRoot [32]byte,
) [32]byte {
	var domain [32]byte
	copy(domain[:], domainTag)

	var chainIDBE [32]byte
	big.NewInt(chainID).FillBytes(chainIDBE[:])

	preimage := make([]byte, 0, 32*6)
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, chainIDBE[:]...)
	preimage = append(preimage, anchorId[:]...)
	preimage = append(preimage, payloadCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, validatorSetRoot[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// =============================================================================
// bundleId (V6.1 anchorId) derivation
// Mirror of CertenAnchorV6_1.createAnchor's require check.
// =============================================================================

// V6_1Commitments matches the on-chain commitments struct (only the 4 fields
// V6.1's bundleId derivation reads). Kept here to avoid forcing the consensus
// package to import the full execution/contracts CommitmentData (which has
// additional non-V6.1 fields).
type V6_1Commitments struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	ExecutionCommitment  [32]byte
}

// DeriveV6_1BundleID computes the V6.1 anchorId. Commits operationID and
// uses the v1.1 domain tag.
//
// Wire format:
//   keccak256(abi.encodePacked(
//     "certen:bundleid:v1.1",
//     uint256(chainId),
//     bytes32(adiURLHash),
//     bytes32(op), bytes32(cc), bytes32(gov), bytes32(exec),
//     bytes32(operationID),
//     uint256(accumulateBlockHeight)
//   ))
func DeriveV6_1BundleID(
	chainID int64,
	adiURLHash [32]byte,
	commits V6_1Commitments,
	operationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	chainIDBytes32 := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes32)
	heightBytes32 := make([]byte, 32)
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBytes32)

	digest := crypto.Keccak256(
		[]byte("certen:bundleid:v1.1"),
		chainIDBytes32,
		adiURLHash[:],
		commits.OperationCommitment[:],
		commits.CrossChainCommitment[:],
		commits.GovernanceRoot[:],
		commits.ExecutionCommitment[:],
		operationID[:],
		heightBytes32,
	)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// =============================================================================
// High-level builder — both BFT signing and EVM submission call this with
// identical primitive inputs, producing identical (anchorId, messageHash).
// =============================================================================

// V6_1PreExecBundleInputs is the complete set of primitives needed to derive
// the V6.1 A+++ pre-execution (anchorId, messageHash). All fields are
// chain-portable bytes — no intent/proof types here, so this package stays
// import-cycle-free.
type V6_1PreExecBundleInputs struct {
	ChainID               int64
	ValidatorSetRoot      [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	ExecutionCommitment   [32]byte
	OperationID           [32]byte
	AccumulateBlockHeight uint64
	GovRootInputs         AccumulateGovRootInputs
}

// BuildV6_1PreExecBundle is the SINGLE SOURCE OF TRUTH for the V6.1 A+++
// pre-execution binding. Both:
//   - pkg/consensus/bft_integration.go (BFT signing path)
//   - pkg/execution/ethereum_contracts.go (EVM submission path)
// call this with primitives derived from the same (intent, proof). Because
// the derivation is deterministic and the function is pure, validator and
// submitter compute byte-identical anchorId + messageHash.
//
// Returns (anchorId, govRoot, messageHash) so the caller can store all three
// on the proof / log them for debugging.
func BuildV6_1PreExecBundle(in V6_1PreExecBundleInputs) (anchorId, govRoot, messageHash [32]byte) {
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)
	commits := V6_1Commitments{
		OperationCommitment:  in.OperationCommitment,
		CrossChainCommitment: in.CrossChainCommitment,
		GovernanceRoot:       govRoot,
		ExecutionCommitment:  in.ExecutionCommitment,
	}
	anchorId = DeriveV6_1BundleID(in.ChainID, in.AdiURLHash, commits, in.OperationID, in.AccumulateBlockHeight)
	messageHash = ComputeEvmMessageHashV6_1_Pre(
		in.ChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}

// =============================================================================
// A+++ govRoot — Accumulate Total State Binding
// =============================================================================

// AccumulateGovRootInputs is everything that flows into A+++ govRoot. All
// fields are pre-hashed / canonicalized to 32-byte values so this function
// is a flat concatenation. Callers (BFT signer, EVM submitter) MUST pass
// byte-identical inputs to produce a byte-identical root.
//
// A zero [32]byte for any optional field (e.g. G2 not yet generated for a
// G1-level intent) is acceptable — the binding still commits to "what was
// computed" with stable empty values, and the contract doesn't care about
// semantic interpretation. Both sides must agree on which fields were
// populated, which is enforced by the canonicalization helpers in this file.
type AccumulateGovRootInputs struct {
	L1AccountHash       [32]byte // L1 — Accumulate account state hash
	L2BPTRoot           [32]byte // L2 — Binary Patricia Trie root
	L3BlockHash         [32]byte // L3 — Accumulate block hash containing TX
	L4ConsensusProofH   [32]byte // L4 — hash of consensus proof bytes
	G0CanonicalHash     [32]byte // G0 — canonical hash of G0Result
	G1CanonicalHash     [32]byte // G1 — canonical hash of G1Result
	G2CanonicalHash     [32]byte // G2 — canonical hash of G2Result
	KeypageURLHash      [32]byte // keccak256(keypage URL string)
	KeybookURLHash      [32]byte // keccak256(keybook URL string)
	OperationID         [32]byte // intent operationID (4-blob hash)
}

// ComputeAccumulateGovRoot is the A+++ 10-field govRoot. Binds every piece
// of Accumulate-side state the cross-chain claim depends on, so a forged
// inclusion proof, governance bypass, or witness mismatch invalidates the
// BLS aggregate via anchorId.
//
// Wire format:
//   keccak256(
//     bytes32("certen:govroot:v1.1")  ||  // domain
//     L1AccountHash                  ||  // 32B
//     L2BPTRoot                      ||  // 32B
//     L3BlockHash                    ||  // 32B
//     L4ConsensusProofH              ||  // 32B
//     G0CanonicalHash                ||  // 32B
//     G1CanonicalHash                ||  // 32B
//     G2CanonicalHash                ||  // 32B
//     KeypageURLHash                 ||  // 32B
//     KeybookURLHash                 ||  // 32B
//     OperationID                        // 32B
//   )
// Total preimage: 32 (domain) + 10 × 32 (fields) = 352 bytes.
func ComputeAccumulateGovRoot(inp AccumulateGovRootInputs) [32]byte {
	var domain [32]byte
	copy(domain[:], []byte("certen:govroot:v1.1"))

	preimage := make([]byte, 0, 32*11)
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, inp.L1AccountHash[:]...)
	preimage = append(preimage, inp.L2BPTRoot[:]...)
	preimage = append(preimage, inp.L3BlockHash[:]...)
	preimage = append(preimage, inp.L4ConsensusProofH[:]...)
	preimage = append(preimage, inp.G0CanonicalHash[:]...)
	preimage = append(preimage, inp.G1CanonicalHash[:]...)
	preimage = append(preimage, inp.G2CanonicalHash[:]...)
	preimage = append(preimage, inp.KeypageURLHash[:]...)
	preimage = append(preimage, inp.KeybookURLHash[:]...)
	preimage = append(preimage, inp.OperationID[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// =============================================================================
// Canonical hashes for governance proof outputs
//
// All three use the same recipe:
//   keccak256(domain || sha256(canonicalJSON(result)))
//
// json.Marshal in Go is deterministic for our types: struct fields encode in
// declaration order, and map keys sort alphabetically (Go 1.12+). All validators
// run identical struct definitions, so they all produce byte-identical JSON.
//
// If a governance result type's struct is ever extended/reordered, the
// canonical hash changes — bump the domain version (":v1" -> ":v2") and
// coordinate a network-wide upgrade. This is the intended behavior.
// =============================================================================

// CanonicalHashGovernance computes a stable 32-byte digest for any governance
// result. `domainTag` selects the level (see "certen:g0/g1/g2:v1" tags above).
// The caller must pass the result struct itself (not a pointer to it) so json
// Marshal can never silently inject `null`.
//
// On nil input (i.e., the proof wasn't generated at this level), returns
// the zero [32]byte. Both signer and verifier follow the same rule, so they
// agree on the absence of the proof.
func CanonicalHashGovernance(domainTag string, resultJSON []byte) [32]byte {
	if len(resultJSON) == 0 {
		return [32]byte{}
	}
	inner := sha256.Sum256(resultJSON)
	preimage := make([]byte, 0, len(domainTag)+1+32)
	preimage = append(preimage, []byte(domainTag)...)
	preimage = append(preimage, ':')
	preimage = append(preimage, inner[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// CanonicalJSONMarshal returns the deterministic JSON encoding of v. Wraps
// json.Marshal so the call site reads intentfully ("this is a CANONICAL
// serialization") and so we can swap in a stricter canonicalizer later (e.g.,
// RFC 8785 JCS) without touching call sites.
//
// json.Marshal IS deterministic for structs (field declaration order) and
// for maps (sorted keys, Go 1.12+). It is NOT deterministic for floats with
// many representations — our governance types use ints / strings / bools /
// nested structs, so this is safe.
func CanonicalJSONMarshal(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// HashL4ConsensusProof reduces L4 consensus proof bytes (validator quorum
// signatures over an Accumulate block) to a 32-byte canonical hash for
// inclusion in govRoot. Empty input → zero hash (matches "G2 absent" rule).
func HashL4ConsensusProof(consensusProofBytes []byte) [32]byte {
	if len(consensusProofBytes) == 0 {
		return [32]byte{}
	}
	inner := sha256.Sum256(consensusProofBytes)
	preimage := append([]byte("certen:l4:v1:"), inner[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// HashURLString computes keccak256(url) with empty-string normalization. The
// keypage / keybook URL slots in govRoot use this — if a level's URL is
// absent, the slot is zero on BOTH sides.
func HashURLString(url string) [32]byte {
	if url == "" {
		return [32]byte{}
	}
	var out [32]byte
	copy(out[:], crypto.Keccak256([]byte(url)))
	return out
}

// =============================================================================
// Validator set root (V6.1 currentValidatorSetRoot)
// Mirror of CertenAnchorV6_1._recomputeValidatorSetRoot.
// =============================================================================

// ComputeValidatorSetRootV6_1 produces the same validator-set commitment the
// V6.1 contract stores in `currentValidatorSetRoot`. Inputs MUST already be
// sorted ascending by uint160(addr); use SortValidatorsForSetRoot if needed.
//
// Wire format:
//   keccak256(abi.encode(
//     address[] sortedAddresses,
//     uint256[] sortedVotingPowers,
//     uint256(thresholdNumerator),
//     uint256(thresholdDenominator)
//   ))
func ComputeValidatorSetRootV6_1(
	sortedAddrs []common.Address,
	sortedVotingPowers []*big.Int,
	thresholdNumerator *big.Int,
	thresholdDenominator *big.Int,
) ([32]byte, error) {
	if len(sortedAddrs) != len(sortedVotingPowers) {
		return [32]byte{}, fmt.Errorf("sortedAddrs/sortedVotingPowers length mismatch: %d vs %d",
			len(sortedAddrs), len(sortedVotingPowers))
	}

	addrArrTy, err := abi.NewType("address[]", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("address[] abi.NewType: %w", err)
	}
	u256ArrTy, err := abi.NewType("uint256[]", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("uint256[] abi.NewType: %w", err)
	}
	u256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("uint256 abi.NewType: %w", err)
	}

	args := abi.Arguments{
		{Type: addrArrTy},
		{Type: u256ArrTy},
		{Type: u256Ty},
		{Type: u256Ty},
	}

	addrsCopy := make([]common.Address, len(sortedAddrs))
	copy(addrsCopy, sortedAddrs)
	powersCopy := make([]*big.Int, len(sortedVotingPowers))
	for i, p := range sortedVotingPowers {
		powersCopy[i] = new(big.Int).Set(p)
	}

	encoded, err := args.Pack(
		addrsCopy,
		powersCopy,
		new(big.Int).Set(thresholdNumerator),
		new(big.Int).Set(thresholdDenominator),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("abi pack validator set root: %w", err)
	}

	var root [32]byte
	copy(root[:], crypto.Keccak256(encoded))
	return root, nil
}

// SortValidatorsForSetRoot sorts addresses ascending by uint160 and reorders
// votingPowers to match. Returns new slices; inputs are unchanged. Matches
// the contract's insertion sort byte-for-byte.
func SortValidatorsForSetRoot(
	addrs []common.Address,
	votingPowers []*big.Int,
) ([]common.Address, []*big.Int) {
	n := len(addrs)
	sortedAddrs := make([]common.Address, n)
	sortedPowers := make([]*big.Int, n)
	copy(sortedAddrs, addrs)
	for i, p := range votingPowers {
		sortedPowers[i] = new(big.Int).Set(p)
	}
	for i := 1; i < n; i++ {
		keyA := sortedAddrs[i]
		keyP := sortedPowers[i]
		j := i
		for j > 0 && new(big.Int).SetBytes(sortedAddrs[j-1].Bytes()).Cmp(new(big.Int).SetBytes(keyA.Bytes())) > 0 {
			sortedAddrs[j] = sortedAddrs[j-1]
			sortedPowers[j] = sortedPowers[j-1]
			j--
		}
		sortedAddrs[j] = keyA
		sortedPowers[j] = keyP
	}
	return sortedAddrs, sortedPowers
}

// =============================================================================
// Misc binary encodings used by canonical hashers
// =============================================================================

// Uint64BE returns the 8-byte big-endian encoding of v. Helper for canonical
// serializers that include integer fields without abi-style 32-byte padding.
func Uint64BE(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}
