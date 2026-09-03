// V8.2 binding primitives — the ACCUMULATE half of the anchor binding.
//
// PURE functions, no certen-internal imports, so this file can be referenced
// from BOTH the BFT signing path (pkg/consensus) and the EVM submission path
// (pkg/execution) without creating an import cycle. Same rule as
// v6_1_binding.go, which this file extends rather than replaces.
//
// # WHAT V8.2 ADDS AND WHY
//
// V8.1 committed CERTEN's own validator set (currentValidatorSetRoot) and
// nothing at all about Accumulate's. What reached the chain about Accumulate
// was, inside govRoot's L4LegSummary, only WHO SIGNED (Signers) and HOW MANY
// WERE NEEDED (Threshold) — never WHO WAS ELIGIBLE. The denominator was
// missing, so a fabricated proof listing arbitrary keys as Signers produced an
// internally consistent govRoot that no on-chain check could distinguish from
// a real one.
//
// V8.2 adds two fields to the pre-exec message:
//
//	accumulateValidatorSetRoot — the Accumulate validator set the quorum
//	    attested to: MEMBERSHIP and THRESHOLD, not just the signers.
//	accumulateIncarnation — WHICH Accumulate chain. The network has forked and
//	    restarted, re-creating state at a new genesis each time, and no chain
//	    contains a commitment to the one before it. A permanent on-chain record
//	    that cannot say which chain it refers to is worth less than it looks.
//
// WHAT THIS DOES NOT DO. The contract COMMITS the Accumulate validator set. It
// does NOT validate it — it cannot run the induction walk and cannot verify an
// ed25519 quorum on chain. Validation stays offline, in a verifier that expands
// accumulateValidatorSetRoot from evidence the proof artifact carries. Anyone
// reading this as "the chain now verifies Accumulate governance" has been
// misled, and comments here exist to prevent that reading.
//
// CRITICAL INVARIANT: every byte produced here is recomputed on-chain inside
// CertenAnchorV8_2.sol. If you change a domain tag, slot order, or encoding you
// MUST change both sides and bump the version suffix.
//
// Domain tags introduced by V8.2 (all bumped, so no V8.1 signature can replay):
//
//	"certen:bls:v2:pre"      — pre-execution BLS messageHash (was v1:pre)
//	"certen:bls:v2:post"     — post-execution BLS messageHash (was v1:post)
//	"certen:bundleid:v1.2"   — single-leg bundleId (was v1.1)
//	"certen:batchbundle:v2"  — batch bundleId (was v1)
//	"certen:accval:v1"       — Accumulate validator-set root (new)
package contracts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// EVM messageHash (pre-exec) — 8 fields, keccak256 over 256 bytes.
// Mirror of CertenAnchorV8_2.sol::_verifyBLSProof.
// =============================================================================

// ComputeEvmMessageHashV8_2_Pre is the V8.2 pre-execution messageHash.
// Validators sign this; the V8.2 anchor recomputes it during verification.
//
// Wire format (abi.encode == 32-byte slots, no length-or-type ambiguity):
//
//	keccak256(abi.encode(
//	  bytes32("certen:bls:v2:pre"),      // domain — BUMPED from v1:pre
//	  uint256(chainId),                   // cross-chain replay defeat
//	  anchorId,                           // bytes32 — commitment-bound bundleId
//	  executionCommitment,                // bytes32 — value-moving binding
//	  operationID,                        // bytes32 — 4-blob intent hash
//	  validatorSetRoot,                   // bytes32 — CERTEN's quorum snapshot
//	  accumulateValidatorSetRoot,         // bytes32 — ACCUMULATE's set  (V8.2)
//	  accumulateIncarnation               // bytes32 — which chain       (V8.2)
//	))
//
// Total preimage: 256 bytes (8 × 32).
func ComputeEvmMessageHashV8_2_Pre(
	chainID int64,
	anchorId, executionCommitment, operationID, validatorSetRoot [32]byte,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) [32]byte {
	return computeEvmMessageHashV8_2(
		[]byte("certen:bls:v2:pre"),
		chainID, anchorId, executionCommitment, operationID, validatorSetRoot,
		accumulateValidatorSetRoot, accumulateIncarnation,
	)
}

// ComputeEvmMessageHashV8_2_Post is the V8.2 post-execution messageHash for
// Phase 8 attestations. The domain tag differs from pre so a pre-exec
// signature can never satisfy a post-exec gate, and vice versa.
// executionResultRoot replaces executionCommitment to bind the actual outcome.
func ComputeEvmMessageHashV8_2_Post(
	chainID int64,
	anchorId, executionResultRoot, operationID, validatorSetRoot [32]byte,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) [32]byte {
	return computeEvmMessageHashV8_2(
		[]byte("certen:bls:v2:post"),
		chainID, anchorId, executionResultRoot, operationID, validatorSetRoot,
		accumulateValidatorSetRoot, accumulateIncarnation,
	)
}

func computeEvmMessageHashV8_2(
	domainTag []byte,
	chainID int64,
	anchorId, payloadCommitment, operationID, validatorSetRoot [32]byte,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) [32]byte {
	var domain [32]byte
	copy(domain[:], domainTag)

	var chainIDBE [32]byte
	big.NewInt(chainID).FillBytes(chainIDBE[:])

	preimage := make([]byte, 0, 32*8)
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, chainIDBE[:]...)
	preimage = append(preimage, anchorId[:]...)
	preimage = append(preimage, payloadCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, validatorSetRoot[:]...)
	preimage = append(preimage, accumulateValidatorSetRoot[:]...)
	preimage = append(preimage, accumulateIncarnation[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// =============================================================================
// The Accumulate validator-set root
// =============================================================================

// AccumulateValidator is one entry of Accumulate's NetworkDefinition.Validators,
// reduced to the fields the root commits to.
type AccumulateValidator struct {
	// PublicKey is the validator's 32-byte ed25519 public key.
	PublicKey [32]byte
	// ActiveOn is the set of partition IDs the validator is active on
	// ("Directory", "BVN1", ...). Case is preserved as Accumulate reports it;
	// ordering is normalised here.
	ActiveOn []string
}

// AccumulateValidatorSetRootInputs is everything the root commits to.
//
// It deliberately carries the THRESHOLD as well as the membership. The
// threshold is the denominator that govRoot's L4LegSummary was missing: a
// commitment to who signed, without a commitment to how many were eligible,
// cannot distinguish a real quorum from three arbitrary keys.
type AccumulateValidatorSetRootInputs struct {
	// Incarnation identifies which Accumulate chain this set belongs to —
	// the genesis root anchor, anchor(directory)-root[0]. The network has
	// restarted more than once and no chain commits to its predecessor, so
	// without this the root is ambiguous across incarnations.
	Incarnation [32]byte

	// ThresholdNumerator / ThresholdDenominator are the network's own
	// validatorAcceptThreshold (globals), e.g. 2/3. Stored as the rational the
	// network publishes rather than as a computed count, so the root tracks the
	// network instead of a snapshot of today's validator count.
	ThresholdNumerator   uint64
	ThresholdDenominator uint64

	// Validators is the full set. Order is irrelevant on input — this function
	// sorts. Duplicates are rejected.
	Validators []AccumulateValidator
}

// ComputeAccumulateValidatorSetRoot returns the canonical root committed by the
// V8.2 pre-exec message.
//
// CANONICAL ENCODING. Sorted, length-prefixed, domain-separated. Two validators
// reading identical chain data MUST produce identical bytes — the same rule
// L4LegSummary.Signers documents, and for the same reason: an unstable encoding
// produces an intermittent, unreproducible on-chain revert, which is close to
// the worst failure mode available here.
//
//	keccak256(
//	  "certen:accval:v1"                 // 16-byte domain tag, literal
//	  || incarnation                      // 32 bytes
//	  || uint64BE(thresholdNumerator)     //  8 bytes
//	  || uint64BE(thresholdDenominator)   //  8 bytes
//	  || uint32BE(len(validators))        //  4 bytes — length prefix
//	  || for each validator, SORTED by publicKey ascending:
//	         publicKey                    // 32 bytes
//	      || uint32BE(len(activeOn))      //  4 bytes — length prefix
//	      || for each partition, SORTED ascending:
//	             uint32BE(len(partition)) //  4 bytes — length prefix
//	          || partition                //  n bytes, UTF-8, case preserved
//	)
//
// Every variable-length field is length-prefixed, so no two distinct inputs can
// produce the same byte string by concatenation ambiguity — e.g. partitions
// {"BVN1","BVN2"} and {"BVN1BVN2"} encode differently.
//
// This is NOT an abi.encode. The on-chain side never recomputes this root — the
// contract only stores and commits to it (it cannot expand it, having no access
// to Accumulate state). The expansion happens in the offline verifier, which is
// why the encoding is optimised for unambiguous re-derivation from an artifact
// rather than for Solidity's decoder.
func ComputeAccumulateValidatorSetRoot(in AccumulateValidatorSetRootInputs) ([32]byte, error) {
	var zero [32]byte

	if in.Incarnation == zero {
		return zero, fmt.Errorf("accumulate validator-set root: incarnation is required " +
			"(a root that cannot say which chain it is about is not a commitment)")
	}
	if in.ThresholdDenominator == 0 {
		return zero, fmt.Errorf("accumulate validator-set root: zero threshold denominator")
	}
	if in.ThresholdNumerator == 0 {
		return zero, fmt.Errorf("accumulate validator-set root: zero threshold numerator " +
			"would admit an unsigned anchor")
	}
	if in.ThresholdNumerator > in.ThresholdDenominator {
		return zero, fmt.Errorf("accumulate validator-set root: threshold numerator %d exceeds denominator %d",
			in.ThresholdNumerator, in.ThresholdDenominator)
	}
	if len(in.Validators) == 0 {
		return zero, fmt.Errorf("accumulate validator-set root: empty validator set")
	}
	if len(in.Validators) > 0xFFFFFFFF {
		return zero, fmt.Errorf("accumulate validator-set root: %d validators overflows the length prefix",
			len(in.Validators))
	}

	// Sort a copy; the caller's slice is not modified.
	vals := make([]AccumulateValidator, len(in.Validators))
	copy(vals, in.Validators)
	sort.Slice(vals, func(i, j int) bool {
		return bytes.Compare(vals[i].PublicKey[:], vals[j].PublicKey[:]) < 0
	})
	for i := 1; i < len(vals); i++ {
		if vals[i].PublicKey == vals[i-1].PublicKey {
			return zero, fmt.Errorf("accumulate validator-set root: duplicate public key %x", vals[i].PublicKey[:8])
		}
	}

	var buf bytes.Buffer
	buf.WriteString("certen:accval:v1")
	buf.Write(in.Incarnation[:])
	buf.Write(Uint64BE(in.ThresholdNumerator))
	buf.Write(Uint64BE(in.ThresholdDenominator))
	buf.Write(uint32BE(uint32(len(vals))))

	for _, v := range vals {
		buf.Write(v.PublicKey[:])

		parts := make([]string, len(v.ActiveOn))
		copy(parts, v.ActiveOn)
		sort.Strings(parts)
		for i := 1; i < len(parts); i++ {
			if parts[i] == parts[i-1] {
				return zero, fmt.Errorf("accumulate validator-set root: validator %x lists partition %q twice",
					v.PublicKey[:8], parts[i])
			}
		}
		if len(parts) > 0xFFFFFFFF {
			return zero, fmt.Errorf("accumulate validator-set root: too many partitions")
		}
		buf.Write(uint32BE(uint32(len(parts))))
		for _, p := range parts {
			if len(p) > 0xFFFFFFFF {
				return zero, fmt.Errorf("accumulate validator-set root: partition name too long")
			}
			buf.Write(uint32BE(uint32(len(p))))
			buf.WriteString(p)
		}
	}

	var root [32]byte
	copy(root[:], crypto.Keccak256(buf.Bytes()))
	return root, nil
}

func uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// =============================================================================
// bundleId derivation — tags bumped, the two new fields folded in
// =============================================================================

// DeriveV8_2BundleID computes the V8.2 single-leg anchorId.
//
// The two Accumulate fields are folded into the bundleId for the same reason
// EVM-004 folded in the commitments: the BLS quorum signs bundleId, so anything
// stored beside it rather than bound into it could be substituted by a rogue
// validator front-running with a different Accumulate set under the bundleId
// the honest quorum signed. Tag bumped v1.1 -> v1.2.
//
//	keccak256(abi.encodePacked(
//	  "certen:bundleid:v1.2",
//	  uint256(chainId), bytes32(adiURLHash),
//	  bytes32(op), bytes32(cc), bytes32(gov), bytes32(exec),
//	  bytes32(operationID), uint256(accumulateBlockHeight),
//	  bytes32(accumulateValidatorSetRoot), bytes32(accumulateIncarnation)
//	))
func DeriveV8_2BundleID(
	chainID int64,
	adiURLHash [32]byte,
	commits V6_1Commitments,
	operationID [32]byte,
	accumulateBlockHeight uint64,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) [32]byte {
	var chainIDBytes32, heightBytes32 [32]byte
	big.NewInt(chainID).FillBytes(chainIDBytes32[:])
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBytes32[:])

	digest := crypto.Keccak256(
		[]byte("certen:bundleid:v1.2"),
		chainIDBytes32[:],
		adiURLHash[:],
		commits.OperationCommitment[:],
		commits.CrossChainCommitment[:],
		commits.GovernanceRoot[:],
		commits.ExecutionCommitment[:],
		operationID[:],
		heightBytes32[:],
		accumulateValidatorSetRoot[:],
		accumulateIncarnation[:],
	)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// DeriveV8_2BatchBundleID computes the V8.2 batch anchorId. Tag bumped v1 -> v2.
//
//	keccak256(abi.encodePacked(
//	  "certen:batchbundle:v2",
//	  uint256(chainId), bytes32(batchRoot), uint256(leafCount),
//	  bytes32(batchOperationID), uint256(accumulateBlockHeight),
//	  bytes32(accumulateValidatorSetRoot), bytes32(accumulateIncarnation)
//	))
func DeriveV8_2BatchBundleID(
	chainID int64,
	batchRoot [32]byte,
	leafCount uint64,
	batchOperationID [32]byte,
	accumulateBlockHeight uint64,
	accumulateValidatorSetRoot, accumulateIncarnation [32]byte,
) [32]byte {
	var chainIDBytes32, leafBytes32, heightBytes32 [32]byte
	big.NewInt(chainID).FillBytes(chainIDBytes32[:])
	new(big.Int).SetUint64(leafCount).FillBytes(leafBytes32[:])
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBytes32[:])

	digest := crypto.Keccak256(
		[]byte("certen:batchbundle:v2"),
		chainIDBytes32[:],
		batchRoot[:],
		leafBytes32[:],
		batchOperationID[:],
		heightBytes32[:],
		accumulateValidatorSetRoot[:],
		accumulateIncarnation[:],
	)
	var out [32]byte
	copy(out[:], digest)
	return out
}

// =============================================================================
// High-level builder
// =============================================================================

// V8_2PreExecBundleInputs is V6_1PreExecBundleInputs plus the Accumulate half.
// All fields are chain-portable bytes — no intent/proof types — so this package
// stays import-cycle-free.
type V8_2PreExecBundleInputs struct {
	ChainID               int64
	ValidatorSetRoot      [32]byte // CERTEN's operators
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	ExecutionCommitment   [32]byte
	OperationID           [32]byte
	AccumulateBlockHeight uint64
	GovRootInputs         AccumulateGovRootInputs

	// AccumulateValidatorSet is the set that signed L4, and the incarnation it
	// belongs to. Required: there is deliberately no "unknown" encoding, because
	// a zero root would be a weaker claim wearing the same shape as a real one.
	// A proof that cannot establish this is recorded off-chain in a named weaker
	// state and is not anchored as a governance claim at all.
	AccumulateValidatorSet AccumulateValidatorSetRootInputs
}

// BuildV8_2PreExecBundle is the SINGLE SOURCE OF TRUTH for the V8.2 pre-exec
// binding. Both the BFT signing path and the EVM submission path call it with
// primitives derived from the same (intent, proof); because the derivation is
// deterministic and the function is pure, validator and submitter compute
// byte-identical anchorId and messageHash.
//
// Returns (anchorId, govRoot, accumulateValidatorSetRoot, messageHash) so the
// caller can store all four on the proof and log them when the two paths
// disagree.
//
// Note govRoot is computed exactly as in V6.1 and is NOT widened. The Accumulate
// set root travels in the anchor message, not in govRoot's preimage — govRoot
// would have been cryptographically sufficient too, but the message is where the
// CERTEN quorum explicitly attests to which Accumulate set it saw, and it puts
// both validator states side by side in one signed object.
func BuildV8_2PreExecBundle(in V8_2PreExecBundleInputs) (
	anchorId, govRoot, accumulateValidatorSetRoot, messageHash [32]byte, err error,
) {
	accumulateValidatorSetRoot, err = ComputeAccumulateValidatorSetRoot(in.AccumulateValidatorSet)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}, err
	}

	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)
	commits := V6_1Commitments{
		OperationCommitment:  in.OperationCommitment,
		CrossChainCommitment: in.CrossChainCommitment,
		GovernanceRoot:       govRoot,
		ExecutionCommitment:  in.ExecutionCommitment,
	}
	anchorId = DeriveV8_2BundleID(
		in.ChainID, in.AdiURLHash, commits, in.OperationID, in.AccumulateBlockHeight,
		accumulateValidatorSetRoot, in.AccumulateValidatorSet.Incarnation,
	)
	messageHash = ComputeEvmMessageHashV8_2_Pre(
		in.ChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
		accumulateValidatorSetRoot,
		in.AccumulateValidatorSet.Incarnation,
	)
	return anchorId, govRoot, accumulateValidatorSetRoot, messageHash, nil
}
