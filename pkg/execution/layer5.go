// Copyright 2026 Certen Protocol
//
// Layer 5 — bind a verified L1-L4 proof to its publication on an external chain.
//
// # WHY THIS FILE LIVES IN pkg/execution
//
// The runbook puts Layer5 "in the lite client, beside Layer4". It cannot be there, and it
// cannot be in pkg/proof either. Both would put it out of reach of the ONE thing it must
// agree with bit-for-bit: pkg/execution/batch_tree.go, which is the cross-language contract
// with CertenAnchorV8_1._verifyMerkleProof and CertenAccountV7.computeLeaf.
//
// An earlier version of this file lived in pkg/proof and verified with pkg/merkle. That was
// WRONG, and wrong in a way a single-leaf test could not catch:
//
//	batch tree (what actually built the stored root)  keccak256(sorted(a,b))  order-independent
//	pkg/merkle (what this used to verify with)        sha256(left||right)     positional
//
// Different hash function AND different pairing rule. Every multi-member batch path would
// have been rejected; only N=1 passed, because there both rules collapse to leaf == root.
// Verifying a batch inclusion against a rule the batch was not built with is not a weaker
// check, it is a different question.
//
// So L5 now replays VerifyBranch — the same walk the validator runs before spending gas on
// createBatchAnchor, and the same one the anchor contract runs on chain. One implementation.
//
// # WHAT L5 IS
//
// L4 ends at "a threshold quorum of Accumulate validators signed this state
// root." That is a CONSENSUS claim. It carries no evidence that the claim was
// published anywhere it cannot later be retracted, so it cannot by itself answer
// "was this history rewritten afterwards".
//
// L5 answers the part of that question CERTEN can answer: this proof's leaf is
// under a batch root, and that batch root was written to an external chain at a
// stated block.
//
//	leaf -> batchRoot   verifies OFFLINE, here, with no network.
//	batchRoot -> chain  is COORDINATES plus an OPTIONAL online check.
//
// The second half is deliberately not claimed as offline. Proving it offline
// would require a light client for the target chain, and "offline" stops meaning
// anything the moment you must trust a block header handed to you from
// somewhere. That is out of scope and is not a temporary shortcut.
//
// # WHAT L5 IS NOT
//
// It does NOT add a security property. CERTEN already anchors the govRoot
// externally on every intent — createBatchAnchor on base-sepolia — so the
// immutability/timestamp property ALREADY EXISTS. L5 makes it CHECKABLE, and
// closes the gap between "we have a tx hash somewhere" and "here is the path
// proving this proof is in that anchored batch".
//
// It does NOT establish that the Accumulate validator set which signed L4 is the
// legitimate one. NOTHING in this stage does. An external timestamp attests to
// WHATEVER WAS SIGNED; it says nothing about whether the signers were the right
// ones. Closing that would need an Accumulate validator-set history rooted at
// genesis, which no part of this work touches. Do not describe L5 as though it
// does.
//
// Accumulate itself does not anchor into Bitcoin or Ethereum — verified: every
// anchor type in accumulate-core/protocol/types_gen.go is internal
// (BlockValidatorAnchor, DirectoryAnchor, PartitionAnchor, AnchorLedger), and
// AnchorLedger.MajorBlockIndex is Accumulate's own periodic checkpoint, not a
// publication elsewhere. L5 does not consume it and must not be described as
// waiting for it.
//
// # L5 IS NOT IN THE govROOT, AND STRUCTURALLY CANNOT BE
//
// ComputeAccumulateGovRoot is a fixed ten-slot, 352-byte preimage and the EVM
// contract agrees with it; an eleventh slot is a contract change plus an atomic
// fleet upgrade. But the deeper reason is ordering, not conservatism: L5
// describes the anchoring of a govRoot that must ALREADY EXIST before the anchor
// can be written. It cannot be inside what it describes. L5 is storage and
// read-path only.
package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
)

// MerkleStep is one step of a leaf->batchRoot branch, in the shape it is stored in
// (database.MerklePathNode).
//
// Position IS NOT USED FOR VERIFICATION and must not be. The batch tree pairs with
// keccak256(sorted(a,b)) — the smaller value first — so the walk is ORDER-INDEPENDENT at
// every node and a sibling's side carries no information. It is retained only so a stored
// row round-trips unchanged; treating it as meaningful would invite a second, positional
// implementation of a rule that is deliberately not positional.
type MerkleStep struct {
	Hash     string `json:"hash"`               // hex32 sibling
	Position string `json:"position,omitempty"` // informational only — NOT used in the walk
}

// Layer5 binds a verified L1-L4 proof to its publication on an external chain.
type Layer5 struct {
	// External chain coordinates. These are what an auditor takes to a block
	// explorer; they are NOT verified offline.
	ChainID     int64  `json:"chainId"`
	Network     string `json:"network"`
	AnchorTx    string `json:"anchorTx"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash,omitempty"`

	// The offline half.
	BatchRoot string       `json:"batchRoot"` // hex32 — what was anchored
	LeafHash  string       `json:"leafHash"`  // hex32 — this proof's leaf
	LeafIndex uint64       `json:"leafIndex"`
	Path      []MerkleStep `json:"path"` // leaf -> batchRoot; empty IFF leaf == root

	// Accumulate is the L5 extension (Q15(iii)): which Accumulate incarnation
	// this proof belongs to, and the evidence expanding the validator-set root
	// that CertenAnchorV8_2's pre-exec message commits.
	//
	// OPTIONAL, and optional on purpose. VerifyOffline does not require it and
	// does not fail without it: a missing extension is a named weaker state, not
	// a rejection. Making it mandatory would turn an evidence outage into a
	// governance-proof failure.
	//
	// It is additive to the stored layer JSON and is NOT part of govRoot, which
	// commits L1-L4 and G0-G2 only. See layer5_accumulate.go.
	Accumulate *AccumulateBinding `json:"accumulate,omitempty"`
}

// VerifyOffline recomputes leaf -> batchRoot and checks the coordinates are
// actionable. It performs NO network access.
//
// Fail-closed, mirroring Layer4.VerifyOffline:
//
//  1. leafHash and batchRoot must be 32 bytes of hex.
//  2. An empty branch requires leafHash == batchRoot. That is not a special case bolted on:
//     MerkleRoot over one leaf RETURNS THAT LEAF, so a one-member batch genuinely has an
//     empty branch and a root equal to its leaf. Any OTHER empty branch is rejected —
//     accept it and every proof "verifies" by carrying no evidence.
//  3. The walk is VerifyBranch: keccak256(sorted(a,b)) at each node, which is exactly
//     CertenAnchorV8_1._verifyMerkleProof and exactly what built the stored root. ONE
//     implementation, shared with the pre-flight check the validator runs before paying for
//     an anchor.
//  4. anchorTx must be non-empty and blockNumber > 0, or the coordinates are not actionable.
//
// Note what step 4 does and does not assert. It checks the coordinates are PRESENT and
// usable, not that the transaction exists or contains this batch root. That is the online
// half, reported separately so the two are never conflated.
func (l *Layer5) VerifyOffline() error {
	if l == nil {
		return fmt.Errorf("layer5: absent")
	}

	leaf, err := decodeHex32(l.LeafHash, "layer5.leafHash")
	if err != nil {
		return err
	}
	root, err := decodeHex32(l.BatchRoot, "layer5.batchRoot")
	if err != nil {
		return err
	}

	if len(l.Path) == 0 {
		// A SINGLE-LEAF BATCH is legitimate and common: one intent settled alone
		// forms a one-member tree whose root IS its leaf, and the Phase 6 e2e
		// proof's stored path is exactly []. It is accepted ONLY on that
		// condition. This is where a vacuous pass hides, so the two directions
		// are separated explicitly rather than left to the walk.
		if l.LeafHash != l.BatchRoot {
			return fmt.Errorf(
				"layer5: empty merkle path but leafHash != batchRoot (%s… != %s…); "+
					"this proof is NOT proven to be in the anchored batch",
				short16(l.LeafHash), short16(l.BatchRoot))
		}
		return l.checkCoordinates()
	}

	branch := make([][32]byte, 0, len(l.Path))
	for i, step := range l.Path {
		h, err := decodeHex32(step.Hash, fmt.Sprintf("layer5.path[%d].hash", i))
		if err != nil {
			return err
		}
		var sib [32]byte
		copy(sib[:], h)
		branch = append(branch, sib)
	}

	var leafArr, rootArr [32]byte
	copy(leafArr[:], leaf)
	copy(rootArr[:], root)

	// The same walk the anchor contract performs, and the same one the validator runs
	// before spending gas. Sorted pairing means step.Position is never consulted.
	if !VerifyBranch(branch, rootArr, leafArr) {
		return fmt.Errorf(
			"layer5: leaf %s… does not recompute to batch root %s… over %d step(s); "+
				"this proof is not in the anchored batch",
			short16(l.LeafHash), short16(l.BatchRoot), len(l.Path))
	}

	return l.checkCoordinates()
}

// checkCoordinates requires the external half to be actionable.
//
// Separate from the merkle walk because it is a DIFFERENT KIND of claim: the
// walk is proof, this is a pointer. A layer whose leaf verifies into a root that
// was never published anywhere records an internal consistency and nothing more,
// and reporting that as "anchored" is the overclaim this stage must not make.
func (l *Layer5) checkCoordinates() error {
	if l.AnchorTx == "" {
		return fmt.Errorf("layer5: no anchorTx — the batch root is not stated to have been " +
			"published anywhere, so there is nothing to check against")
	}
	if l.BlockNumber == 0 {
		return fmt.Errorf("layer5: blockNumber is 0 for anchorTx %s — the coordinates are not "+
			"actionable", l.AnchorTx)
	}
	return nil
}

// ExternalClaim renders, in one sentence, exactly what L5 does and does not
// establish.
//
// Exists so that the boundary travels with the artifact instead of living only
// in a runbook. An operator reading a verified L5 must not come away believing
// the Accumulate validator set was independently established, and the easiest
// way to prevent that is to say so on the line that reports the pass.
func (l *Layer5) ExternalClaim() string {
	if l == nil {
		return "no external anchor recorded"
	}
	base := fmt.Sprintf(
		"leaf is under batch root %s… (verified offline); that root is stated to be in tx %s "+
			"at block %d on %s (chainId %d) — COORDINATES, not an offline proof.",
		short16(l.BatchRoot), l.AnchorTx, l.BlockNumber, l.Network, l.ChainID)

	// The caveat is CONDITIONAL, not absolute — but it only shrinks when the
	// evidence is actually carried, and even then it never disappears.
	//
	// Without the extension the original sentence stands verbatim: an external
	// timestamp attests to WHATEVER WAS SIGNED and says nothing about whether the
	// signers were the right ones.
	if l.Accumulate == nil || l.Accumulate.ValidatorSetProof == nil {
		return base + " This attests to whatever was signed, NOT to whether the Accumulate " +
			"validator set that signed L4 was the legitimate one."
	}

	// With the extension, the honest statement is narrower and still bounded. The
	// set is derived rather than asserted; whether it is BOUND to a quorum-signed
	// anchor, and whether the incarnation was checked against an out-of-band pin,
	// are separate questions this string must not answer on the reader's behalf.
	inc := l.Accumulate.Incarnation
	if inc == "" && l.Accumulate.ValidatorSetProof != nil {
		inc = l.Accumulate.ValidatorSetProof.Incarnation
	}
	return base + fmt.Sprintf(
		" It carries the Accumulate validator set as EVIDENCE (incarnation %s…), so the set "+
			"that signed L4 can be derived from chain state rather than taken on trust — but "+
			"this line does not say the derivation was bound to a quorum-signed anchor, nor "+
			"that the incarnation was checked against an out-of-band pin. Verify the binding "+
			"and read its verdict; do not infer either from the presence of this evidence.",
		short16(inc))
}

func decodeHex32(s, label string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%s: empty", label)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %w", label, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s: %d bytes, expected 32", label, len(b))
	}
	return b, nil
}

func short16(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}

// =============================================================================
// Reading L5 back out of storage
// =============================================================================

// ErrNoLayer5 reports that no external-anchor layer was stored for this proof.
//
// This is SUMMARY-ONLY FOR L5, not a failure, and the distinction is load
// bearing: every proof written before Stage 3 is in this state, and so is every
// proof that settled with no observable external transaction. Nothing about such
// a proof is known to be wrong — its L1-L4 chain may verify perfectly. What is
// absent is the binding to a publication, and absence is not a defect to report
// as one.
var ErrNoLayer5 = errors.New("no external anchor layer (L5) stored for this proof: the proof is not bound to a publication")

// Layer5FromStorage reads the external-anchor layer for a proof.
//
// Reuses the same ProofStorageReader the L1-L4 reassembly uses, so a caller that
// can read one can read the other, and a test double serves both.
func Layer5FromStorage(ctx context.Context, store certenproof.ProofStorageReader, proofID uuid.UUID) (*Layer5, error) {
	if store == nil {
		return nil, fmt.Errorf("chained proof storage reader is nil")
	}
	rows, err := store.LayerRows(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("read layer rows for proof %s: %w", proofID, err)
	}
	for _, row := range rows {
		if row.LayerNumber != 5 || len(row.LayerJSON) == 0 {
			continue
		}
		l5 := new(Layer5)
		if err := json.Unmarshal(row.LayerJSON, l5); err != nil {
			// A layer-5 row that will not parse is a corrupt record. Reporting
			// it as absent would turn a corruption into "never stored", which
			// are different facts about a database an operator has to trust.
			return nil, fmt.Errorf("proof %s layer 5 (%s): does not decode: %w",
				proofID, row.LayerName, err)
		}
		return l5, nil
	}
	return nil, fmt.Errorf("proof %s: %w", proofID, ErrNoLayer5)
}

// VerifyStoredLayer5 reads the external-anchor layer back and recomputes
// leaf -> batchRoot from the stored bytes alone. No network access.
//
// Returns the layer even on failure, so a caller can report WHICH binding failed
// and print its coordinates rather than only that something did.
func VerifyStoredLayer5(ctx context.Context, store certenproof.ProofStorageReader, proofID uuid.UUID) (*Layer5, error) {
	l5, err := Layer5FromStorage(ctx, store, proofID)
	if err != nil {
		return nil, err
	}
	if err := l5.VerifyOffline(); err != nil {
		return l5, fmt.Errorf("proof %s failed L5 offline verification from storage: %w", proofID, err)
	}
	return l5, nil
}
