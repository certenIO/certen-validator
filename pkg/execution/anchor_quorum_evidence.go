package execution

import (
	"context"
	"math/big"
	"time"
)

// AnchorQuorumEvidence is what a proven anchor actually establishes, kept instead of discarded.
//
// # WHY THIS EXISTS
//
// `prove` folds the peers' partials into a verified aggregate, submits executeComprehensiveProof and
// confirms the anchor's proofExecuted flag — and then returned only `error`. The aggregate signature, the
// signer set and the voting power that carried the quorum all went out of scope. Live example, chain
// 11155111: "[BATCH-QUORUM] quorum formed: 700 of 700 voting power from 7 signer(s)", recorded nowhere.
//
// The consequences were not cosmetic. anchor_batches' Phase 5 columns (quorum_reached,
// attestation_count, aggregated_signature/public_key, consensus_completed_at) were never written by any
// live path: 70,236 rows all time, zero with quorum_reached. proofs_service reads
// COALESCE(ab.quorum_reached, FALSE), so every intent reported batch_quorum_met=false — including the
// 7-of-7 above — and the L5 binding, having no canonical row to use, bound a root that was never
// published to the settlement transaction (see layer5 rows: root d2d24ab3… claimed to be in tx
// 0x9e4ff6ab…, which settled root 2fd899ae…).
//
// # WHAT IT IS NOT
//
// It is not a claim: every field is copied from something already verified or confirmed on-chain —
// the aggregate that AggregateBatchAttestations accepted against the registry, the verify transaction
// that mined, and the anchor flag that AnchorProofExecutedConfirmed read back. Nothing here is inferred
// from "we asked and did not see a failure".
type AnchorQuorumEvidence struct {
	ChainID          int64
	BundleID         [32]byte
	Root             [32]byte
	BatchOperationID [32]byte
	// MessageHash is what every partial signed: the V6.1 pre-execution message over
	// (chainID, bundleID, root, batchOperationID, validatorSetRoot).
	MessageHash [32]byte
	SetRoot     [32]byte

	/// VerifyTx is the executeComprehensiveProof transaction that carried the aggregate on-chain.
	VerifyTx string

	AggregateSignatureHex string
	AggregatePublicKeyHex string
	// Signers are EVM addresses, ascending, and SignerPowers is aligned index-for-index. The anchor
	// itself re-derives the signed power from these, so they are the set that actually signed.
	Signers           []string
	SignerPowers      []*big.Int
	SignedVotingPower *big.Int
	TotalVotingPower  *big.Int

	// Lane distinguishes the one-member on-demand anchor from a cadence batch. Both prove the same way;
	// only membership differs.
	Lane string

	Members []AnchorQuorumMember

	// AttestedAt is when proofExecuted was confirmed by this validator, not when the row is written.
	AttestedAt time.Time
}

// AnchorQuorumMember is one member of the attested batch, with the branch that proves it.
type AnchorQuorumMember struct {
	// IntentID is known on the on-demand lane; a cadence member is identified by its OperationID, which
	// is the Accumulate 4-blob intent hash and the value bound into the leaf.
	IntentID    string
	OperationID [32]byte
	ADIURL      string
	Leaf        [32]byte
	LeafIndex   int
	Branch      [][32]byte
}

// AnchorLaneOnDemand and AnchorLaneOnCadence name the two lanes.
const (
	AnchorLaneOnDemand  = "on_demand"
	AnchorLaneOnCadence = "on_cadence"
)

// AnchorAttestedHook receives the evidence for an anchor whose proof is confirmed executed.
//
// It is called on the proving path, so it MUST NOT block: the expectation is the same as the
// consensus persister's — hand off and return. A hook that fails must not fail the anchor, because the
// anchor already happened on-chain and the database is a projection of it.
type AnchorAttestedHook func(ctx context.Context, ev *AnchorQuorumEvidence)

// membersFromTree derives the member list (leaf, index, branch) from the tree that was attested.
//
// intentByOperation supplies intent ids where the caller knows them (the on-demand lane knows exactly
// one). A missing id is left empty rather than guessed: the operation id is the durable identifier and
// the join the backfill uses.
func membersFromTree(tree *BatchTree, intentByOperation map[[32]byte]string) []AnchorQuorumMember {
	if tree == nil {
		return nil
	}
	members := make([]AnchorQuorumMember, 0, len(tree.Inputs))
	for i, in := range tree.Inputs {
		branch, err := tree.BranchFor(i)
		if err != nil {
			// BuildBatchTree self-verifies every branch, so this cannot happen for a tree that was
			// attested; record the member without a branch rather than dropping it from the evidence.
			branch = nil
		}
		var leaf [32]byte
		if i < len(tree.Leaves) {
			leaf = tree.Leaves[i]
		}
		members = append(members, AnchorQuorumMember{
			IntentID:    intentByOperation[in.OperationID],
			OperationID: in.OperationID,
			ADIURL:      in.ADIURL,
			Leaf:        leaf,
			LeafIndex:   i,
			Branch:      branch,
		})
	}
	return members
}
