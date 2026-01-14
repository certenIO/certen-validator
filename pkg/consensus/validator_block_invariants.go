package consensus

import (
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/commitment"
)

// VerifyValidatorBlockInvariants verifies that a ValidatorBlock satisfies the
// canonical invariants defined in the ValidatorBlock spec.
//
// IMPORTANT:
//   - This only checks invariants that can be derived from the ValidatorBlock itself
//     and the shared commitment functions.
//   - It does NOT talk to Accumulate, Ethereum, or any external chain.
//   - It does NOT validate BLS signatures or lite client proofs cryptographically.
//
// Typical usage:
//
//	if err := VerifyValidatorBlockInvariants(vb); err != nil {
//	    // Reject block / tx carrying this ValidatorBlock
//	}
func VerifyValidatorBlockInvariants(vb *ValidatorBlock) error {
	if vb == nil {
		return fmt.Errorf("ValidatorBlock cannot be nil")
	}

	var violations []string
	add := func(msg string) {
		violations = append(violations, msg)
	}

	// -----------------------
	// Basic metadata checks
	// -----------------------
	if vb.ValidatorID == "" {
		add("validator_id must not be empty")
	}
	if vb.BundleID == "" {
		add("bundle_id must not be empty")
	}
	if vb.OperationCommitment == "" {
		add("operation_commitment must not be empty")
	}
	if vb.Timestamp == "" {
		add("timestamp must not be empty")
	} else if _, err := time.Parse(time.RFC3339, vb.Timestamp); err != nil {
		add(fmt.Sprintf("timestamp is not valid RFC3339: %v", err))
	}
	// BlockHeight == 0 might be allowed for pre-commit stages;
	// if you want to enforce >0, uncomment:
	// if vb.BlockHeight == 0 {
	// 	add("block_height must be > 0")
	// }

	// -----------------------
	// Operation ID invariants
	// -----------------------

	// CrossChainProof.OperationID must match OperationCommitment
	if vb.CrossChainProof.OperationID == "" {
		add("cross_chain_proof.operation_id must not be empty")
	} else if vb.CrossChainProof.OperationID != vb.OperationCommitment {
		add(fmt.Sprintf(
			"cross_chain_proof.operation_id (%s) must equal operation_commitment (%s)",
			vb.CrossChainProof.OperationID, vb.OperationCommitment,
		))
	}

	// All ResultAttestations must reference the same operation
	for i, att := range vb.ResultAttestations {
		if att.OperationID == "" {
			add(fmt.Sprintf("result_attestations[%d].operation_id must not be empty", i))
			continue
		}
		if att.OperationID != vb.OperationCommitment {
			add(fmt.Sprintf(
				"result_attestations[%d].operation_id (%s) must equal operation_commitment (%s)",
				i, att.OperationID, vb.OperationCommitment,
			))
		}
	}

	// ------------------------------
	// Governance Merkle invariants
	// ------------------------------

	gov := vb.GovernanceProof

	if gov.OrganizationADI == "" {
		add("governance_proof.organization_adi must not be empty")
	}
	if len(gov.AuthorizationLeaves) == 0 {
		add("governance_proof.authorization_leaves must not be empty")
	} else {
		// Recompute Merkle root from AuthorizationLeaves
		leaves := make([]interface{}, len(gov.AuthorizationLeaves))
		for i, leaf := range gov.AuthorizationLeaves {
			leaves[i] = leaf
		}

		root, err := commitment.ComputeGovernanceMerkleRoot(leaves)
		if err != nil {
			add(fmt.Sprintf("failed to recompute governance Merkle root: %v", err))
		} else if gov.MerkleRoot == "" {
			add("governance_proof.merkle_root must not be empty")
		} else if gov.MerkleRoot != root {
			add(fmt.Sprintf(
				"governance_proof.merkle_root mismatch: got %s, expected %s",
				gov.MerkleRoot, root,
			))
		}
	}

	if gov.BLSAggregateSignature == "" {
		add("governance_proof.bls_aggregate_signature must not be empty")
	}
	if gov.BLSValidatorSetPubKey == "" {
		add("governance_proof.bls_validator_set_pubkey must not be empty")
	}

	// ------------------------------
	// Cross-chain commitment checks
	// ------------------------------

	cc := vb.CrossChainProof

	if len(cc.ChainTargets) == 0 {
		add("cross_chain_proof.chain_targets must not be empty")
	} else {
		// All targets must share the same expiry and have non-empty commitments
		expiry := cc.ChainTargets[0].Expiry
		if expiry == "" {
			add("cross_chain_proof.chain_targets[0].expiry must not be empty")
		}
		commitments := make([]string, len(cc.ChainTargets))

		for i, t := range cc.ChainTargets {
			if t.Chain == "" {
				add(fmt.Sprintf("cross_chain_proof.chain_targets[%d].chain must not be empty", i))
			}
			if t.ContractAddress == "" {
				add(fmt.Sprintf("cross_chain_proof.chain_targets[%d].contract_address must not be empty", i))
			}
			if t.Commitment == "" {
				add(fmt.Sprintf("cross_chain_proof.chain_targets[%d].commitment must not be empty", i))
			}
			if t.Expiry == "" {
				add(fmt.Sprintf("cross_chain_proof.chain_targets[%d].expiry must not be empty", i))
			}
			if t.Expiry != expiry {
				add(fmt.Sprintf(
					"cross_chain_proof.chain_targets[%d].expiry (%s) must equal first target expiry (%s)",
					i, t.Expiry, expiry,
				))
			}

			commitments[i] = t.Commitment
		}

		// Validate cross-chain commitment consistency
		// Note: In the canonical 4-blob model, the cross-chain commitment is derived
		// from the original cross-chain blob data, not from operation_id + commitments
		if cc.CrossChainCommitment == "" {
			add("cross_chain_proof.cross_chain_commitment must not be empty")
		}
		// Cross-chain commitment validation is now handled during block creation
		// using the canonical commitment computation from proof.ComputeCrossChainCommitment()
	}

	// ------------------------------
	// Bundle ID invariant
	// ------------------------------

	if gov.MerkleRoot != "" && cc.CrossChainCommitment != "" {
		recomputedBundleID, err := commitment.ComputeBundleID(gov, cc)
		if err != nil {
			add(fmt.Sprintf("failed to recompute bundle_id: %v", err))
		} else if vb.BundleID != "" && vb.BundleID != recomputedBundleID {
			add(fmt.Sprintf(
				"bundle_id mismatch: got %s, expected %s",
				vb.BundleID, recomputedBundleID,
			))
		}
	}

	// ------------------------------
	// ExecutionProof invariants
	// ------------------------------

	exec := vb.ExecutionProof
	switch exec.Stage {
	case "", ExecutionStagePre, ExecutionStagePost:
		// valid labels (empty means pre-execution)
	default:
		add(fmt.Sprintf("execution_proof.stage has invalid value: %q", exec.Stage))
	}

	stage := exec.Stage
	if stage == "" {
		stage = ExecutionStagePre
	}

	if stage == ExecutionStagePre {
		// Pre-execution: expect validator signatures, no external results
		if len(exec.ValidatorSignatures) == 0 {
			add("pre-execution block must include execution_proof.validator_signatures")
		}
		if len(exec.ExternalChainResults) != 0 {
			add("pre-execution block must not include external_chain_results")
		}
	}

	if stage == ExecutionStagePost {
		// Post-execution: expect external results
		if len(exec.ExternalChainResults) == 0 {
			add("post-execution block must include execution_proof.external_chain_results")
		}
	}

	// ------------------------------
	// Optional extra validation checks
	// ------------------------------

	// AccumulateAnchorReference sanity checks
	if vb.AccumulateAnchorReference.TxHash == "" {
		add("accumulate_anchor_reference.tx_hash must not be empty")
	}
	if vb.AccumulateAnchorReference.BlockHeight == 0 {
		add("accumulate_anchor_reference.block_height must be > 0")
	}

	// ExternalChainResult shape validation for post-execution
	if stage == ExecutionStagePost {
		for i, r := range exec.ExternalChainResults {
			if r.Chain == "" {
				add(fmt.Sprintf("execution_proof.external_chain_results[%d].chain must not be empty", i))
			}
			if r.TxHash == "" {
				add(fmt.Sprintf("execution_proof.external_chain_results[%d].tx_hash must not be empty", i))
			}
		}
	}

	// SyntheticTx sanity checks
	for i, st := range vb.SyntheticTransactions {
		if st.Type == "" {
			add(fmt.Sprintf("synthetic_transactions[%d].type must not be empty", i))
		}
	}

	// ------------------------------
	// Final aggregation
	// ------------------------------

	if len(violations) > 0 {
		return fmt.Errorf(
			"validator block invariant violations (%d):\n- %s",
			len(violations),
			strings.Join(violations, "\n- "),
		)
	}

	return nil
}
