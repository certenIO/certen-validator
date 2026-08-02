package execution

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch quorum attestor — the leader side of Phase 3
// =============================================================================
//
// Produces the attestation that makes a batch anchor spendable, by collecting REAL partial
// signatures from peer validators and folding them.
//
// # WHAT THIS REPLACES, AND WHY THE OLD SHAPE WAS UNSAFE
//
// The previous implementation (consensus.signBatchPreExecBLS) signed with km.PrivateKey() —
// this validator alone — while the submitter declared TotalVotingPower 700 / SignedVotingPower
// 700. The chain rejected the raw single signature, so it failed SAFE, and the one-line "fix"
// was to wrap that signature in generateBLSZKProof. That would have minted a structurally
// valid ZK proof asserting 700/700 signed power from one key: the CRYPTO-007 quorum forgery
// the anchor's 29 authorized-subset commitments exist to prevent (they cover subsets of size
// 5, 6 and 7 only — a single-signer aggregate is not among them).
//
// So the signed power here is never a constant and never the total. It is whatever
// AggregateBatchAttestations summed from partials that actually verified against the
// REGISTERED public keys.
//
// # WHY THE LEADER'S OWN PARTIAL NEEDS NO ROUND TRIP
//
// The leader reproduced the batch by constructing it. Its partial is generated locally and
// folded in alongside the peers' — but it is subject to the identical registry check inside
// AggregateBatchAttestations, so a leader whose key is not registered contributes nothing
// rather than contributing unchecked power.
//
// # WHY REFUSALS ARE NORMAL
//
// A peer that has not yet seen one of the intents derives a different bundleId and declines.
// That costs liveness, never safety: quorum is 5-of-7 by power, and a batch that cannot reach
// it falls back to the per-intent path rather than settling on a weaker signature.

// batchQuorumThresholdNum / Den express the quorum rule the anchor enforces (2/3 by power).
const (
	batchQuorumThresholdNum int64 = 2
	batchQuorumThresholdDen int64 = 3
)

// BatchQuorumAttestor implements QuorumProver by running a real peer quorum.
type BatchQuorumAttestor struct {
	chains      EVMChainResolver
	submitter   *BatchProofSubmitterImpl
	peers       []string
	validatorID string
	timeout     time.Duration
	logf        func(string, ...interface{})
}

// NewBatchQuorumAttestor builds the attestor.
//
// peers may be empty on a single-node devnet, in which case the local partial alone must meet
// threshold — with a one-validator registry it does, and with the production seven-validator
// registry it correctly does not.
func NewBatchQuorumAttestor(
	chains EVMChainResolver,
	submitter *BatchProofSubmitterImpl,
	peers []string,
	validatorID string,
	timeout time.Duration,
	logf func(string, ...interface{}),
) (*BatchQuorumAttestor, error) {
	if chains == nil {
		return nil, fmt.Errorf("batch quorum attestor requires a chain resolver")
	}
	if submitter == nil {
		return nil, fmt.Errorf("batch quorum attestor requires a proof submitter")
	}
	if timeout <= 0 {
		timeout = DefaultBatchAttestationTimeout
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &BatchQuorumAttestor{
		chains:      chains,
		submitter:   submitter,
		peers:       peers,
		validatorID: validatorID,
		timeout:     timeout,
		logf:        logf,
	}, nil
}

// ProveBatchRoot satisfies QuorumProver.
//
// Takes the TREE rather than loose fields so the bundleId, root and batch operationID it
// signs over cannot drift from one another, and so the peer request is built from the same
// object the leaf branches came from.
//
// Returns only once the anchor's proofExecuted flag is confirmed set: every subsequent member
// call would revert with "anchor proof not executed" otherwise, after the gas was already
// spent.
func (a *BatchQuorumAttestor) ProveBatchRoot(
	ctx context.Context,
	tree *BatchTree,
	cutoffHeight uint64,
) error {
	if tree == nil {
		return fmt.Errorf("nil batch tree")
	}
	chainID := tree.ChainID

	ecm, anchorAddr, err := a.chains.ManagerForChain(chainID)
	if err != nil {
		return fmt.Errorf("resolving chain %d: %w", chainID, err)
	}

	// ---- Registry and identity, both from the chain -------------------------
	registry, err := ReadValidatorRegistry(ctx, ecm, anchorAddr)
	if err != nil {
		return fmt.Errorf("reading validator registry: %w", err)
	}
	me, err := ResolveOwnEVMAddress(registry)
	if err != nil {
		return fmt.Errorf("resolving this validator's registry identity: %w", err)
	}

	// ---- The message every partial must cover -------------------------------
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return fmt.Errorf("validator-set root: %w", err)
	}
	msgHash := contracts.ComputeEvmMessageHashV6_1_Pre(
		chainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot,
	)

	// ---- This validator's own partial ---------------------------------------
	km := bls.GetValidatorBLSKey()
	if km == nil || km.PrivateKey() == nil {
		return fmt.Errorf("validator BLS private key not loaded; cannot contribute a partial")
	}
	sk := km.PrivateKey()
	ownSig, err := consensus.SignBatchAttestation(sk, msgHash)
	if err != nil {
		return fmt.Errorf("signing own partial: %w", err)
	}
	partials := []consensus.BatchAttestationEntry{{
		ValidatorID:  a.validatorID,
		EVMAddress:   me,
		SignatureHex: ownSig,
		PublicKeyHex: sk.PublicKey().Hex(),
	}}

	// ---- Peers ---------------------------------------------------------------
	req, err := NewBatchAttestationRequest(tree, cutoffHeight, a.validatorID)
	if err != nil {
		return fmt.Errorf("building attestation request: %w", err)
	}
	// A real logger, not nil: the collector's per-peer lines ("declined: bundleId mismatch",
	// "unreachable") are the only visibility into WHY a quorum came up short, and a burst of
	// mismatches means peers are seeing a different mempool — worth noticing early.
	responses := CollectBatchAttestations(
		ctx, log.New(log.Writer(), "[BATCH-QUORUM] ", log.LstdFlags), a.peers, req, a.timeout)
	for _, r := range responses {
		if r == nil {
			continue
		}
		partials = append(partials, consensus.BatchAttestationEntry{
			ValidatorID:  r.ValidatorID,
			EVMAddress:   r.EVMAddress,
			SignatureHex: r.SignatureHex,
			PublicKeyHex: r.PublicKeyHex,
		})
	}

	a.logf("[BATCH-QUORUM] chain=%d anchor 0x%x: %d partial(s) collected from %d peer(s) + self",
		chainID, tree.BundleID[:8], len(partials), len(a.peers))

	// ---- Fold. This is where a forgery would have to get past ----------------
	agg, err := consensus.AggregateBatchAttestations(
		partials, registry, msgHash, batchQuorumThresholdNum, batchQuorumThresholdDen,
	)
	if err != nil {
		return fmt.Errorf("quorum not formed over batch root 0x%x: %w", tree.Root[:8], err)
	}

	a.logf("[BATCH-QUORUM] chain=%d quorum formed: %s of %s voting power from %d signer(s) %v",
		chainID, agg.SignedVotingPower, agg.TotalVotingPower, len(agg.Signers), agg.Signers)

	// ---- Submit --------------------------------------------------------------
	if err := a.submitter.SubmitBatchQuorumProof(
		ctx, chainID, tree.BundleID, tree.Root, tree.BatchOperationID, agg, msgHash,
	); err != nil {
		return fmt.Errorf("submitting batch quorum proof: %w", err)
	}

	// Confirm rather than assume. A submit that mined with status 1 but did not set the flag
	// would otherwise send every member into a revert with a misleading error.
	executed, err := a.submitter.AnchorProofExecuted(ctx, chainID, tree.BundleID)
	if err != nil {
		return fmt.Errorf("confirming anchor attestation: %w", err)
	}
	if !executed {
		return fmt.Errorf(
			"batch anchor 0x%x still reports proofExecuted=false after submission; "+
				"no account will accept it", tree.BundleID[:8])
	}

	a.logf("[BATCH-QUORUM] chain=%d anchor 0x%x attested; root 0x%x is now spendable",
		chainID, tree.BundleID[:8], tree.Root[:8])
	return nil
}

// ComputeBatchQuorumMessage is the message a batch quorum signs, exported so an operator or a
// test can reproduce independently what the validator set actually attested to.
func ComputeBatchQuorumMessage(tree *BatchTree, setRoot [32]byte) ([32]byte, error) {
	if tree == nil {
		return [32]byte{}, fmt.Errorf("nil tree")
	}
	return contracts.ComputeEvmMessageHashV6_1_Pre(
		tree.ChainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot,
	), nil
}
