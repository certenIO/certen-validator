package consensus

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/verification"
)

// =============================================================================
// Batch quorum prover
// =============================================================================
//
// Closes the seam BatchOrchestrator declares via execution.QuorumProver.
//
// A batch anchor is created by a validator but is NOT spendable until the quorum has
// attested to its ROOT — CertenAccountV7 refuses any anchor whose proofExecuted flag is
// false, so an unattested batch authorizes nothing. This type produces that attestation.
//
// WHY NO CIRCUIT CHANGE IS NEEDED
//
// CertenAnchorV7._verifyBLSProof reconstructs the SAME six-field V6.1 pre-exec message it
// always did:
//
//	keccak256(abi.encode(
//	    bytes32("certen:bls:v1:pre"), chainId, anchorId,
//	    anchor.executionCommitment, anchor.operationID, validatorSetRoot))
//
// createBatchAnchor stores batchRoot in executionCommitment and batchOperationID in
// operationID. So signing a batch is the ordinary V6.1 pre-exec signature with those two
// values substituted — the BLSZKVerifierV2 circuit is untouched, and the same
// bls_zkp.SignV6_1PreExec produces a satisfying signature.
//
// WHAT THE QUORUM IS ATTESTING TO
//
// The root, and through it every member leaf. Because bundleId is a pure function of
// (root, leafCount, batchOperationID, height), a rogue validator cannot move a signature
// from one batch to another: any change to the membership changes the root, which changes
// the id, which changes the message the quorum signed.

// ComputeBatchPreExecMessage returns the message the quorum must sign for a batch anchor.
//
// Exported so an operator (or a test) can reproduce it independently and confirm what the
// validator set actually signed.
func ComputeBatchPreExecMessage(
	chainID int64,
	bundleID [32]byte,
	batchRoot [32]byte,
	batchOperationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	// executionCommitment slot carries the batch root — see createBatchAnchor.
	return contracts.ComputeEvmMessageHashV6_1_Pre(
		chainID, bundleID, batchRoot, batchOperationID, validatorSetRoot,
	)
}

// signBatchPreExecBLS signs the batch root with this validator's BLS key.
//
// Mirrors signV6_1PreExecBLS's EVM tail exactly, including the use of SignV6_1PreExec rather
// than SignWithDomain: the latter hashes to a different G1 point and makes the V2 circuit
// unsatisfiable, which is the failure that took Sepolia test #7 down.
func signBatchPreExecBLS(
	logger Logger,
	chainID int64,
	bundleID [32]byte,
	batchRoot [32]byte,
	batchOperationID [32]byte,
) (string, [32]byte, error) {
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return "", [32]byte{}, fmt.Errorf("validator-set root: %w", err)
	}

	msgHash := ComputeBatchPreExecMessage(chainID, bundleID, batchRoot, batchOperationID, setRoot)

	if logger != nil {
		logger.Printf("[BLS-SIG-BATCH] chainId=%d bundleId=0x%x root=0x%x batchOpID=0x%x msg=0x%x setRoot=0x%x",
			chainID, bundleID[:8], batchRoot[:8], batchOperationID[:8], msgHash[:8], setRoot[:8])
	}

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return "", msgHash, fmt.Errorf("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return "", msgHash, fmt.Errorf("validator BLS private key not loaded")
	}

	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", msgHash, fmt.Errorf("batch BLS sign returned nil")
	}
	return sig.Hex(), msgHash, nil
}

// BatchProofSubmitter submits executeComprehensiveProof for a batch anchor on one chain.
//
// Kept as an interface so this file does not import pkg/execution (which already imports
// pkg/consensus indirectly), and so the submission path can be exercised in tests without a
// chain.
type BatchProofSubmitter interface {
	SubmitBatchComprehensiveProof(
		ctx context.Context,
		chainID int64,
		bundleID [32]byte,
		batchRoot [32]byte,
		batchOperationID [32]byte,
		aggregateSignature string,
		messageHash [32]byte,
	) error

	// AnchorProofExecuted reports whether the anchor's proofExecuted flag is set. Used to
	// confirm the attestation actually landed rather than trusting the submit call.
	AnchorProofExecuted(ctx context.Context, chainID int64, bundleID [32]byte) (bool, error)
}

// BatchQuorumProver implements execution.QuorumProver.
type BatchQuorumProver struct {
	logger    Logger
	submitter BatchProofSubmitter
}

// NewBatchQuorumProver builds a prover. submitter must be non-nil; without it the prover
// could sign but never land the attestation, and the orchestrator would proceed to account
// calls against an anchor no account accepts.
func NewBatchQuorumProver(logger Logger, submitter BatchProofSubmitter) (*BatchQuorumProver, error) {
	if submitter == nil {
		return nil, fmt.Errorf("batch quorum prover requires a proof submitter")
	}
	return &BatchQuorumProver{logger: logger, submitter: submitter}, nil
}

// ProveBatchRoot obtains quorum attestation over a batch root and submits it.
//
// Satisfies execution.QuorumProver. Returns only once the anchor's proofExecuted flag is
// confirmed set — the orchestrator relies on that, because every subsequent account call
// would revert with "anchor proof not executed" otherwise.
func (p *BatchQuorumProver) ProveBatchRoot(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
	batchRoot [32]byte,
) error {
	// The batch operationID is recoverable from the anchor itself, but requiring it here
	// would force a chain read on a value the caller already has. Instead it is derived
	// from the same bundleId binding the contract enforces: the caller cannot pass a root
	// and id that do not correspond, because createBatchAnchor already rejected that.
	batchOperationID, err := p.batchOperationIDFor(ctx, chainID, bundleID)
	if err != nil {
		return err
	}

	sigHex, msgHash, err := signBatchPreExecBLS(p.logger, chainID, bundleID, batchRoot, batchOperationID)
	if err != nil {
		return fmt.Errorf("signing batch root: %w", err)
	}

	if err := p.submitter.SubmitBatchComprehensiveProof(
		ctx, chainID, bundleID, batchRoot, batchOperationID, sigHex, msgHash,
	); err != nil {
		return fmt.Errorf("submitting batch comprehensive proof: %w", err)
	}

	// Confirm rather than assume. A submit that mined with status 1 but did not set the
	// flag would otherwise send every member into a revert with a misleading error.
	executed, err := p.submitter.AnchorProofExecuted(ctx, chainID, bundleID)
	if err != nil {
		return fmt.Errorf("confirming anchor attestation: %w", err)
	}
	if !executed {
		return fmt.Errorf(
			"batch anchor 0x%x still reports proofExecuted=false after submission; "+
				"no account will accept it", bundleID[:8])
	}

	if p.logger != nil {
		p.logger.Printf("[BLS-BATCH] chain=%d anchor 0x%x attested; root 0x%x is now spendable",
			chainID, bundleID[:8], batchRoot[:8])
	}
	return nil
}

// batchOperationIDFor reads the anchor's stored batch operationID.
func (p *BatchQuorumProver) batchOperationIDFor(
	ctx context.Context,
	chainID int64,
	bundleID [32]byte,
) ([32]byte, error) {
	type opIDReader interface {
		BatchOperationID(ctx context.Context, chainID int64, bundleID [32]byte) ([32]byte, error)
	}
	if r, ok := p.submitter.(opIDReader); ok {
		return r.BatchOperationID(ctx, chainID, bundleID)
	}
	return [32]byte{}, fmt.Errorf(
		"proof submitter does not expose BatchOperationID; cannot reconstruct the quorum "+
			"message for bundle 0x%x", bundleID[:8])
}

// =============================================================================
// Intent -> batch member extraction
// =============================================================================

// BatchLeg mirrors the fields pkg/execution needs to build a member's execution commitment.
// Declared here (rather than importing execution) because execution already depends on this
// package's types via the prover; the enqueuer converts it on the other side.
type BatchLeg struct {
	LegID   string
	ChainID int64
	Target  [20]byte
	Value   *big.Int
	Data    []byte
}

// batchInputsFromIntent extracts what the batch mempool needs from a consensus intent.
//
// Rejects anything the batch path cannot represent honestly, so a malformed member is
// refused at enqueue time and falls back to the per-intent path — rather than poisoning a
// tree that other ADIs' intents are waiting on.
func (bv *BFTValidator) batchInputsFromIntent(
	ci *CertenIntent,
) (legs []BatchLeg, chainID int64, account [20]byte, operationID [32]byte, err error) {
	if ci == nil {
		return nil, 0, account, operationID, fmt.Errorf("nil intent")
	}

	// operationID is the canonical 4-blob hash. The anchor requires it non-zero and it is
	// bound into the member's leaf, preserving third-party verifiability of a single member
	// against the batch root.
	opHex, oerr := ci.OperationID()
	if oerr != nil {
		return nil, 0, account, operationID, fmt.Errorf("operationID: %w", oerr)
	}
	ob, derr := hex.DecodeString(strings.TrimPrefix(opHex, "0x"))
	if derr != nil || len(ob) != 32 {
		return nil, 0, account, operationID, fmt.Errorf("operationID malformed: %q", opHex)
	}
	copy(operationID[:], ob)

	env, cerr := ci.ParseCrossChain()
	if cerr != nil {
		return nil, 0, account, operationID, fmt.Errorf("parse cross-chain: %w", cerr)
	}
	if len(env.Legs) == 0 {
		return nil, 0, account, operationID, fmt.Errorf("intent has no legs")
	}

	for i, leg := range env.Legs {
		ep := leg.ExecutionPayload
		if ep == nil {
			return nil, 0, account, operationID, fmt.Errorf("leg %d has no executionPayload", i)
		}
		if leg.ChainID == 0 {
			return nil, 0, account, operationID, fmt.Errorf("leg %d has no chainID", i)
		}
		// A batch is one anchor on one chain; a multi-chain intent cannot be one member.
		if chainID == 0 {
			chainID = leg.ChainID
		} else if leg.ChainID != chainID {
			return nil, 0, account, operationID,
				fmt.Errorf("intent spans chains %d and %d; not batchable as one member",
					chainID, leg.ChainID)
		}

		var target [20]byte
		tb, terr := hex.DecodeString(strings.TrimPrefix(ep.Target, "0x"))
		if terr != nil || len(tb) != 20 {
			return nil, 0, account, operationID, fmt.Errorf("leg %d target malformed: %q", i, ep.Target)
		}
		copy(target[:], tb)

		val := new(big.Int)
		if ep.Value != "" {
			if _, ok := val.SetString(strings.TrimPrefix(ep.Value, "0x"), 10); !ok {
				if _, ok16 := val.SetString(strings.TrimPrefix(ep.Value, "0x"), 16); !ok16 {
					return nil, 0, account, operationID, fmt.Errorf("leg %d value malformed: %q", i, ep.Value)
				}
			}
		}

		var data []byte
		if cd := strings.TrimPrefix(ep.CallData, "0x"); cd != "" && cd != "0x" {
			data, derr = hex.DecodeString(cd)
			if derr != nil {
				return nil, 0, account, operationID, fmt.Errorf("leg %d callData malformed", i)
			}
		}

		// Every leg must come from the SAME account: one member is one account call.
		var from [20]byte
		fb, ferr := hex.DecodeString(strings.TrimPrefix(leg.From, "0x"))
		if ferr != nil || len(fb) != 20 {
			return nil, 0, account, operationID, fmt.Errorf("leg %d has no usable source account", i)
		}
		copy(from[:], fb)
		if account == ([20]byte{}) {
			account = from
		} else if from != account {
			return nil, 0, account, operationID,
				fmt.Errorf("intent legs span two source accounts; not batchable as one member")
		}

		legs = append(legs, BatchLeg{
			LegID:   leg.LegID,
			ChainID: leg.ChainID,
			Target:  target,
			Value:   val,
			Data:    data,
		})
	}

	if account == ([20]byte{}) {
		return nil, 0, account, operationID, fmt.Errorf("no source account resolved")
	}
	return legs, chainID, account, operationID, nil
}

// RunBatchMemberAttestation closes the proof cycle for ONE member of a settled batch.
//
// Bridges execution's flush loop back into Phase 7-9. The snapshot arrives as interface{}
// because the flush loop lives in pkg/execution and must not import this package.
//
// A member whose batch FAILED is still passed through with success=false: attesting the
// failure is what stops the intent sitting pending forever with nothing recording why.
func (bv *BFTValidator) RunBatchMemberAttestation(
	ctx context.Context,
	attestation interface{},
	txHash string,
	chainID int64,
	success bool,
) {
	att, ok := attestation.(*PendingAttestation)
	if !ok || att == nil {
		bv.logger.Printf("⚠️ [BATCH-ATTEST] snapshot was not a *PendingAttestation; member cannot attest")
		return
	}

	res := &verification.AnchorExecutionResult{
		AnchorTxID:               txHash,
		Network:                  fmt.Sprintf("evm-%d", chainID),
		GovernanceTxHash:         txHash,
		AllTransactionsConfirmed: success,
	}
	if !success {
		bv.logger.Printf("⚠️ [BATCH-ATTEST] intent %s did not settle; attesting failure", att.IntentID)
	}
	bv.RunProofCycle(ctx, att, res)
}
