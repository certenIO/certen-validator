package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

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

// REMOVED: signBatchPreExecBLS / BatchQuorumProver / BatchProofSubmitter.
//
// They signed a batch root with THIS validator's key alone and handed the resulting single
// signature to a submitter that declared SignedVotingPower == TotalVotingPower. The chain
// refused the raw 48-byte signature, so it failed safe — but the shape invited the one-line
// "fix" of wrapping it in generateBLSZKProof, which would have minted a valid proof asserting
// 700/700 signed power from one key (the CRYPTO-007 quorum forgery).
//
// The replacement is execution.BatchQuorumAttestor: it collects partials from peers over the
// existing attestation HTTP channel, folds them with AggregateBatchAttestations against the
// anchor's REGISTERED public keys, and submits a signed power summed from validators that
// actually signed. It lives in pkg/execution because it needs the peer client, the chain
// resolver, and the ZK prover — and pkg/consensus cannot import pkg/execution (the dependency
// runs the other way, via executor.go).
//
// What remains here is what genuinely belongs to consensus: the message definition
// (ComputeBatchPreExecMessage), the fold and its security rules (batch_quorum_aggregate.go),
// and intent -> member extraction below.

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

// RunBatchMemberFallback executes a member the batch path had to DROP, individually.
//
// The approved failure policy is "fall back, never requeue". Requeueing a dropped member
// re-forms the identical tree, derives the identical bundleId, and reverts with
// AnchorAlreadyExists — which hides the real fault and can leave the batch permanently stuck.
// Falling back costs a full per-intent anchor (~800k gas instead of an amortised share) but it
// settles, which is the whole point.
//
// A member that reaches here without its submission snapshot cannot be re-executed. That case
// still attests the FAILURE rather than returning silently: an intent sitting pending forever
// with nothing recording why is the outcome this path exists to prevent.
func (bv *BFTValidator) RunBatchMemberFallback(ctx context.Context, attestation interface{}) {
	att, ok := attestation.(*PendingAttestation)
	if !ok || att == nil {
		bv.logger.Printf("⚠️ [BATCH-FALLBACK] snapshot was not a *PendingAttestation; member cannot fall back")
		return
	}

	if bv.targets == nil || att.SubmitVB == nil || att.SubmitBFT == nil {
		bv.logger.Printf("⚠️ [BATCH-FALLBACK] intent %s was dropped from its batch but carries no "+
			"per-intent submission inputs (targets=%v vb=%v bft=%v); attesting failure so it does "+
			"not sit pending silently",
			att.IntentID, bv.targets != nil, att.SubmitVB != nil, att.SubmitBFT != nil)
		bv.RunProofCycle(ctx, att, &verification.AnchorExecutionResult{
			AllTransactionsConfirmed: false,
		})
		return
	}

	bv.logger.Printf("↩️  [BATCH-FALLBACK] intent %s dropped from its batch — executing on the "+
		"per-intent path", att.IntentID)

	subCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := bv.targets.SubmitAnchorFromValidatorBlock(subCtx, att.SubmitVB, att.SubmitBFT)
	if err != nil || res == nil {
		bv.logger.Printf("❌ [BATCH-FALLBACK] intent %s failed on the per-intent path too: %v",
			att.IntentID, err)
		bv.RunProofCycle(ctx, att, &verification.AnchorExecutionResult{
			AllTransactionsConfirmed: false,
		})
		return
	}

	bv.logger.Printf("✅ [BATCH-FALLBACK] intent %s settled individually: tx=%s network=%s",
		att.IntentID, res.AnchorTxID, res.Network)
	bv.RunProofCycle(ctx, att, res)
}

// =============================================================================
// Batch period leadership
// =============================================================================

// ObservedConsensusHeight reports the highest BFT height this validator has seen a round
// commit at.
//
// This — not a chain read and not a wall clock — is the right cutoff source: it is the exact
// value stamped onto members by EnqueueForBatch, so a cutoff derived from it can never exclude
// every member by being ahead of them all.
func (bv *BFTValidator) ObservedConsensusHeight() uint64 {
	return bv.observedHeight.Load()
}

// noteConsensusHeight records a committed BFT height. Monotonic: a late-arriving lower height
// must not rewind the cutoff, or a period already flushed could be re-formed and revert.
func (bv *BFTValidator) noteConsensusHeight(h uint64) {
	for {
		cur := bv.observedHeight.Load()
		if h <= cur {
			return
		}
		if bv.observedHeight.CompareAndSwap(cur, h) {
			return
		}
	}
}

// IsBatchPeriodLeader reports whether this validator is the elected submitter for one chain's
// batch period.
//
// Every validator must reach the SAME answer, so the selection is a pure function of
// (chainID, cutoffHeight) over the same roster — no local state, no wall clock, no ordering.
// Rotating on the cutoff spreads anchor gas across the set instead of parking it on one node.
//
// Without this every validator races to anchor the same period: one wins and six burn gas
// reverting with AnchorAlreadyExists, and the winner is whoever's timer fired first rather
// than whoever the set agreed on.
func (bv *BFTValidator) IsBatchPeriodLeader(chainID int64, cutoffHeight uint64) bool {
	roster := batchLeaderRoster()
	if len(roster) == 0 {
		return false
	}
	key := fmt.Sprintf("certen:batchperiod:v1|%d|%d", chainID, cutoffHeight)
	sum := sha256.Sum256([]byte(key))
	// Fold four bytes rather than one: with a single byte and a 7-way modulus the selection is
	// measurably biased toward the low indices (256 = 7*36 + 4).
	idx := binary.BigEndian.Uint32(sum[:4]) % uint32(len(roster))
	return roster[idx] == bv.validatorID
}

// batchLeaderRoster returns the validator IDs eligible to lead a batch period, in a
// deterministic order.
//
// Read from BATCH_LEADER_VALIDATORS when set, so a set change does not require a code change;
// otherwise the seven production IDs. The order is normalised by sorting, because a roster
// that differs only in order would elect different leaders on different nodes.
func batchLeaderRoster() []string {
	raw := strings.TrimSpace(os.Getenv("BATCH_LEADER_VALIDATORS"))
	var ids []string
	if raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ids = append(ids, p)
			}
		}
	} else {
		ids = []string{
			"validator-1", "validator-2", "validator-3", "validator-4",
			"validator-5", "validator-6", "validator-7",
		}
	}
	sort.Strings(ids)
	return ids
}

// memberADIURL resolves the ADI URL to hash into a batch member's Merkle leaf.
//
// This value is consensus-critical in a way that is easy to miss. ComputeBatchLeaf hashes
// keccak256(adiURL) into the leaf, and CertenAccountV7.computeLeaf recomputes that leaf from
// the account's OWN immutable adiURL, set at deployment by CertenAccountFactoryV9. If the two
// strings differ by even one character the leaf is not in the root the account checks against,
// so executeGovernanceProofDirect reverts — AFTER the batch anchor and its BLS attestation
// have been paid for on chain. The intent then sits pending forever with nothing recording why.
//
// CertenIntent carries two URLs that look interchangeable and are not:
//
//	AccountURL      — the principal where the WriteData tx lives: "acc://org.acme/data"
//	OrganizationADI — the org ADI itself:                          "acc://org.acme"
//
// Only the second is what the account was deployed with. The batch path originally passed
// AccountURL, which made every batched member unspendable.
//
// The "/data" trim is a fallback for intents whose OrganizationADI was never populated, not
// the primary path. Anything still carrying a "/data" suffix, or empty, or not an acc:// URL,
// is refused: falling back to the per-intent path costs more gas but settles, whereas a wrong
// leaf cannot settle at all.
func memberADIURL(ci *CertenIntent) (string, error) {
	if ci == nil {
		return "", fmt.Errorf("nil intent")
	}

	adi := strings.TrimSpace(ci.OrganizationADI)
	if adi == "" {
		// Fallback only. AccountURL is the data account, so the suffix must come off.
		adi = strings.TrimSuffix(strings.TrimSpace(ci.AccountURL), "/data")
	}

	if adi == "" {
		return "", fmt.Errorf("intent carries neither organizationAdi nor accountUrl")
	}
	if !strings.HasPrefix(adi, "acc://") {
		return "", fmt.Errorf("resolved ADI %q is not an acc:// URL", adi)
	}
	// A trailing "/data" here means we resolved the data account, not the ADI. Refuse rather
	// than emit a leaf the account can never verify.
	if strings.HasSuffix(adi, "/data") {
		return "", fmt.Errorf("resolved ADI %q is a data account, not an org ADI", adi)
	}
	if strings.HasSuffix(adi, "/") {
		return "", fmt.Errorf("resolved ADI %q has a trailing slash; the account's adiURL will not match", adi)
	}
	return adi, nil
}
