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

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
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
// onlyChain, when non-zero, restricts extraction to the legs on that chain. A cross-chain intent
// is a valid batch input once split: each chain contributes its OWN member, with its own source
// account and its own leaf. The leaf binds chainid, so two members of the same intent on different
// chains cannot collide even though they share an operationID and ADI URL.
func (bv *BFTValidator) batchInputsFromIntentForChain(
	ci *CertenIntent,
	onlyChain int64,
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
		if onlyChain != 0 && leg.ChainID != onlyChain {
			continue
		}
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

	if len(legs) == 0 {
		return nil, 0, account, operationID, fmt.Errorf("no legs on chain %d", onlyChain)
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

	// STAGE 1, THE DANGEROUS DIRECTION. Everywhere else in this change,
	// AllTransactionsConfirmed == false now means "unresolved" rather than
	// "failed" — because a submit window is not evidence. HERE IT REALLY DOES
	// MEAN FAILED, so it is stated explicitly rather than left to the default.
	//
	// Checked at every caller (main.go → BatchFlushConfig.Attest and
	// OnDemandSubmitterConfig.Attest) before relying on it: success=false is
	// produced only by batch_assembly.go's res.Failed loop (the member's own
	// transaction reverted), by its AlreadySettled-but-never-executed release,
	// and by OnDemandSubmitter.dispose when the member did not settle. None of
	// those is a timeout. If a future caller passes false for "I gave up
	// waiting", it must set att.TargetChainOutcome = TargetChainPending itself —
	// silently downgrading a revert to "still pending" is precisely the harm this
	// stage must not cause.
	if success {
		att.TargetChainOutcome = TargetChainConfirmedOutcome
	} else {
		att.TargetChainOutcome = TargetChainFailed
		bv.logger.Printf("⚠️ [BATCH-ATTEST] intent %s did not settle; attesting failure (tx=%q) — "+
			"a KNOWN failure, not an unresolved settlement", att.IntentID, txHash)
	}
	bv.RunProofCycle(ctx, att, res)
}

// enqueueForBatch places one on_cadence intent into THIS validator's batch mempool and reports
// whether it was accepted.
//
// Called by every validator on every committed on_cadence round, elected executor or not. That
// is the point: a peer can only attest to a batch it can independently rebuild from its own
// mempool, so a mempool populated on one node alone makes quorum impossible by construction.
//
// It creates no transaction and spends nothing. Duplicate SUBMISSION is prevented separately,
// by the batch period leader election — a different election from the round executor.
//
// Returns false when the intent cannot be represented as a batch member, so the caller falls
// through to the per-intent path rather than dropping it.
func (bv *BFTValidator) enqueueForBatch(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	vb *ValidatorBlock,
	vbMeta *verification.ValidatorBlockMetadata,
	bftMeta *verification.BFTExecutionMetadata,
	blockHeight uint64,
	g0Proof *proof.G0Result,
	g1Proof *proof.G1Result,
	g2Proof *proof.G2Result,
	blsSignature string,
	validatorSignatures []string,
	governanceLevel string,
	commitHeight uint64,
) bool {
	// The attestation snapshot is captured HERE, while the round's values are in scope. The
	// batch settles minutes later on the flush loop, long after this round is gone.
	batchAtt := bv.captureAttestation(vb, certenIntent, certenProof, blockHeight,
		g0Proof, g1Proof, g2Proof, blsSignature, validatorSignatures, governanceLevel)
	batchAtt.Replayed = true
	// Carry the per-intent submission inputs with the member. If the batch later has to drop it
	// (quorum not reached over the root, or the anchor mines unusable), this is the ONLY way it
	// can still settle — the batch path never requeues.
	batchAtt.SubmitVB = vbMeta
	batchAtt.SubmitBFT = bftMeta

	// One member PER CHAIN.
	//
	// A cross-chain intent used to be refused outright ("intent spans chains X and Y") and fell
	// through to the per-intent path, which has no quorum collection — so it submitted a proof
	// with no validators and the anchor rejected it. Splitting is the honest representation: each
	// chain settles its own legs, under its own anchor, from its own account, and the leaf binds
	// chainid so the two members cannot collide despite sharing an operationID and ADI URL.
	//
	// Partial outcomes are already handled: members settle and fail independently, and a member
	// that reverts is attested as failed without touching the other chain's member.
	chains, chainsErr := bv.batchChainsOfIntent(certenIntent)
	if chainsErr != nil || len(chains) == 0 {
		bv.logger.Printf("⚠️ [BATCH-QUEUE] intent %s cannot be batched (%v) — falling back",
			certenIntent.IntentID, chainsErr)
		return false
	}

	// The ADI URL is keccak'd into the member's Merkle leaf, and the account contract recomputes
	// that leaf from its OWN immutable adiURL. They must be the identical string. AccountURL is
	// the DATA account (".../data") — passing it here produced a leaf no account could ever
	// verify, so every batched member would anchor, attest, and then revert at settlement with
	// the intent stranded. Resolve the org ADI.
	adiURL, adiErr := memberADIURL(certenIntent)
	if adiErr != nil {
		bv.logger.Printf("⚠️ [BATCH-QUEUE] intent %s has no usable ADI URL (%v) — falling back",
			certenIntent.IntentID, adiErr)
		return false
	}

	// commitHeight is the ACCUMULATE block height the intent was written in. It must be a value
	// every validator computes identically for a given intent, because batch membership is the
	// set of intents falling in one height window and the resulting root and bundleId have to
	// match across nodes for the batch to be co-signable.
	//
	// The CometBFT height is NOT such a value: each validator broadcasts its own ValidatorBlock
	// transaction, so one intent commits at a different height on every node (observed live:
	// 230/232/234/235/235/236/237 for a single intent). The Accumulate height is a property of
	// the intent itself — the same reason roundID is built from it.
	// All-or-nothing across chains: if any chain's member cannot be built or queued, none are.
	// A half-queued cross-chain intent would settle on one chain and silently drop the other.
	type pendingMember struct {
		legs    []BatchLeg
		chainID int64
		account [20]byte
		opID    [32]byte
	}
	members := make([]pendingMember, 0, len(chains))
	for _, ch := range chains {
		legs, chainID, account, opID, extractErr := bv.batchInputsFromIntentForChain(certenIntent, ch)
		if extractErr != nil {
			bv.logger.Printf("⚠️ [BATCH-QUEUE] intent %s cannot be batched on chain %d (%v) — "+
				"falling back for the WHOLE intent so it is not split across two paths",
				certenIntent.IntentID, ch, extractErr)
			return false
		}
		members = append(members, pendingMember{legs, chainID, account, opID})
	}

	// LANE ROUTING. proofClass decides WHICH MECHANISM settles the member — never WHETHER to
	// enqueue it. Both lanes are the batch path: routing on_demand off it entirely cannot settle
	// a CertenAccountV7 account, because _authorizeLeaf only ever computes the batch-form leaf.
	// TestEnqueueIsNotGatedOnProofClass guards that.
	//
	// An unrecognised proofClass falls back rather than defaulting to a lane. A member in the
	// wrong lane on one node derives a bundleId its peers never will.
	proofClass, pcErr := certenIntent.GetProofClass()
	if pcErr != nil {
		bv.logger.Printf("⚠️ [BATCH-QUEUE] intent %s has no usable proof class (%v) — falling back",
			certenIntent.IntentID, pcErr)
		return false
	}
	onDemand := proofClass == "on_demand" && onDemandLaneEnabled()

	for _, m := range members {
		var enqErr error
		if onDemand {
			enqErr = bv.batchEnqueuer.EnqueueOnDemand(
				certenIntent.IntentID, adiURL, m.chainID, m.account, m.opID, m.legs, batchAtt, commitHeight)
		} else {
			enqErr = bv.batchEnqueuer.EnqueueForBatch(
				certenIntent.IntentID, adiURL, m.chainID, m.account, m.opID, m.legs, batchAtt, commitHeight)
		}
		if enqErr != nil {
			bv.logger.Printf("⚠️ [BATCH-QUEUE] intent %s not queued on chain %d (%v) — falling back",
				certenIntent.IntentID, m.chainID, enqErr)
			return false
		}
		lane := "on_cadence period"
		if onDemand {
			lane = "ON-DEMAND intent-keyed"
		}
		bv.logger.Printf("📦 [BATCH-QUEUE] intent %s queued for %s settlement on chain %d at height %d (%d of %d chain member(s))",
			certenIntent.IntentID, lane, m.chainID, commitHeight, len(m.legs), len(members))
	}
	return true
}

// onDemandLaneEnabled reports whether intent-keyed on-demand settlement is switched on.
//
// Default OFF. With the flag off an on_demand intent takes the period path exactly as it does
// today, so deploying this code changes nothing until the flag is set — and turning it off again
// is a restart, not a rollback.
func onDemandLaneEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("ON_DEMAND_INTENT_KEYED")), "true")
}

// OnDemandLaneEnabled is onDemandLaneEnabled exported so the wiring can log which lane is live.
func OnDemandLaneEnabled() bool { return onDemandLaneEnabled() }

// RunBatchMemberFallback closes out a member the batch path could not settle.
//
// # WHY THIS NO LONGER RE-EXECUTES
//
// It used to call SubmitAnchorFromValidatorBlock, on the policy "fall back to the per-intent
// path, never requeue". That path CANNOT LAND against CertenAnchorV8_1:
//
//   - extractVotingPower declared power from invented defaults (300/200) rather than from any
//     real signer set, and _verifyBLSProof requires totalVotingPower to equal the registered
//     total (700), so the submission is rejected before the pairing is reached;
//   - its ZK witness proves against the block signer's recorded key, which is not always the
//     key that signed, giving the unsatisfied constraint #774716 seen live.
//
// So routing members there reported a fallback that never occurred, and stranded them. Since
// quorum failures are now RETRIED for the same period (see FlushChain — createBatchAnchor
// treats an existing anchor as success and an already-attested one short-circuits), reaching
// here means the retries are exhausted and the batch genuinely cannot settle.
//
// The honest close-out is therefore to attest the FAILURE, loudly. An intent recorded as failed
// can be reprocessed deliberately; one silently handed to an impossible path cannot, and the
// round has already told the caller it was handled.
//
// Restoring a real per-intent path means giving it the same quorum the batch path uses — a
// one-member batch, which the design already anticipates ("N=1 IS NOT A SPECIAL CASE"), and
// which CertenAccountV7 effectively requires anyway since _authorizeLeaf only ever computes the
// batch-form leaf. That is a change in its own right, not a branch to bolt on here.
func (bv *BFTValidator) RunBatchMemberFallback(ctx context.Context, attestation interface{}) {
	att, ok := attestation.(*PendingAttestation)
	if !ok || att == nil {
		bv.logger.Printf("⚠️ [BATCH-FALLBACK] snapshot was not a *PendingAttestation; member cannot be closed out")
		return
	}

	bv.logger.Printf("❌ [BATCH-FALLBACK] intent %s could not reach quorum after %d attempts and is "+
		"being attested as FAILED. It is NOT being re-executed: the per-intent submitter declares "+
		"voting power the anchor rejects (registered total is authoritative) and proves against a "+
		"key that did not necessarily sign. Re-run it deliberately once the per-intent path uses "+
		"the same aggregate the batch path does.", att.IntentID, maxQuorumAttemptsForLog)

	// STAGE 1: a GENUINE failure, stated as one. The function's own log line
	// already says "attested as FAILED" — quorum was never reached after the full
	// retry budget and the member is deliberately not re-executed — so there is
	// nothing unresolved about it. Left to the pending default it would report as
	// a settlement still in flight that never lands.
	att.TargetChainOutcome = TargetChainFailed

	bv.RunProofCycle(ctx, att, &verification.AnchorExecutionResult{
		AllTransactionsConfirmed: false,
	})
}

// maxQuorumAttemptsForLog mirrors execution.maxQuorumAttempts for the message above. Kept as a
// constant rather than plumbed through, because it is only ever used to explain the failure.
const maxQuorumAttemptsForLog = 5

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
// elapsedPeriods rotates leadership so a DOWN validator cannot freeze a period forever.
//
// Leadership is a pure hash of (chainID, cutoffHeight), so exactly one node may flush a given
// period. If that node is offline the period is unflushable — every other node correctly declines
// and nothing ever settles. Observed live 2026-08-04: validator-3 was stuck in Docker's "Created"
// state, and because it was elected for both pending Base periods the chain sat frozen for 90
// minutes with members queued and no error anywhere.
//
// After batchLeaderFailoverPeriods have elapsed the next node in the roster takes over, and again
// each interval after that, so any period is eventually reachable while at most one node leads at
// a time. elapsedPeriods is derived from currentPeriodStart, which every node computes the same
// way, so the hand-off is deterministic rather than a race.
//
// Nodes momentarily disagreeing at an interval boundary is tolerable: the loser's createAnchor
// returns already-exists and anchorAlreadyAttested short-circuits the rest, which is the same
// path a legitimately duplicated flush already takes.
func (bv *BFTValidator) IsBatchPeriodLeader(chainID int64, cutoffHeight, elapsedPeriods uint64) bool {
	roster := batchLeaderRoster()
	if len(roster) == 0 {
		return false
	}
	key := fmt.Sprintf("certen:batchperiod:v1|%d|%d", chainID, cutoffHeight)
	sum := sha256.Sum256([]byte(key))
	// Fold four bytes rather than one: with a single byte and a 7-way modulus the selection is
	// measurably biased toward the low indices (256 = 7*36 + 4).
	base := uint64(binary.BigEndian.Uint32(sum[:4]))
	// Hand off to the next node every failover interval the period stays unflushed.
	handoffs := elapsedPeriods / batchLeaderFailoverPeriods
	idx := (base + handoffs) % uint64(len(roster))
	return roster[idx] == bv.validatorID
}

// batchLeaderRoster returns the validator IDs eligible to lead a batch period, in a
// deterministic order.
//
// Read from BATCH_LEADER_VALIDATORS when set, so a set change does not require a code change;
// otherwise the seven production IDs. The order is normalised by sorting, because a roster
// that differs only in order would elect different leaders on different nodes.
// BatchLeaderRoster is batchLeaderRoster exported for the on-demand submitter, which elects on
// (chain, operationID) over the SAME roster. Both lanes must agree on who exists, or two nodes
// could each believe they lead the same member.
func BatchLeaderRoster() []string { return batchLeaderRoster() }

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

// batchChainsOfIntent lists the distinct chains an intent's legs touch, ascending.
//
// Sorted so every validator partitions the same intent into the same members in the same order.
// Batch membership must be identical on all nodes or the root and bundleId diverge and the batch
// cannot be co-signed.
func (bv *BFTValidator) batchChainsOfIntent(ci *CertenIntent) ([]int64, error) {
	if ci == nil {
		return nil, fmt.Errorf("nil intent")
	}
	env, err := ci.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain: %w", err)
	}
	seen := map[int64]struct{}{}
	out := make([]int64, 0, len(env.Legs))
	for _, leg := range env.Legs {
		if leg.ChainID == 0 {
			return nil, fmt.Errorf("leg %q has no chainID", leg.LegID)
		}
		if _, dup := seen[leg.ChainID]; dup {
			continue
		}
		seen[leg.ChainID] = struct{}{}
		out = append(out, leg.ChainID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// batchLeaderFailoverPeriods is how many closed periods must pass before leadership for an
// unflushed period moves to the next node in the roster.
//
// Long enough that an ordinary slow flush is never stolen mid-flight, short enough that a node
// being down does not strand members until the 50-period pruner deletes them.
const batchLeaderFailoverPeriods uint64 = 3
