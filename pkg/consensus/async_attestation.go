package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/verification"
)

// =============================================================================
// Async attestation
// =============================================================================
//
// WHY THIS EXISTS
//
// Phase 7-9 (observation, attestation, write-back to Accumulate) used to run only
// inline, as an anonymous goroutine in executeCanonicalBFTWorkflow, closing over ~a
// dozen consensus-round locals. That worked for on_demand intents, which execute
// during the same round.
//
// It did NOT work for on_cadence intents. Those return early from the round after
// being queued (ConsensusHash "cadence_queued_..."), so the inline block was never
// reached — the BFTSchedulerAdapter executed them minutes later on its own ticker and
// nothing ever ran the proof cycle for them. On-cadence intents settled on-chain and
// never attested back to Accumulate.
//
// The fix is to make the attestation inputs CAPTURABLE. Everything Phase 7-9 needs is
// snapshotted into a PendingAttestation at consensus time, when those values are in
// scope and correct. The snapshot can then be replayed whenever execution actually
// completes — immediately for on_demand, or after a batch flush for on_cadence.
//
// Both paths call RunProofCycle, so the two can never drift.

// =============================================================================
// Commitment-map keys — the contract between the attestation and the persisters
// =============================================================================
//
// RunProofCycle hands the persistence layer a map[string]interface{}. Both
// orchestrators read it, and until Stage 2 the keys were spelled out as string
// literals at each end — which is exactly how the legacy G-level writer came to
// look for "g0Proof" while the only writer in the tree wrote "att.G0Proof". That
// key was READ in one place and WRITTEN IN ZERO, so the real G-results never
// reached the database from that path and it always took its stub fallback.
//
// Constants, so the two ends cannot disagree again without the compiler saying
// so. The existing spellings are preserved exactly: they are already in flight
// on the fleet and renaming them would break the readers that do match.
const (
	G0ProofCommitmentKey = "att.G0Proof"
	G1ProofCommitmentKey = "att.G1Proof"
	G2ProofCommitmentKey = "att.G2Proof"

	// GovReceiptsCommitmentKey carries []proof.GovReceiptEvidence as JSON — the
	// merkle paths, beside the results and never inside them.
	GovReceiptsCommitmentKey = "att.GovReceipts"

	// EvidenceErrorCommitmentKey names evidence that was present in the round and could not be carried: its
	// governance levels are refused rather than stored without it (RB4-F69).
	EvidenceErrorCommitmentKey = "att.EvidenceError"

	// GovDecisionCommitmentKey carries the governance decision record as hex, and GovAuthorizationCommitmentKey
	// the G1 vote record it was derived from as JSON (RB4-F66).
	GovDecisionCommitmentKey      = "att.GovDecision"
	GovAuthorizationCommitmentKey = "att.GovAuthorization"
	// GovVoteEvidenceCommitmentKey carries the vote record's evidence as JSON.
	GovVoteEvidenceCommitmentKey = "att.GovVoteEvidence"

	// GovTimingBasisCommitmentKey carries []proof.SignatureTimingBasis as JSON —
	// which counted signatures' ordering rests on execution inclusion rather
	// than on a local block comparison. Beside the results for the same reason
	// the receipts are: the flag it qualifies lives inside the govRoot preimage.
	GovTimingBasisCommitmentKey = "att.GovTimingBasis"

	// GovernanceLevelCommitmentKey is the level actually achieved ("G0"|"G1"|"G2").
	GovernanceLevelCommitmentKey = "att.GovernanceLevel"
)

// PendingAttestation is a self-contained snapshot of everything Phase 7-9 needs.
//
// It is built at consensus time and may be replayed much later, so it must not hold
// references to anything round-scoped that mutates (contexts, cancel funcs, the round's
// mutable state). Every field here is either immutable proof data or a value copy.
type PendingAttestation struct {
	// Identity
	IntentID string
	// IntentMessageHex is the per-intent message this validator's ValidatorBlock certified (RB5 D3), empty for a
	// block built before a BLS registry was in force.
	IntentMessageHex string
	// SettlementLane is the batch lane that settled - or dropped - this member: "on_cadence" (a
	// height-bucketed period sharing one anchor) or "on_demand" (one member, one anchor). It is the
	// member's proof class as stored, stamped by the lane itself (RB3-F74).
	SettlementLane string
	UserID         string
	BundleID       [32]byte

	// The canonical intent and its proof — needed to rebuild the commitment map and to
	// resolve leg/chain structure at replay time.
	CertenIntent *CertenIntent
	CertenProof  *proof.CertenProof

	// ValidatorBlock-derived values. Copied out rather than holding the block itself,
	// so a replay cannot observe a mutated block.
	BundleIDHex           string
	GovernanceProofRoot   string
	OperationCommitment   string
	AccumulateBlockHeight uint64

	// Governance proof results (G0/G1/G2) as generated during the round.
	G0Proof *proof.G0Result
	G1Proof *proof.G1Result
	G2Proof *proof.G2Result

	// GovReceipts is the merkle path for each level's execution receipt.
	//
	// STAGE 2. The results above are CONCLUSIONS — "the right key page authorised
	// this" — and until now that conclusion reached the database as a verdict flag
	// with nothing to check it against. This is the evidence, captured at
	// consensus time from the GovernanceProof wrapper, which is not part of any
	// canonical hash.
	//
	// Snapshotted like everything else here: replayed minutes later on the cadence
	// path, it must be the path the proof was BUILT on, not one fetched again
	// afterwards.
	GovReceipts []proof.GovReceiptEvidence

	// GovTimingBasis is which counted signatures' timing rests on the weaker
	// basis. Snapshotted with everything else here: replayed minutes later on
	// the cadence path it must be what the proof was BUILT on.
	GovTimingBasis []proof.SignatureTimingBasis

	// GovDecision and GovAuthorization are who decided the transaction and the G1 vote record it was derived from
	// (RB4-F66), snapshotted with the rest: the proof cycle stores them with the G1 level, and the batch member
	// commits to the decision.
	GovDecision      []byte
	GovAuthorization *proof.AuthorizationRecord
	GovVoteEvidence  *govvote.Evidence

	// Signatures and level captured during the round.
	BLSSignature        string
	ValidatorSignatures []string
	GovernanceLevel     string
	ValidatorID         string

	// Accumulate write-back references.
	AccountURL      string
	TransactionHash string

	// Replayed marks an attestation being closed from the cadence queue rather than
	// inline. Logging only — the proof cycle itself is identical either way.
	Replayed bool

	// TargetChainOutcome is what the SUBMITTER already knew when it handed this
	// attestation over. It is not the final answer — Phase 7's observation of the
	// real receipt is — but it separates the two shapes the proof cycle cannot
	// otherwise tell apart:
	//
	//	pending : submitted, no terminal receipt inside the submit window. The
	//	          ordinary case (~51s measured lag against a 60s window).
	//	failed  : the caller KNOWS this settlement failed — quorum was never
	//	          reached, or the batch member did not settle. Stated explicitly so
	//	          the pending default can never launder a real failure into "still
	//	          waiting". See RunBatchMemberAttestation and RunBatchMemberRefusal.
	//
	// The zero value normalizes to pending, which is why the failure sites set it
	// deliberately rather than relying on a bool being false.
	TargetChainOutcome TargetChainOutcome

	// FailureReason is why the caller KNOWS this settlement failed, when it does - e.g. the cause a
	// batch member was dropped for. It is what the failed proof cycle records as its reason. Empty
	// means no cause beyond what the cycle itself establishes.
	FailureReason string

	// BatchedWith lists the other intent IDs settled by the SAME on-chain batch
	// transaction, empty for a solo execution. Recorded in the commitment map so the
	// attestation is honest about the fact that one tx settled several intents.
	BatchedWith []string
}

// CostAttribution returns the identifiers billing needs to attribute this intent's on-chain
// cost: the Accumulate transaction hash and the owning org.
//
// Exists as a method rather than as direct field access because pkg/execution settles the batch
// and must not import pkg/consensus — consensus already imports execution, so the dependency
// only runs one way. The batch orchestrator therefore type-asserts on this method set instead.
//
// The Accumulate transaction hash is load-bearing: it is the ONLY identifier the gateway and the
// validator both hold. IntentID is the validator's own and means nothing to the gateway, which
// keys intents by a different UUID. A cost event without it can be stored but never joined to an
// intent, so the measured gas never reaches settlement.
func (p *PendingAttestation) CostAttribution() (accumTxHash string, orgID string) {
	if p == nil {
		return "", ""
	}
	return p.TransactionHash, p.UserID
}

// SignedIntentBlobs is the user-signed intent the round admitted, as its four blobs (intent, cross-chain, governance,
// replay): what a batch member's committed calls and effects are read from. A validator keeps them with every batch
// tree it signs, so it can state the members' outcomes from its own copy once the batch settles (RB5 D4).
func (p *PendingAttestation) SignedIntentBlobs() ([][]byte, error) {
	if p == nil || p.CertenIntent == nil {
		return nil, fmt.Errorf("the round's snapshot carries no signed intent")
	}
	ci := p.CertenIntent
	if len(ci.IntentData) == 0 || len(ci.CrossChainData) == 0 {
		return nil, fmt.Errorf("intent %s: the round's snapshot carries an incomplete signed intent", ci.IntentID)
	}
	return [][]byte{ci.IntentData, ci.CrossChainData, ci.GovernanceData, ci.ReplayData}, nil
}

// IsCadence reports whether this attestation is being replayed from the cadence queue.
func (p *PendingAttestation) IsCadence() bool { return p != nil && p.Replayed }

// AttestationRunner is the surface the anchor scheduler needs in order to close the
// proof cycle after a deferred batch executes.
//
// It is an interface rather than a concrete *BFTValidator so pkg/anchor does not have
// to import pkg/consensus (which would be an import cycle: consensus already imports
// anchor for the scheduler).
type AttestationRunner interface {
	// RunProofCycle performs Phase 7-9 for one executed intent. It is safe to call
	// from any goroutine and never blocks the caller's critical path.
	RunProofCycle(ctx context.Context, att *PendingAttestation, res *verification.AnchorExecutionResult)
}

// RunProofCycle performs Phase 7-9 for one executed intent: observation of the target
// chain effect, attestation, and write-back to Accumulate.
//
// This is the ONLY implementation. Both callers use it:
//   - on_demand: invoked inline (in a goroutine) right after the round executes.
//   - on_cadence: invoked by the anchor scheduler after the deferred batch settles,
//     replaying the snapshot captured during the round.
//
// Keeping one implementation is the point. When this logic lived inline as an anonymous
// closure it was structurally impossible for the cadence path to reach it, which is why
// on_cadence intents executed on-chain and never attested.
//
// res carries the tx hashes actually produced. For a batched flush every intent in the
// batch shares one governance tx hash; att.BatchedWith records the siblings so the
// attestation is explicit that one transaction settled several intents.
//
// Never returns an error: attestation failure must not invalidate an execution that
// already happened on-chain. Failures are logged for operator follow-up.
func (bv *BFTValidator) RunProofCycle(
	ctx context.Context,
	att *PendingAttestation,
	res *verification.AnchorExecutionResult,
) {
	if att == nil || res == nil {
		return
	}
	if bv.proofCycleOrchestrator == nil {
		bv.logger.Printf("⚠️ [PROOF-CYCLE] no orchestrator configured; intent %s cannot be "+
			"attested back to Accumulate", att.IntentID)
		return
	}

	// STAGE 1 — this function is the RESOLVER for a pending settlement.
	//
	// The warning that started this stage was never retracted because nothing
	// downstream logged against the same intent ID once the truth was known. Say
	// here, on entry, that the resolution is under way; the terminal answer is
	// logged by executePhase7 from the actual receipt (see resolveTargetChain).
	//
	// The submitter's belief is carried on att.TargetChainOutcome, and it is
	// deliberately NOT authoritative: it is what one node knew inside a 60-second
	// window, and the measured lag is ~51s.
	if att.TargetChainOutcome.IsPending() {
		bv.logger.Printf("⏳ [PROOF-CYCLE] intent %s: settlement is IN FLIGHT (tx=%q) — resolving it "+
			"is this cycle's job; no failure has been observed",
			att.IntentID, TargetChainTxRef(res))
	}

	// A member with NO transaction at all — one whose settlement never reached the chain. (A
	// settlement that REVERTED has a transaction, and is observed and recorded like any other.)
	//
	// This used to return silently, which is the failure mode the whole batch design exists to
	// avoid: the intent settled nowhere, was recorded nowhere, and its ADI learned nothing. It
	// is not an observation problem — there is genuinely nothing on the destination chain to
	// observe — so Phase 7 is skipped deliberately and the FAILURE is recorded instead.
	if extractRawTxHash(res.GovernanceTxHash) == "" && extractRawTxHash(res.AnchorTxID) == "" {
		// A caller that says the member SETTLED but has no transaction to show for it is not
		// describing a failure. Failover validators did exactly this for every settled on-demand
		// intent until they learned to tell their own settlement from another's; recording it as
		// failed would contradict the chain.
		if att.TargetChainOutcome == TargetChainConfirmedOutcome {
			bv.logger.Printf("⚠️ [PROOF-CYCLE] intent %s reported settled with no settlement transaction; "+
				"nothing to observe and no failure to record", att.IntentID)
			return
		}
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s has no settlement transaction — none reached the "+
			"target chain; skipping Phase 7 observation and recording the FAILURE so the intent is "+
			"not silently lost", att.IntentID)
		bv.recordFailedProofCycle(ctx, att, res)
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// The chain this member settled on: the chain its batch was flushed on, which
	// RunBatchMemberAttestation stamps on res.Network. Phase 7 observes there and nowhere else - not on
	// the chain the intent's free-text leg name suggests, and not on a configured default (RB3-F45).
	settledChainID, cerr := settledChainOf(res)
	if cerr != nil {
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: %v — its settlement cannot be observed or recorded; "+
			"needs operator attention", att.IntentID, cerr)
		return
	}

	mode := "inline"
	if att.Replayed {
		mode = "cadence-replay"
	}
	bv.logger.Printf("[PROOF-CYCLE] Phase 7-9 (%s) for intent %s (batched with %d sibling(s))",
		mode, att.IntentID, len(att.BatchedWith))

	// Parse bundle ID from ValidatorBlock (hex string → raw bytes). One that does not parse is not taken as zero:
	// the commitment cannot be stated, and the write-back refuses (RB4-F69).
	var bundleID [32]byte
	bundleIDHex := strings.TrimPrefix(att.BundleIDHex, "0x")
	decoded, derr := hex.DecodeString(bundleIDHex)
	if derr == nil && len(decoded) != 32 {
		derr = fmt.Errorf("%d bytes, not 32", len(decoded))
	}
	if derr == nil {
		copy(bundleID[:], decoded)
	}

	// SECURITY CRITICAL: Build execution commitment from intent's CrossChainData
	commitMap, cerr := bv.buildExecutionCommitmentFromIntent(att.CertenIntent, bundleID, settledChainID)
	if cerr == nil && derr != nil {
		cerr = fmt.Errorf("the round's bundle id %q is not a 32-byte hex id: %w", att.BundleIDHex, derr)
	}
	if cerr != nil {
		// The cycle still runs - Phase 7 observes and records the settlement - but Phase 9 refuses to
		// write back a record it cannot state the commitment of (commitmentError).
		bv.logger.Printf("❌ [COMMITMENT] intent %s on chain %d: %v", att.IntentID, settledChainID, cerr)
		commitMap = map[string]interface{}{
			"bundleID": hex.EncodeToString(bundleID[:]), "intentID": att.IntentID,
			"commitmentError": cerr.Error(),
		}
	}
	var commitment interface{} = commitMap

	// Add governance data from ValidatorBlock for G1/G2 proof levels
	{
		if att.GovernanceProofRoot != "" {
			commitMap["governanceRoot"] = att.GovernanceProofRoot
		}
		if att.OperationCommitment != "" {
			commitMap["operationCommitment"] = att.OperationCommitment
		}
		commitMap["targetChain"] = strconv.FormatInt(settledChainID, 10)
		commitMap["chainID"] = settledChainID
		// The lane that settled it: the proof class its artifact states (RB3-F74).
		commitMap["proofClass"] = att.SettlementLane
		// The intent's member set and this member's share of its legs: the intent's status is
		// derived from every member's outcome over this set (RB3-F50).
		if chains, legs, merr := memberSetOf(att.CertenIntent, settledChainID); merr == nil {
			commitMap["memberChains"] = chains
			commitMap["memberLegs"] = legs
		} else {
			bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: %v — its outcome cannot be placed in its member set", att.IntentID, merr)
		}
		commitMap["accumulateBlockHeight"] = att.AccumulateBlockHeight
		commitMap["accumulateTxHash"] = att.CertenIntent.TransactionHash

		// The committed calls, their effects and the operationID are not carried here: every validator
		// reads them from the user-signed intent itself (execution.signedMemberLegs, RB3-F77). The
		// descriptors that used to be written here were read by nothing once that landed (RB3-F69).

		// The proof's evidence: L1-L4, G0-G2, their receipts, timing basis and governance decision.
		putProofEvidence(commitMap, att, func(key string, err error) {
			bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: %s does not marshal: %v", att.IntentID, key, err)
		})

		// Wire BLS/validator signatures
		commitMap["att.BLSSignature"] = att.BLSSignature
		commitMap["att.ValidatorSignatures"] = att.ValidatorSignatures
		commitMap[GovernanceLevelCommitmentKey] = att.GovernanceLevel
		commitMap["validatorID"] = att.ValidatorID
	}

	legCount, _ := att.CertenIntent.GetLegCount()
	bv.logger.Printf("🔄 [PROOF-CYCLE] Triggering Phase 7-9 for intent: %s on chain %d (legs=%d)",
		att.CertenIntent.IntentID, settledChainID, legCount)
	bv.logger.Printf("   Accumulate ref: accountURL=%s, txHash=%s", att.CertenIntent.AccountURL, att.CertenIntent.TransactionHash)

	// Every cycle is ONE chain member's. A cross-chain intent is split into one batch member per
	// chain (batchChainsOfIntent); each settles under its own anchor, on its own chain, and closes
	// its own cycle here with the one transaction it has. Routing a member into the multi-leg
	// aggregator asked for one chain group per leg and supplied one - the aggregator is
	// per-validator, so neither group could complete (observed live 2026-08-04, intent 763f8429).
	// The routing used to depend on the member's Replayed flag and on the shape of its hash string;
	// it depends on neither now.

	txHashes := &AnchorWorkflowTxHashes{
		CreateTxHash:     common.HexToHash(extractPureHexHash(res.CreateTxHash)),
		VerifyTxHash:     common.HexToHash(extractPureHexHash(res.VerifyTxHash)),
		GovernanceTxHash: common.HexToHash(extractPureHexHash(res.GovernanceTxHash)),
		PrimaryTxHash:    common.HexToHash(extractPureHexHash(res.AnchorTxID)),
		// ONLY the hashes that exist.
		//
		// This was a fixed three-slot list. A BATCH member has no separate create or verify
		// transaction — the anchor and its quorum attestation are paid ONCE for the whole tree,
		// which is the entire point of batching — so those two slots were empty strings. Phase 7
		// iterates the list and polls for a receipt per entry, so it hit index 0 = "" and burned
		// the full observation timeout:
		//
		//	observe transaction 0 (): wait for receipt: context deadline exceeded
		//
		// Phase 7 then returned an error, so Phase 8 (the post-exec BLS attestation) and Phase 9
		// (write-back to acc://certen-protocol.acme/execution-results) never ran. Every batched
		// intent settled on chain and was never recorded back on Accumulate — the on-chain half
		// completed and the loop never closed. Observed live 2026-08-03.
		//
		// Filtering keeps Phase 7 doing exactly its job: it observes the transactions that
		// genuinely exist and builds real inclusion proofs for them.
		//
		// AnchorTxID is included because the guard at the top of this function admits an intent on
		// AnchorTxID ALONE. Filtering over only the three hashes above therefore let a batch member
		// pass that guard and still reach Phase 7 with an EMPTY list — nothing to observe, so no
		// inclusion proof, so Phase 8 had nothing to attest and Phase 9 wrote nothing. It failed
		// silently, because an empty list was not an error anywhere on this path.
		RawTxHashes: nonEmptyTxHashes(res.CreateTxHash, res.VerifyTxHash, res.GovernanceTxHash, res.AnchorTxID),
	}

	// Phase 7 cannot do its job without at least one transaction to observe, and the guard above
	// has already established that this intent HAS one. An empty list here means the settlement
	// hash was dropped between that check and this construction, which is a defect — not a
	// legitimate state. Fail loudly and record the cycle as failed so the outcome still reaches
	// acc://certen-protocol.acme/execution-results, rather than returning and leaving the ADI with
	// no record at all. Silence here is what hid this for days.
	if len(txHashes.RawTxHashes) == 0 {
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: no observable transaction for Phase 7 "+
			"(anchor=%q governance=%q create=%q verify=%q) — recording as a failed proof cycle",
			att.CertenIntent.IntentID, res.AnchorTxID, res.GovernanceTxHash, res.CreateTxHash, res.VerifyTxHash)
		bv.recordFailedProofCycle(ctx, att, res)
		return
	}

	if err := bv.proofCycleOrchestrator.StartProofCycleWithAccumulateRef(
		ctx,
		att.CertenIntent.IntentID,
		att.CertenIntent.UserID,
		bundleID,
		txHashes,
		commitment,
		att.CertenIntent.AccountURL,
		att.CertenIntent.TransactionHash,
		// The BVN the transaction was written on - the chain's answer, and the one consensus built its
		// proof on (RB4-F46: this was the Directory Network partition discovery found it through). It used
		// to be "", leaving the cycle to recompute it (RB3-F89).
		att.CertenIntent.ProofPartition,
	); err != nil {
		// The orchestrator records the refusal as the member's outcome where the member can be placed
		// (RB3-F103); this line is the validator's own record of it.
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: proof cycle not started: %v", att.IntentID, err)
	}
}

// captureAttestation snapshots everything Phase 7-9 will need, at the moment those values
// are in scope and correct.
//
// This is what makes deferred attestation sound. An on_cadence intent executes minutes
// after its consensus round ends; by then the round's locals are gone. Copying the values
// out here — rather than holding the round's ValidatorBlock — also means a later replay
// cannot observe state that has since changed.
func (bv *BFTValidator) captureAttestation(
	vb *ValidatorBlock,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	blockHeight uint64,
	g0Proof *proof.G0Result,
	g1Proof *proof.G1Result,
	g2Proof *proof.G2Result,
	blsSignature string,
	validatorSignatures []string,
	governanceLevel string,
) *PendingAttestation {
	att := &PendingAttestation{
		CertenIntent:          certenIntent,
		CertenProof:           certenProof,
		AccumulateBlockHeight: blockHeight,
		G0Proof:               g0Proof,
		G1Proof:               g1Proof,
		G2Proof:               g2Proof,
		BLSSignature:          blsSignature,
		ValidatorSignatures:   validatorSignatures,
		GovernanceLevel:       governanceLevel,
		ValidatorID:           bv.validatorID,
	}

	if vb != nil {
		if vb.IntentCertificate != nil {
			att.IntentMessageHex = vb.IntentCertificate.Message
		}
		att.BundleIDHex = vb.BundleID
		att.OperationCommitment = vb.OperationCommitment
		att.GovernanceProofRoot = vb.GovernanceProof.MerkleRoot
	}
	if certenIntent != nil {
		att.IntentID = certenIntent.IntentID
		att.UserID = certenIntent.UserID
		att.AccountURL = certenIntent.AccountURL
		att.TransactionHash = certenIntent.TransactionHash
	}
	// STAGE 2: the receipt evidence rides on certenProof, which is where
	// executeCanonicalBFTWorkflow put it after generating G0-G2. Taken from there
	// rather than passed as three more parameters, so the cadence replay and the
	// inline path cannot diverge on which receipts they captured.
	if certenProof != nil {
		att.GovReceipts = certenProof.GovReceipts
		att.GovTimingBasis = certenProof.GovTimingBasis
		att.GovDecision = certenProof.GovDecision
		att.GovAuthorization = certenProof.GovAuthorization
		att.GovVoteEvidence = certenProof.GovVoteEvidence
	}

	bundleIDHex := strings.TrimPrefix(att.BundleIDHex, "0x")
	if decoded, err := hex.DecodeString(bundleIDHex); err == nil && len(decoded) >= 32 {
		copy(att.BundleID[:], decoded[:32])
	}

	return att
}

// GovernanceCommitment is the commitment to who decided the intent, from the decision the round derived: what its
// batch member commits to (RB4-F66). An error when the round recorded none.
// CertifiedIntentMessage is the intent message this validator's block certified, zero for a block built before a
// BLS registry was in force.
func (att *PendingAttestation) CertifiedIntentMessage() ([32]byte, error) {
	if att.IntentMessageHex == "" {
		return [32]byte{}, nil
	}
	m, err := hex32(att.IntentMessageHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the certified intent message: %w", err)
	}
	if m == ([32]byte{}) {
		return [32]byte{}, fmt.Errorf("the certified intent message is zero")
	}
	return m, nil
}

func (att *PendingAttestation) GovernanceCommitment() ([32]byte, error) {
	if att == nil || len(att.GovDecision) == 0 {
		return [32]byte{}, fmt.Errorf("%w: the round recorded no governance decision", ErrNoGovernanceCommitment)
	}
	return proof.GovernanceCommitment(att.GovDecision), nil
}

// AccumulateSetRoot is the root of the Accumulate validator set the round's own proof was verified against - its L4
// Directory leg - under the given incarnation, through the one reduction every path uses (pkg/accumulateset, RB5
// design D2). It is what the member's V8.2 anchor commits.
func (att *PendingAttestation) AccumulateSetRoot(incarnation [32]byte) ([32]byte, error) {
	if att == nil || att.CertenProof == nil || att.CertenProof.LiteClientProof == nil ||
		att.CertenProof.LiteClientProof.CompleteProof == nil {
		return [32]byte{}, fmt.Errorf("%w: the round's snapshot carries no L1-L4 proof", ErrNoAccumulateSetRoot)
	}
	root, err := accumulateset.CommittedAccumulateSetRoot(att.CertenProof.LiteClientProof.CompleteProof.Layer4DN, incarnation)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrNoAccumulateSetRoot, err)
	}
	return root, nil
}

// nonEmptyTxHashes returns the raw hashes that are actually present.
//
// Phase 7 observes one transaction per entry, so an empty entry is not a harmless placeholder —
// it is a receipt poll that can never resolve, and it fails the whole cycle.
// nonEmptyTxHashes returns the candidates that carry a real hash, in order and without repeats.
//
// Deduplicated because a single-leg batch member records the SAME settlement transaction as both
// its anchor and its governance hash. Phase 7 polls for a receipt per entry, so a duplicate makes
// it observe one transaction twice and build the same inclusion proof twice — wasted work, and a
// leaf count that no longer matches the number of distinct transactions actually settled.
func nonEmptyTxHashes(candidates ...string) []string {
	out := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		v := extractRawTxHash(c)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// recordFailedProofCycle records an intent that produced no settlement transaction.
//
// Phase 7 is genuinely inapplicable — there is no transaction to observe and no inclusion proof
// to build — but Phases 8 and 9 still matter: the outcome must be attested and written back to
// acc://certen-protocol.acme/execution-results, or the ADI has no record that its intent was
// attempted and failed. Silence is indistinguishable from an intent that was never processed.
func (bv *BFTValidator) recordFailedProofCycle(
	ctx context.Context,
	att *PendingAttestation,
	res *verification.AnchorExecutionResult,
) {
	if bv.proofCycleOrchestrator == nil || att == nil {
		return
	}

	// STAGE 1, THE DANGEROUS DIRECTION — this one really is failed.
	//
	// Reached only when there is NO settlement transaction on any chain: the two
	// guards in RunProofCycle establish that before calling here. That is not a
	// timeout and not an observation problem, so it must not be softened to
	// pending by the new default. Stated explicitly so the classification is a
	// decision in the code rather than a property of a zero value.
	att.TargetChainOutcome = TargetChainFailed

	failed := &verification.AnchorExecutionResult{
		Network:                  res.Network,
		AllTransactionsConfirmed: false,
	}
	// An empty tx-hash set is the signal to the orchestrator that there is nothing to observe.
	// It carries the same Accumulate reference as a successful cycle, so the write-back lands
	// against the same intent.
	txHashes := &AnchorWorkflowTxHashes{RawTxHashes: nil}

	var bundleID [32]byte
	if decoded, derr := hex.DecodeString(strings.TrimPrefix(att.BundleIDHex, "0x")); derr == nil && len(decoded) >= 32 {
		copy(bundleID[:], decoded[:32])
	}
	// The reason states what is KNOWN. Both callers reach here only when no settlement transaction
	// reached the target chain - which is all that can be said unless the caller knows why (a
	// dropped batch member carries its cause). It used to say "execution reverted on the target
	// chain" for every failure, which is false whenever nothing was sent (RB3-F37).
	reason := "no settlement transaction reached the target chain"
	if att.FailureReason != "" {
		reason = reason + ": " + att.FailureReason
	}
	// The failure is recorded against the chain the member was queued on - never a default.
	chainID, cerr := settledChainOf(res)
	if cerr != nil {
		bv.logger.Printf("⚠️ [PROOF-CYCLE] could not record the failure of intent %s: %v — the intent is "+
			"settled nowhere AND recorded nowhere, which needs operator attention", att.IntentID, cerr)
		return
	}
	commitment := map[string]interface{}{
		"intentId":                 att.IntentID,
		"outcome":                  "failed",
		"reason":                   reason,
		"allTransactionsConfirmed": false,
		"network":                  failed.Network,
		"targetChain":              strconv.FormatInt(chainID, 10),
		"chainID":                  chainID,
		"proofClass":               att.SettlementLane,
	}
	// The member's operation: the executor finds its own copy of the member by it, and every peer
	// verifies the non-settlement from its own copy (RB3-F49).
	if opID, oerr := att.CertenIntent.OperationID(); oerr == nil {
		commitment["nonSettlementOperationID"] = opID
	} else {
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: operation id: %v — its failure cannot be attested", att.IntentID, oerr)
	}
	if chains, legs, merr := memberSetOf(att.CertenIntent, chainID); merr == nil {
		commitment["memberChains"] = chains
		commitment["memberLegs"] = legs
	} else {
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s: %v — its failure cannot be placed in its member set", att.IntentID, merr)
	}

	if err := bv.proofCycleOrchestrator.StartProofCycleWithAccumulateRef(
		ctx,
		att.CertenIntent.IntentID,
		att.CertenIntent.UserID,
		bundleID,
		txHashes,
		commitment,
		att.CertenIntent.AccountURL,
		att.CertenIntent.TransactionHash,
		// The BVN the transaction was written on - the chain's answer, and the one consensus built its
		// proof on (RB4-F46: this was the Directory Network partition discovery found it through). It used
		// to be "", leaving the cycle to recompute it (RB3-F89).
		att.CertenIntent.ProofPartition,
	); err != nil {
		bv.logger.Printf("⚠️ [PROOF-CYCLE] could not record the failure of intent %s: %v — the "+
			"intent is settled nowhere AND recorded nowhere, which needs operator attention",
			att.IntentID, err)
	}
}

// memberSetOf is the intent's member set - the distinct chains of its signed legs, ascending, one batch
// member each - and how many of its legs the member on chainID carries.
func memberSetOf(ci *CertenIntent, chainID int64) ([]int64, int, error) {
	if ci == nil {
		return nil, 0, fmt.Errorf("no intent")
	}
	env, err := ci.ParseCrossChain()
	if err != nil {
		return nil, 0, fmt.Errorf("legs cannot be read: %w", err)
	}
	seen := map[int64]bool{}
	var chains []int64
	legs := 0
	for _, l := range env.Legs {
		if !seen[l.ChainID] {
			seen[l.ChainID] = true
			chains = append(chains, l.ChainID)
		}
		if l.ChainID == chainID {
			legs++
		}
	}
	if legs == 0 {
		return nil, 0, fmt.Errorf("chain %d carries none of the intent's legs", chainID)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i] < chains[j] })
	return chains, legs, nil
}

// settledChainOf is the chain a member settled on, from its execution result's Network
// ("evm-<chainID>"), and it must be a chain CERTEN executes on.
func settledChainOf(res *verification.AnchorExecutionResult) (int64, error) {
	if res == nil {
		return 0, fmt.Errorf("no execution result")
	}
	n := strings.TrimSpace(strings.ToLower(res.Network))
	id, err := strconv.ParseInt(strings.TrimPrefix(n, "evm-"), 10, 64)
	if !strings.HasPrefix(n, "evm-") || err != nil {
		return 0, fmt.Errorf("settlement chain not identifiable from network %q", res.Network)
	}
	if !IsSupportedTargetChain(id) {
		return 0, fmt.Errorf("settlement chain %d is not a chain CERTEN executes on", id)
	}
	return id, nil
}

// putProofEvidence stores the proof's evidence in the proof cycle's commitment map: the L1-L4 chained proof, the
// G0-G2 results, their receipts and timing basis, and who decided the transaction.
//
// Evidence that does not marshal is not left out - that reads downstream as "the generator recorded none" - it is
// recorded under EvidenceErrorCommitmentKey, which the proof's governance levels refuse (RB4-F69).
func putProofEvidence(commitMap map[string]interface{}, att *PendingAttestation, logf func(key string, err error)) {
	putJSON := func(key string, v interface{}) {
		b, err := json.Marshal(v)
		if err != nil {
			prev, _ := commitMap[EvidenceErrorCommitmentKey].(string)
			if prev != "" {
				prev += "; "
			}
			commitMap[EvidenceErrorCommitmentKey] = prev + fmt.Sprintf("%s: %v", key, err)
			logf(key, err)
			return
		}
		commitMap[key] = string(b)
	}

	// Wire L1-L3 chained proof data so persistProofArtifact can store it
	if att.CertenProof != nil && att.CertenProof.LiteClientProof != nil {
		putJSON("liteClientProof", att.CertenProof.LiteClientProof)
	}

	// Wire governance proof results (G0/G1/G2)
	if att.G0Proof != nil {
		putJSON(G0ProofCommitmentKey, att.G0Proof)
	}
	if att.G1Proof != nil {
		putJSON(G1ProofCommitmentKey, att.G1Proof)
	}
	if att.G2Proof != nil {
		putJSON(G2ProofCommitmentKey, att.G2Proof)
	}

	// STAGE 2 — the evidence for the three results above.
	//
	// Under its own key rather than inside att.G0Proof/G1Proof/G2Proof: those
	// marshal G*Result, which is inside the govRoot, and this must never be
	// able to reach that shape. The G-level writers read this key and store the
	// path in level_json beside the result.
	if len(att.GovReceipts) > 0 {
		putJSON(GovReceiptsCommitmentKey, att.GovReceipts)
	}

	// PHASE 8 ITEM 2 — under its own key, and never inside att.G1Proof/G2Proof
	// for the same reason: those marshal G*Result, which is inside the
	// govRoot, and this must never be able to reach that shape.
	if len(att.GovTimingBasis) > 0 {
		putJSON(GovTimingBasisCommitmentKey, att.GovTimingBasis)
	}

	// RB4-F66: who decided the transaction, under their own keys for the same reason as the receipts.
	if len(att.GovDecision) > 0 {
		commitMap[GovDecisionCommitmentKey] = hex.EncodeToString(att.GovDecision)
	}
	if att.GovAuthorization != nil {
		putJSON(GovAuthorizationCommitmentKey, att.GovAuthorization)
	}
	if att.GovVoteEvidence != nil {
		putJSON(GovVoteEvidenceCommitmentKey, att.GovVoteEvidence)
	}
}
