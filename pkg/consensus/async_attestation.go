package consensus

import (
	"strconv"

	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/certen/independant-validator/pkg/ethrpc"
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
	UserID   string
	BundleID [32]byte

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
	//	          waiting". See RunBatchMemberAttestation and RunBatchMemberFallback.
	//
	// The zero value normalizes to pending, which is why the failure sites set it
	// deliberately rather than relying on a bool being false.
	TargetChainOutcome TargetChainOutcome

	// SubmitVB / SubmitBFT are the two metadata structs the per-intent (on_demand) submission
	// path takes. Captured only on the batch path, and only so a member the batch had to drop
	// can still be executed individually.
	//
	// Without them a dropped member has nowhere to go. The approved failure policy is "fall
	// back to the per-intent path, never requeue" — requeueing re-derives the same bundleId
	// and reverts AnchorAlreadyExists — and SubmitAnchorFromValidatorBlock IS that path.
	// Holding the snapshot rather than the live structs keeps a late fallback from observing
	// a round that has since moved on.
	SubmitVB  *verification.ValidatorBlockMetadata
	SubmitBFT *verification.BFTExecutionMetadata

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

	// A member with NO transaction at all — a batch member whose settlement reverted.
	//
	// This used to return silently, which is the failure mode the whole batch design exists to
	// avoid: the intent settled nowhere, was recorded nowhere, and its ADI learned nothing. It
	// is not an observation problem — there is genuinely nothing on the destination chain to
	// observe — so Phase 7 is skipped deliberately and the FAILURE is recorded instead.
	if extractRawTxHash(res.GovernanceTxHash) == "" && extractRawTxHash(res.AnchorTxID) == "" {
		bv.logger.Printf("❌ [PROOF-CYCLE] intent %s has no settlement transaction (execution "+
			"reverted); skipping Phase 7 observation — there is nothing on chain to observe — "+
			"and recording the FAILURE so the intent is not silently lost", att.IntentID)
		bv.recordFailedProofCycle(ctx, att, res)
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	mode := "inline"
	if att.Replayed {
		mode = "cadence-replay"
	}
	bv.logger.Printf("[PROOF-CYCLE] Phase 7-9 (%s) for intent %s (batched with %d sibling(s))",
		mode, att.IntentID, len(att.BatchedWith))

	// Parse bundle ID from ValidatorBlock (hex string → raw bytes)
	var bundleID [32]byte
	bundleIDHex := strings.TrimPrefix(att.BundleIDHex, "0x")
	if decoded, err := hex.DecodeString(bundleIDHex); err == nil && len(decoded) >= 32 {
		copy(bundleID[:], decoded[:32])
	}

	// SECURITY CRITICAL: Build execution commitment from intent's CrossChainData
	commitment := bv.buildExecutionCommitmentFromIntent(att.CertenIntent, bundleID)

	// Add governance data from ValidatorBlock for G1/G2 proof levels
	if commitMap, ok := commitment.(map[string]interface{}); ok {
		if att.GovernanceProofRoot != "" {
			commitMap["governanceRoot"] = att.GovernanceProofRoot
		}
		if att.OperationCommitment != "" {
			commitMap["operationCommitment"] = att.OperationCommitment
		}
		commitMap["accumulateBlockHeight"] = att.AccumulateBlockHeight
		commitMap["accumulateTxHash"] = att.CertenIntent.TransactionHash
		commitMap["rawCreateTxHashes"] = res.CreateTxHash
		commitMap["rawVerifyTxHashes"] = res.VerifyTxHash
		commitMap["rawGovernanceTxHashes"] = res.GovernanceTxHash

		// RB-2/RB-4/RB-5: surface per-leg contract-call verification data so the
		// Phase 7 attestation gate can cryptographically verify EACH executed call.
		// Inspect ALL legs (not just leg 0) so a contract-call leg anywhere in a
		// multi-leg intent is gated — otherwise a native leg 0 + call leg 1 would slip
		// through. Each entry carries its chain (for per-chain-group matching), target,
		// and committed events/state; the gate verifies the effect against that chain
		// group's inclusion-proven receipt(s).
		if ccEnv, ccErr := att.CertenIntent.ParseCrossChain(); ccErr == nil && len(ccEnv.Legs) > 0 {
			govByChain := parseMultiChainTxHashes(res.GovernanceTxHash)
			rbLegs := make([]map[string]interface{}, 0, len(ccEnv.Legs))
			for _, leg := range ccEnv.Legs {
				ep := leg.ExecutionPayload
				if ep == nil {
					continue
				}
				cd := strings.TrimSpace(ep.CallData)
				if cd == "" || cd == "0x" || cd == "0X" {
					continue // native/ERC-20 leg — CRITICAL-003 already binds it, no event gate
				}
				chainKey := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
				execTx := extractRawTxHash(res.GovernanceTxHash) // single-leg default
				if hs := govByChain[chainKey]; len(hs) > 0 {
					execTx = extractRawTxHash(hs[len(hs)-1]) // per-chain governance tx (last)
				}
				evs := make([]map[string]interface{}, 0, len(ep.ExpectedEvents))
				for _, e := range ep.ExpectedEvents {
					evs = append(evs, map[string]interface{}{"contract": e.Contract, "topic0": e.Topic0, "dataHash": e.DataHash})
				}
				sts := make([]map[string]interface{}, 0, len(ep.ExpectedState))
				for _, s := range ep.ExpectedState {
					sts = append(sts, map[string]interface{}{"account": s.Account, "slot": s.Slot, "value": s.Value})
				}
				rbLegs = append(rbLegs, map[string]interface{}{
					"chainKey":       chainKey,
					"target":         ep.Target,
					"value":          ep.Value,
					"execTxHash":     execTx,
					"expectedEvents": evs,
					"expectedState":  sts,
				})
			}
			if len(rbLegs) > 0 {
				commitMap["rbContractCall"] = true
				commitMap["rbContractCallLegs"] = rbLegs
				bv.logger.Printf("🔒 [RB-GATE] %d contract-call leg(s) flagged for Phase 7 verification", len(rbLegs))
			}
		}

		// Wire L1-L3 chained proof data so persistProofArtifact can store it
		if att.CertenProof != nil && att.CertenProof.LiteClientProof != nil {
			if proofJSON, err := json.Marshal(att.CertenProof.LiteClientProof); err == nil {
				commitMap["liteClientProof"] = string(proofJSON)
			}
		}

		// Wire governance proof results (G0/G1/G2)
		if att.G0Proof != nil {
			if g0JSON, err := json.Marshal(att.G0Proof); err == nil {
				commitMap[G0ProofCommitmentKey] = string(g0JSON)
			}
		}
		if att.G1Proof != nil {
			if g1JSON, err := json.Marshal(att.G1Proof); err == nil {
				commitMap[G1ProofCommitmentKey] = string(g1JSON)
			}
		}
		if att.G2Proof != nil {
			if g2JSON, err := json.Marshal(att.G2Proof); err == nil {
				commitMap[G2ProofCommitmentKey] = string(g2JSON)
			}
		}

		// STAGE 2 — the evidence for the three results above.
		//
		// Under its own key rather than inside att.G0Proof/G1Proof/G2Proof: those
		// marshal G*Result, which is inside the govRoot, and this must never be
		// able to reach that shape. The G-level writers read this key and store the
		// path in level_json beside the result.
		if len(att.GovReceipts) > 0 {
			if evJSON, err := json.Marshal(att.GovReceipts); err == nil {
				commitMap[GovReceiptsCommitmentKey] = string(evJSON)
			}
		}

		// PHASE 8 ITEM 2 — under its own key, and never inside att.G1Proof/G2Proof
		// for the same reason: those marshal G*Result, which is inside the
		// govRoot, and this must never be able to reach that shape.
		if len(att.GovTimingBasis) > 0 {
			if tbJSON, err := json.Marshal(att.GovTimingBasis); err == nil {
				commitMap[GovTimingBasisCommitmentKey] = string(tbJSON)
			}
		}

		// Wire BLS/validator signatures
		commitMap["att.BLSSignature"] = att.BLSSignature
		commitMap["att.ValidatorSignatures"] = att.ValidatorSignatures
		commitMap[GovernanceLevelCommitmentKey] = att.GovernanceLevel
		commitMap["validatorID"] = att.ValidatorID
	}

	// Determine leg count for multi-leg vs single-leg routing
	legCount, _ := att.CertenIntent.GetLegCount()
	isMultiLeg := legCount > 1

	bv.logger.Printf("🔄 [PROOF-CYCLE] Triggering Phase 7-9 for intent: %s (legs=%d, multi=%v)",
		att.CertenIntent.IntentID, legCount, isMultiLeg)
	bv.logger.Printf("   Accumulate ref: accountURL=%s, txHash=%s", att.CertenIntent.AccountURL, att.CertenIntent.TransactionHash)

	// A CHAIN-SCOPED BATCH MEMBER closes its own cycle; it must not wait on another chain.
	//
	// A cross-chain intent is split into one batch member per chain (see batchChainsOfIntent).
	// Each member settles under its own anchor, on its own chain, and is replayed here by
	// whichever validator flushed THAT chain — so it can observe exactly one chain's transaction
	// and knows nothing of its sibling's.
	//
	// Routing it into the multi-leg aggregator asked for one chain group per leg and supplied
	// one, and the aggregator is per-validator: the node that flushed Sepolia never sees Base's
	// group and vice versa, so neither cycle can ever complete. Both settled on chain and neither
	// wrote back. Observed live 2026-08-04 on intent 763f8429.
	//
	// The single-chain path below is the correct one for a member: it observes the transaction it
	// actually has and writes back that leg's outcome. The intent's other chain does the same
	// independently, which is exactly how the split settles it.
	if isMultiLeg && att.Replayed && extractRawTxHash(res.GovernanceTxHash) != "" &&
		len(parseMultiChainTxHashes(res.GovernanceTxHash)) <= 1 {
		bv.logger.Printf("🧩 [MULTI-LEG-PROOF] intent %s is a chain-scoped batch member (network=%s); "+
			"closing its own single-chain cycle rather than waiting on a sibling chain this node "+
			"cannot observe", att.CertenIntent.IntentID, res.Network)
		isMultiLeg = false

		// The member's OWN chain decides which RPC Phase 7 observes on.
		//
		// commitment["targetChain"] is intent-level, and a cross-chain intent names only one of
		// its chains there. The member for the OTHER chain then inherited that value and searched
		// an RPC where its transaction cannot exist — burning the full observation deadline on a
		// transaction that had already settled. Observed live 2026-08-04: intent 16b8266d's Base
		// leg settled in block 45033109 (status 1) while its cycle spent 10m looking on Arbitrum.
		if commitMap, ok := commitment.(map[string]interface{}); ok {
			if ck := chainKeyFromNetwork(res.Network); ck != "" {
				if prev, _ := commitMap["targetChain"].(string); prev != ck {
					bv.logger.Printf("🧭 [MULTI-LEG-PROOF] intent %s: retargeting Phase 7 from %q to %q "+
						"(the chain this member actually settled on)",
						att.CertenIntent.IntentID, prev, ck)
				}
				commitMap["targetChain"] = ck
			}
		}
	}

	if isMultiLeg {
		// MULTI-LEG: Start per-chain proof cycles with unified write-back
		bv.logger.Printf("🔀 [MULTI-LEG-PROOF] Starting per-chain proof cycles for %d legs", legCount)

		// Parse governance tx hashes into per-chain groups
		chainTxHashes := parseMultiChainTxHashes(res.GovernanceTxHash)
		if len(chainTxHashes) == 0 {
			// Fallback: use create tx hashes if no governance hashes at all
			chainTxHashes = parseMultiChainTxHashes(res.CreateTxHash)
		} else {
			// For chains with failed governance (filtered by _failed), fall back
			// to their create tx hashes so the proof cycle can still observe them
			createTxHashes := parseMultiChainTxHashes(res.CreateTxHash)
			for ck, txHashes := range createTxHashes {
				if _, hasGov := chainTxHashes[ck]; !hasGov {
					bv.logger.Printf("🔄 [MULTI-LEG-PROOF] Chain %s governance failed, using create tx for observation", ck)
					chainTxHashes[ck] = txHashes
				}
			}
		}

		// Build leg info from CrossChainData
		ccEnvelope, ccErr := att.CertenIntent.ParseCrossChain()
		if ccErr != nil {
			bv.logger.Printf("⚠️ [MULTI-LEG-PROOF] Failed to parse CrossChainData: %v - falling back to single proof cycle", ccErr)
		} else {
			var legInfos []ChainLegInfo
			for i, leg := range ccEnvelope.Legs {
				chainKey := strings.ToLower(strings.ReplaceAll(leg.Chain, " ", "-"))
				legInfos = append(legInfos, ChainLegInfo{
					LegIndex:  i,
					LegID:     leg.LegID,
					ChainKey:  chainKey,
					ChainName: leg.Chain,
					ChainID:   leg.ChainID,
				})
			}

			// Re-key the "default" bucket onto the chain the legs actually name.
			//
			// parseMultiChainTxHashes files an un-prefixed hash under "default". A multi-leg intent
			// whose legs are all on ONE chain produces exactly that — a single plain hash — so the
			// group arrives keyed "default" while every leg is keyed e.g. "ethereum-sepolia". The
			// keys never match, so sequential-mode dependency resolution cannot satisfy the group
			// and defers it forever: "Deferring chain group default (dependencies not met)". The
			// legs settle on chain and the proof cycle never runs, so Phases 8 and 9 never close.
			//
			// Only re-keyed when every leg shares one chain, which is the only case where the
			// mapping is unambiguous. A genuine cross-chain intent keeps its per-chain keys.
			if hashes, hasDefault := chainTxHashes["default"]; hasDefault && len(chainTxHashes) == 1 {
				uniq := map[string]struct{}{}
				for _, li := range legInfos {
					uniq[li.ChainKey] = struct{}{}
				}
				if len(uniq) == 1 {
					for ck := range uniq {
						bv.logger.Printf("🔑 [MULTI-LEG-PROOF] re-keying chain group \"default\" to %q "+
							"(all %d leg(s) on one chain); the group would otherwise never match a leg "+
							"and would be deferred indefinitely", ck, len(legInfos))
						chainTxHashes[ck] = hashes
						delete(chainTxHashes, "default")
					}
				}
			}

			executionMode, _ := att.CertenIntent.GetExecutionMode()
			operationID := att.CertenIntent.IntentID

			// Never hand the aggregator legs it has no transactions to resolve.
			//
			// This called StartPerChainProofCycles unconditionally. When every leg failed to
			// execute, res.GovernanceTxHash holds "execution_failed_leg-..." markers rather than
			// hashes, parseMultiChainTxHashes yields ZERO groups, and the call still registered
			// the intent as awaiting one group PER LEG. It then logged success — "started for 0
			// chain groups" under a ✅ — and returned, skipping the single-leg fallback. The
			// intent waited forever on groups that were never created: no settlement, no failure,
			// and nothing written back to acc://certen-protocol.acme/execution-results. Observed
			// live 2026-08-03 on a two-leg Sepolia+Base intent.
			//
			// With no groups there is nothing multi-leg to do, so fall through to the single-leg
			// path, which fails closed and records the outcome.
			if len(chainTxHashes) == 0 {
				bv.logger.Printf("❌ [MULTI-LEG-PROOF] intent %s has %d leg(s) but NO observable "+
					"transaction on any chain (governance=%q create=%q) — not registering with the "+
					"aggregator; falling through so the outcome is recorded",
					att.CertenIntent.IntentID, len(legInfos), res.GovernanceTxHash, res.CreateTxHash)
			} else {
				// A partial set still stalls: the aggregator waits on every leg it was told about,
				// so a leg whose chain produced no transaction never reports. Name them.
				uniqLegChains := map[string]struct{}{}
				for _, li := range legInfos {
					uniqLegChains[li.ChainKey] = struct{}{}
				}
				// Compare against DISTINCT leg chains, not leg count: two legs on one chain
				// legitimately produce one group.
				if len(chainTxHashes) < len(uniqLegChains) {
					missing := make([]string, 0, len(legInfos))
					for _, li := range legInfos {
						if _, ok := chainTxHashes[li.ChainKey]; !ok {
							missing = append(missing, li.ChainKey)
						}
					}
					bv.logger.Printf("⚠️ [MULTI-LEG-PROOF] intent %s: %d leg(s) but only %d chain "+
						"group(s); no transaction for %v — those legs cannot resolve",
						att.CertenIntent.IntentID, len(legInfos), len(chainTxHashes), missing)
				}
				if err := bv.proofCycleOrchestrator.StartPerChainProofCycles(
					ctx, att.CertenIntent.IntentID, operationID, bundleID,
					chainTxHashes, legInfos, executionMode, commitment,
					att.CertenIntent.AccountURL, att.CertenIntent.TransactionHash, "",
				); err != nil {
					bv.logger.Printf("⚠️ [MULTI-LEG-PROOF] Per-chain proof cycles failed: %v", err)
				} else {
					bv.logger.Printf("✅ [MULTI-LEG-PROOF] Per-chain proof cycles started for %d chain groups", len(chainTxHashes))
					return // Multi-leg handled - skip single-leg fallback
				}
			}
		}
	}

	// SINGLE-LEG (or multi-leg fallback): Original behavior
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
		"",
	); err != nil {
		bv.logger.Printf("⚠️ [PROOF-CYCLE] Failed to start proof cycle: %v", err)
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
	}

	bundleIDHex := strings.TrimPrefix(att.BundleIDHex, "0x")
	if decoded, err := hex.DecodeString(bundleIDHex); err == nil && len(decoded) >= 32 {
		copy(att.BundleID[:], decoded[:32])
	}

	return att
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
	commitment := map[string]interface{}{
		"intentId":                 att.IntentID,
		"outcome":                  "failed",
		"reason":                   "no settlement transaction; execution reverted on the target chain",
		"allTransactionsConfirmed": false,
		"network":                  failed.Network,
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
		"",
	); err != nil {
		bv.logger.Printf("⚠️ [PROOF-CYCLE] could not record the failure of intent %s: %v — the "+
			"intent is settled nowhere AND recorded nowhere, which needs operator attention",
			att.IntentID, err)
	}
}

// chainKeyFromNetwork maps an execution result's Network ("evm-<chainID>") to the chain key the
// strategy registry uses. Returns "" when the form is unrecognised, so the caller leaves the
// existing target alone rather than guessing.
func chainKeyFromNetwork(network string) string {
	n := strings.TrimSpace(strings.ToLower(network))
	if !strings.HasPrefix(n, "evm-") {
		return ""
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(n, "evm-"), 10, 64)
	if err != nil {
		return ""
	}
	return ethrpc.ChainKeyForID(id)
}
