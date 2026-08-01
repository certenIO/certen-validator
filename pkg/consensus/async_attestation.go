package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
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

	// BatchedWith lists the other intent IDs settled by the SAME on-chain batch
	// transaction, empty for a solo execution. Recorded in the commitment map so the
	// attestation is honest about the fact that one tx settled several intents.
	BatchedWith []string
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
	if bv.proofCycleOrchestrator == nil || res.AnchorTxID == "" {
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
				commitMap["att.G0Proof"] = string(g0JSON)
			}
		}
		if att.G1Proof != nil {
			if g1JSON, err := json.Marshal(att.G1Proof); err == nil {
				commitMap["att.G1Proof"] = string(g1JSON)
			}
		}
		if att.G2Proof != nil {
			if g2JSON, err := json.Marshal(att.G2Proof); err == nil {
				commitMap["att.G2Proof"] = string(g2JSON)
			}
		}

		// Wire BLS/validator signatures
		commitMap["att.BLSSignature"] = att.BLSSignature
		commitMap["att.ValidatorSignatures"] = att.ValidatorSignatures
		commitMap["att.GovernanceLevel"] = att.GovernanceLevel
		commitMap["validatorID"] = att.ValidatorID
	}

	// Determine leg count for multi-leg vs single-leg routing
	legCount, _ := att.CertenIntent.GetLegCount()
	isMultiLeg := legCount > 1

	bv.logger.Printf("🔄 [PROOF-CYCLE] Triggering Phase 7-9 for intent: %s (legs=%d, multi=%v)",
		att.CertenIntent.IntentID, legCount, isMultiLeg)
	bv.logger.Printf("   Accumulate ref: accountURL=%s, txHash=%s", att.CertenIntent.AccountURL, att.CertenIntent.TransactionHash)

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

			executionMode, _ := att.CertenIntent.GetExecutionMode()
			operationID := att.CertenIntent.IntentID

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

	// SINGLE-LEG (or multi-leg fallback): Original behavior
	txHashes := &AnchorWorkflowTxHashes{
		CreateTxHash:     common.HexToHash(extractPureHexHash(res.CreateTxHash)),
		VerifyTxHash:     common.HexToHash(extractPureHexHash(res.VerifyTxHash)),
		GovernanceTxHash: common.HexToHash(extractPureHexHash(res.GovernanceTxHash)),
		PrimaryTxHash:    common.HexToHash(extractPureHexHash(res.AnchorTxID)),
		RawTxHashes: []string{
			extractRawTxHash(res.CreateTxHash),
			extractRawTxHash(res.VerifyTxHash),
			extractRawTxHash(res.GovernanceTxHash),
		},
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

	bundleIDHex := strings.TrimPrefix(att.BundleIDHex, "0x")
	if decoded, err := hex.DecodeString(bundleIDHex); err == nil && len(decoded) >= 32 {
		copy(att.BundleID[:], decoded[:32])
	}

	return att
}
