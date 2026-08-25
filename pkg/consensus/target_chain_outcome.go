package consensus

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/verification"
)

// =============================================================================
// STAGE 1 — the three answers a bool cannot hold
// =============================================================================
//
// TargetChainConfirmed was a bool, so "not confirmed YET" and "confirmed FAILED"
// were the same value: false. Everything downstream read that false as a failure.
//
// Measured on intent 1638327d-af2c-439c-a188-be53cdb5c854, 2026-08-25:
//
//	07:33:41  ⚠️ ... target-chain execution did NOT confirm: targetChainError=""
//	          — gas may have been spent on a reverted transaction
//	07:33:41  ✅ Intent ... processed successfully and marked complete
//	07:34:32  chain_execution_results: base-sepolia status=1 block=45937480
//
// FIFTY-ONE SECONDS against a 60-second submit window. The transaction was fine.
// The empty targetChainError is the tell, and it is machine-readable: a tx hash
// with no error is the textbook signature of PENDING, and "gas may have been
// spent on a reverted transaction" was speculation printed as a finding in
// precisely the case with no evidence of a revert.
//
// A TIMEOUT IS NEVER EVIDENCE OF FAILURE. AllTransactionsConfirmed == false on
// its own means "I did not see a receipt inside my window" and nothing more.
//
// This is the same class of error the ExecutionTaskResult comment was written to
// fix one level down after the 2026-08-09 incident: that split CONSENSUS success
// from EXECUTION success, and left EXECUTION UNKNOWN collapsed into EXECUTION
// FAILED.
//
// Nothing here changes what is provable. No canonical struct is touched and no
// hash moves — this is correctness and observability only.

// TargetChainOutcome distinguishes the three answers a bool cannot hold.
type TargetChainOutcome string

const (
	// TargetChainOutcomeUnset is the zero value. It means nobody classified this
	// result, NOT that the settlement failed. Normalize maps it to pending, which
	// is the honest reading of "no evidence either way".
	TargetChainOutcomeUnset TargetChainOutcome = ""

	// TargetChainConfirmedOutcome: a receipt was seen and it succeeded.
	TargetChainConfirmedOutcome TargetChainOutcome = "confirmed"

	// TargetChainPending: SUBMITTED, no terminal receipt yet. This is NOT a
	// failure and must never be reported as one. Measured lag on base-sepolia is
	// ~51s against a 60s submit window, so pending is the ORDINARY case, not the
	// exception.
	TargetChainPending TargetChainOutcome = "pending"

	// TargetChainFailed: a receipt was seen and it reverted, or submission itself
	// errored. ONLY this value justifies saying gas was spent on a reverted
	// transaction.
	TargetChainFailed TargetChainOutcome = "failed"
)

// Normalize resolves the zero value to pending.
//
// Deliberately NOT to failed: an unset field is the absence of a classification,
// and inferring failure from absence is the exact defect this type exists to fix.
func (o TargetChainOutcome) Normalize() TargetChainOutcome {
	if o == TargetChainOutcomeUnset {
		return TargetChainPending
	}
	return o
}

// IsConfirmed reports a receipt seen with status 1.
func (o TargetChainOutcome) IsConfirmed() bool { return o == TargetChainConfirmedOutcome }

// IsPending reports submitted-but-unresolved. The zero value counts as pending.
func (o TargetChainOutcome) IsPending() bool { return o.Normalize() == TargetChainPending }

// IsFailed reports a receipt seen with status 0, or a submission error.
func (o TargetChainOutcome) IsFailed() bool { return o == TargetChainFailed }

// IsTerminal reports whether this outcome will not change. Pending will.
func (o TargetChainOutcome) IsTerminal() bool {
	return o == TargetChainConfirmedOutcome || o == TargetChainFailed
}

// TargetChainOutcomeFromReceiptStatus maps an observed receipt status onto the
// outcome. strategy.ObservationResult.Status is 0=pending, 1=success, 2=failed.
//
// This is the only input that produces a terminal answer honestly: it is the
// receipt itself, not the submitter's patience.
func TargetChainOutcomeFromReceiptStatus(status uint8) TargetChainOutcome {
	switch status {
	case 1:
		return TargetChainConfirmedOutcome
	case 2:
		return TargetChainFailed
	default:
		return TargetChainPending
	}
}

// ClassifyTargetChainOutcome implements the classification rule, and it is the
// whole of Stage 1:
//
//	submission returned an error              -> failed
//	all transactions confirmed                -> confirmed
//	tx hash present, no error, no receipt yet -> PENDING
//	no tx hash, no error (never submitted)    -> pending (reported differently)
//
// submitErr is the error returned by SubmitAnchorFromValidatorBlock; res is what
// the executor observed and may be nil.
//
// Note what is deliberately NOT here: there is no path from
// AllTransactionsConfirmed == false to failed. That field answers "did I see
// every receipt inside my window", and a window is not evidence.
func ClassifyTargetChainOutcome(res *verification.AnchorExecutionResult, submitErr error) TargetChainOutcome {
	// A submission error is the one case where the caller genuinely holds
	// evidence of failure: the write did not go out, or went out and errored.
	if submitErr != nil {
		return TargetChainFailed
	}
	if res == nil {
		// No result and no error. Nothing was observed, so nothing is known.
		return TargetChainPending
	}
	if res.AllTransactionsConfirmed {
		return TargetChainConfirmedOutcome
	}
	// Everything else is "I did not see a terminal receipt in my window". That is
	// unresolved, not failed — whether or not a tx hash came back. The terminal
	// answer arrives later, from Phase 7's observation of the actual receipt.
	return TargetChainPending
}

// TargetChainTxRef returns the first transaction hash the result carries, or ""
// when nothing was submitted.
//
// A pending line MUST print this. "Pending" with no hash is unactionable; with
// the hash an operator resolves it on a block explorer in one click, which is the
// difference between an alert and a status.
func TargetChainTxRef(res *verification.AnchorExecutionResult) string {
	if res == nil {
		return ""
	}
	for _, c := range []string{res.AnchorTxID, res.GovernanceTxHash, res.CreateTxHash, res.VerifyTxHash} {
		if h := extractRawTxHash(c); h != "" {
			return h
		}
	}
	return ""
}

// RenderTargetChainOutcomeLog renders the operator-facing line for one intent's
// settlement outcome.
//
// A pure function on purpose: the sentence "gas may have been spent on a
// reverted transaction" appearing under a PENDING outcome is the regression this
// stage exists to prevent, and a pure renderer makes that a one-line assertion in
// a unit test rather than a live-log inspection nobody performs.
//
// THE GAS SENTENCE APPEARS ONLY UNDER failed. Do not move it.
func RenderTargetChainOutcomeLog(intentID string, outcome TargetChainOutcome, txRef, targetChainErr string) string {
	switch outcome.Normalize() {
	case TargetChainConfirmedOutcome:
		return fmt.Sprintf("✅ [BFT-CANONICAL] Canonical intent executed successfully: %s", intentID)

	case TargetChainFailed:
		// The only branch entitled to speculate about gas, because it is the only
		// branch holding evidence of a revert or a submission error.
		return fmt.Sprintf("❌ [BFT-CANONICAL] Consensus committed and target-chain execution FAILED: "+
			"intent=%s tx=%s targetChainError=%q — gas may have been spent on a reverted transaction",
			intentID, txRefOrNone(txRef), targetChainErr)

	default: // pending
		if txRef == "" {
			// Nothing was submitted from this node. Ordinary for the six validators
			// that are not the elected executor, and for an intent handed to the
			// batch or cadence queue. Not a warning.
			return fmt.Sprintf("ℹ️ [BFT-CANONICAL] Consensus committed; no target-chain submission from this node: "+
				"intent=%s — settlement belongs to another node or to a later batch, and its proof "+
				"cycle records the terminal status", intentID)
		}
		return fmt.Sprintf("⏳ [BFT-CANONICAL] Consensus committed; target-chain settlement PENDING (not a failure): "+
			"intent=%s tx=%s — no terminal receipt inside the submit window; the proof cycle "+
			"(Phase 7 observation) will record the terminal status against this intent ID",
			intentID, txRef)
	}
}

func txRefOrNone(txRef string) string {
	if txRef == "" {
		return "<none>"
	}
	return txRef
}
