package consensus

import "fmt"

// Execution-rules versioning.
//
// # WHY THIS EXISTS
//
// The app hash is a chain over the bundle-ids of ACCEPTED transactions:
//
//	appHash(H) = SHA256( appHash(H-1) || sorted(unique bundle-ids in block H) )
//
// So anything that changes whether a transaction is accepted changes the app
// hash of every block containing such a transaction. Replaying history under
// different rules than committed it produces a different hash, and CometBFT
// panics at handshake:
//
//	panic: state.AppHash does not match AppHash after replay.
//	  Got 9B34726E…, expected 8028A10C…
//
// That panic happens before the node can serve, names neither the cause nor the
// remedy, and does not self-recover: the app persists the recomputed hash, so
// every subsequent restart skips the replay and fails identically. On
// 2026-07-27 it took all seven validators down for two hours and cost the chain
// its history.
//
// Recording which rules produced the committed state turns that into a startup
// error that says what happened and what to do.
//
// # WHEN TO BUMP
//
// Bump CurrentExecutionRulesVersion whenever a change can alter the ACCEPT or
// REJECT outcome of a ValidatorBlock. Adding a validity check, removing one,
// changing an existing one's verdict, or altering how the app hash is derived
// all qualify. Logging, metrics, query paths and proposer-side behaviour do not
// — the proposer may be non-deterministic because its output travels inside the
// block; only verification must be deterministic.
//
// When in doubt, bump. A needless bump costs one coordinated restart. A missed
// one costs an outage that looks like data corruption.
const (
	// v1 — bundle-id app-hash chain, no entitlement gate.
	executionRulesV1 uint64 = 1

	// v2 — the entitlement gate participates in accept/reject
	// (`processValidatorTransaction` returns Code 4 for an unentitled block,
	// which withholds its bundle-id from the app hash). Landed in 55416dc.
	executionRulesV2 uint64 = 2

	// CurrentExecutionRulesVersion is what THIS binary implements.
	CurrentExecutionRulesVersion = executionRulesV2
)

// ExecutionRulesMismatchError explains a refusal to start in terms an operator
// can act on. The failure it replaces is a raw hash comparison that names
// neither the cause nor the fix.
type ExecutionRulesMismatchError struct {
	Persisted uint64
	Binary    uint64
	Height    int64
}

func (e *ExecutionRulesMismatchError) Error() string {
	if e.Binary > e.Persisted {
		return fmt.Sprintf(
			"execution rules mismatch: this binary implements v%d, but chain state at height %d was "+
				"committed under v%d.\n"+
				"Starting anyway would replay history under the new rules, produce a different app hash "+
				"than CometBFT recorded, and panic at handshake with no way to recover.\n"+
				"Resolve by either (a) running a binary that implements v%d, or (b) resetting BOTH "+
				"CometBFT chain state and the application ledger so the chain restarts from genesis "+
				"under v%d. Resetting only one recreates this mismatch.",
			e.Binary, e.Height, e.Persisted, e.Persisted, e.Binary)
	}
	return fmt.Sprintf(
		"execution rules mismatch: this binary implements v%d, but chain state at height %d was "+
			"committed under the NEWER v%d — the binary has been rolled back past an upgrade.\n"+
			"History committed under v%d cannot be replayed by v%d rules. Roll forward to a binary "+
			"implementing v%d, or reset both CometBFT state and the application ledger.",
		e.Binary, e.Height, e.Persisted, e.Persisted, e.Binary, e.Persisted)
}

// checkExecutionRulesVersion compares persisted state against this binary.
//
// Returns the version that should be recorded going forward, and an error if
// the node must not start.
//
// A persisted zero means the state predates this field. Adopting the current
// version is the only workable choice — there is nothing to compare against —
// and it is safe in practice because the field ships alongside the check, so
// the first run after upgrading simply stamps the state it already had.
func checkExecutionRulesVersion(persisted uint64, height int64) (uint64, error) {
	if persisted == 0 {
		return CurrentExecutionRulesVersion, nil
	}
	if persisted != CurrentExecutionRulesVersion {
		return persisted, &ExecutionRulesMismatchError{
			Persisted: persisted,
			Binary:    CurrentExecutionRulesVersion,
			Height:    height,
		}
	}
	return persisted, nil
}
