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

	// v3 — PolicyUpdate transactions are a recognised type. They contribute an
	// id to the app hash when accepted, and the entitlement rule can now change
	// at an activation height, so acceptance depends on committed policy state
	// rather than on a fixed rule.
	executionRulesV3 uint64 = 3

	// v4 — principal binding. A ValidatorBlock whose
	// accumulate_anchor_reference.account_url names a different IDENTITY from
	// governance_proof.organization_adi is rejected. Before v4 those two fields
	// could be set independently, so a proposer could name an entitled account
	// while the governance proof described an unentitled one, attach that
	// account's public evidence, and have the gate accept it.
	//
	// This rejects blocks v3 accepted, so it changes the app hash of any block
	// carrying such a ValidatorBlock — hence a version bump rather than a
	// silent tightening.
	executionRulesV4 uint64 = 4

	// v5 — MinActivationDelay lowered from 200 to 10. This changes which
	// PolicyUpdate transactions VerifyPolicyUpdate accepts, and acceptance
	// contributes the update's id to the app hash, so it is a consensus rule
	// like any other.
	//
	// No policy update had been committed when this landed, so no existing
	// history could replay differently — but the version is bumped regardless.
	// Deciding case by case whether a rule change "really" needs a bump is how
	// the discipline erodes, and the cost of a needless bump is one coordinated
	// restart against an outage that looks like data corruption.
	executionRulesV5 uint64 = 5

	// v6 — two changes, both altering accept/reject:
	//
	//   - Policy activation is judged against BLOCK TIME rather than block
	//     height, so which rule applies to a block can differ from v5.
	//   - A carried lite-client proof is verified: its receipts must hash from
	//     start to anchor, it must name the same identity as the principal, and
	//     it must concern the transaction the block anchors. Blocks carrying an
	//     inconsistent proof were accepted under v5 and are refused under v6.
	executionRulesV6 uint64 = 6

	// v7 — the "epoch from the future" check is removed. Block time advances
	// only when this chain produces blocks, so after an idle period every
	// freshly published epoch reads as future-dated and legitimate work is
	// refused. Blocks refused under v6 are accepted under v7, which is a change
	// to accept/reject and therefore to the app hash.
	executionRulesV7 uint64 = 7

	// v8 — validator consensus-key rotation (RB3-F95), and policy updates bound to the chain (RB3-F117:
	// an update's admin signatures now cover its chain id; an unbound one is accepted only if it is one
	// of the two committed on certen-testnet before v8, so their replay is unchanged). Two recognised
	// transaction kinds:
	// `certen.validator.rotate/v1` (signed by the sealed admin quorum; accepted, it contributes its id
	// to the app hash and returns ValidatorUpdates) and `certen.chain.tick/v1` (accepted, changes
	// nothing - it makes an idle chain produce a block). Under v7 both were judged as ValidatorBlocks and
	// refused with a different result code.
	//
	// v8 CONTINUES v7 state without a reset (see compatibleContinuations). The two rule sets differ only
	// on transactions of those two kinds - in result code as well as app hash, and the result codes are
	// hashed into the next block header (LastResultsHash), so the claim has to cover every such
	// transaction, valid or not. It is checked, not assumed: `validator-rotate history-check` reads
	// every committed block and finds no transaction of either kind (run on the production chain
	// 2026-09-27 before this shipped; runbook step 0 repeats it before the deploy). The fleet then runs
	// v8 together, verified by every node reporting app version 8 before the first rotation.
	executionRulesV8 uint64 = 8

	// v9 - two changes to accept/reject (RB3-F140, RB3-F141):
	//
	//   - A ValidatorBlock naming no validator fails the invariants (code 2). v8 filled in the chain id
	//     first, which made the check unreachable and committed such a block under the chain's name.
	//   - From block time duplicateOperationRuleFrom, a validator's second ValidatorBlock for an operation
	//     its block already committed is refused (code 8). Before that time it is accepted, as v8 did:
	//     history holds 161 such blocks and replay must reproduce them.
	//
	// v9 CONTINUES v7 and v8 state without a reset. The claim is that v9 decides every committed block of
	// that history exactly as it was decided - the same outcome and the same result code. It is checked,
	// not assumed: before CometBFT's handshake every node reads its committed blocks (IndexCommittedHistory)
	// and refuses to start on any transaction v9 would decide differently. On the production chain it holds
	// by construction as well as by that check: every committed ValidatorBlock names its validator, no
	// transaction was ever refused, and the chain's last block (height 2622, 2026-09-27T14:14Z) precedes
	// duplicateOperationRuleFrom. The state stays stamped v7 or v8 until a block is decided in a way only
	// v9 decides it (committedRulesVersion), so a rollback stays open until then.
	executionRulesV9 uint64 = 9

	// CurrentExecutionRulesVersion is what THIS binary implements.
	CurrentExecutionRulesVersion = executionRulesV9
)

// compatibleContinuations names the older rules whose committed state this binary may continue, and why
// that is sound: an entry says the newer rules accept and reject exactly what the older ones did on every
// block the older ones could have committed. Anything not listed refuses to start, as before. An entry is
// a claim about history, made once per bump and never by default.
var compatibleContinuations = map[uint64]uint64{
	// v8 added only the rotation and tick kinds, which pre-v8 history does not contain (see
	// executionRulesV8 - checked against every committed block before the deploy). v9 decides v7 and v8
	// history as they did, which every node checks before it starts (see executionRulesV9).
	executionRulesV7: executionRulesV9,
	executionRulesV8: executionRulesV9,
}

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
	if next, ok := compatibleContinuations[persisted]; ok && next == CurrentExecutionRulesVersion {
		// Continued, and from the next commit stamped with the rules that commit it.
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
