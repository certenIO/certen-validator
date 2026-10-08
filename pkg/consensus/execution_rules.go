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

	// v10 - CERTEN's BLS registry becomes consensus state (RB5 D3): a recognised transaction kind
	// `certen.blsregistry.set/v1`, authorised by the sealed admin quorum over the chain id, every key proving
	// possession. Accepted, it contributes its id to the app hash; refused, it returns code 9. v9 judged the
	// same bytes as a ValidatorBlock and refused them with code 2, so the version is bumped.
	//
	// v10 CONTINUES v7, v8 and v9 state without a reset: the kind is new, so no committed history contains it,
	// and that is checked, not assumed - IndexCommittedHistory refuses to start on any committed registry-kind
	// transaction decided with v9's code. The state stays stamped with the older version until a block accepts
	// or refuses a registry (committedRulesVersion).
	executionRulesV10 uint64 = 10

	// v11 - the admin re-seal (admin_reseal.go): a recognised transaction kind `certen.admin.reseal/v1` that replaces
	// certen-testnet's sealed admin set, whose secrets were lost, ONCE, with the set written into the rule (three keys,
	// threshold 2), and only while the lost set is in force. Accepted, it contributes its id to the app hash and is
	// recorded append-only; refused, it returns code 11. v10 judged the same bytes as a ValidatorBlock and refused them
	// with code 2, so the version is bumped. From v11 every admin-signed transaction (policy update, rotation, BLS
	// registry) is judged by the admin set in force for its block (AdminSetAt) - identical to v10 on every chain that
	// has not re-sealed, since the set in force is then the genesis seal v10 used.
	//
	// v11 CONTINUES v7..v10 state without a reset: the kind is new, so no committed history contains it, and that is
	// checked, not assumed - IndexCommittedHistory refuses to start on any committed re-seal-kind transaction decided
	// with v10's code. The state stays stamped with the older version until a block accepts or refuses a re-seal
	// (committedRulesVersion).
	executionRulesV11 uint64 = 11

	// v12 - the admin rotation (admin_rotate.go, RB5-F37): a recognised transaction kind `certen.admin.rotate/v1` by
	// which the admin quorum IN FORCE replaces the admin set - replacing, adding or removing keys and changing the
	// threshold - so a lost or compromised admin key never again needs a one-time rules repair like v11's re-seal. It is
	// authorised by the threshold of distinct keys of the set in force for its block (AdminSetAt), bound to the chain,
	// to its sequence (one more than the admin-set changes recorded) and to the id of the set in force, and every new
	// key proves possession. Accepted, it contributes its id to the app hash and is appended to the same record the
	// re-seal writes, in force from the next height; refused, it returns code 12. v11 judged the same bytes as a
	// ValidatorBlock and decided them with a ValidatorBlock's code, so the version is bumped.
	//
	// v12 also refuses (code 6) a second copy, in other bytes, of the validator rotation its block already accepted.
	// v11 accepted the copy and returned the rotation's validator updates twice, which CometBFT refuses as a duplicate
	// entry - every node fails to apply such a block and the chain halts - so no live history holds one; that too is
	// checked at every start (rotationBlockVerdicts).
	//
	// v12 refuses (code 5) a policy update whose version an EARLIER block scheduled. v11 accepted it as a no-op (code 0,
	// its id in the app hash) whatever it carried, which made "an update cannot be replayed" untrue; every start checks
	// that no committed block holds one accepted that way (kindViolation), and history-check --rules 12 checks it
	// against the live chain before the deploy. The same update again within its own block stays the accepted no-op.
	//
	// And from v12 every admin threshold - policy update, validator rotation, BLS registry, admin rotation - counts
	// distinct KEYS, not distinct ids: one key named under two ids used to count twice. The two counts differ only for
	// an admin set naming one key twice, so a node refuses to continue older state if any admin set its chain has had
	// does (checkAdminKeyCountingContinuity); certen-testnet's sets - the lost genesis pair and the re-seal's three -
	// name distinct keys, and genesis no longer seals such a set.
	//
	// v12 CONTINUES v7..v11 state without a reset: the kind is new, so no committed history contains it, and that is
	// checked, not assumed - IndexCommittedHistory refuses to start on any committed admin-rotation-kind transaction that
	// v12 did not decide (a ValidatorBlock's code, or an acceptance with no rotation recorded for it). Every other kind
	// is decided exactly as v11 decided it. Every accepted registry, re-seal and admin rotation must also be found in the
	// committed records at its height under its id: an acceptance without its record is divergent or corrupt state, and
	// the node refuses to start on it. The state stays stamped with the older version until a block accepts or
	// refuses an admin rotation (committedRulesVersion).
	executionRulesV12 uint64 = 12

	// v13 - the Accumulate validator-set spine becomes consensus state (accumulate_spine.go, RB6; docs/proof/PROOF_V2.md,
	// GOVROOT_V3.md): a proof v2 must be judged inside FinalizeBlock with no I/O, so the chain itself holds the spine its
	// validator sets are traced along. Two recognised transaction kinds:
	// `certen.accumulate.spine.genesis/v1`, signed by the admin quorum in force (a governed act: it switches the chain to
	// v3 intent certificates), and accepted only when its facts recompute the Accumulate incarnation of the BLS
	// registry in force and the recorded spine is not already of that incarnation - so the spine starts from the
	// registry's incarnation and follows it when an admin-signed registry moves to a new one, replacing the dead
	// incarnation's spine - and `certen.accumulate.spine.extend/v1`, the next major blocks in sequence after the last
	// checkpoint, each verified from the spine the chain holds (pkg/proof/v2 consensus_spine.go), on a spine of the
	// registry's incarnation only. Accepted, each contributes its id to the app hash; refused, a genesis returns code 13,
	// an extension code 14, or code 15 when the chain has already verified its first major block (a lost race between
	// submitters, told apart from an invalid extension). v12 judged the same bytes as a ValidatorBlock and decided them
	// with a ValidatorBlock's code, so the version is bumped.
	//
	// v13 CONTINUES v7..v12 state without a reset: the kinds are new, so no committed history contains them, and that is
	// checked, not assumed - IndexCommittedHistory refuses to start on any committed spine-kind transaction that v13 did
	// not decide (a ValidatorBlock's code, or an acceptance with no record of it in the committed spine log). Every other
	// kind is decided exactly as v12 decided it. The state stays stamped with the older version until a block accepts
	// or refuses a spine transaction (committedRulesVersion).
	executionRulesV13 uint64 = 13

	// v14 - CERTEN's anchor set becomes consensus state, and the entitlement cost ceiling binds (RB4-F35, RB4-F6):
	//
	//   - a recognised transaction kind `certen.anchorset.set/v1` (anchor_set.go): the V8 anchor of every settlement
	//     chain, authorised by the admin quorum in force (AdminSetAt) over the chain id and the version, sequential
	//     versions, recorded like the BLS registry and served at /certen/anchor_set. Accepted, it contributes its id to
	//     the app hash; refused, it returns code 16. v13 judged the same bytes as a ValidatorBlock.
	//   - From the height after the chain's FIRST accepted anchor set - the v14 activation, a fact of committed state on
	//     every node, never a date or a node's environment - every ValidatorBlock is judged by two more rules: each chain
	//     target names its chain's committed anchor, or the block is refused with code 17 (ANCHOR_NOT_COMMITTED); and a
	//     cost ceiling that touches a chain the epoch publishes no basis for is refused (code 4, ENTITLEMENT_UNPRICED),
	//     as is a negative or overflowing basis (code 4, ENTITLEMENT_COST_BASIS_INVALID). v13 skipped the ceiling in both
	//     cases and checked no anchor.
	//
	// Until the activation the v14 binary decides every block exactly as v13 did - the explicitly named behaviour for a
	// chain with no anchor set is "v14 not yet activated" - and the v14 proposer admits no intent at all
	// (ErrAnchorSetNotCommitted, retried), so the window between the deploy and the anchor set carries no new work. The
	// runbook commits the anchor set immediately after the fleet runs v14 (docs/runbooks/rules-v14-ceiling-anchor-set.md).
	//
	// v14 CONTINUES v7..v13 state without a reset: the kind is new, so no committed history contains it, and that is
	// checked, not assumed - IndexCommittedHistory refuses to start on any committed anchor-set-kind transaction that v14
	// did not decide (a ValidatorBlock's code, or an acceptance with no anchor set recorded for it). No committed history
	// holds an anchor set, so none reaches the activation, and every other block is decided exactly as v13 decided it.
	// The state stays stamped with the older version until a block accepts or refuses an anchor set
	// (committedRulesVersion).
	executionRulesV14 uint64 = 14

	// CurrentExecutionRulesVersion is what THIS binary implements.
	CurrentExecutionRulesVersion = executionRulesV14
)

// compatibleContinuations names the older rules whose committed state this binary may continue, and why
// that is sound: an entry says the newer rules accept and reject exactly what the older ones did on every
// block the older ones could have committed. Anything not listed refuses to start, as before. An entry is
// a claim about history, made once per bump and never by default.
var compatibleContinuations = map[uint64]uint64{
	// v8 added only the rotation and tick kinds, which pre-v8 history does not contain (see
	// executionRulesV8 - checked against every committed block before the deploy). v9 decides v7 and v8
	// history as they did, which every node checks before it starts (see executionRulesV9).
	// v10 adds only the registry kind, which no committed history contains (checked at every start).
	// v11 adds only the re-seal kind, which no committed history contains (checked at every start), and judges admin
	// signatures by the set in force, which is the genesis seal until a re-seal is committed.
	// v12 adds only the admin-rotation kind, which no committed history contains (checked at every start).
	// v13 adds only the two spine kinds, which no committed history contains (checked at every start).
	// v14 adds only the anchor-set kind, which no committed history contains (checked at every start), and its
	// ValidatorBlock rules apply only from the height after an accepted anchor set, which no committed history reaches.
	executionRulesV7:  executionRulesV14,
	executionRulesV8:  executionRulesV14,
	executionRulesV9:  executionRulesV14,
	executionRulesV10: executionRulesV14,
	executionRulesV11: executionRulesV14,
	executionRulesV12: executionRulesV14,
	executionRulesV13: executionRulesV14,
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
