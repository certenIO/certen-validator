// Copyright 2026 Certen Protocol

package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// A validator's ValidatorBlock for an operation commits once (RB3-F141).
//
// Production committed 161 bundles twice: a proposer that had not seen its first commit - the inclusion poll
// gave up after 15 seconds, a stalled discovery watermark re-queued the block, a restart rewound 600 blocks
// and forgot every intent it had finished - rebuilt the same block and broadcast it again, and nothing on
// either side knew it had already committed. The app now keeps its own record of what committed
// (ledger.CommittedOperation, written in Commit): the proposer asks it before broadcasting, and from
// duplicateOperationRuleFrom consensus refuses a second block for a committed operation.

// duplicateOperationRuleFrom is the block time from which a validator's second ValidatorBlock for an
// operation it already committed is refused (execution rules v9). Before it, such a block is accepted as it
// always was: the chain's history holds 161 of them, and replay has to reproduce it. A chain started after
// this time - a new incarnation - applies the rule from its first block. Keyed on block time like policy
// activation, and checked against history before a node starts on it (verifyCommittedHistory).
var duplicateOperationRuleFrom = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// codeDuplicateOperation is the result code of a refused second block for a committed operation.
const codeDuplicateOperation uint32 = 8

// checkTxClock is the wall clock CheckTx's mempool filter reads (a variable so tests can set it).
var checkTxClock = time.Now

// refuseCommittedOperation judges a ValidatorBlock that passed every other rule: it is refused when the
// same validator's block for the same operation committed at a lower height or earlier in this block, from
// duplicateOperationRuleFrom on. An accepted block is staged for the index, which Commit writes. It runs
// last, so the only outcome it can change is an acceptance.
func (app *ValidatorApp) refuseCommittedOperation(vb *ValidatorBlock, tx []byte) *abcitypes.ExecTxResult {
	height := int64(app.currentBlockHeight)
	prior, err := app.priorCommit(vb.ValidatorID, vb.CrossChainProof.OperationID, height)
	if err != nil {
		// The index is the rule's input; a node that cannot read it cannot judge the block the way its
		// peers do.
		app.logger.Fatalf("❌ [COMMITTED-OP] the committed-operation index could not be read at height %d: %v", height, err)
	}
	if prior != "" && !app.currentBlockTime.Before(duplicateOperationRuleFrom) {
		app.blockRulesV9Verdict = true
		app.logger.Printf("🚫 [COMMITTED-OP] REFUSED bundle=%s: validator %s's block for operation %s already committed %s",
			vb.BundleID, vb.ValidatorID, vb.CrossChainProof.OperationID, prior)
		return &abcitypes.ExecTxResult{
			Code: codeDuplicateOperation,
			Log:  fmt.Sprintf("validator %s's block for operation %s already committed %s", vb.ValidatorID, vb.CrossChainProof.OperationID, prior),
		}
	}
	sum := sha256.Sum256(tx)
	app.blockOperations = append(app.blockOperations, ledger.CommittedOperationEntry{
		ValidatorID: vb.ValidatorID,
		OperationID: vb.CrossChainProof.OperationID,
		Committed: ledger.CommittedOperation{Height: height, BundleID: vb.BundleID,
			TxHash: strings.ToUpper(hex.EncodeToString(sum[:])), BlockTime: app.currentBlockTime.UTC()},
	})
	return nil
}

// priorCommit names where the validator's block for the operation committed before this one - at a lower
// height, or earlier in this block - or returns "". A record at this height is this block replayed, not a
// prior commit.
func (app *ValidatorApp) priorCommit(validatorID, operationID string, height int64) (string, error) {
	for _, e := range app.blockOperations {
		if e.ValidatorID == validatorID && e.OperationID == operationID {
			return fmt.Sprintf("earlier in block %d (bundle %s)", height, e.Committed.BundleID), nil
		}
	}
	if app.ledgerStore == nil {
		return "", errors.New("no ledger store")
	}
	rec, err := app.ledgerStore.GetCommittedOperation(validatorID, operationID)
	if err != nil || rec == nil || rec.Height >= height {
		return "", err
	}
	return fmt.Sprintf("at height %d (bundle %s)", rec.Height, rec.BundleID), nil
}

// recordCommittedOperations writes this block's accepted ValidatorBlocks to the index, and the first v8- or
// v9-only verdict if this block produced one. Called by Commit, before the ABCI state (and its rules stamp)
// is saved.
func (app *ValidatorApp) recordCommittedOperations(height int64) {
	if err := app.ledgerStore.RecordCommittedBlock(height, app.blockOperations); err != nil {
		// Every later block would be judged against an index that is missing this one.
		app.logger.Fatalf("❌ [COMMITTED-OP] could not index committed block %d: %v", height, err)
	}
	app.blockOperations = nil
	if app.blockRulesV8Verdict {
		app.recordFirstVerdict(executionRulesV8, &app.rulesV8FirstVerdict, height)
		app.blockRulesV8Verdict = false
	}
	if app.blockRulesV9Verdict {
		app.recordFirstVerdict(executionRulesV9, &app.rulesV9FirstVerdict, height)
		app.blockRulesV9Verdict = false
	}
	if app.blockRulesV10Verdict {
		app.recordFirstVerdict(executionRulesV10, &app.rulesV10FirstVerdict, height)
		app.blockRulesV10Verdict = false
	}
	if app.blockRulesV11Verdict {
		app.recordFirstVerdict(executionRulesV11, &app.rulesV11FirstVerdict, height)
		app.blockRulesV11Verdict = false
	}
	if app.blockRulesV12Verdict {
		app.recordFirstVerdict(executionRulesV12, &app.rulesV12FirstVerdict, height)
		app.blockRulesV12Verdict = false
	}
	// This binary decided this block, so it holds nothing this version decides differently (checkCommittedKinds).
	if err := app.ledgerStore.AdvanceKindsChecked(CurrentExecutionRulesVersion, height); err != nil {
		app.logger.Fatalf("❌ [HISTORY] could not record committed block %d as checked: %v", height, err)
	}
}

// recordFirstVerdict persists the first height a rules version decided something only it decides.
func (app *ValidatorApp) recordFirstVerdict(version uint64, first *int64, height int64) {
	if err := app.ledgerStore.SaveRulesFirstVerdict(version, height); err != nil {
		app.logger.Fatalf("❌ could not record the first v%d verdict at height %d: %v", version, height, err)
	}
	if *first == 0 || height < *first {
		*first = height
	}
}

// ErrCommittedOperationsUnavailable is an index that cannot answer for the committed chain.
var ErrCommittedOperationsUnavailable = errors.New("the committed-operation index cannot answer")

// CommittedOperation is the chain's answer to "has this validator's block for this operation committed?":
// where it first committed (nil if it has not), and the height the answer covers - everything the app has
// committed. It refuses rather than answer from an index that does not cover the committed chain.
func (app *ValidatorApp) CommittedOperation(validatorID, operationID string) (*ledger.CommittedOperation, int64, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return nil, 0, fmt.Errorf("%w: no ledger store", ErrCommittedOperationsUnavailable)
	}
	upTo, err := app.ledgerStore.CommittedOperationsUpTo()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCommittedOperationsUnavailable, err)
	}
	if upTo != app.latestHeight {
		return nil, 0, fmt.Errorf("%w: it covers height %d and the app has committed %d", ErrCommittedOperationsUnavailable, upTo, app.latestHeight)
	}
	rec, err := app.ledgerStore.GetCommittedOperation(validatorID, operationID)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCommittedOperationsUnavailable, err)
	}
	return rec, upTo, nil
}

// committedOperationReader answers whether a validator's block for an operation has committed (the app's
// committed-operation index).
type committedOperationReader interface {
	CommittedOperation(validatorID, operationID string) (*ledger.CommittedOperation, int64, error)
}

// CommittedOperation answers from the engine's app, the committed-operation index.
func (e *RealCometBFTEngine) CommittedOperation(validatorID, operationID string) (*ledger.CommittedOperation, int64, error) {
	app, ok := e.app.(*ValidatorApp)
	if !ok {
		return nil, 0, fmt.Errorf("%w: this engine runs %T, not the ValidatorApp", ErrCommittedOperationsUnavailable, e.app)
	}
	return app.CommittedOperation(validatorID, operationID)
}

// deadlineInstant is the instant an intent's deadline is judged at (RB4-F60). When this validator's block for the
// intent's operation has committed, the deadline was decided at that commit and is judged at its block time - the
// same on every node, however long after the intent is processed again (a restart re-deriving it, a repair
// re-driving a member). Otherwise this is new work, judged now. An index that cannot answer is not an answer.
func deadlineInstant(r committedOperationReader, validatorID string, ci *CertenIntent, now time.Time) (time.Time, string, error) {
	if r == nil {
		return time.Time{}, "", fmt.Errorf("%w: no committed-operation index to say whether intent %s committed", ErrCommittedOperationsUnavailable, ci.IntentID)
	}
	opID, err := ci.OperationID()
	if err != nil {
		return time.Time{}, "", err
	}
	prior, _, err := r.CommittedOperation(validatorID, opID)
	if err != nil {
		return time.Time{}, "", err
	}
	if prior != nil {
		return prior.BlockTime, fmt.Sprintf("operation %s committed at height %d", opID, prior.Height), nil
	}
	return now, fmt.Sprintf("operation %s not committed: new work, judged now", opID), nil
}

// committedHistory is the chain this node has committed, read from CometBFT's own stores.
type committedHistory interface {
	// Base and Height bound the blocks the store holds.
	Base() int64
	Height() int64
	// Block is a committed block's transactions and header time.
	Block(height int64) ([][]byte, time.Time, error)
	// ResultCodes are the result codes FinalizeBlock returned for the block's transactions, in order.
	ResultCodes(height int64) ([]uint32, error)
}

// ErrCommittedHistoryUnderCurrentRules is committed history that v9 rules would not reproduce.
var ErrCommittedHistoryUnderCurrentRules = fmt.Errorf("committed history that execution rules v%d do not reproduce", CurrentExecutionRulesVersion)

// IndexCommittedHistory indexes every block the app committed that the index does not yet cover - the
// chain before this index existed, or blocks a binary without it committed - and checks each against the
// v9 rules as it goes. A node never starts on history v9 would have decided differently: that is the claim
// behind continuing v7 and v8 state (compatibleContinuations), checked here on every node rather than
// assumed. Called before CometBFT's handshake, which replays any later block through FinalizeBlock and
// Commit, and those index themselves.
//
// It then checks every committed block no binary of this version has checked or decided (checkCommittedKinds): the
// index above reads only the blocks it does not yet cover, but a block an older binary committed AND indexed can
// still hold a transaction of a kind a later version added, decided the older way - the claim behind every
// continuation from v10 on, which must hold for the whole chain, not only its unindexed tail.
func (app *ValidatorApp) IndexCommittedHistory(h committedHistory) error {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.ledgerStore == nil {
		return errors.New("committed history cannot be indexed without a ledger store")
	}
	if err := app.indexCommittedOperations(h); err != nil {
		return err
	}
	return app.checkCommittedKinds(h)
}

// indexCommittedOperations is IndexCommittedHistory's index of the blocks the committed-operation index does not
// cover, each checked as it is read. The caller holds app.mu.
func (app *ValidatorApp) indexCommittedOperations(h committedHistory) error {
	upTo, err := app.ledgerStore.CommittedOperationsUpTo()
	if err != nil {
		return err
	}
	if upTo >= app.latestHeight {
		return nil
	}
	// A chain whose genesis starts above height 1 has no blocks below its initial height.
	if upTo == 0 && app.genesisInitialHeight > 1 {
		upTo = app.genesisInitialHeight - 1
	}
	if base := h.Base(); upTo+1 < base {
		return fmt.Errorf("the block store starts at height %d, so heights %d-%d the app committed cannot be indexed", base, upTo+1, base-1)
	}
	if top := h.Height(); top < app.latestHeight {
		return fmt.Errorf("the block store ends at height %d, below the app's committed height %d", top, app.latestHeight)
	}
	app.logger.Printf("🗂️ [COMMITTED-OP] indexing committed heights %d-%d", upTo+1, app.latestHeight)
	var violations []string
	indexed := 0
	for height := upTo + 1; height <= app.latestHeight; height++ {
		txs, blockTime, err := h.Block(height)
		if err != nil {
			return fmt.Errorf("committed block %d: %w", height, err)
		}
		codes, err := h.ResultCodes(height)
		if err != nil {
			return fmt.Errorf("results of committed block %d: %w", height, err)
		}
		if len(codes) != len(txs) {
			return fmt.Errorf("committed block %d has %d transactions and %d results", height, len(txs), len(codes))
		}
		entries, found, err := app.historicalOperations(height, blockTime, txs, codes)
		if err != nil {
			return err
		}
		rotationFound, v12 := rotationBlockVerdicts(height, txs, codes)
		found = append(found, rotationFound...)
		if v12 {
			app.recordFirstVerdict(executionRulesV12, &app.rulesV12FirstVerdict, height)
		}
		replayRefused, err := app.policyReplayRefused(height, txs, codes)
		if err != nil {
			return err
		}
		if replayRefused {
			app.recordFirstVerdict(executionRulesV12, &app.rulesV12FirstVerdict, height)
		}
		for _, tx := range txs {
			if _, ok := DecodeValidatorRotation(tx); ok {
				app.recordFirstVerdict(executionRulesV8, &app.rulesV8FirstVerdict, height)
			} else if _, ok := DecodeChainTick(tx); ok {
				app.recordFirstVerdict(executionRulesV8, &app.rulesV8FirstVerdict, height)
			} else if _, ok := DecodeBLSRegistry(tx); ok {
				app.recordFirstVerdict(executionRulesV10, &app.rulesV10FirstVerdict, height)
			} else if _, ok := DecodeAdminReseal(tx); ok {
				app.recordFirstVerdict(executionRulesV11, &app.rulesV11FirstVerdict, height)
			} else if _, ok := DecodeAdminRotate(tx); ok {
				app.recordFirstVerdict(executionRulesV12, &app.rulesV12FirstVerdict, height)
			}
		}
		violations = append(violations, found...)
		if err := app.ledgerStore.RecordCommittedBlock(height, entries); err != nil {
			return err
		}
		indexed += len(entries)
	}
	if len(violations) > 0 {
		return fmt.Errorf("%w (%d):\n  %s\nThis state was committed by rules this binary does not continue. Run the binary that "+
			"committed it, or reset both CometBFT and the application ledger", ErrCommittedHistoryUnderCurrentRules, len(violations), strings.Join(violations, "\n  "))
	}
	app.logger.Printf("✅ [COMMITTED-OP] indexed %d committed ValidatorBlocks through height %d; history is what v%d rules decide",
		indexed, app.latestHeight, CurrentExecutionRulesVersion)
	return nil
}

// historicalOperations reads one committed block the way FinalizeBlock judged it: its accepted
// ValidatorBlocks, and every transaction whose recorded outcome v9 rules would not reproduce.
func (app *ValidatorApp) historicalOperations(height int64, blockTime time.Time, txs [][]byte, codes []uint32) ([]ledger.CommittedOperationEntry, []string, error) {
	var entries []ledger.CommittedOperationEntry
	var violations []string
	for i, tx := range txs {
		violation, isKind, err := app.kindViolation(height, i, tx, codes[i])
		if err != nil {
			return nil, nil, err
		}
		if violation != "" {
			violations = append(violations, violation)
			continue
		}
		if isKind || !isValidatorBlockTx(tx) {
			continue
		}
		var vb ValidatorBlock
		if err := json.Unmarshal(tx, &vb); err != nil {
			continue // refused as undecodable under every rules version
		}
		// v9 no longer names a validator for a block that names none (RB3-F140): such a block fails the
		// invariants, unless the proof-class check refused it first.
		if vb.ValidatorID == "" {
			want := uint32(2)
			if pc := vb.ExecutionProof.ProofClass; pc != "" && pc != "on_demand" && pc != "on_cadence" {
				want = 3
			}
			if codes[i] != want {
				violations = append(violations, fmt.Sprintf("height %d tx %d (bundle %s) names no validator and was decided with code %d; v9 decides %d",
					height, i, vb.BundleID, codes[i], want))
			}
			continue
		}
		if codes[i] != 0 {
			continue
		}
		prior := ""
		for _, e := range entries {
			if e.ValidatorID == vb.ValidatorID && e.OperationID == vb.CrossChainProof.OperationID {
				prior = fmt.Sprintf("earlier in the block (bundle %s)", e.Committed.BundleID)
			}
		}
		if prior == "" {
			rec, err := app.ledgerStore.GetCommittedOperation(vb.ValidatorID, vb.CrossChainProof.OperationID)
			if err != nil {
				return nil, nil, err
			}
			if rec != nil && rec.Height < height {
				prior = fmt.Sprintf("at height %d (bundle %s)", rec.Height, rec.BundleID)
			}
		}
		if prior != "" && !blockTime.Before(duplicateOperationRuleFrom) {
			violations = append(violations, fmt.Sprintf("height %d tx %d (bundle %s) was accepted although validator %s's block for operation %s committed %s; v9 refuses it",
				height, i, vb.BundleID, vb.ValidatorID, vb.CrossChainProof.OperationID, prior))
			continue
		}
		sum := sha256.Sum256(tx)
		entries = append(entries, ledger.CommittedOperationEntry{
			ValidatorID: vb.ValidatorID,
			OperationID: vb.CrossChainProof.OperationID,
			Committed: ledger.CommittedOperation{Height: height, BundleID: vb.BundleID,
				TxHash: strings.ToUpper(hex.EncodeToString(sum[:])), BlockTime: blockTime.UTC()},
		})
	}
	return entries, violations, nil
}

// isValidatorBlockTx reports whether FinalizeBlock judges a transaction as a ValidatorBlock: everything that
// is not a policy update, a validator rotation or a tick. Everything that reads committed blocks back uses
// it, so none of them mistakes another kind for a ValidatorBlock (RB3-F145).
func isValidatorBlockTx(tx []byte) bool {
	if _, ok := DecodePolicyUpdate(tx); ok {
		return false
	}
	if _, ok := DecodeValidatorRotation(tx); ok {
		return false
	}
	if _, ok := DecodeChainTick(tx); ok {
		return false
	}
	if _, ok := DecodeBLSRegistry(tx); ok {
		return false
	}
	if _, ok := DecodeAdminReseal(tx); ok {
		return false
	}
	if _, ok := DecodeAdminRotate(tx); ok {
		return false
	}
	return true
}

// kindViolation judges one committed transaction of a kind a rules version after v9 added - the BLS registry (v10),
// the admin re-seal (v11), the admin rotation (v12) - against what this binary decides for it. isKind says whether the
// transaction is one of those kinds; violation, when not empty, says how its recorded outcome is one this binary does
// not reproduce: the version before each judged those bytes as a ValidatorBlock, with a ValidatorBlock's code.
func (app *ValidatorApp) kindViolation(height int64, i int, tx []byte, code uint32) (violation string, isKind bool, err error) {
	return kindViolationWith(height, i, tx, code, app.ledgerStore.LoadEntitlementPolicy)
}

// kindViolationWith is kindViolation with the committed policy read through policy, only when an accepted admin rotation
// has to be found in its record.
func kindViolationWith(height int64, i int, tx []byte, code uint32,
	policy func() (*ledger.EntitlementPolicyState, error)) (violation string, isKind bool, err error) {
	if _, ok := DecodeBLSRegistry(tx); ok {
		// v9 judged a registry-kind transaction as a ValidatorBlock and refused it with code 2; v10 accepts it or
		// refuses it with code 9. History holding one decided v9's way is history v10 does not reproduce.
		switch {
		case code == 2:
			return fmt.Sprintf("height %d tx %d is a BLS registry transaction that v9 judged as a ValidatorBlock (code 2); "+
				"v10 decides it as a registry", height, i), true, nil
		case code != 0 && code != codeBLSRegistryRefused:
			return fmt.Sprintf("height %d tx %d is a BLS registry transaction decided with code %d, which v10 never "+
				"returns for one (it accepts, or refuses with code %d)", height, i, code, codeBLSRegistryRefused), true, nil
		}
		return "", true, nil
	}
	if _, ok := DecodeAdminReseal(tx); ok {
		// v10 judged an admin-re-seal-kind transaction as a ValidatorBlock and refused it with code 2; v11 accepts it or
		// refuses it with code 11. History holding one decided v10's way is history v11 does not reproduce.
		switch {
		case code == 2:
			return fmt.Sprintf("height %d tx %d is an admin re-seal that v10 judged as a ValidatorBlock (code 2); "+
				"v11 decides it as a re-seal", height, i), true, nil
		case code != 0 && code != codeAdminResealRefused:
			return fmt.Sprintf("height %d tx %d is an admin re-seal decided with code %d, which v11 never returns for "+
				"one (it accepts, or refuses with code %d)", height, i, code, codeAdminResealRefused), true, nil
		}
		return "", true, nil
	}
	if pu, ok := DecodePolicyUpdate(tx); ok {
		// v11 accepted (code 0) a policy update whose version an earlier block had scheduled, as a no-op; v12 refuses it
		// (code 5). History holding one accepted that way is history v12 does not reproduce.
		if code != 0 {
			return "", true, nil
		}
		state, err := policy()
		if err != nil {
			return "", true, fmt.Errorf("the committed policy, to check the policy update at height %d: %w", height, err)
		}
		if state != nil {
			for _, e := range state.Schedule {
				if e.Version == pu.Version && e.ProposedAtHeight < height {
					return fmt.Sprintf("height %d tx %d is a policy update accepted again: version %d was scheduled at height %d, "+
						"and v12 refuses it", height, i, pu.Version, e.ProposedAtHeight), true, nil
				}
			}
		}
		return "", true, nil
	}
	if ar, ok := DecodeAdminRotate(tx); ok {
		// v11 judged an admin-rotation-kind transaction as a ValidatorBlock. v12 refuses one with code 12 - a code no
		// earlier version returns - or accepts it and records it, at its height, under its id. Anything else is a
		// ValidatorBlock's verdict, which v12 does not reproduce.
		switch code {
		case codeAdminRotateRefused:
			return "", true, nil
		case 0:
			state, err := policy()
			if err != nil {
				return "", true, fmt.Errorf("the committed policy, to check the admin rotation at height %d: %w", height, err)
			}
			if state != nil {
				for _, r := range state.AdminReseals {
					if r.Kind == AdminRotateKind && r.Height == height && r.ID == ar.RotationID() {
						return "", true, nil
					}
				}
			}
			return fmt.Sprintf("height %d tx %d is an admin rotation that was accepted, but no admin rotation is recorded "+
				"for it: v11 accepted it as a ValidatorBlock; v12 decides it as an admin rotation", height, i), true, nil
		default:
			return fmt.Sprintf("height %d tx %d is an admin rotation that v11 judged as a ValidatorBlock (code %d); "+
				"v12 decides it as an admin rotation", height, i, code), true, nil
		}
	}
	return "", false, nil
}

// checkCommittedKinds checks every committed block above the kinds watermark (ledger KindsCheckedThrough) with
// kindViolation, and advances the watermark to the app's height when all of them hold. Blocks this binary commits
// advance it themselves (Commit): this version decided them. The caller holds app.mu.
func (app *ValidatorApp) checkCommittedKinds(h committedHistory) error {
	from, err := app.ledgerStore.KindsCheckedThrough(CurrentExecutionRulesVersion)
	if err != nil {
		return err
	}
	if from >= app.latestHeight {
		return nil
	}
	if from == 0 && app.genesisInitialHeight > 1 {
		from = app.genesisInitialHeight - 1
	}
	if base := h.Base(); from+1 < base {
		return fmt.Errorf("the block store starts at height %d, so heights %d-%d the app committed cannot be checked "+
			"against execution rules v%d", base, from+1, base-1, CurrentExecutionRulesVersion)
	}
	if top := h.Height(); top < app.latestHeight {
		return fmt.Errorf("the block store ends at height %d, below the app's committed height %d", top, app.latestHeight)
	}
	app.logger.Printf("🗂️ [HISTORY] checking committed heights %d-%d for transactions of kinds rules v10-v%d added",
		from+1, app.latestHeight, CurrentExecutionRulesVersion)
	var violations []string
	for height := from + 1; height <= app.latestHeight; height++ {
		txs, _, err := h.Block(height)
		if err != nil {
			return fmt.Errorf("committed block %d: %w", height, err)
		}
		codes, err := h.ResultCodes(height)
		if err != nil {
			return fmt.Errorf("results of committed block %d: %w", height, err)
		}
		if len(codes) != len(txs) {
			return fmt.Errorf("committed block %d has %d transactions and %d results", height, len(txs), len(codes))
		}
		for i, tx := range txs {
			v, _, err := app.kindViolation(height, i, tx, codes[i])
			if err != nil {
				return err
			}
			if v != "" {
				violations = append(violations, v)
			}
		}
		found, _ := rotationBlockVerdicts(height, txs, codes)
		violations = append(violations, found...)
	}
	if len(violations) > 0 {
		return fmt.Errorf("%w (%d):\n  %s\nThis state was committed by rules this binary does not continue. Run the binary that "+
			"committed it, or reset both CometBFT and the application ledger", ErrCommittedHistoryUnderCurrentRules, len(violations), strings.Join(violations, "\n  "))
	}
	if err := app.ledgerStore.SaveKindsCheckedThrough(CurrentExecutionRulesVersion, app.latestHeight); err != nil {
		return err
	}
	app.logger.Printf("✅ [HISTORY] committed heights %d-%d hold no transaction rules v%d decide differently",
		from+1, app.latestHeight, CurrentExecutionRulesVersion)
	return nil
}

// rotationBlockVerdicts judges a committed block's validator rotations as a whole: at most one is accepted per block.
// v11 accepted a second copy of the block's accepted rotation (other bytes, the same content) and returned its updates
// twice - which CometBFT refuses, so no live chain holds such a block; v12 refuses the copy with code 6. v12 reports
// whether the block holds such a refusal - a verdict only v12 reaches.
func rotationBlockVerdicts(height int64, txs [][]byte, codes []uint32) (violations []string, v12 bool) {
	accepted := map[string]int{} // rotation id -> index of the accepted one
	for i, tx := range txs {
		vr, ok := DecodeValidatorRotation(tx)
		if !ok {
			continue
		}
		id := vr.RotationID()
		switch first, seen := accepted[id]; {
		case codes[i] == 0 && len(accepted) > 0:
			violations = append(violations, fmt.Sprintf("height %d tx %d is a second validator rotation accepted in one block; "+
				"v12 accepts one rotation per block", height, i))
		case codes[i] == 0:
			accepted[id] = i
		case seen && first < i:
			v12 = true
		}
	}
	return violations, v12
}

// CommittedBlockViolations judges one committed block - its transactions and the result codes it committed - the way
// every node judges its history before it starts (IndexCommittedHistory): each transaction of a kind rules v10-v12
// added, and the block's validator rotations as a whole. policy is the chain's committed policy (nil when none can be
// read: an accepted admin rotation then has no record to be found in). Tools run it over a chain before an upgrade.
func CommittedBlockViolations(height int64, txs [][]byte, codes []uint32, policy *ledger.EntitlementPolicyState) ([]string, error) {
	if len(codes) != len(txs) {
		return nil, fmt.Errorf("block %d has %d transactions and %d results", height, len(txs), len(codes))
	}
	var out []string
	for i, tx := range txs {
		v, _, err := kindViolationWith(height, i, tx, codes[i], func() (*ledger.EntitlementPolicyState, error) { return policy, nil })
		if err != nil {
			return nil, err
		}
		if v != "" {
			out = append(out, v)
		}
	}
	found, _ := rotationBlockVerdicts(height, txs, codes)
	return append(out, found...), nil
}

// policyReplayRefused reports whether a committed block refused a policy update whose version an earlier block had
// scheduled - a verdict only v12 reaches (v11 accepted it as a no-op).
func (app *ValidatorApp) policyReplayRefused(height int64, txs [][]byte, codes []uint32) (bool, error) {
	var state *ledger.EntitlementPolicyState
	for i, tx := range txs {
		pu, ok := DecodePolicyUpdate(tx)
		if !ok || codes[i] == 0 {
			continue
		}
		if state == nil {
			s, err := app.ledgerStore.LoadEntitlementPolicy()
			if err != nil || s == nil {
				return false, err
			}
			state = s
		}
		for _, e := range state.Schedule {
			if e.Version == pu.Version && e.ProposedAtHeight < height {
				return true, nil
			}
		}
	}
	return false, nil
}
