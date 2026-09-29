// Copyright 2026 Certen Protocol
//
// A chain member's outcome is written back to Accumulate once (RB4-F59).

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrMemberAlreadyWrittenBack: the member's outcome is already on Accumulate; another write-back would be a
// second entry for the same member.
var ErrMemberAlreadyWrittenBack = errors.New("member already written back")

// ErrMemberWriteBackUnresolved: a cycle claimed the member's write-back and its outcome is not known - the
// submission may have reached Accumulate. No other write-back is submitted until that is established.
var ErrMemberWriteBackUnresolved = errors.New("member write-back outcome unknown")

// MemberWriteBack is a member's write-back as registered.
type MemberWriteBack struct {
	IntentID    string
	ChainID     int64
	State       string // claimed | written | not_sent
	CycleID     string
	ValidatorID string
	WriteBackTx string
	Reason      string
	ClaimedAt   time.Time
}

// Write-back register states.
const (
	MemberWriteBackClaimed = "claimed"
	MemberWriteBackWritten = "written"
	MemberWriteBackNotSent = "not_sent"
)

// MemberWriteBackOf returns a member's registered write-back, or nil when none is registered.
func (r *IntentLifecycleRepository) MemberWriteBackOf(ctx context.Context, intentID string, chainID int64) (*MemberWriteBack, error) {
	return memberWriteBackOf(ctx, r.client.db, intentID, chainID, false)
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func memberWriteBackOf(ctx context.Context, q queryRower, intentID string, chainID int64, lock bool) (*MemberWriteBack, error) {
	query := `SELECT state, cycle_id, validator_id, write_back_tx, reason, claimed_at
		FROM member_write_backs WHERE intent_id = $1 AND chain_id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	w := MemberWriteBack{IntentID: intentID, ChainID: chainID}
	var tx, reason sql.NullString
	err := q.QueryRowContext(ctx, query, intentID, chainID).Scan(&w.State, &w.CycleID, &w.ValidatorID, &tx, &reason, &w.ClaimedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the write-back of %s/%d: %w", intentID, chainID, err)
	}
	w.WriteBackTx, w.Reason = tx.String, reason.String
	return &w, nil
}

// refusal names why a registered write-back stops another one, or nil when it does not.
func (w *MemberWriteBack) refusal() error {
	switch {
	case w == nil || w.State == MemberWriteBackNotSent:
		return nil
	case w.State == MemberWriteBackWritten:
		return fmt.Errorf("%w: intent %s member %d as %s by cycle %s (%s)",
			ErrMemberAlreadyWrittenBack, w.IntentID, w.ChainID, w.WriteBackTx, w.CycleID, w.ValidatorID)
	default:
		return fmt.Errorf("%w: intent %s member %d was claimed by cycle %s (%s) at %s and its outcome was never recorded",
			ErrMemberWriteBackUnresolved, w.IntentID, w.ChainID, w.CycleID, w.ValidatorID, w.ClaimedAt.UTC().Format(time.RFC3339))
	}
}

// MemberWriteBackAllowed is nil when the member may be written back - nothing registered, or a claim that was
// never sent - and otherwise names why not.
func (r *IntentLifecycleRepository) MemberWriteBackAllowed(ctx context.Context, intentID string, chainID int64) error {
	w, err := r.MemberWriteBackOf(ctx, intentID, chainID)
	if err != nil {
		return err
	}
	return w.refusal()
}

// ClaimMemberWriteBack claims the member's write-back for a cycle, before it is submitted. A member written back,
// or claimed with its outcome unknown, is refused by name; a claim never sent is taken over.
func (r *IntentLifecycleRepository) ClaimMemberWriteBack(ctx context.Context, intentID string, chainID int64, cycleID, validatorID string) error {
	if intentID == "" || chainID == 0 || cycleID == "" || validatorID == "" {
		return fmt.Errorf("claim a write-back: intent, chain, cycle and validator are required")
	}
	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin write-back claim: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a committed transaction ignores it

	res, err := tx.ExecContext(ctx, `
		INSERT INTO member_write_backs (intent_id, chain_id, state, cycle_id, validator_id)
		VALUES ($1, $2, 'claimed', $3, $4)
		ON CONFLICT (intent_id, chain_id) DO NOTHING`, intentID, chainID, cycleID, validatorID)
	if err != nil {
		return fmt.Errorf("claim the write-back of %s/%d: %w", intentID, chainID, err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return tx.Commit()
	}
	w, err := memberWriteBackOf(ctx, tx, intentID, chainID, true)
	if err != nil {
		return err
	}
	if w == nil {
		return fmt.Errorf("claim the write-back of %s/%d: the registered claim vanished", intentID, chainID)
	}
	if refusal := w.refusal(); refusal != nil {
		return refusal
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE member_write_backs SET state = 'claimed', cycle_id = $3, validator_id = $4, reason = NULL,
			claimed_at = now(), resolved_at = NULL
		WHERE intent_id = $1 AND chain_id = $2 AND state = 'not_sent'`, intentID, chainID, cycleID, validatorID); err != nil {
		return fmt.Errorf("take over the unsent write-back of %s/%d: %w", intentID, chainID, err)
	}
	return tx.Commit()
}

// RecordMemberWriteBack records the claimed write-back as written.
func (r *IntentLifecycleRepository) RecordMemberWriteBack(ctx context.Context, intentID string, chainID int64, cycleID, writeBackTx string) error {
	if writeBackTx == "" {
		return fmt.Errorf("record the write-back of %s/%d: no transaction", intentID, chainID)
	}
	return r.resolveMemberWriteBack(ctx, intentID, chainID, cycleID, MemberWriteBackWritten, writeBackTx, "")
}

// ReleaseMemberWriteBack records that the claiming cycle sent nothing, with why, so another cycle may claim it.
func (r *IntentLifecycleRepository) ReleaseMemberWriteBack(ctx context.Context, intentID string, chainID int64, cycleID, reason string) error {
	if reason == "" {
		return fmt.Errorf("release the write-back of %s/%d: no reason", intentID, chainID)
	}
	return r.resolveMemberWriteBack(ctx, intentID, chainID, cycleID, MemberWriteBackNotSent, "", reason)
}

func (r *IntentLifecycleRepository) resolveMemberWriteBack(ctx context.Context, intentID string, chainID int64, cycleID, state, writeBackTx, reason string) error {
	res, err := r.client.db.ExecContext(ctx, `
		UPDATE member_write_backs SET state = $4, write_back_tx = NULLIF($5, ''), reason = NULLIF($6, ''), resolved_at = now()
		WHERE intent_id = $1 AND chain_id = $2 AND cycle_id = $3 AND state = 'claimed'`,
		intentID, chainID, cycleID, state, writeBackTx, reason)
	if err != nil {
		return fmt.Errorf("record the write-back of %s/%d as %s: %w", intentID, chainID, state, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("record the write-back of %s/%d as %s: cycle %s holds no claim on it", intentID, chainID, state, cycleID)
	}
	return nil
}
