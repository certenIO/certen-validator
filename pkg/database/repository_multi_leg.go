// Copyright 2025 Certen Protocol
//
// Multi-Leg Pending State Repository
// Persists multi-leg aggregation state to survive validator crashes (GAP 4).

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// MultiLegPendingState represents a persisted multi-leg aggregation entry
type MultiLegPendingState struct {
	IntentID           string          `json:"intent_id"`
	OperationID        string          `json:"operation_id"`
	TotalLegs          int             `json:"total_legs"`
	ExecutionMode      string          `json:"execution_mode"`
	LegMapping         json.RawMessage `json:"leg_mapping"`
	LegIndicesPerChain json.RawMessage `json:"leg_indices_per_chain"`
	CompletedCycles    json.RawMessage `json:"completed_cycles"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
}

// MultiLegRepository provides persistence for multi-leg aggregation state
type MultiLegRepository struct {
	db *sql.DB
}

// NewMultiLegRepository creates a new multi-leg repository
func NewMultiLegRepository(db *sql.DB) *MultiLegRepository {
	return &MultiLegRepository{db: db}
}

// UpsertPendingState inserts or updates the pending state for a multi-leg intent
func (r *MultiLegRepository) UpsertPendingState(ctx context.Context, state *MultiLegPendingState) error {
	query := `
		INSERT INTO multi_leg_pending_state (
			intent_id, operation_id, total_legs, execution_mode,
			leg_mapping, leg_indices_per_chain, completed_cycles,
			created_at, updated_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
		ON CONFLICT (intent_id) DO UPDATE SET
			completed_cycles = $7,
			updated_at = NOW()
	`

	expiresAt := state.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(2 * time.Hour)
	}

	_, err := r.db.ExecContext(ctx, query,
		state.IntentID,
		state.OperationID,
		state.TotalLegs,
		state.ExecutionMode,
		state.LegMapping,
		state.LegIndicesPerChain,
		state.CompletedCycles,
		state.CreatedAt,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("upsert multi-leg pending state: %w", err)
	}
	return nil
}

// UpdateCompletedCycles updates just the completed_cycles JSONB for an intent
func (r *MultiLegRepository) UpdateCompletedCycles(ctx context.Context, intentID string, completedCycles json.RawMessage) error {
	query := `
		UPDATE multi_leg_pending_state
		SET completed_cycles = $2, updated_at = NOW()
		WHERE intent_id = $1
	`
	result, err := r.db.ExecContext(ctx, query, intentID, completedCycles)
	if err != nil {
		return fmt.Errorf("update completed cycles: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("intent %s not found in multi_leg_pending_state", intentID)
	}
	return nil
}

// DeletePendingState removes a completed intent's pending state
func (r *MultiLegRepository) DeletePendingState(ctx context.Context, intentID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM multi_leg_pending_state WHERE intent_id = $1`, intentID)
	if err != nil {
		return fmt.Errorf("delete multi-leg pending state: %w", err)
	}
	return nil
}

// LoadAllPending loads all non-expired pending multi-leg intents
func (r *MultiLegRepository) LoadAllPending(ctx context.Context) ([]*MultiLegPendingState, error) {
	query := `
		SELECT intent_id, operation_id, total_legs, execution_mode,
			   leg_mapping, leg_indices_per_chain, completed_cycles,
			   created_at, updated_at, expires_at
		FROM multi_leg_pending_state
		WHERE expires_at > NOW()
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("load pending multi-leg states: %w", err)
	}
	defer rows.Close()

	var states []*MultiLegPendingState
	for rows.Next() {
		s := &MultiLegPendingState{}
		if err := rows.Scan(
			&s.IntentID, &s.OperationID, &s.TotalLegs, &s.ExecutionMode,
			&s.LegMapping, &s.LegIndicesPerChain, &s.CompletedCycles,
			&s.CreatedAt, &s.UpdatedAt, &s.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan pending multi-leg state: %w", err)
		}
		states = append(states, s)
	}

	return states, rows.Err()
}

// CleanupExpired removes expired entries
func (r *MultiLegRepository) CleanupExpired(ctx context.Context) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM multi_leg_pending_state WHERE expires_at <= NOW()`)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired multi-leg states: %w", err)
	}
	return result.RowsAffected()
}
