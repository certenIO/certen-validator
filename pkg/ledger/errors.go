// Copyright 2025 Certen Protocol
//
// Package ledger provides sentinel errors for ledger operations.
// F.4 remediation: Explicit errors instead of nil, nil returns

package ledger

import "errors"

// Sentinel errors for ledger operations
var (
	// ErrMetaNotFound is returned when system ledger metadata is not found
	ErrMetaNotFound = errors.New("ledger metadata not found")

	// ErrAnchorMetaNotFound is returned when anchor ledger metadata is not found
	ErrAnchorMetaNotFound = errors.New("anchor ledger metadata not found")
)
