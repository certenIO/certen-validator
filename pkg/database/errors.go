// Copyright 2025 Certen Protocol
//
// Package database provides sentinel errors for repository operations.
// F.4 remediation: Explicit errors instead of nil, nil returns

package database

import "errors"

// Sentinel errors for database operations
var (
	// ErrNotFound is returned when a requested entity is not found in the database
	ErrNotFound = errors.New("entity not found")

	// ErrAnchorNotFound is returned when an anchor record is not found
	ErrAnchorNotFound = errors.New("anchor not found")

	// ErrProofNotFound is returned when a proof record is not found
	ErrProofNotFound = errors.New("proof not found")

	// ErrAttestationNotFound is returned when an attestation record is not found
	ErrAttestationNotFound = errors.New("attestation not found")

	// ErrRequestNotFound is returned when a proof request is not found
	ErrRequestNotFound = errors.New("request not found")

	// ErrBatchNotFound is returned when a batch is not found
	ErrBatchNotFound = errors.New("batch not found")

	// ErrTransactionNotFound is returned when a batch transaction is not found
	ErrTransactionNotFound = errors.New("transaction not found")
)
