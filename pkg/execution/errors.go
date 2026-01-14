// Copyright 2025 Certen Protocol
//
// Package execution provides sentinel errors for execution operations.
// F.4 remediation: Explicit errors instead of nil, nil returns

package execution

import "errors"

// Sentinel errors for execution operations
var (
	// ErrNotYetMined is returned when a transaction has not yet been mined
	ErrNotYetMined = errors.New("transaction not yet mined")

	// ErrNotYetFinalized is returned when a transaction lacks required confirmations
	ErrNotYetFinalized = errors.New("transaction not yet finalized")

	// ErrProofResultNotFound is returned when a proof result cannot be retrieved
	ErrProofResultNotFound = errors.New("proof result not found")

	// ErrExecutionResultNotFound is returned when an execution result cannot be retrieved
	ErrExecutionResultNotFound = errors.New("execution result not found")

	// ErrInsufficientResultData is returned when contract response is too short
	ErrInsufficientResultData = errors.New("insufficient result data from contract")
)
