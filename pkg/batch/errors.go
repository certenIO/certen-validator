// Copyright 2025 Certen Protocol
//
// Batch package errors

package batch

import "errors"

// Common errors for the batch package
var (
	ErrNilCollector     = errors.New("collector cannot be nil")
	ErrNilProcessor     = errors.New("processor cannot be nil")
	ErrBatchNotFound    = errors.New("batch not found")
	ErrBatchClosed      = errors.New("batch is already closed")
	ErrBatchEmpty       = errors.New("batch is empty")
	ErrInvalidTxHash    = errors.New("transaction hash must be 32 bytes")
	ErrSchedulerRunning = errors.New("scheduler is already running")
)
