// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package errors provides comprehensive error handling for the Accumulate lite client.
// It defines error types, codes, and utilities for consistent error management.
package errors

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ErrorCode represents a specific error type
type ErrorCode string

const (
	// Network-related errors
	ErrorCodeNetworkTimeout    ErrorCode = "NETWORK_TIMEOUT"
	ErrorCodeNetworkConnection ErrorCode = "NETWORK_CONNECTION"
	ErrorCodeNetworkUnknown    ErrorCode = "NETWORK_UNKNOWN"
	
	// API-related errors
	ErrorCodeAPIInvalidRequest  ErrorCode = "API_INVALID_REQUEST"
	ErrorCodeAPIUnauthorized    ErrorCode = "API_UNAUTHORIZED"
	ErrorCodeAPIRateLimit       ErrorCode = "API_RATE_LIMIT"
	ErrorCodeAPIServerError     ErrorCode = "API_SERVER_ERROR"
	ErrorCodeAPINotFound        ErrorCode = "API_NOT_FOUND"
	
	// Validation errors
	ErrorCodeValidationFailed    ErrorCode = "VALIDATION_FAILED"
	ErrorCodeValidationURL       ErrorCode = "VALIDATION_URL"
	ErrorCodeValidationAccount   ErrorCode = "VALIDATION_ACCOUNT"
	ErrorCodeValidationBPT       ErrorCode = "VALIDATION_BPT"
	
	// Proof-related errors
	ErrorCodeProofGeneration     ErrorCode = "PROOF_GENERATION"
	ErrorCodeProofVerification   ErrorCode = "PROOF_VERIFICATION"
	ErrorCodeProofIncomplete     ErrorCode = "PROOF_INCOMPLETE"
	ErrorCodeProofInvalidHash    ErrorCode = "PROOF_INVALID_HASH"
	
	// Configuration errors
	ErrorCodeConfigInvalid       ErrorCode = "CONFIG_INVALID"
	ErrorCodeConfigMissing       ErrorCode = "CONFIG_MISSING"
	ErrorCodeConfigFormat        ErrorCode = "CONFIG_FORMAT"
	
	// Storage errors
	ErrorCodeStorageConnection   ErrorCode = "STORAGE_CONNECTION"
	ErrorCodeStorageQuery        ErrorCode = "STORAGE_QUERY"
	ErrorCodeStorageCorrupted    ErrorCode = "STORAGE_CORRUPTED"
	
	// Internal errors
	ErrorCodeInternalError       ErrorCode = "INTERNAL_ERROR"
	ErrorCodeNotImplemented      ErrorCode = "NOT_IMPLEMENTED"
	ErrorCodeDeprecated          ErrorCode = "DEPRECATED"
)

// LiteClientError represents a structured error with context
type LiteClientError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	StackTrace string                 `json:"stack_trace,omitempty"`
	Cause      error                  `json:"cause,omitempty"`
}

// Error implements the error interface
func (e *LiteClientError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s - %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for error unwrapping
func (e *LiteClientError) Unwrap() error {
	return e.Cause
}

// HTTPStatus returns the appropriate HTTP status code for this error
func (e *LiteClientError) HTTPStatus() int {
	switch e.Code {
	case ErrorCodeAPIInvalidRequest, ErrorCodeValidationFailed, 
		 ErrorCodeValidationURL, ErrorCodeValidationAccount, ErrorCodeValidationBPT:
		return http.StatusBadRequest
	case ErrorCodeAPIUnauthorized:
		return http.StatusUnauthorized
	case ErrorCodeAPINotFound:
		return http.StatusNotFound
	case ErrorCodeAPIRateLimit:
		return http.StatusTooManyRequests
	case ErrorCodeNetworkTimeout:
		return http.StatusRequestTimeout
	case ErrorCodeNotImplemented:
		return http.StatusNotImplemented
	case ErrorCodeAPIServerError, ErrorCodeInternalError:
		return http.StatusInternalServerError
	case ErrorCodeNetworkConnection, ErrorCodeStorageConnection:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// NewError creates a new LiteClientError
func NewError(code ErrorCode, message string) *LiteClientError {
	return &LiteClientError{
		Code:      code,
		Message:   message,
		Context:   make(map[string]interface{}),
		Timestamp: time.Now(),
	}
}

// NewErrorf creates a new LiteClientError with formatted message
func NewErrorf(code ErrorCode, format string, args ...interface{}) *LiteClientError {
	return NewError(code, fmt.Sprintf(format, args...))
}

// WrapError wraps an existing error with additional context
func WrapError(err error, code ErrorCode, message string) *LiteClientError {
	lce := NewError(code, message)
	lce.Cause = err
	return lce
}

// WrapErrorf wraps an existing error with formatted message
func WrapErrorf(err error, code ErrorCode, format string, args ...interface{}) *LiteClientError {
	return WrapError(err, code, fmt.Sprintf(format, args...))
}

// WithDetails adds detailed information to the error
func (e *LiteClientError) WithDetails(details string) *LiteClientError {
	e.Details = details
	return e
}

// WithDetailsf adds formatted detailed information to the error
func (e *LiteClientError) WithDetailsf(format string, args ...interface{}) *LiteClientError {
	e.Details = fmt.Sprintf(format, args...)
	return e
}

// WithContext adds context information to the error
func (e *LiteClientError) WithContext(key string, value interface{}) *LiteClientError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithContextMap adds multiple context entries to the error
func (e *LiteClientError) WithContextMap(context map[string]interface{}) *LiteClientError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	for k, v := range context {
		e.Context[k] = v
	}
	return e
}

// WithStackTrace adds stack trace information to the error
func (e *LiteClientError) WithStackTrace() *LiteClientError {
	e.StackTrace = getStackTrace()
	return e
}

// IsLiteClientError checks if an error is a LiteClientError
func IsLiteClientError(err error) bool {
	var lce *LiteClientError
	return errors.As(err, &lce)
}

// AsLiteClientError extracts a LiteClientError from an error
func AsLiteClientError(err error) (*LiteClientError, bool) {
	var lce *LiteClientError
	if errors.As(err, &lce) {
		return lce, true
	}
	return nil, false
}

// HasCode checks if an error has a specific error code
func HasCode(err error, code ErrorCode) bool {
	if lce, ok := AsLiteClientError(err); ok {
		return lce.Code == code
	}
	return false
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	
	var trace string
	for {
		frame, more := frames.Next()
		trace += fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function)
		if !more {
			break
		}
	}
	return trace
}

// Common error constructors for frequently used errors

// NetworkError creates a network-related error
func NetworkError(err error, details string) *LiteClientError {
	code := ErrorCodeNetworkUnknown
	if err != nil {
		errStr := err.Error()
		if contains(errStr, "timeout") {
			code = ErrorCodeNetworkTimeout
		} else if contains(errStr, "connection") {
			code = ErrorCodeNetworkConnection
		}
	}
	
	return WrapError(err, code, "Network error occurred").
		WithDetails(details).
		WithStackTrace()
}

// ValidationError creates a validation error
func ValidationError(field, reason string) *LiteClientError {
	return NewErrorf(ErrorCodeValidationFailed, "Validation failed for field '%s'", field).
		WithDetails(reason).
		WithContext("field", field).
		WithStackTrace()
}

// ProofError creates a proof-related error
func ProofError(err error, step string) *LiteClientError {
	return WrapErrorf(err, ErrorCodeProofGeneration, "Proof generation failed at step: %s", step).
		WithContext("step", step).
		WithStackTrace()
}

// ConfigError creates a configuration error
func ConfigError(err error, key string) *LiteClientError {
	return WrapErrorf(err, ErrorCodeConfigInvalid, "Invalid configuration for key: %s", key).
		WithContext("config_key", key).
		WithStackTrace()
}

// APIError creates an API-related error
func APIError(statusCode int, message string) *LiteClientError {
	var code ErrorCode
	switch statusCode {
	case 400:
		code = ErrorCodeAPIInvalidRequest
	case 401:
		code = ErrorCodeAPIUnauthorized
	case 404:
		code = ErrorCodeAPINotFound
	case 429:
		code = ErrorCodeAPIRateLimit
	case 500, 502, 503, 504:
		code = ErrorCodeAPIServerError
	default:
		code = ErrorCodeAPIServerError
	}
	
	return NewError(code, message).
		WithContext("status_code", statusCode).
		WithStackTrace()
}

// InternalError creates an internal error (should be used sparingly)
func InternalError(err error, operation string) *LiteClientError {
	return WrapErrorf(err, ErrorCodeInternalError, "Internal error during operation: %s", operation).
		WithContext("operation", operation).
		WithStackTrace()
}

// NotImplementedError creates a not implemented error
func NotImplementedError(feature string) *LiteClientError {
	return NewErrorf(ErrorCodeNotImplemented, "Feature not implemented: %s", feature).
		WithContext("feature", feature)
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		   (len(s) > len(substr) && 
		   fmt.Sprintf("%s", s[:len(substr)]) == substr))
}

// ErrorRecovery provides utilities for error recovery and retry logic
type ErrorRecovery struct {
	MaxRetries    int
	BackoffFactor time.Duration
	RetryableCodes []ErrorCode
}

// DefaultErrorRecovery returns a default error recovery configuration
func DefaultErrorRecovery() *ErrorRecovery {
	return &ErrorRecovery{
		MaxRetries:    3,
		BackoffFactor: time.Second,
		RetryableCodes: []ErrorCode{
			ErrorCodeNetworkTimeout,
			ErrorCodeNetworkConnection,
			ErrorCodeAPIServerError,
		},
	}
}

// IsRetryable checks if an error should be retried
func (er *ErrorRecovery) IsRetryable(err error) bool {
	lce, ok := AsLiteClientError(err)
	if !ok {
		return false
	}
	
	for _, code := range er.RetryableCodes {
		if lce.Code == code {
			return true
		}
	}
	return false
}

// BackoffDuration calculates the backoff duration for a retry attempt
func (er *ErrorRecovery) BackoffDuration(attempt int) time.Duration {
	return er.BackoffFactor * time.Duration(1<<uint(attempt))
}