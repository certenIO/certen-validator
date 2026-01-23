// Copyright 2025 Certen Protocol
//
// Batch Status Helpers - Centralized status message generation and delay detection
// Per Implementation Plan: Communicate batch type context in API responses
//
// This module provides:
// - Status message generation based on batch type and status
// - Delay expectation detection for on-cadence vs on-demand batches
// - Expected completion time calculation for on-cadence batches

package batch

import (
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// BatchStatusInfo provides detailed status information for a batch
type BatchStatusInfo struct {
	Status              database.BatchStatus `json:"status"`
	StatusMessage       string               `json:"status_message"`
	IsDelayExpected     bool                 `json:"is_delay_expected"`
	ExpectedCompletionAt *time.Time          `json:"expected_completion_at,omitempty"`
	PriceTier           string               `json:"price_tier"`
	BatchType           database.BatchType   `json:"batch_type"`
}

// Pricing constants per whitepaper Section 3.4.2
const (
	OnCadencePricePerProof = "$0.05"
	OnDemandPricePerProof  = "$0.25"

	// Default batch interval for on-cadence batches
	DefaultBatchInterval = 15 * time.Minute

	// Grace period buffer before flagging on-cadence batch as potentially stalled
	OnCadenceGracePeriod = 5 * time.Minute
)

// GetStatusMessage returns an appropriate status message based on batch type and status
// This provides human-readable context for ecosystem components interpreting batch state
func GetStatusMessage(batchType database.BatchType, status database.BatchStatus) string {
	switch status {
	case database.BatchStatusPending:
		if batchType == database.BatchTypeOnCadence {
			return "Batch is open and accepting transactions. Anchoring occurs on ~15 minute cadence."
		}
		return "On-demand batch is collecting transactions for immediate anchoring."

	case database.BatchStatusClosed:
		if batchType == database.BatchTypeOnCadence {
			return "On-cadence batch closed. Preparing for anchor transaction submission."
		}
		return "On-demand batch closed. Anchor transaction being submitted."

	case database.BatchStatusAnchoring:
		return "Anchor transaction submitted to external chain. Waiting for confirmation."

	case database.BatchStatusAnchored:
		return "Anchor transaction confirmed. Waiting for additional confirmations for finality."

	case database.BatchStatusConfirmed:
		return "Anchor has reached sufficient confirmations. Proofs are now final."

	case database.BatchStatusFailed:
		return "Anchoring failed. This batch may be retried or requires investigation."

	case database.BatchStatusWaitingForBatch:
		return "Transaction added to on-cadence batch. Waiting for batch window to close (~15 minutes)."

	case database.BatchStatusWaitingConfirms:
		return "Anchor submitted. Waiting for blockchain confirmations for finality."

	default:
		return "Unknown batch status."
	}
}

// IsDelayExpected returns true if the current batch state represents an expected delay
// On-cadence batches in pending state have expected delays up to 15 minutes
// On-demand batches should process quickly, so delays are not expected
func IsDelayExpected(batchType database.BatchType, status database.BatchStatus) bool {
	// On-cadence batches: delays are expected while pending
	if batchType == database.BatchTypeOnCadence {
		switch status {
		case database.BatchStatusPending:
			// Delays up to 15 minutes are normal for on-cadence batches
			return true
		case database.BatchStatusWaitingForBatch:
			// Explicitly waiting for batch window - delay expected
			return true
		case database.BatchStatusAnchoring, database.BatchStatusAnchored:
			// Some delay expected during blockchain confirmation
			return true
		case database.BatchStatusWaitingConfirms:
			// Waiting for confirmations - delay expected
			return true
		}
	}

	// On-demand batches: delays are generally not expected
	// except for blockchain confirmation phases
	if batchType == database.BatchTypeOnDemand {
		switch status {
		case database.BatchStatusAnchoring, database.BatchStatusAnchored:
			// Brief delay for blockchain confirmation is expected
			return true
		case database.BatchStatusWaitingConfirms:
			return true
		}
	}

	return false
}

// CalculateExpectedCompletion estimates when an on-cadence batch will close
// based on the batch start time and configured interval
func CalculateExpectedCompletion(batchStartTime time.Time, batchInterval time.Duration) time.Time {
	if batchInterval <= 0 {
		batchInterval = DefaultBatchInterval
	}
	return batchStartTime.Add(batchInterval)
}

// GetPriceTier returns the price tier string for a batch type
func GetPriceTier(batchType database.BatchType) string {
	if batchType == database.BatchTypeOnDemand {
		return OnDemandPricePerProof
	}
	return OnCadencePricePerProof
}

// GetBatchStatusInfo returns comprehensive status information for a batch
func GetBatchStatusInfo(
	batchType database.BatchType,
	status database.BatchStatus,
	startTime time.Time,
	batchInterval time.Duration,
) *BatchStatusInfo {
	info := &BatchStatusInfo{
		Status:          status,
		StatusMessage:   GetStatusMessage(batchType, status),
		IsDelayExpected: IsDelayExpected(batchType, status),
		PriceTier:       GetPriceTier(batchType),
		BatchType:       batchType,
	}

	// Calculate expected completion for pending on-cadence batches
	if batchType == database.BatchTypeOnCadence &&
		(status == database.BatchStatusPending || status == database.BatchStatusWaitingForBatch) {
		expectedCompletion := CalculateExpectedCompletion(startTime, batchInterval)
		info.ExpectedCompletionAt = &expectedCompletion
	}

	return info
}

// IsBatchStalled checks if a batch appears to be stalled beyond expected delays
// For on-cadence: stalled if pending > interval + grace period
// For on-demand: stalled if pending > 2 minutes
func IsBatchStalled(batchType database.BatchType, status database.BatchStatus, age time.Duration, batchInterval time.Duration) bool {
	if batchInterval <= 0 {
		batchInterval = DefaultBatchInterval
	}

	if status == database.BatchStatusFailed {
		return true
	}

	if status == database.BatchStatusPending {
		if batchType == database.BatchTypeOnCadence {
			// On-cadence: stalled if exceeds interval + grace period
			return age > (batchInterval + OnCadenceGracePeriod)
		}
		// On-demand: stalled if exceeds 2 minutes
		return age > 2*time.Minute
	}

	if status == database.BatchStatusAnchoring {
		// Anchoring shouldn't take more than 5 minutes
		return age > 5*time.Minute
	}

	return false
}

// BatchHealthStatus represents the health status of the batch system
type BatchHealthStatus struct {
	OverallStatus        string `json:"overall_status"` // "healthy", "delayed", "stalled", "error"
	OnCadenceStatus      string `json:"on_cadence_status"`
	OnDemandStatus       string `json:"on_demand_status"`
	OnCadencePending     bool   `json:"on_cadence_pending"`
	OnDemandPending      bool   `json:"on_demand_pending"`
	OnCadenceDelayNormal bool   `json:"on_cadence_delay_normal"`
	StatusMessage        string `json:"status_message"`
}

// GetBatchSystemHealth returns the overall health status of the batch system
func GetBatchSystemHealth(
	onCadenceInfo *BatchInfo,
	onDemandInfo *BatchInfo,
	batchInterval time.Duration,
) *BatchHealthStatus {
	health := &BatchHealthStatus{
		OverallStatus:        "healthy",
		OnCadenceStatus:      "idle",
		OnDemandStatus:       "idle",
		OnCadencePending:     false,
		OnDemandPending:      false,
		OnCadenceDelayNormal: true,
		StatusMessage:        "Batch system operational. No pending batches.",
	}

	if batchInterval <= 0 {
		batchInterval = DefaultBatchInterval
	}

	// Check on-cadence batch
	if onCadenceInfo != nil && onCadenceInfo.TxCount > 0 {
		health.OnCadencePending = true
		health.OnCadenceStatus = "pending"

		if IsBatchStalled(database.BatchTypeOnCadence, database.BatchStatusPending, onCadenceInfo.Age, batchInterval) {
			health.OnCadenceStatus = "stalled"
			health.OnCadenceDelayNormal = false
			health.OverallStatus = "degraded"
		} else if onCadenceInfo.Age > batchInterval {
			health.OnCadenceStatus = "closing"
			health.OnCadenceDelayNormal = true
		} else {
			// Within normal window
			health.OnCadenceDelayNormal = true
		}
	}

	// Check on-demand batch
	if onDemandInfo != nil && onDemandInfo.TxCount > 0 {
		health.OnDemandPending = true
		health.OnDemandStatus = "pending"

		if IsBatchStalled(database.BatchTypeOnDemand, database.BatchStatusPending, onDemandInfo.Age, batchInterval) {
			health.OnDemandStatus = "stalled"
			health.OverallStatus = "degraded"
		}
	}

	// Update status message
	if health.OnCadencePending && health.OnCadenceDelayNormal {
		remaining := batchInterval - onCadenceInfo.Age
		if remaining > 0 {
			health.StatusMessage = "On-cadence batch collecting transactions. This is normal operation. " +
				"Delays up to 15 minutes are expected for cost-efficient batching."
		} else {
			health.StatusMessage = "On-cadence batch closing. Anchor transaction will be submitted shortly."
		}
	} else if health.OnDemandPending {
		health.StatusMessage = "On-demand batch processing. Anchor will be submitted shortly."
	}

	if health.OverallStatus == "degraded" {
		health.StatusMessage = "One or more batches may be stalled. Investigation recommended."
	}

	return health
}
