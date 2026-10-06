// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A proof request carries an end time exactly while it is in an ending status (completed, failed, cancelled): every
// writer that ends one stamps completed_at, every writer that re-opens one clears it (RB7 Task 5 #1). MarkFailed used
// to leave it NULL - all 144 failed requests in production had none - so a failure could not be placed in time.
func TestAProofRequestCarriesAnEndTimeExactlyWhileEnded(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	requests := NewRequestRepository(NewClientFromDB(testDB))
	request, err := requests.CreateRequest(ctx, &NewProofRequest{AccumTxHash: "end-time-" + uuid.NewString(), RequestType: RequestTypeOnDemand})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM proof_requests WHERE request_id = $1`, request.RequestID)
	})
	read := func(step string) *ProofRequest {
		t.Helper()
		got, err := requests.GetRequest(ctx, request.RequestID)
		if err != nil {
			t.Fatalf("%s: GetRequest: %v", step, err)
		}
		return got
	}
	ended := func(step string, want RequestStatus) time.Time {
		t.Helper()
		got := read(step)
		if got.Status != want || !got.CompletedAt.Valid {
			t.Fatalf("%s: request is %s with completed_at %v; an ended request must carry its end time", step, got.Status, got.CompletedAt)
		}
		return got.CompletedAt.Time
	}
	open := func(step string, want RequestStatus) {
		t.Helper()
		got := read(step)
		if got.Status != want || got.CompletedAt.Valid {
			t.Fatalf("%s: request is %s with completed_at %v; a request that has not ended carries no end time", step, got.Status, got.CompletedAt)
		}
	}

	if err := requests.MarkProcessing(ctx, request.RequestID); err != nil {
		t.Fatalf("MarkProcessing: %v", err)
	}
	open("claimed", RequestStatusProcessing)

	if err := requests.MarkFailed(ctx, request.RequestID, "no proof within 10m0s of the attempt starting"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	ended("failed", RequestStatusFailed)

	if err := requests.ResetToRetry(ctx, request.RequestID); err != nil {
		t.Fatalf("ResetToRetry: %v", err)
	}
	open("re-queued", RequestStatusPending)

	if err := requests.UpdateRequestStatus(ctx, request.RequestID, RequestStatusCancelled, "withdrawn"); err != nil {
		t.Fatalf("UpdateRequestStatus cancelled: %v", err)
	}
	cancelledAt := ended("cancelled", RequestStatusCancelled)
	if err := requests.UpdateRequestStatus(ctx, request.RequestID, RequestStatusCancelled, ""); err != nil {
		t.Fatalf("UpdateRequestStatus cancelled again: %v", err)
	}
	if again := ended("cancelled again", RequestStatusCancelled); !again.Equal(cancelledAt) {
		t.Fatalf("writing the same ending status again moved the end time from %s to %s", cancelledAt, again)
	}

	if err := requests.UpdateRequestStatus(ctx, request.RequestID, RequestStatusPending, ""); err != nil {
		t.Fatalf("UpdateRequestStatus pending: %v", err)
	}
	open("re-opened", RequestStatusPending)
	if err := requests.UpdateRequestStatus(ctx, request.RequestID, RequestStatusFailed, "refused"); err != nil {
		t.Fatalf("UpdateRequestStatus failed: %v", err)
	}
	ended("failed by status", RequestStatusFailed)
}
