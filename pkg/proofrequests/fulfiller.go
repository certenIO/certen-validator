// Copyright 2025 Certen Protocol
//
// Package proofrequests fulfils proof requests: the API records a request as pending, and this worker
// moves it through to a proof.
//
//	pending    -> processing   claimed by one validator (MarkProcessing only succeeds from pending)
//	processing -> batched      its transaction was placed in an anchor batch
//	processing -> completed    a proof artifact for its transaction exists
//	           -> failed       no proof within the request's deadline
//	failed     -> pending      retried, up to MaxRetries attempts
//
// Every validator runs the worker against the shared database. Claims and terminal transitions are
// conditional updates, so exactly one validator completes or fails a request, and only that validator
// calls the request's callback.
package proofrequests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// Config tunes the fulfiller.
type Config struct {
	Interval         time.Duration // how often to look for work (default 15s)
	OnDemandDeadline time.Duration // how long an on-demand request waits for its proof (default 30m)
	CadenceDeadline  time.Duration // how long an on-cadence request waits (default 24h)
	MaxRetries       int           // attempts before a failed request stays failed (default 3)
	BatchSize        int           // requests retried and claimed per pass, and read per page when settling (default 100)
	ValidatorID      string
	HTTPClient       *http.Client // for callbacks (default: 10s timeout)
	Logger           *log.Logger
	Now              func() time.Time // for tests
}

// Fulfiller drives proof requests to completion.
type Fulfiller struct {
	requests  *database.RequestRepository
	artifacts *database.ProofArtifactRepository
	batches   *database.BatchRepository
	cfg       Config

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// New creates a fulfiller over the shared repositories.
func New(repos *database.Repositories, cfg Config) (*Fulfiller, error) {
	if repos == nil || repos.Requests == nil || repos.ProofArtifacts == nil {
		return nil, errors.New("proof request fulfiller needs the request and proof artifact repositories")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.OnDemandDeadline <= 0 {
		cfg.OnDemandDeadline = 30 * time.Minute
	}
	if cfg.CadenceDeadline <= 0 {
		cfg.CadenceDeadline = 24 * time.Hour
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[ProofRequests] ", log.LstdFlags)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Fulfiller{requests: repos.Requests, artifacts: repos.ProofArtifacts, batches: repos.Batches, cfg: cfg}, nil
}

// Start runs the fulfiller until Stop or ctx is done.
func (f *Fulfiller) Start(ctx context.Context) {
	f.mu.Lock()
	if f.running {
		f.mu.Unlock()
		return
	}
	f.running = true
	f.stopCh = make(chan struct{})
	f.doneCh = make(chan struct{})
	f.mu.Unlock()

	go func() {
		defer close(f.doneCh)
		ticker := time.NewTicker(f.cfg.Interval)
		defer ticker.Stop()
		for {
			f.RunOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-f.stopCh:
				return
			case <-ticker.C:
			}
		}
	}()
	f.cfg.Logger.Printf("started (every %s; on-demand deadline %s, on-cadence %s, %d attempts)",
		f.cfg.Interval, f.cfg.OnDemandDeadline, f.cfg.CadenceDeadline, f.cfg.MaxRetries)
}

// Stop halts the fulfiller and waits for the current pass to finish.
func (f *Fulfiller) Stop() {
	f.mu.Lock()
	if !f.running {
		f.mu.Unlock()
		return
	}
	f.running = false
	close(f.stopCh)
	f.mu.Unlock()
	<-f.doneCh
}

// PassResult counts what one pass did, for logs and tests.
type PassResult struct {
	Retried, Claimed, Batched, Completed, Failed int
}

// RunOnce performs one pass: re-queue retryable failures, claim pending requests, then settle every
// claimed request that now has a proof or has run out of time.
func (f *Fulfiller) RunOnce(ctx context.Context) PassResult {
	var result PassResult

	retryable, err := f.requests.GetFailedRequestsForRetry(ctx, f.cfg.MaxRetries, f.cfg.BatchSize)
	if err != nil {
		f.cfg.Logger.Printf("list retryable requests: %v", err)
	}
	for _, request := range retryable {
		if err := f.requests.ResetToRetry(ctx, request.RequestID); err == nil {
			result.Retried++
		}
	}

	pending, err := f.requests.GetPendingRequests(ctx, f.cfg.BatchSize)
	if err != nil {
		f.cfg.Logger.Printf("list pending requests: %v", err)
	}
	for _, request := range pending {
		if err := f.requests.MarkProcessingAt(ctx, request.RequestID, f.cfg.Now()); err == nil {
			result.Claimed++
		} else if !errors.Is(err, database.ErrRequestNotFound) {
			f.cfg.Logger.Printf("claim request %s: %v", request.RequestID, err)
		}
	}

	// Every validator settles claimed requests, so one that stops mid-request does not strand it. Most
	// in-flight requests are still waiting and stay in flight, so the pass pages through all of them;
	// taking only the first page would leave every request behind it unsettled until the ones in front
	// time out.
	var after *database.ProofRequest
	for ctx.Err() == nil {
		inFlight, err := f.requests.GetProcessingRequestsAfter(ctx, after, f.cfg.BatchSize)
		if err != nil {
			f.cfg.Logger.Printf("list processing requests: %v", err)
			break
		}
		for _, request := range inFlight {
			switch f.settle(ctx, request) {
			case outcomeBatched:
				result.Batched++
			case outcomeCompleted:
				result.Completed++
			case outcomeFailed:
				result.Failed++
			}
		}
		if len(inFlight) < f.cfg.BatchSize {
			break
		}
		after = inFlight[len(inFlight)-1]
	}
	if result != (PassResult{}) {
		f.cfg.Logger.Printf("pass: %+v", result)
	}
	return result
}

type outcome int

const (
	outcomeWaiting outcome = iota
	outcomeBatched
	outcomeCompleted
	outcomeFailed
)

func (f *Fulfiller) settle(ctx context.Context, request *database.ProofRequest) outcome {
	proofID, err := f.findProof(ctx, request)
	if err != nil {
		f.cfg.Logger.Printf("look up proof for request %s: %v", request.RequestID, err)
		return outcomeWaiting
	}
	if proofID != uuid.Nil {
		if err := f.requests.MarkCompleted(ctx, request.RequestID, proofID); err != nil {
			// Another validator settled it first.
			return outcomeWaiting
		}
		f.notify(ctx, request, database.RequestStatusCompleted, proofID, "")
		return outcomeCompleted
	}

	// Each attempt gets its own window, measured from when it was claimed; a retried request is not
	// failed again at once for the time its earlier attempts took.
	started := request.RequestedAt
	if request.ProcessedAt.Valid {
		started = request.ProcessedAt.Time
	}
	if f.cfg.Now().Sub(started) > f.deadline(request) {
		reason := fmt.Sprintf("no proof within %s of the attempt starting", f.deadline(request))
		if err := f.requests.MarkFailed(ctx, request.RequestID, reason); err != nil {
			return outcomeWaiting
		}
		f.notify(ctx, request, database.RequestStatusFailed, uuid.Nil, reason)
		return outcomeFailed
	}

	if request.Status != database.RequestStatusBatched && request.AccumTxHash.Valid && f.batches != nil {
		tx, err := f.batches.GetTransactionByAccumHash(ctx, request.AccumTxHash.String)
		if err == nil && tx != nil {
			if err := f.requests.MarkBatched(ctx, request.RequestID, tx.BatchID); err == nil {
				return outcomeBatched
			}
		}
	}
	return outcomeWaiting
}

func (f *Fulfiller) deadline(request *database.ProofRequest) time.Duration {
	if request.RequestType == database.RequestTypeOnCadence {
		return f.cfg.CadenceDeadline
	}
	return f.cfg.OnDemandDeadline
}

// findProof returns the proof that answers a request: the artifact for its transaction, or for an
// account-only request the newest artifact for that account created after the request was made.
// Requests carry whatever the client sent, usually the transaction ID (acc://<hash>@<principal>); the
// repositories look transactions up by database.TransactionHashKey, so every form finds the artifact.
func (f *Fulfiller) findProof(ctx context.Context, request *database.ProofRequest) (uuid.UUID, error) {
	if request.AccumTxHash.Valid && request.AccumTxHash.String != "" {
		artifact, err := f.artifacts.GetProofByTxHash(ctx, request.AccumTxHash.String)
		if err != nil || artifact == nil {
			return uuid.Nil, err
		}
		return artifact.ProofID, nil
	}
	if request.AccountURL.Valid && request.AccountURL.String != "" {
		proofs, err := f.artifacts.GetProofsByAccount(ctx, request.AccountURL.String, 1, 0)
		if err != nil || len(proofs) == 0 {
			return uuid.Nil, err
		}
		if !proofs[0].CreatedAt.Before(request.RequestedAt) {
			return proofs[0].ProofID, nil
		}
	}
	return uuid.Nil, nil
}

// CallbackPayload is POSTed to a request's callback URL when it completes or fails.
type CallbackPayload struct {
	RequestID   uuid.UUID `json:"request_id"`
	Status      string    `json:"status"`
	ProofID     string    `json:"proof_id,omitempty"`
	Error       string    `json:"error,omitempty"`
	AccumTxHash string    `json:"accum_tx_hash,omitempty"`
	AccountURL  string    `json:"account_url,omitempty"`
	SettledBy   string    `json:"settled_by,omitempty"`
	SettledAt   time.Time `json:"settled_at"`
}

// notify POSTs the outcome to the request's callback URL. Only http(s) URLs are called; a failed
// callback is logged and not retried, because the request's state is already recorded and queryable.
func (f *Fulfiller) notify(ctx context.Context, request *database.ProofRequest, status database.RequestStatus, proofID uuid.UUID, reason string) {
	if !request.CallbackURL.Valid || request.CallbackURL.String == "" {
		return
	}
	target, err := url.Parse(request.CallbackURL.String)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" {
		f.cfg.Logger.Printf("request %s: callback URL %q is not an http(s) URL; not called", request.RequestID, request.CallbackURL.String)
		return
	}
	payload := CallbackPayload{
		RequestID: request.RequestID, Status: string(status), Error: reason,
		AccumTxHash: request.AccumTxHash.String, AccountURL: request.AccountURL.String,
		SettledBy: f.cfg.ValidatorID, SettledAt: f.cfg.Now().UTC(),
	}
	if proofID != uuid.Nil {
		payload.ProofID = proofID.String()
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		f.cfg.Logger.Printf("request %s: build callback: %v", request.RequestID, err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	response, err := f.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		f.cfg.Logger.Printf("request %s: callback to %s failed: %v", request.RequestID, target.Host, err)
		return
	}
	response.Body.Close()
	if response.StatusCode >= 300 {
		f.cfg.Logger.Printf("request %s: callback to %s answered %d", request.RequestID, target.Host, response.StatusCode)
		return
	}
	f.cfg.Logger.Printf("request %s: %s, callback delivered to %s", request.RequestID, strings.ToLower(string(status)), target.Host)
}
