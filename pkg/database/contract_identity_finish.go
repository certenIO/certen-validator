// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/finality"
)

// FinishOutcome names how a finished leg ended. Every outcome but Appended and Duplicate stores nothing, and each is logged by name.
type FinishOutcome string

const (
	FinishAppended      FinishOutcome = "appended"        // a new row of proof_contract_identity
	FinishDuplicate     FinishOutcome = "duplicate"       // the same container is already the greatest seq
	FinishBetterPresent FinishOutcome = "better_present"  // a Stated container while a captured one is stored
	FinishRefused       FinishOutcome = "refused"         // the real Verify refused the container at level included: nothing stored
	FinishNoProof       FinishOutcome = "no_proof"        // no proof_artifacts row carries the settlement transaction within the wait
	FinishAmbiguous     FinishOutcome = "ambiguous_proof" // more than one proof carries it: nothing stored (OQ-S8-12)
	FinishChainMismatch FinishOutcome = "chain_mismatch"  // the proof's leg is on another chain than the capture
	FinishContextFailed FinishOutcome = "context_failed"  // the stored rows could not be composed within the wait
	FinishAbandoned     FinishOutcome = "abandoned"       // the validator is stopping, or too many legs are waiting
)

// Defaults of the wait for the proof row: the settlement is captured at first observation, and the proof row and its bundle are written by the
// proof builder some time later.
const (
	DefaultFinishWait    = 15 * time.Minute
	DefaultFinishPoll    = 15 * time.Second
	DefaultFinishPending = 64
)

// IdentityFinisher is the production path from the capture runtime to proof_contract_identity (WP-S8-7): for each finished leg it finds the
// proof the leg belongs to, composes the LegContext from the stored rows, assembles the container's parts, and appends through the
// repository's Appender, whose verifier is the REAL composed one. It never blocks the runtime (OnLeg returns at once), never writes
// anything but the repository's Append, and holds no secret.
type IdentityFinisher struct {
	ctx     context.Context
	client  *Client
	store   capture.Store
	man     *ci.Manifest
	repo    *ContractIdentityRepository
	src     *ContractIdentitySource
	logf    func(string, ...any)
	wait    time.Duration
	poll    time.Duration
	pending chan struct{}
	wg      sync.WaitGroup
}

// NewIdentityFinisher builds the finisher. The pins are the embedded S7 pins the composed S7 report is judged under.
func NewIdentityFinisher(ctx context.Context, client *Client, store capture.Store, m *ci.Manifest, logf func(string, ...any)) (*IdentityFinisher, error) {
	switch {
	case client == nil:
		return nil, errors.New("contract identity finisher: no database client")
	case store == nil:
		return nil, errors.New("contract identity finisher: no capture store")
	case m == nil:
		return nil, errors.New("contract identity finisher: no manifest")
	}
	pins, err := finality.EmbeddedPins()
	if err != nil {
		return nil, fmt.Errorf("contract identity finisher: the embedded pins: %w", err)
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &IdentityFinisher{ctx: ctx, client: client, store: store, man: m, repo: NewContractIdentityRepository(client),
		src: NewContractIdentitySource(client, NewFinalityAddendaRepository(client), pins), logf: logf,
		wait: DefaultFinishWait, poll: DefaultFinishPoll, pending: make(chan struct{}, DefaultFinishPending)}, nil
}

// WithTiming sets the wait for the proof row and the poll interval (tests lower them).
func (f *IdentityFinisher) WithTiming(wait, poll time.Duration) *IdentityFinisher {
	f.wait, f.poll = wait, poll
	return f
}

// OnLeg is capture.Deps.OnLeg: it returns at once. A leg beyond the pending bound is abandoned by name (logged), never queued without bound.
func (f *IdentityFinisher) OnLeg(l capture.CapturedLeg) {
	select {
	case f.pending <- struct{}{}:
	default:
		f.logf("⚠️ [CONTRACT-IDENTITY] chain %d leg %s: %s (more than %d legs are waiting for their proof row)", l.Chain, l.Tx.Hex(), FinishAbandoned, DefaultFinishPending)
		return
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer func() { <-f.pending }()
		defer func() {
			if r := recover(); r != nil {
				f.logf("⚠️ [CONTRACT-IDENTITY] chain %d leg %s: the finisher panicked: %v", l.Chain, l.Tx.Hex(), r)
			}
		}()
		out, err := f.Finish(f.ctx, l)
		if err != nil {
			f.logf("⚠️ [CONTRACT-IDENTITY] chain %d leg %s: %s: %v", l.Chain, l.Tx.Hex(), out, err)
			return
		}
		f.logf("[CONTRACT-IDENTITY] chain %d leg %s: %s", l.Chain, l.Tx.Hex(), out)
	}()
}

// Wait blocks until every leg handed to OnLeg has ended (tests, shutdown).
func (f *IdentityFinisher) Wait() { f.wg.Wait() }

// proofFor maps a settlement transaction to its proof: proof_artifacts.settlement_tx_hash is "0x" + 64 lowercase hex on every live row (575 of
// 575), a transaction hash is global, and the capture's chain is checked against the composed leg afterwards. Exactly one proof qualifies; two
// or more is ambiguous (11 live settlement hashes are shared by several proofs) and stores nothing.
func (f *IdentityFinisher) proofFor(ctx context.Context, l capture.CapturedLeg) (string, int, error) {
	rows, err := f.client.DB().QueryContext(ctx, `SELECT proof_id::text FROM proof_artifacts WHERE lower(settlement_tx_hash) = $1 ORDER BY created_at, proof_id LIMIT 2`, "0x"+hex.EncodeToString(l.Tx[:]))
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	if len(ids) == 1 {
		return ids[0], 1, nil
	}
	return "", len(ids), nil
}

func (f *IdentityFinisher) sleep(ctx context.Context) bool {
	t := time.NewTimer(f.poll)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Finish runs one leg to its outcome (synchronously; OnLeg runs it on its own goroutine). A returned error accompanies an outcome that
// stored nothing for a reason that is not a verdict (a store failure, the last composition error).
func (f *IdentityFinisher) Finish(ctx context.Context, l capture.CapturedLeg) (FinishOutcome, error) {
	deadline := time.Now().Add(f.wait)
	var proofID string
	var lc ci.LegContext
	var lastErr error
	for {
		id, n, err := f.proofFor(ctx, l)
		switch {
		case err != nil:
			lastErr = err
		case n > 1:
			return FinishAmbiguous, fmt.Errorf("%d proofs carry the settlement transaction", n)
		case n == 1:
			lc, err = f.src.ComposeContractIdentity(ctx, id)
			if err == nil {
				proofID = id
			} else {
				lastErr = err // the bundle is written right after the proof row: wait for it
			}
		}
		if proofID != "" {
			break
		}
		if !time.Now().Before(deadline) || !f.sleep(ctx) {
			if lastErr != nil {
				return FinishContextFailed, lastErr
			}
			return FinishNoProof, nil
		}
	}
	if lc.Chain != l.Chain {
		return FinishChainMismatch, fmt.Errorf("the proof's leg is on chain %d, the capture on chain %d", lc.Chain, l.Chain)
	}
	parts, err := capture.AssembleParts(ctx, f.store, f.man, l)
	if err != nil {
		return FinishContextFailed, err
	}
	ap, err := f.repo.Appender(proofID, f.man)
	if err != nil {
		return FinishContextFailed, err
	}
	before, had, err := f.repo.Latest(ctx, proofID)
	if err != nil {
		return FinishContextFailed, err
	}
	res, err := ap.Append(ctx, lc, parts)
	var refused *capture.RefusedError
	switch {
	case errors.As(err, &refused):
		code := ""
		if refused.Report.Headline.First != nil {
			code = refused.Report.Headline.First.Code
		}
		return FinishRefused, fmt.Errorf("the real Verify refused the container (%s)", code)
	case errors.Is(err, ErrContractIdentityBetterPresent):
		return FinishBetterPresent, nil
	case err != nil:
		return FinishContextFailed, err
	}
	after, _, err := f.repo.Latest(ctx, proofID)
	if err != nil {
		return FinishContextFailed, err
	}
	if had && after.Seq == before.Seq && after.Digest == res.Digest {
		return FinishDuplicate, nil
	}
	return FinishAppended, nil
}
