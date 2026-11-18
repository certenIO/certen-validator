// Copyright 2025 Certen Protocol
//
// Repair of anchor references written without their anchor block's hash and time (AGT-F11, since 2026-09-27).
// Each row's anchor transaction is read back from its chain; the receipt's block must be the stored block (a mismatch
// is refused by name and left untouched), and only then are the block hash and the header time recorded, where empty.
// Idempotent. Without Apply nothing is written and only counts are reported.

package execution

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// AnchorBlockFieldsStore is the part of the proof-artifact repository the repair needs.
type AnchorBlockFieldsStore interface {
	ListAnchorReferencesMissingBlock(ctx context.Context, since time.Time) ([]database.AnchorReferenceBlockRow, error)
	FillAnchorReferenceBlock(ctx context.Context, row database.AnchorReferenceBlockRow, blockHash string, blockTime time.Time) (bool, error)
}

// AnchorBlockFieldsSince is where the defect starts: the first anchor reference written without its block hash.
var AnchorBlockFieldsSince = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

// AnchorBlockFieldsReport is counts only (no hashes, no ids beyond the refused rows' proof ids).
type AnchorBlockFieldsReport struct {
	Rows       int      `json:"rows"`
	Filled     int      `json:"filled"`
	WouldFill  int      `json:"would_fill"`
	Unchanged  int      `json:"unchanged"`
	Refused    int      `json:"refused"`
	Unreadable int      `json:"unreadable"`
	RefusedIDs []string `json:"refused_proof_ids,omitempty"`
}

// RepairAnchorBlockFields fills anchor_block_hash and anchor_timestamp from chain reads of each row's anchor transaction.
func RepairAnchorBlockFields(ctx context.Context, store AnchorBlockFieldsStore, reader AnchorTxReader, since time.Time,
	apply bool, logf func(string, ...interface{})) (*AnchorBlockFieldsReport, error) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	rows, err := store.ListAnchorReferencesMissingBlock(ctx, since)
	if err != nil {
		return nil, err
	}
	rep := &AnchorBlockFieldsReport{Rows: len(rows)}
	for _, row := range rows {
		chainID, perr := strconv.ParseInt(strings.TrimSpace(row.ChainID), 10, 64)
		if perr != nil || !IsTransactionHash(row.AnchorTxHash) || row.AnchorBlockNumber <= 0 {
			rep.Unreadable++
			logf("anchor-block-fields: proof %s: %s{chain=%q,block=%d}: not a readable anchor", row.ProofID, AnchorBlockUnread, row.ChainID, row.AnchorBlockNumber)
			continue
		}
		reading, rerr := reader.ReadAnchorTx(ctx, chainID, row.AnchorTxHash)
		if rerr != nil || reading == nil || !reading.Found || !reading.Succeeded || reading.BlockNumber == 0 ||
			!IsTransactionHash(reading.BlockHash) || reading.BlockTime == 0 {
			rep.Unreadable++
			logf("anchor-block-fields: proof %s: %s: anchor not read back (%v)", row.ProofID, AnchorBlockUnread, rerr)
			continue
		}
		if reading.BlockNumber != uint64(row.AnchorBlockNumber) {
			rep.Refused++
			rep.RefusedIDs = append(rep.RefusedIDs, row.ProofID.String())
			logf("anchor-block-fields: proof %s: %s{recorded=%d,receipt=%d}: left unchanged", row.ProofID, ErrAnchorBlockMismatch,
				row.AnchorBlockNumber, reading.BlockNumber)
			continue
		}
		if !apply {
			rep.WouldFill++
			continue
		}
		changed, ferr := store.FillAnchorReferenceBlock(ctx, row, reading.BlockHash, time.Unix(int64(reading.BlockTime), 0).UTC())
		if ferr != nil {
			return rep, fmt.Errorf("proof %s: %w", row.ProofID, ferr)
		}
		if changed {
			rep.Filled++
		} else {
			rep.Unchanged++
		}
	}
	return rep, nil
}

// UnreadAnchorStore is what the completer needs: layer-5 rows left in state anchor_block_unread, and the write of
// their anchor reference once the block is read.
type UnreadAnchorStore interface {
	ListUnreadAnchorLayers(ctx context.Context, layerName, state string, since time.Time, limit int) ([]database.UnreadAnchorLayer, error)
	CompleteAnchorReference(ctx context.Context, u database.UnreadAnchorLayer, targetChain string, blockNumber int64, blockHash string, blockTime time.Time) (bool, error)
}

// UnreadAnchorReport counts one completion pass.
type UnreadAnchorReport struct {
	Rows          int      `json:"rows"`
	Completed     int      `json:"completed"`
	WouldComplete int      `json:"would_complete"`
	StillUnread   int      `json:"still_unread"`
	Refused       int      `json:"refused"`
	RefusedIDs    []string `json:"refused_proof_ids,omitempty"`
}

// CompleteUnreadAnchors reads the anchor block of each layer 5 left in state anchor_block_unread and, when its receipt
// is readable, writes the proof's anchor reference with the block hash and time. A receipt in another block than the
// layer states is refused by name (anchor_block_mismatch) and nothing is written. The layer row (evidence) is never
// rewritten. Idempotent: a proof with a reference is not listed again.
func CompleteUnreadAnchors(ctx context.Context, store UnreadAnchorStore, reader AnchorTxReader, since time.Time, limit int,
	apply bool, logf func(string, ...interface{})) (*UnreadAnchorReport, error) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	rows, err := store.ListUnreadAnchorLayers(ctx, Layer5RowName, AnchorBlockUnread, since, limit)
	if err != nil {
		return nil, err
	}
	rep := &UnreadAnchorReport{Rows: len(rows)}
	for _, u := range rows {
		if u.ChainID == 0 || !IsTransactionHash(u.AnchorTxHash) {
			rep.StillUnread++
			continue
		}
		reading, rerr := reader.ReadAnchorTx(ctx, u.ChainID, u.AnchorTxHash)
		if rerr != nil || reading == nil || !reading.Found || !reading.Succeeded || reading.BlockNumber == 0 ||
			!IsTransactionHash(reading.BlockHash) || reading.BlockTime == 0 {
			rep.StillUnread++
			logf("anchor-completer: proof %s: still %s (%v)", u.ProofID, AnchorBlockUnread, rerr)
			continue
		}
		if u.AnchorBlockNumber > 0 && reading.BlockNumber != uint64(u.AnchorBlockNumber) {
			rep.Refused++
			rep.RefusedIDs = append(rep.RefusedIDs, u.ProofID.String())
			logf("anchor-completer: proof %s: %s{layer=%d,receipt=%d}: no anchor reference", u.ProofID, ErrAnchorBlockMismatch,
				u.AnchorBlockNumber, reading.BlockNumber)
			continue
		}
		if !apply {
			rep.WouldComplete++
			continue
		}
		done, cerr := store.CompleteAnchorReference(ctx, u, "evm", int64(reading.BlockNumber), reading.BlockHash,
			time.Unix(int64(reading.BlockTime), 0).UTC())
		if cerr != nil {
			return rep, fmt.Errorf("proof %s: %w", u.ProofID, cerr)
		}
		if done {
			rep.Completed++
		}
	}
	return rep, nil
}

// RunAnchorBlockCompleter completes unread anchors on a bounded schedule: every interval, at most limit rows created in
// the last window. It returns when ctx ends.
func RunAnchorBlockCompleter(ctx context.Context, store UnreadAnchorStore, reader AnchorTxReader, interval, window time.Duration,
	limit int, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			passCtx, cancel := context.WithTimeout(ctx, interval/2)
			rep, err := CompleteUnreadAnchors(passCtx, store, reader, time.Now().Add(-window), limit, true, logf)
			cancel()
			if err != nil {
				logf("anchor-completer: pass stopped: %v", err)
			} else if rep.Rows > 0 {
				logf("anchor-completer: %d unread, %d completed, %d still unread, %d refused", rep.Rows, rep.Completed, rep.StillUnread, rep.Refused)
			}
		}
	}
}
