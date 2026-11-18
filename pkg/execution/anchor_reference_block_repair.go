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
