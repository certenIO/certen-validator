// Copyright 2026 Certen Protocol

package consensus

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmthttp "github.com/cometbft/cometbft/rpc/client/http"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// Restating the consensus records written before RB3-F138 from the commit that committed their height.
// `validator repair consensus-records` runs this against the node's own block store.

// commitReader reads a height's commit and its block time from a block store.
type commitReader interface {
	CommitQuorum(ctx context.Context, height int64) (*commitQuorum, error)
	BlockTime(ctx context.Context, height int64) (time.Time, error)
	// BatchIDsAt are the consensus batch ids of the validator blocks the block at a height accepted.
	BatchIDsAt(ctx context.Context, height int64) (map[uuid.UUID]bool, error)
}

// BatchIDsAt implements commitReader: the batch id each accepted validator block's entry is written under.
func (s *rpcCommittedBlockSource) BatchIDsAt(ctx context.Context, height int64) (map[uuid.UUID]bool, error) {
	blk, err := s.CommittedValidatorBlocks(ctx, height)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]bool{}
	for _, vb := range blk.blocks {
		out[consensusBatchID(vb.BundleID)] = true
	}
	return out, nil
}

// BlockTime is the committed block's header time.
func (s *rpcCommittedBlockSource) BlockTime(ctx context.Context, height int64) (time.Time, error) {
	h := height
	blk, err := s.reader.Block(ctx, &h)
	if err != nil {
		return time.Time{}, classifyBlockStoreError(height, err)
	}
	if blk == nil || blk.Block == nil || blk.Block.Header.Height != height || blk.Block.Header.Time.IsZero() {
		return time.Time{}, fmt.Errorf("height %d: the block store returned no block of that height", height)
	}
	return blk.Block.Header.Time, nil
}

// ConsensusRecordsRepairReport says what a run found and did (or, without Apply, would do).
type ConsensusRecordsRepairReport struct {
	Entries               int      `json:"entries"`
	Corrected             int      `json:"corrected_from_commit"`
	EarlierIncarnation    int      `json:"restated_as_earlier_incarnation"`
	AttestationsWithdrawn int64    `json:"attestations_withdrawn"`
	Unavailable           []string `json:"heights_not_in_block_store"`
	Refused               []string `json:"refused"`
	Changed               []string `json:"changed_underneath"`
}

// RepairConsensusRecords restates every stale consensus entry from its height's commit. A height the block
// store no longer holds is reported, never guessed.
func RepairConsensusRecords(ctx context.Context, repair *database.EvidenceRepair, commits commitReader, by string, apply bool) (*ConsensusRecordsRepairReport, error) {
	if repair == nil || commits == nil || by == "" {
		return nil, errors.New("consensus records repair needs the repository, a block store and the validator id")
	}
	entries, err := repair.ListStaleConsensusEntries(ctx)
	if err != nil {
		return nil, err
	}
	report := &ConsensusRecordsRepairReport{Entries: len(entries), Unavailable: []string{}, Refused: []string{}, Changed: []string{}}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		label := fmt.Sprintf("entry %s (height %d)", e.EntryID, e.Height)
		if e.Height <= 0 {
			report.Refused = append(report.Refused, label+": the entry names no height")
			continue
		}
		// The block at this height must be the entry's: the chain has restarted, and an earlier incarnation's
		// height is a different block now. Its commit is not this entry's.
		batches, err := commits.BatchIDsAt(ctx, e.Height)
		if err == nil && !batches[e.BatchID] {
			facts := database.EarlierIncarnationFacts{Height: e.Height, BlockTime: e.StartTime, BundlesAtThat: len(batches),
				Basis:  fmt.Sprintf("the block at height %d in this node's block store holds %d other validator block(s), not this entry's bundle", e.Height, len(batches)),
				ReadAt: time.Now().UTC().Format(time.RFC3339Nano)}
			if !apply {
				report.EarlierIncarnation++
				continue
			}
			n, cerr := repair.CorrectConsensusEntryFromEarlierIncarnation(ctx, e, facts, by)
			switch {
			case errors.Is(cerr, database.ErrEvidenceChanged):
				report.Changed = append(report.Changed, label)
			case cerr != nil:
				return report, cerr
			default:
				report.EarlierIncarnation++
				report.AttestationsWithdrawn += n
			}
			continue
		}
		var q *commitQuorum
		if err == nil {
			q, err = commits.CommitQuorum(ctx, e.Height)
		}
		if err == nil {
			var t time.Time
			t, err = commits.BlockTime(ctx, e.Height)
			if err == nil {
				facts := database.ConsensusCommitFacts{Height: e.Height, BlockTime: t, Signers: q.Signers, Validators: q.Validators,
					SignedPower: q.SignedPower, TotalPower: q.TotalPower, ReadAt: time.Now().UTC().Format(time.RFC3339Nano)}
				if !apply {
					report.Corrected++
					continue
				}
				n, cerr := repair.CorrectConsensusEntry(ctx, e, facts, by)
				switch {
				case errors.Is(cerr, database.ErrEvidenceChanged):
					report.Changed = append(report.Changed, label)
				case cerr != nil:
					return report, cerr
				default:
					report.Corrected++
					report.AttestationsWithdrawn += n
				}
				continue
			}
		}
		if errors.Is(err, errCommittedBlockUnavailable) {
			report.Unavailable = append(report.Unavailable, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		report.Refused = append(report.Refused, fmt.Sprintf("%s: %v", label, err))
	}
	return report, nil
}

// NewBlockStoreCommitReader reads commits and block times from a CometBFT node's RPC.
func NewBlockStoreCommitReader(rpcAddr string) (commitReader, error) {
	if rpcAddr == "" {
		return nil, errors.New("no CometBFT RPC address")
	}
	client, err := cmthttp.New(rpcAddr, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("connect CometBFT RPC %s: %w", rpcAddr, err)
	}
	return &rpcCommittedBlockSource{reader: client}, nil
}
