package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// AnchorQuorumBackfillOptions controls one run.
type AnchorQuorumBackfillOptions struct {
	// DryRun examines and verifies every candidate and writes nothing. The default in the CLI: a
	// backfill that has not been read before it runs is a migration nobody reviewed.
	DryRun bool
	// Limit stops after this many candidates (0 = all).
	Limit int
	// Pause between candidates, to spare shared RPC endpoints.
	Pause time.Duration
	Logf  func(string, ...interface{})
}

// AnchorQuorumBackfillReport is what a run established.
type AnchorQuorumBackfillReport struct {
	Candidates       int
	AlreadyCanonical int
	Written          int
	WouldWrite       int
	Rejected         int
	Errors           int
	Conflicts        int
	// Refusals lists each rejection, so a dry run is a readable audit rather than a count.
	Refusals []string
}

// anchorQuorumStore is the database surface a backfill needs.
type anchorQuorumStore interface {
	GetAnchorQuorum(ctx context.Context, chainID int64, bundleID string) (*database.AnchorQuorumRow, error)
	RecordAnchorQuorum(ctx context.Context, rec *database.AnchorQuorumRecord) (bool, error)
}

// RunAnchorQuorumBackfill reconstructs canonical rows for the given verify transactions.
//
// Ordering matters: a candidate is verified against the chain BEFORE the database is consulted for a
// write, and a bundle that already has a canonical row is left exactly as it is. Live evidence beats
// reconstructed evidence — a live row carries the member list and the aggregate, which a backfill cannot
// recover — so a backfill never overwrites, never "completes" and never conflicts its way into one.
func RunAnchorQuorumBackfill(
	ctx context.Context,
	chain BackfillChain,
	store anchorQuorumStore,
	candidates []BackfillCandidate,
	opts AnchorQuorumBackfillOptions,
) (*AnchorQuorumBackfillReport, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	rep := &AnchorQuorumBackfillReport{}

	for i, cand := range candidates {
		if opts.Limit > 0 && i >= opts.Limit {
			break
		}
		if err := ctx.Err(); err != nil {
			logf("[BACKFILL] interrupted after %d candidate(s)", i)
			return rep, nil
		}
		if i > 0 && opts.Pause > 0 {
			select {
			case <-ctx.Done():
				return rep, nil
			case <-time.After(opts.Pause):
			}
		}
		rep.Candidates++

		out := ReconstructAnchorQuorum(ctx, chain, cand, DecodeExecuteComprehensiveProof)
		switch {
		case out.Err != nil:
			rep.Errors++
			logf("[BACKFILL] chain=%d tx=%s could not be examined: %v", cand.ChainID, cand.TxHash, out.Err)
			continue
		case out.Rejected != "":
			rep.Rejected++
			refusal := fmt.Sprintf("chain=%d tx=%s REFUSED: %s", cand.ChainID, cand.TxHash, out.Rejected)
			rep.Refusals = append(rep.Refusals, refusal)
			logf("[BACKFILL] %s", refusal)
			continue
		}

		rec := out.Record
		existing, err := store.GetAnchorQuorum(ctx, rec.ChainID, rec.BundleID)
		if err != nil {
			rep.Errors++
			logf("[BACKFILL] reading existing row for %s: %v", rec.BundleID, err)
			continue
		}
		if existing != nil {
			rep.AlreadyCanonical++
			logf("[BACKFILL] chain=%d bundle=%s already canonical (evidence_source=%s, %d member(s)); left alone",
				rec.ChainID, rec.BundleID, existing.EvidenceSource, existing.MemberCount)
			continue
		}

		if opts.DryRun {
			rep.WouldWrite++
			logf("[BACKFILL] WOULD WRITE chain=%d bundle=%s root=0x%x verify=%s@%d signers=%d power=%s/%s",
				rec.ChainID, rec.BundleID, rec.Root[:8], rec.VerifyTx, rec.VerifyBlock,
				len(rec.Signers), rec.SignedVotingPower, rec.TotalVotingPower)
			continue
		}

		written, err := store.RecordAnchorQuorum(ctx, rec)
		var conflict *database.AnchorQuorumConflict
		switch {
		case errors.As(err, &conflict):
			// Another row for this anchor disagrees. Never resolved by overwriting: see RecordAnchorQuorum.
			rep.Conflicts++
			logf("[BACKFILL] CONFLICT %v", conflict)
		case err != nil:
			rep.Errors++
			logf("[BACKFILL] writing %s: %v", rec.BundleID, err)
		case written:
			rep.Written++
			logf("[BACKFILL] wrote chain=%d bundle=%s from verify tx %s", rec.ChainID, rec.BundleID, rec.VerifyTx)
		default:
			rep.AlreadyCanonical++
		}
	}
	return rep, nil
}
