// Copyright 2026 Certen Protocol
//
// proofverify — read a governance proof out of PostgreSQL and verify it
// offline, L1 through L4.
//
// This is the operator-facing form of the claim Phase 6 exists to make good
// on. Governance spec §4 requires a governance proof to be verifiable offline;
// until the L4 quorum evidence was persisted, nothing could make that check,
// because the signatures, validator set and signed bytes a verifier needs were
// stored nowhere.
//
// It answers three DIFFERENT questions with three different exit codes,
// because collapsing them is how a weaker claim ends up wearing a stronger
// one's name:
//
//	0  verified      — reassembled from storage and checked by the real
//	                   verifier, with no network access.
//	3  summary-only  — the record carries the CONCLUSIONS of the quorum check
//	                   and not the evidence. Nothing is known to be wrong; it
//	                   simply cannot be re-checked. Every proof written before
//	                   Phase 6 is in this state and cannot be repaired:
//	                   re-querying Accumulate returns today's validator set,
//	                   not the one that signed.
//	1  FAILED        — the evidence is present and does not check out. This is
//	                   the only one of the three that means something is wrong.
//
// Verification performs no network access. The --offline flag does not enable
// that — it installs a dialer that makes any outbound connection a hard error,
// so "offline" is enforced rather than asserted.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

const (
	exitVerified    = 0
	exitFailed      = 1
	exitUsage       = 2
	exitSummaryOnly = 3
)

type refusingDialer struct{}

func (refusingDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("BLOCKED: verification attempted to reach %s/%s; "+
		"an offline proof must not need the network", network, addr)
}

func main() {
	var (
		proofID = flag.String("proof-id", "", "proof_artifacts.proof_id to verify (UUID)")
		dsn     = flag.String("db", os.Getenv("CERTEN_DB"), "PostgreSQL DSN (default $CERTEN_DB)")
		offline = flag.Bool("offline", true, "refuse all outbound network access during verification")
		verbose = flag.Bool("v", false, "print the reassembled proof's layer summary")
		govern  = flag.Bool("governance", false, "also recompute the stored G0/G1/G2 receipts from level_json")
	)
	flag.Parse()

	if *proofID == "" || *dsn == "" {
		fmt.Fprintln(os.Stderr, "usage: proofverify --proof-id <uuid> --db <dsn> [--offline] [--governance] [-v]")
		os.Exit(exitUsage)
	}
	id, err := uuid.Parse(*proofID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proof-id %q is not a UUID: %v\n", *proofID, err)
		os.Exit(exitUsage)
	}

	// Cut the network BEFORE opening the database, so the block cannot be
	// mistaken for "we happened not to call out this time". The database
	// connection is made through lib/pq's own dialer, not http.
	if *offline {
		dead := &http.Transport{DialContext: refusingDialer{}.DialContext, ResponseHeaderTimeout: time.Millisecond}
		http.DefaultTransport = dead
		http.DefaultClient = &http.Client{Transport: dead}
	}

	db, err := sql.Open("postgres", *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(exitFailed)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(exitFailed)
	}

	store := certenproof.NewPostgresProofStorage(db)
	cp, err := certenproof.VerifyStoredProof(ctx, store, id)

	switch {
	case err == nil:
		fmt.Printf("VERIFIED  %s\n", id)
		fmt.Printf("  network:  disabled (offline=%v)\n", *offline)
		fmt.Printf("  L1  leaf %s… in BVN block %d\n", short(cp.Layer1.Leaf), cp.Layer1.BVNMinorBlockIndex)
		fmt.Printf("  L2  BVN stateTreeAnchor %s… at DN block %d\n", short(cp.Layer2.BVNStateTreeAnchor), cp.Layer2.DNMinorBlockIndex)
		fmt.Printf("  L3  DN stateTreeAnchor  %s… at consensus height %d\n", short(cp.Layer3.DNStateTreeAnchor), cp.Layer3.DNConsensusHeight)
		fmt.Printf("  L4  %s quorum: %d/%d distinct signers over %d validators\n",
			cp.Layer4BVN.Partition, len(cp.Layer4BVN.Signatures), cp.Layer4BVN.Threshold, len(cp.Layer4BVN.ValidatorSet))
		fmt.Printf("  L4  %s quorum: %d/%d distinct signers over %d validators\n",
			cp.Layer4DN.Partition, len(cp.Layer4DN.Signatures), cp.Layer4DN.Threshold, len(cp.Layer4DN.ValidatorSet))
		if *verbose {
			fmt.Printf("  L4  %s signedHash %s…\n", cp.Layer4BVN.Partition, short(cp.Layer4BVN.SignedHash))
			fmt.Printf("  L4  %s signedHash %s…\n", cp.Layer4DN.Partition, short(cp.Layer4DN.SignedHash))
		}
		if *govern {
			os.Exit(reportGovernance(ctx, store, id, *verbose))
		}
		os.Exit(exitVerified)

	case errors.Is(err, certenproof.ErrSummaryOnly), errors.Is(err, certenproof.ErrNoStoredProof):
		// Not a failure. The distinction is the whole point of this tool.
		fmt.Printf("SUMMARY-ONLY  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  Nothing about this proof is known to be wrong — its quorum was checked in\n")
		fmt.Printf("  flight and the governance root commits to that conclusion. What is missing is\n")
		fmt.Printf("  the evidence needed to check it again, and it cannot be recovered.\n")
		os.Exit(exitSummaryOnly)

	default:
		fmt.Printf("FAILED  %s\n", id)
		fmt.Printf("  %v\n", err)
		os.Exit(exitFailed)
	}
}

func short(hexStr string) string {
	if len(hexStr) <= 16 {
		return hexStr
	}
	return hexStr[:16]
}

// reportGovernance recomputes every stored governance receipt FROM level_json
// ALONE and returns the exit code for the combined result.
//
// Kept separate from the L1-L4 verdict on purpose. They are different claims
// about different evidence, and a proof can perfectly well have a checkable
// quorum and an uncheckable governance level: the L4 legs were persisted in
// Phase 6 and the receipt paths only from Stage 2, so every proof written
// between those two is exactly that shape. Collapsing them would report the
// weaker of the two under the stronger one's name, which is the failure mode
// this tool exists to prevent.
//
// The same three-way discipline applies: 0 verified, 3 summary-only, 1 failed.
// L1-L4 has already verified by the time this runs, so a governance level with
// no evidence downgrades the RESULT to summary-only rather than failing it —
// nothing is known to be wrong.
func reportGovernance(ctx context.Context, store *certenproof.PostgresProofStorage, id uuid.UUID, verbose bool) int {
	levels, err := certenproof.VerifyStoredGovernanceLevels(ctx, store, id)

	for _, l := range levels {
		switch {
		case l.HasEvidence():
			fmt.Printf("  %-3s RECOMPUTED from level_json: %d merkle step(s), leaf %s… under anchor %s…\n",
				l.Level, len(l.Receipt.Entries), short(l.Receipt.Start), short(l.Receipt.Anchor))
			if verbose && l.HasResult() {
				fmt.Printf("      result stored (%d bytes of canonical G-result)\n", len(l.Result))
			}
		case l.HasResult():
			fmt.Printf("  %-3s result stored but NO receipt path — the conclusion is recorded and cannot be checked\n", l.Level)
		default:
			fmt.Printf("  %-3s verdict flags only — this row does not contain the governance proof\n", l.Level)
		}
	}

	switch {
	case err == nil:
		fmt.Printf("  governance: every stored level recomputes from level_json alone, network disabled\n")
		return exitVerified

	case errors.Is(err, certenproof.ErrGovernanceSummaryOnly),
		errors.Is(err, certenproof.ErrNoStoredGovernanceLevels):
		fmt.Printf("SUMMARY-ONLY (governance)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  L1-L4 verified. Nothing about the governance levels is known to be wrong — the\n")
		fmt.Printf("  proof was generated and checked in flight and the govRoot commits to its\n")
		fmt.Printf("  canonical hash. What is missing is the receipt merkle path needed to check it\n")
		fmt.Printf("  again, and it cannot be recovered: a receipt fetched today is not necessarily\n")
		fmt.Printf("  the one this proof was built on.\n")
		return exitSummaryOnly

	default:
		fmt.Printf("FAILED (governance)  %s\n", id)
		fmt.Printf("  %v\n", err)
		fmt.Printf("  The receipt evidence IS present and does not recompute to its own anchor.\n")
		fmt.Printf("  This is the one outcome that means something is wrong.\n")
		return exitFailed
	}
}
