// anchorquorumverify runs the anchor quorum acceptance gate against a live fleet.
//
// This is §4.E and §4.D of docs/runbooks/anchor-quorum-evidence-and-phase5.md as a command. Those were
// written as a checklist for a person: settle an intent, then hand-check eight things across a database,
// a chain and a UI. A checklist executed by hand is checked once, by whoever was on shift, and produces
// no artefact anyone can re-read — which is how the original defect survived: every individual step
// looked right.
//
// # WHAT IT CHECKS
//
//	E1  exactly one canonical row for (chain_id, bundle_id)
//	E2  quorum_reached, attestation_count, and signed voting power equal to total
//	E3  verify_tx, root and proofExecuted agree with the chain           (needs -rpc)
//	E4  one attestation row per DISTINCT signer address
//	E5  the expression proofs_service reads reports batch_quorum_met=true
//	E6  every standing layer-5 row for this anchor names the anchor-create tx and the published root
//	E7  no evidence sits in this node's outbox quarantine                (needs -outbox)
//	E8  no intent settled in the window without a canonical row
//
//	D3  how many rows were rebuilt from the chain
//	D4  NO shadow row asserts a quorum, by label and by missing bundle id
//
// A check that cannot be evaluated does NOT pass. Without -rpc, E3 fails; without -outbox, E7 fails. A
// gate that quietly drops the checks it could not run reports a clean sheet for an anchor nobody verified,
// which is worse than no gate at all.
//
// # RUNNING IT
//
//	anchorquorumverify -chain 84532 -bundle 0x2fd8…            # one anchor, database only
//	anchorquorumverify -chain 84532 -bundle 0x2fd8… -rpc -outbox /var/lib/certen/anchor_quorum_outbox
//	anchorquorumverify -gate-only                              # §4.D over the whole table
//
// Exit status is the gate: 0 when every evaluated check passed, 1 otherwise. That makes it usable as the
// last step of a deploy rather than a paragraph in a runbook.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
)

func main() {
	chainID := flag.Int64("chain", 0, "chain id of the anchor to verify")
	bundleID := flag.String("bundle", "", "bundle id (0x…) of the anchor to verify")
	useRPC := flag.Bool("rpc", false, "read the chain so E3 can be evaluated (needs the anchor RPC config)")
	outboxDir := flag.String("outbox", "", "anchor quorum outbox directory, so E7 can be evaluated")
	signers := flag.Int("signers", 7, "expected signer count for E2/E4 (0 = accept whatever the row records)")
	window := flag.Duration("window", time.Hour, "window for E8")
	gateOnly := flag.Bool("gate-only", false, "run only the whole-table §4.D gate")
	flag.Parse()

	if !*gateOnly && (*chainID == 0 || *bundleID == "") {
		log.Fatal("-chain and -bundle are required (or use -gate-only for the whole-table checks)")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	client, err := database.NewClient(&config.Config{DatabaseURL: dsn})
	if err != nil {
		log.Fatalf("connecting to database: %v", err)
	}
	defer client.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ok := true

	if !*gateOnly {
		opts := database.AnchorQuorumAcceptanceOptions{
			ExpectedSigners: *signers,
			SettledWindow:   *window,
			// Negative means "not inspected", which leaves E7 failed. Only an outbox that was actually
			// read may satisfy it.
			QuarantinedEntries: -1,
		}

		if *outboxDir != "" {
			n, qErr := countQuarantined(*outboxDir)
			if qErr != nil {
				log.Printf("⚠️  could not inspect the outbox quarantine at %s: %v", *outboxDir, qErr)
			} else {
				opts.QuarantinedEntries = n
			}
		}

		if *useRPC {
			onChain, cErr := readChain(ctx, *chainID, *bundleID)
			if cErr != nil {
				log.Printf("⚠️  could not read the chain: %v", cErr)
			} else {
				opts.OnChain = onChain
			}
		}

		res, aErr := database.RunAnchorQuorumAcceptance(ctx, client.DB(), *chainID, *bundleID, opts)
		if aErr != nil {
			log.Fatalf("acceptance gate: %v", aErr)
		}

		fmt.Printf("\nAnchor quorum acceptance — chain %d bundle %s\n", res.ChainID, res.BundleID)
		fmt.Println(strings.Repeat("─", 100))
		for _, c := range res.Checks {
			mark := "FAIL"
			if c.Passed {
				mark = "pass"
			}
			fmt.Printf("  %-3s %-4s %-58s %s\n", c.ID, mark, c.Name, c.Detail)
		}
		fmt.Println(strings.Repeat("─", 100))
		if res.Passed() {
			fmt.Printf("  ALL %d CHECKS PASSED\n", len(res.Checks))
		} else {
			fmt.Printf("  %d of %d checks FAILED\n", len(res.Failures()), len(res.Checks))
			ok = false
		}
	}

	gate, gErr := database.RunAnchorQuorumBackfillGate(ctx, client.DB())
	if gErr != nil {
		log.Fatalf("backfill gate: %v", gErr)
	}
	fmt.Printf("\nWhole-table gate (§4.D)\n")
	fmt.Println(strings.Repeat("─", 100))
	fmt.Printf("  D3   rows rebuilt from the chain ....................... %d\n", gate.BackfilledRows)
	fmt.Printf("  D4   shadow rows claiming a quorum (must be 0) ......... %d\n", gate.ShadowRowsClaimingQuorum)
	fmt.Printf("       quorum on a row with no bundle id (must be 0) .... %d\n", gate.CanonicalRowsWithoutBundle)
	fmt.Printf("       standing contradicted layer-5 rows (must be 0) ... %d\n", gate.ContradictedLayer5Rows)
	fmt.Println(strings.Repeat("─", 100))
	if !gate.Passed() {
		fmt.Println("  WHOLE-TABLE GATE FAILED")
		ok = false
	} else {
		fmt.Println("  whole-table gate passed")
	}

	if !ok {
		os.Exit(1)
	}
}

// countQuarantined reports how much evidence this node has set aside as conflicting or undecodable.
func countQuarantined(dir string) (int, error) {
	entries, err := os.ReadDir(dir + string(os.PathSeparator) + "quarantine")
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // nothing was ever quarantined
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n, nil
}

// readChain asks the anchor contract what it holds for this bundle.
func readChain(ctx context.Context, chainID int64, bundleID string) (*database.AnchorQuorumOnChain, error) {
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("loading anchor configuration: %w", err)
	}
	resolver, err := execution.NewReadOnlyChainsFromEnv(anchorCfg, []int64{chainID})
	if err != nil {
		return nil, fmt.Errorf("resolving chain %d: %w", chainID, err)
	}
	defer resolver.Close()

	bundle, err := execution.ParseBundleID(bundleID)
	if err != nil {
		return nil, err
	}
	reader := execution.NewChainBackfillReader(resolver)
	state, err := reader.AnchorState(ctx, chainID, bundle)
	if err != nil {
		return nil, err
	}
	out := &database.AnchorQuorumOnChain{
		Root:          append([]byte(nil), state.MerkleRoot[:]...),
		ProofExecuted: state.ProofExecuted,
	}

	// The anchor's own state does not record which transaction proved it, so the verify transaction comes
	// from the ProofExecuted log this anchor emitted. Without it E3 can still check the root and
	// proofExecuted, but not that the stored verify_tx is the right one.
	if tx, lErr := findProofExecutedTx(ctx, reader, chainID, bundle); lErr != nil {
		log.Printf("⚠️  could not locate the ProofExecuted log for this bundle (%v); "+
			"E3 will compare the root and proofExecuted only", lErr)
	} else {
		out.VerifyTx = tx
	}
	return out, nil
}

// findProofExecutedTx scans recent history for the log that proved this bundle.
func findProofExecutedTx(
	ctx context.Context,
	reader *execution.ChainBackfillReader,
	chainID int64,
	bundle [32]byte,
) (string, error) {
	head, err := reader.LatestBlock(ctx, chainID)
	if err != nil {
		return "", err
	}
	const (
		lookback = uint64(200000)
		window   = uint64(2000) // public endpoints commonly refuse a wider eth_getLogs range
	)
	from := uint64(0)
	if head > lookback {
		from = head - lookback
	}
	// Newest first: the anchor being verified was almost certainly proven recently, so this normally
	// finds it in the first window rather than after scanning the whole lookback.
	for end := head; ; {
		start := uint64(0)
		if end >= window {
			start = end - window + 1
		}
		if start < from {
			start = from
		}
		logs, sErr := reader.ScanProofExecuted(ctx, chainID, start, end)
		if sErr != nil {
			return "", sErr
		}
		for _, l := range logs {
			if l.BundleID == bundle {
				return l.TxHash, nil
			}
		}
		if start <= from {
			break
		}
		end = start - 1
	}
	return "", fmt.Errorf("no ProofExecuted log for this bundle in the last %d blocks", lookback)
}
