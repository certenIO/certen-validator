// anchorquorumbackfill rebuilds canonical anchor rows for batches proven before the evidence was kept.
//
// Anchors proven by the batch path before migration 018 wrote no canonical row: prove() discarded the
// quorum it had just verified. The evidence is still on-chain, in the executeComprehensiveProof
// transaction that proved each anchor and in the anchor state that transaction wrote, so the rows can be
// rebuilt — from the chain, never from a guess.
//
// # WHAT IT VERIFIES BEFORE IT WRITES ANYTHING
//
// For every candidate: the transaction succeeded; the anchor itself reports valid and proofExecuted; the
// root and operation id written come from ANCHOR STATE, not from the calldata claiming them; the message
// the proof carried equals the message recomputed locally from those fields; every signer is registered
// on-chain with exactly the declared power; the declared signed and total powers match the registry; and
// the signed power meets the 2/3 threshold. Anything that fails is reported and skipped.
//
// The raw BLS aggregate is not in the calldata — the anchor verifies a Groth16 blob over the aggregate
// public key, and sets proofExecuted only if that verification passes. So the signature check is the
// chain's; this tool proves that the on-chain check was about THIS batch and that the arithmetic holds.
// Backfilled rows are labelled evidence_source='chain_backfill' and carry no aggregate bytes and no member
// list, because neither is recoverable from calldata.
//
// # CANDIDATES
//
// One verify transaction per line, "<chainID>,<txHash>", '#' comments ignored:
//
//	84532,0x9e4f…
//	11155111,0x51a1…
//
// The gateway holds the list: the verify leg of every batch was reported as a cost event, so
//
//	SELECT chain_id, tx_hash FROM cost_events WHERE leg = 'verify' ORDER BY created_at;
//
// exports it. Bundles that already have a canonical row are left exactly as they are — live evidence
// carries the member list and the aggregate, which a backfill cannot recover, so it never overwrites.
//
// # RUNNING IT
//
// Where the validator runs, with DATABASE_URL, the per-chain RPC configuration and the
// CERTEN_ANCHOR_V8_<chainId> addresses the batch path uses.
//
//	anchorquorumbackfill -candidates verify-txs.txt                 # DRY RUN — the default
//	anchorquorumbackfill -candidates verify-txs.txt -limit 5 -write # write the first five
//	anchorquorumbackfill -candidates verify-txs.txt -write          # the full run
//
// Writing requires -write. A dry run reads the chain, prints exactly what it would write and every
// refusal with its reason, and touches nothing.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution"
)

func main() {
	candidatesPath := flag.String("candidates", "", "file of '<chainID>,<txHash>' verify transactions (required)")
	write := flag.Bool("write", false, "actually write rows; without it the run is a dry run")
	limit := flag.Int("limit", 0, "stop after this many candidates (0 = all)")
	pause := flag.Duration("pause", 250*time.Millisecond, "delay between candidates, to spare shared RPC endpoints")
	flag.Parse()

	if *candidatesPath == "" {
		log.Fatal("-candidates is required; see the package comment for the export query")
	}
	candidates, err := readCandidates(*candidatesPath)
	if err != nil {
		log.Fatalf("reading candidates: %v", err)
	}
	if len(candidates) == 0 {
		log.Fatalf("%s lists no candidates", *candidatesPath)
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

	// The same environment-based chain configuration the validator itself uses, so the backfill reads
	// the anchors the batch path writes to and no others.
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		log.Fatalf("loading anchor configuration: %v", err)
	}
	// READ-ONLY. This tool issues eth_call, eth_getTransactionByHash, eth_getTransactionReceipt and
	// eth_getBlockByNumber, and nothing else. ReadOnlyChains cannot sign because it holds nothing to sign
	// with, so no ETH_PRIVATE_KEY is read and none is needed — earlier versions went through the transact
	// manager and had to be handed a throwaway key just to construct.
	resolver, err := execution.NewReadOnlyChainsFromEnv(anchorCfg, chainIDsOf(candidates))
	if err != nil {
		log.Fatalf("resolving chains: %v", err)
	}
	defer resolver.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mode := "DRY RUN — nothing will be written"
	if *write {
		mode = "WRITING"
	}
	log.Printf("[BACKFILL] %s: %d candidate(s) from %s", mode, len(candidates), *candidatesPath)

	rep, err := execution.RunAnchorQuorumBackfill(
		ctx,
		execution.NewChainBackfillReader(resolver),
		database.NewBatchRepository(client),
		candidates,
		execution.AnchorQuorumBackfillOptions{
			DryRun: !*write,
			Limit:  *limit,
			Pause:  *pause,
			Logf:   log.Printf,
		},
	)
	if err != nil {
		log.Fatalf("backfill failed: %v", err)
	}

	log.Printf("[BACKFILL] examined=%d written=%d would-write=%d already-canonical=%d refused=%d conflicts=%d errors=%d",
		rep.Candidates, rep.Written, rep.WouldWrite, rep.AlreadyCanonical, rep.Rejected, rep.Conflicts, rep.Errors)

	// A conflict means two descriptions of one anchor disagree. That is a fact to investigate, not a
	// row to fix, and it should not be lost in a successful-looking exit.
	if rep.Conflicts > 0 {
		log.Fatalf("[BACKFILL] %d conflict(s): an existing row disagrees with the chain. Nothing was overwritten; "+
			"investigate before re-running", rep.Conflicts)
	}
	if rep.Errors > 0 {
		log.Fatalf("[BACKFILL] %d candidate(s) could not be examined; re-run for those once the cause is fixed",
			rep.Errors)
	}
}

// readCandidates parses "<chainID>,<txHash>" lines. A malformed line fails the run rather than being
// skipped: a backfill that quietly ignores part of its own input cannot be checked against its input.
func readCandidates(path string) ([]execution.BackfillCandidate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []execution.BackfillCandidate
	seen := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if i := strings.Index(text, "#"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		parts := strings.Split(text, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: expected '<chainID>,<txHash>', got %q", line, text)
		}
		chainID, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q is not a chain id", line, parts[0])
		}
		txHash := strings.ToLower(strings.TrimSpace(parts[1]))
		if !strings.HasPrefix(txHash, "0x") || len(txHash) != 66 {
			return nil, fmt.Errorf("line %d: %q is not a transaction hash", line, parts[1])
		}
		key := fmt.Sprintf("%d,%s", chainID, txHash)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, execution.BackfillCandidate{ChainID: chainID, TxHash: txHash})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func chainIDsOf(candidates []execution.BackfillCandidate) []int64 {
	seen := map[int64]bool{}
	var out []int64
	for _, c := range candidates {
		if !seen[c.ChainID] {
			seen[c.ChainID] = true
			out = append(out, c.ChainID)
		}
	}
	return out
}
