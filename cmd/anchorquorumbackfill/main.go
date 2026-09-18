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
// By default the tool finds its own work: -chains scans each anchor contract's ProofExecuted logs and
// keeps the anchors this database has no canonical row for. That is the chain stating which anchors it
// proved, so nothing has to be exported by hand and nothing can be missed because another service failed
// to record it.
//
// The older input is still accepted. -candidates reads one verify transaction per line,
// "<chainID>,<txHash>", '#' comments ignored:
//
//	84532,0x9e4f…
//	11155111,0x51a1…
//
// which the gateway can export with
//
//	SELECT chain_id, tx_hash FROM cost_events WHERE leg = 'verify' ORDER BY created_at;
//
// Use it to re-examine a specific set; use -chains for everything else. Bundles that already have a
// canonical row are left exactly as they are — live evidence carries the member list and the aggregate,
// which a backfill cannot recover, so it never overwrites.
//
// # RUNNING IT
//
// Where the validator runs, with DATABASE_URL, the per-chain RPC configuration and the
// CERTEN_ANCHOR_V8_<chainId> addresses the batch path uses.
//
//	anchorquorumbackfill -chains 84532                              # DRY RUN over the recent range
//	anchorquorumbackfill -chains 84532,11155111 -lookback 200000    # a wider window
//	anchorquorumbackfill -chains 84532 -from-block N -to-block M    # an exact range
//	anchorquorumbackfill -chains 84532 -write                       # write what it found
//	anchorquorumbackfill -candidates verify-txs.txt -write          # the explicit list instead
//
// Writing requires -write. A dry run reads the chain, prints exactly what it would write and every
// refusal with its reason, and touches nothing.
//
// Scanning needs an endpoint that serves eth_getLogs over the range asked for. A window a provider
// refuses is reported as an error and fails the run: a refused window returned as "no anchors here" is
// indistinguishable from a healthy chain, which is the one wrong answer this tool must never give.
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
	candidatesPath := flag.String("candidates", "", "file of '<chainID>,<txHash>' verify transactions; omit to discover from the chain")
	chainList := flag.String("chains", "", "comma-separated chain ids to scan for anchors with no canonical row")
	fromBlock := flag.Uint64("from-block", 0, "first block to scan (0 = derive from -lookback)")
	toBlock := flag.Uint64("to-block", 0, "last block to scan (0 = the chain head)")
	lookback := flag.Uint64("lookback", 0, "blocks to scan back from the head when -from-block is unset (0 = 50,000)")
	window := flag.Uint64("window", 0, "eth_getLogs block window (0 = 2,000)")
	write := flag.Bool("write", false, "actually write rows; without it the run is a dry run")
	limit := flag.Int("limit", 0, "stop after this many candidates (0 = all)")
	pause := flag.Duration("pause", 250*time.Millisecond, "delay between candidates, to spare shared RPC endpoints")
	flag.Parse()

	if (*candidatesPath == "") == (*chainList == "") {
		log.Fatal("give exactly one of -chains (discover from the chain) or -candidates (an explicit list)")
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
	repo := database.NewBatchRepository(client)

	// Which chains to open clients for. With an explicit list it is the chains that list names; when
	// discovering it is the chains asked for.
	var candidates []execution.BackfillCandidate
	var chainIDs []int64
	if *candidatesPath != "" {
		candidates, err = readCandidates(*candidatesPath)
		if err != nil {
			log.Fatalf("reading candidates: %v", err)
		}
		if len(candidates) == 0 {
			log.Fatalf("%s lists no candidates", *candidatesPath)
		}
		chainIDs = chainIDsOf(candidates)
	} else {
		chainIDs, err = parseChainIDs(*chainList)
		if err != nil {
			log.Fatalf("reading -chains: %v", err)
		}
	}

	// The same environment-based chain configuration the validator itself uses, so the backfill reads
	// the anchors the batch path writes to and no others.
	anchorCfg, err := config.LoadAnchorConfigFromEnv()
	if err != nil {
		log.Fatalf("loading anchor configuration: %v", err)
	}
	// READ-ONLY. This tool issues eth_call, eth_getLogs, eth_getTransactionByHash,
	// eth_getTransactionReceipt and eth_getBlockByNumber, and nothing else. ReadOnlyChains cannot sign
	// because it holds nothing to sign with, so no ETH_PRIVATE_KEY is read and none is needed — earlier
	// versions went through the transact manager and had to be handed a throwaway key just to construct.
	resolver, err := execution.NewReadOnlyChainsFromEnv(anchorCfg, chainIDs)
	if err != nil {
		log.Fatalf("resolving chains: %v", err)
	}
	defer resolver.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	reader := execution.NewChainBackfillReader(resolver)

	mode := "DRY RUN — nothing will be written"
	if *write {
		mode = "WRITING"
	}

	if *candidatesPath != "" {
		log.Printf("[BACKFILL] %s: %d candidate(s) from %s", mode, len(candidates), *candidatesPath)
	} else {
		disc, dErr := execution.DiscoverAnchorQuorumCandidates(ctx, reader,
			func(c context.Context, chainID int64, bundleID string) (bool, error) {
				row, rErr := repo.GetAnchorQuorum(c, chainID, bundleID)
				return row != nil, rErr
			},
			execution.DiscoverOptions{
				Chains:         chainIDs,
				FromBlock:      *fromBlock,
				ToBlock:        *toBlock,
				LookbackBlocks: *lookback,
				WindowSize:     *window,
				Pause:          *pause,
				Logf:           log.Printf,
			})
		if dErr != nil {
			// Never degrade to "nothing to do": a scan that could not read its range has established
			// nothing, and treating that as an empty result is how a backfill silently skips everything.
			log.Fatalf("discovering candidates: %v", dErr)
		}
		log.Printf("[BACKFILL] discovery: %d anchor(s) proven on-chain, %d already canonical, %d to examine",
			disc.ProvenOnChain, disc.AlreadyCanonical, len(disc.Candidates))
		for chainID, to := range disc.ScannedTo {
			log.Printf("[BACKFILL] chain=%d scanned through block %d", chainID, to)
		}
		if len(disc.Candidates) == 0 {
			log.Printf("[BACKFILL] every anchor proven in this range already has a canonical row; nothing to do")
			return
		}
		candidates = disc.Candidates
		log.Printf("[BACKFILL] %s: %d candidate(s) discovered from the chain", mode, len(candidates))
	}

	rep, err := execution.RunAnchorQuorumBackfill(
		ctx,
		reader,
		repo,
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

// parseChainIDs reads "84532,11155111". A malformed entry fails the run rather than being skipped: a scan
// that quietly drops a chain reports "nothing to backfill" for it.
func parseChainIDs(s string) ([]int64, error) {
	seen := map[int64]bool{}
	var out []int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a chain id", part)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no chain ids given")
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
