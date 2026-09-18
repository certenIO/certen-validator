// Copyright 2026 Certen Protocol
//
// Finding the anchors that need a canonical row, from the chain that proved them.

package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ProofExecutedLog is one anchor the chain says it proved.
//
// The event carries the bundle id as an indexed topic, which is the same key the canonical row is stored
// under. That is what makes discovery cheap: the database can be asked "do I already have this anchor"
// before a single further RPC is spent on decoding its transaction.
type ProofExecutedLog struct {
	ChainID     int64
	BundleID    [32]byte
	TxHash      string
	BlockNumber uint64
}

// AnchorLogScanner reads proof-execution events from an anchor contract.
type AnchorLogScanner interface {
	// ScanProofExecuted returns every ProofExecuted log the anchor emitted in [fromBlock, toBlock].
	ScanProofExecuted(ctx context.Context, chainID int64, fromBlock, toBlock uint64) ([]ProofExecutedLog, error)
	// LatestBlock reports the head this endpoint will serve.
	LatestBlock(ctx context.Context, chainID int64) (uint64, error)
}

// ParseBundleID turns the stored "0x…" form back into the 32 bytes the contract keys on.
//
// Strict about length: a short value silently left-padded would address a DIFFERENT anchor, and read as
// "this bundle was never proven" rather than as the typo it is.
func ParseBundleID(s string) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimSpace(s)
	trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X")
	if len(trimmed) != 64 {
		return out, fmt.Errorf("%q is not a bundle id: expected 32 bytes of hex, got %d hex digit(s)",
			s, len(trimmed))
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, fmt.Errorf("%q is not a bundle id: %w", s, err)
	}
	copy(out[:], raw)
	return out, nil
}

// DiscoverOptions bounds one discovery run.
type DiscoverOptions struct {
	// Chains to scan. Required.
	Chains []int64
	// FromBlock and ToBlock bound the scan per chain. ToBlock 0 means the current head.
	FromBlock, ToBlock uint64
	// LookbackBlocks is used when FromBlock is 0: scan the last N blocks before ToBlock.
	LookbackBlocks uint64
	// WindowSize is how many blocks to request at once. Zero means 2,000 — public endpoints commonly
	// refuse a wider eth_getLogs range, and a refusal in the middle of a scan looks like an empty chain.
	WindowSize uint64
	// Pause between windows, to spare shared endpoints.
	Pause time.Duration
	Logf  func(string, ...interface{})
}

// CandidateDiscovery is what a scan found.
type CandidateDiscovery struct {
	// Candidates are the verify transactions worth examining: proven on-chain, no canonical row yet.
	Candidates []BackfillCandidate
	// ProvenOnChain counts distinct anchors the chain reported as proven in the range.
	ProvenOnChain int
	// AlreadyCanonical counts those the database already holds — the healthy majority.
	AlreadyCanonical int
	// ScannedTo records the last block examined per chain, so a repeat run can start from it.
	ScannedTo map[int64]uint64
}

const (
	defaultDiscoveryWindow   = uint64(2000)
	defaultDiscoveryLookback = uint64(50000)
)

// DiscoverAnchorQuorumCandidates finds anchors the chain proved and this database never recorded.
//
// This replaces the hand-exported candidate file the backfill used to require. That file came from a query
// against the GATEWAY's cost_events — a different service's database, exported by a human, listing the
// verify legs it happened to bill for. Reading the anchor contract's own ProofExecuted logs is strictly
// better evidence: it is the chain saying which anchors it proved, it needs no second database, and it
// cannot omit an anchor because a cost event was never written.
//
// Anchors that already have a canonical row are dropped here rather than in the backfill, so a routine run
// over a healthy range costs one eth_getLogs per window and one indexed database read per anchor, instead
// of a full transaction decode and registry read for every anchor ever proven.
func DiscoverAnchorQuorumCandidates(
	ctx context.Context,
	scanner AnchorLogScanner,
	lookup func(ctx context.Context, chainID int64, bundleID string) (bool, error),
	opts DiscoverOptions,
) (*CandidateDiscovery, error) {
	if scanner == nil {
		return nil, fmt.Errorf("discover anchor quorum candidates: a log scanner is required")
	}
	if len(opts.Chains) == 0 {
		return nil, fmt.Errorf("discover anchor quorum candidates: no chains given")
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	window := opts.WindowSize
	if window == 0 {
		window = defaultDiscoveryWindow
	}

	out := &CandidateDiscovery{ScannedTo: map[int64]uint64{}}
	seenTx := map[string]bool{}
	seenBundle := map[string]bool{}

	for _, chainID := range opts.Chains {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		to := opts.ToBlock
		if to == 0 {
			head, err := scanner.LatestBlock(ctx, chainID)
			if err != nil {
				return nil, fmt.Errorf("chain %d: reading head: %w", chainID, err)
			}
			to = head
		}
		from := opts.FromBlock
		if from == 0 {
			lookback := opts.LookbackBlocks
			if lookback == 0 {
				lookback = defaultDiscoveryLookback
			}
			if lookback >= to {
				from = 0
			} else {
				from = to - lookback
			}
		}
		if from > to {
			return nil, fmt.Errorf("chain %d: from block %d is after to block %d", chainID, from, to)
		}

		logf("[DISCOVER] chain=%d scanning blocks %d..%d in windows of %d", chainID, from, to, window)

		for start := from; start <= to; start += window {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			end := start + window - 1
			if end > to {
				end = to
			}

			logs, err := scanner.ScanProofExecuted(ctx, chainID, start, end)
			if err != nil {
				// A window that cannot be read is NOT an empty window. Reporting it as empty is exactly
				// how a scan silently concludes that nothing needs backfilling.
				return nil, fmt.Errorf("chain %d: scanning blocks %d..%d: %w", chainID, start, end, err)
			}

			for _, l := range logs {
				bundleHex := hexPrefixed(l.BundleID[:])
				bundleKey := fmt.Sprintf("%d/%s", l.ChainID, bundleHex)
				if seenBundle[bundleKey] {
					continue
				}
				seenBundle[bundleKey] = true
				out.ProvenOnChain++

				if lookup != nil {
					held, lErr := lookup(ctx, l.ChainID, bundleHex)
					if lErr != nil {
						return nil, fmt.Errorf("chain %d bundle %s: reading existing row: %w",
							l.ChainID, bundleHex, lErr)
					}
					if held {
						out.AlreadyCanonical++
						continue
					}
				}

				txKey := fmt.Sprintf("%d,%s", l.ChainID, l.TxHash)
				if seenTx[txKey] {
					continue
				}
				seenTx[txKey] = true
				out.Candidates = append(out.Candidates, BackfillCandidate{
					ChainID: l.ChainID,
					TxHash:  l.TxHash,
				})
			}

			if opts.Pause > 0 && end < to {
				select {
				case <-ctx.Done():
					return out, ctx.Err()
				case <-time.After(opts.Pause):
				}
			}
			if end == to {
				break
			}
		}
		out.ScannedTo[chainID] = to
	}

	// Stable order so two runs over the same range produce the same report.
	sort.Slice(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].ChainID != out.Candidates[j].ChainID {
			return out.Candidates[i].ChainID < out.Candidates[j].ChainID
		}
		return out.Candidates[i].TxHash < out.Candidates[j].TxHash
	})
	return out, nil
}
