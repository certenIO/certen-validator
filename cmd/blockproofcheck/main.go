// Copyright 2026 Certen Protocol
//
// blockproofcheck — prove every entry of real blocks exactly as a settlement in them would be proven
// (ethproof.CheckBlock: the agreed header, the agreed transaction and receipt encodings re-deriving the header's roots,
// and every entry's inclusion proofs built and verified).
//
// A settlement can only be proven if every transaction and receipt of its block can be encoded. A chain upgrade that
// adds a transaction type, or changes one, makes every block holding it unprovable: a settlement in such a block is
// recorded settled_unproven and is not attested or written back until its block can be proven and the member is repaired
// (validator repair member-proof-cycle). This command finds such blocks before a settlement depends on one.
//
// Two modes:
//
//	range   blockproofcheck -chain-id 421614 -from N -to M      (or -blocks FILE, one number per line)
//	        proves each block once (with retries for unread blocks) and exits:
//	          0  every block proven
//	          1  at least one block CANNOT be proven (named, with its error) — stop the line
//	          3  every block read was proven, but some could not be read (providers did not answer or agree)
//
//	follow  blockproofcheck -follow -chains 11155111,84532,421614 -metrics-addr :9464
//	        the production canary: proves every new finalized block of each chain as it finalizes, for ever, and
//	        exports Prometheus metrics. A block that cannot be proven is logged with its error and counted
//	        (certen_blockproof_refused_total); a block not yet read stays pending and is asked again, never skipped
//	        (certen_blockproof_pending_blocks).
//
// Providers: -rpcs, or every provider configured for the chain (ethrpc.EndpointsForChainID). At least
// ethrpc.MinAgreeingProviders independent hosts are required.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Exit codes of range mode.
const (
	exitProven  = 0
	exitRefused = 1
	exitUnread  = 3
	exitUsage   = 2
)

// result is one block's outcome.
type result struct {
	number uint64
	check  *ethproof.BlockCheck
	err    error // nil: proven; errors.Is(err, ethproof.ErrUnread): not read; otherwise: cannot be proven
}

func (r result) refused() bool { return r.err != nil && !errors.Is(r.err, ethproof.ErrUnread) }

// checkWithRetries checks one block, asking again while it is unread, up to attempts times.
func checkWithRetries(ctx context.Context, src ethproof.NumberedSource, n uint64, attempts int, backoff time.Duration) result {
	var r result
	for a := 1; a <= attempts; a++ {
		c, err := ethproof.CheckBlock(ctx, src, n)
		r = result{number: n, check: c, err: err}
		if err == nil || !errors.Is(err, ethproof.ErrUnread) || ctx.Err() != nil {
			return r
		}
		select {
		case <-ctx.Done():
			return r
		case <-time.After(backoff * time.Duration(a)):
		}
	}
	return r
}

// checkAll checks numbers with workers in parallel and returns the results in the order of numbers.
func checkAll(ctx context.Context, src ethproof.NumberedSource, numbers []uint64, workers, attempts int, backoff time.Duration,
	each func(result)) []result {
	if workers < 1 {
		workers = 1
	}
	out := make([]result, len(numbers))
	jobs := make(chan int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r := checkWithRetries(ctx, src, numbers[i], attempts, backoff)
				out[i] = r
				if each != nil {
					mu.Lock()
					each(r)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range numbers {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

// summary is what a range established.
type summary struct {
	proven, refused, unread, entries int
	types                            map[uint8]int
	refusals, unreads                []result
}

func summarize(rs []result) summary {
	s := summary{types: map[uint8]int{}}
	for _, r := range rs {
		switch {
		case r.err == nil && r.check != nil:
			s.proven++
			s.entries += r.check.Entries
			for t, n := range r.check.Types {
				s.types[t] += n
			}
		case r.refused():
			s.refused++
			s.refusals = append(s.refusals, r)
		default:
			s.unread++
			s.unreads = append(s.unreads, r)
		}
	}
	return s
}

func (s summary) exitCode() int {
	switch {
	case s.refused > 0:
		return exitRefused
	case s.unread > 0:
		return exitUnread
	default:
		return exitProven
	}
}

func (s summary) typesString() string {
	keys := make([]int, 0, len(s.types))
	for t := range s.types {
		keys = append(keys, int(t))
	}
	sort.Ints(keys)
	parts := make([]string, len(keys))
	for i, t := range keys {
		parts[i] = fmt.Sprintf("0x%x:%d", t, s.types[uint8(t)])
	}
	return strings.Join(parts, " ")
}

// =============================================================================
// follow mode
// =============================================================================

var (
	mBlocksProven = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "blocks_proven_total", Help: "Finalized blocks every entry of which was proven"}, []string{"chain_id"})
	mEntriesProven = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "entries_proven_total", Help: "Transactions proven, by EIP-2718 type"}, []string{"chain_id", "tx_type"})
	mRefused = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "refused_total", Help: "Finalized blocks that CANNOT be proven: a settlement in one would be recorded settled_unproven"}, []string{"chain_id"})
	mUnreadAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "unread_total", Help: "Block checks the providers did not answer or agree on (the block stays pending)"}, []string{"chain_id"})
	mPending = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "pending_blocks", Help: "Finalized blocks not yet proven or refused"}, []string{"chain_id"})
	mProvenThrough = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "proven_through_block", Help: "Every finalized block up to this height is proven or refused"}, []string{"chain_id"})
	mFinalized = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "finalized_block", Help: "The agreed finalized height last read"}, []string{"chain_id"})
	mLastCycle = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "blockproof",
		Name: "last_cycle_timestamp_seconds", Help: "When a cycle last read the finalized height"}, []string{"chain_id"})
)

func registerMetrics(reg prometheus.Registerer) {
	reg.MustRegister(mBlocksProven, mEntriesProven, mRefused, mUnreadAttempts, mPending, mProvenThrough, mFinalized, mLastCycle)
}

// follower proves every finalized block of one chain from start on.
type follower struct {
	chainID  int64
	src      ethproof.NumberedSource
	workers  int
	attempts int
	backoff  time.Duration
	maxBatch int
	logf     func(format string, args ...interface{})

	next    uint64          // the lowest height never yet handed to a check
	pending map[uint64]bool // heights handed out and not yet proven or refused
}

func (f *follower) label() string { return strconv.FormatInt(f.chainID, 10) }

// finalized is the agreed finalized height.
func (f *follower) finalized(ctx context.Context) (uint64, error) {
	h, err := f.src.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
	if err != nil {
		return 0, err
	}
	return h.Number.Uint64(), nil
}

// step reads the finalized height and checks the pending blocks plus up to maxBatch new ones. It returns the results.
func (f *follower) step(ctx context.Context) ([]result, error) {
	fin, err := f.finalized(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain %d finalized height: %w", f.chainID, err)
	}
	mFinalized.WithLabelValues(f.label()).Set(float64(fin))
	mLastCycle.WithLabelValues(f.label()).SetToCurrentTime()
	if f.pending == nil {
		f.pending = map[uint64]bool{}
	}
	if f.next == 0 {
		f.next = fin
	}
	for n := f.next; n <= fin && len(f.pending) < f.maxBatch; n++ {
		f.pending[n] = true
		f.next = n + 1
	}
	numbers := make([]uint64, 0, len(f.pending))
	for n := range f.pending {
		numbers = append(numbers, n)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	rs := checkAll(ctx, f.src, numbers, f.workers, f.attempts, f.backoff, nil)
	for _, r := range rs {
		switch {
		case r.err == nil && r.check != nil:
			delete(f.pending, r.number)
			mBlocksProven.WithLabelValues(f.label()).Inc()
			for t, n := range r.check.Types {
				mEntriesProven.WithLabelValues(f.label(), fmt.Sprintf("0x%x", t)).Add(float64(n))
			}
		case r.refused():
			delete(f.pending, r.number)
			mRefused.WithLabelValues(f.label()).Inc()
			f.logf("🚨 [BLOCKPROOF] chain %d block %d CANNOT be proven - a settlement in it would stall: %v", f.chainID, r.number, r.err)
		default:
			mUnreadAttempts.WithLabelValues(f.label()).Inc()
			f.logf("⏳ [BLOCKPROOF] chain %d block %d not read (stays pending): %v", f.chainID, r.number, r.err)
		}
	}
	mPending.WithLabelValues(f.label()).Set(float64(len(f.pending)))
	through := f.next - 1
	for n := range f.pending {
		if n-1 < through {
			through = n - 1
		}
	}
	mProvenThrough.WithLabelValues(f.label()).Set(float64(through))
	return rs, nil
}

// =============================================================================
// main
// =============================================================================

func endpoints(chainID int64, flagged string) []string {
	if flagged != "" {
		return ethrpc.ParseEndpoints(strings.Split(flagged, ",")...)
	}
	return ethrpc.EndpointsForChainID(chainID, "")
}

func readBlockList(path string) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a block number", path, line)
		}
		out = append(out, n)
	}
	return out, sc.Err()
}

func main() {
	chainID := flag.Int64("chain-id", 0, "range mode: the chain")
	chains := flag.String("chains", "", "follow mode: comma-separated chain ids")
	rpcs := flag.String("rpcs", "", "range mode: comma-separated provider URLs (default: the chain's configured providers)")
	from := flag.Uint64("from", 0, "range mode: first block")
	to := flag.Uint64("to", 0, "range mode: last block")
	blocks := flag.String("blocks", "", "range mode: file of block numbers, one per line")
	follow := flag.Bool("follow", false, "follow mode: prove every new finalized block of each -chains chain")
	workers := flag.Int("workers", 4, "blocks checked in parallel")
	attempts := flag.Int("attempts", 5, "checks of an unread block before it is reported unread (range) or retried next cycle (follow)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-provider read timeout")
	poll := flag.Duration("poll", 30*time.Second, "follow mode: time between cycles")
	maxBatch := flag.Int("max-batch", 2000, "follow mode: most blocks checked in one cycle")
	metricsAddr := flag.String("metrics-addr", ":9464", "follow mode: Prometheus /metrics listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)

	if *follow {
		os.Exit(runFollow(ctx, logger, *chains, *workers, *attempts, *timeout, *poll, *maxBatch, *metricsAddr))
	}
	os.Exit(runRange(ctx, logger, *chainID, *rpcs, *from, *to, *blocks, *workers, *attempts, *timeout))
}

func runRange(ctx context.Context, logger *log.Logger, chainID int64, rpcs string, from, to uint64, blocks string, workers, attempts int,
	timeout time.Duration) int {
	if chainID == 0 {
		logger.Print("range mode needs -chain-id")
		return exitUsage
	}
	var numbers []uint64
	switch {
	case blocks != "":
		var err error
		if numbers, err = readBlockList(blocks); err != nil {
			logger.Print(err)
			return exitUsage
		}
	case to >= from && to > 0:
		for n := from; n <= to; n++ {
			numbers = append(numbers, n)
		}
	default:
		logger.Print("range mode needs -from/-to or -blocks")
		return exitUsage
	}
	src, err := ethrpc.NewAgreeingReader(ctx, chainID, endpoints(chainID, rpcs), timeout)
	if err != nil {
		logger.Printf("chain %d providers: %v", chainID, err)
		return exitUsage
	}
	logger.Printf("chain %d: checking %d blocks through %v with %d workers", chainID, len(numbers), src.Hosts(), workers)
	start := time.Now()
	done := 0
	rs := checkAll(ctx, src, numbers, workers, attempts, 2*time.Second, func(r result) {
		done++
		if r.refused() {
			logger.Printf("🚨 block %d CANNOT be proven: %v", r.number, r.err)
		}
		if done%1000 == 0 {
			logger.Printf("… %d/%d blocks (%.1f/s)", done, len(numbers), float64(done)/time.Since(start).Seconds())
		}
	})
	s := summarize(rs)
	for _, r := range s.unreads {
		logger.Printf("⏳ block %d NOT READ: %v", r.number, r.err)
	}
	logger.Printf("chain %d: %d blocks: %d proven (%d entries; types %s), %d CANNOT be proven, %d not read; %s",
		chainID, len(numbers), s.proven, s.entries, s.typesString(), s.refused, s.unread, time.Since(start).Round(time.Second))
	if ctx.Err() != nil {
		logger.Print("interrupted")
		return exitUnread
	}
	return s.exitCode()
}

func runFollow(ctx context.Context, logger *log.Logger, chains string, workers, attempts int, timeout, poll time.Duration, maxBatch int,
	metricsAddr string) int {
	if chains == "" {
		logger.Print("follow mode needs -chains")
		return exitUsage
	}
	registerMetrics(prometheus.DefaultRegisterer)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: metricsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("metrics listener: %v", err)
		}
	}()
	var wg sync.WaitGroup
	for _, part := range strings.Split(chains, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil {
			logger.Printf("-chains: %q is not a chain id", part)
			return exitUsage
		}
		src, err := ethrpc.NewAgreeingReader(ctx, id, endpoints(id, ""), timeout)
		if err != nil {
			logger.Printf("chain %d providers: %v", id, err)
			return exitUsage
		}
		f := &follower{chainID: id, src: src, workers: workers, attempts: attempts, backoff: 2 * time.Second, maxBatch: maxBatch,
			logf: logger.Printf}
		logger.Printf("following chain %d through %v", id, src.Hosts())
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				rs, err := f.step(ctx)
				if err != nil {
					logger.Printf("⏳ [BLOCKPROOF] %v", err)
				} else if len(rs) > 0 {
					s := summarize(rs)
					logger.Printf("[BLOCKPROOF] chain %d: %d proven, %d refused, %d pending; through %d", f.chainID, s.proven, s.refused,
						len(f.pending), f.next-1)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(poll):
				}
			}
		}()
	}
	wg.Wait()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	return exitProven
}
