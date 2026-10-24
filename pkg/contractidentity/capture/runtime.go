// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// The runtime runs the two stations beside the validator's observation (RB12 WP-S8-3b): E1 when a validator learns of an attestation
// transaction (its own receipt of executeComprehensiveProof, or the first sight of the attestation by any other validator), E2 when it
// first observes a settlement. It never blocks the caller (triggers go into bounded queues and are dropped, counted, when full), never
// crashes the process (every worker recovers), never holds more than its byte budget (a reservation released on every path), and its
// settings never stop the validator: a bad setting is a NAMED disabled state (log, metric, /health/detailed) and the validator runs on.

// The variables of the capture. The switch is OFF by default.
const (
	EnvSwitch      = "CERTEN_CONTRACT_IDENTITY_CAPTURE"
	EnvConcurrency = "CERTEN_CONTRACT_IDENTITY_CAPTURE_CONCURRENCY"
	EnvParallel    = "CERTEN_CONTRACT_IDENTITY_CAPTURE_PARALLEL"
	EnvMemory      = "CERTEN_CONTRACT_IDENTITY_CAPTURE_MEMORY_BYTES"
)

// Defaults and bounds (both ends are accepted, one past either is setting_invalid).
const (
	DefaultConcurrency = 4 // captures of one chain at a time: S6's DefaultReplayCaptureConcurrency
	MaxConcurrency     = 16
	DefaultParallel    = 4 // provider calls of one pass at once
	MaxParallel        = 8
	DefaultMemoryBytes = 160 << 20
	MinMemoryBytes     = int64(WorkingSetBytes)
	MaxMemoryBytes     = 2 << 30
	// WorkingSetBytes is what one running capture reserves: its proof pool (2 x the container cap), one provider answer being parsed
	// and the attestation block's transaction list.
	WorkingSetBytes = 2*(4<<20) + MaxResponseBytes + (1 << 20)
	queueDepth      = 64
	seenBound       = 8192
	attestWait      = 30 * time.Second // how long E2 waits for the attestation station's row of its anchor
	receiptWait     = 2 * time.Minute  // how long E2 waits for the settlement to be readable
	jobTimeout      = 3 * time.Minute
)

// Settings are the capture's settings.
type Settings struct {
	Enabled     bool
	Concurrency int
	Parallel    int
	MemoryBytes int64
}

// Disabled is a named disabled state of the capture. Reason is one of DisabledReasons; Setting is the NAME of the variable that caused it
// (never its value, which may hold a credential).
type Disabled struct{ Reason, Setting string }

func (d *Disabled) Error() string {
	if d.Setting == "" {
		return "contract_identity_capture_disabled{" + d.Reason + "}"
	}
	return "contract_identity_capture_disabled{" + d.Reason + "," + d.Setting + "}"
}

// DisabledReasons is the closed set of reasons.
func DisabledReasons() []string {
	return []string{"switch_invalid", "setting_invalid", "no_durable_store", "no_chain_reader", "manifest_unavailable", "start_panicked"}
}

// SettingsFromEnv reads the settings through getenv. An off switch is no error; a switch that is not a switch, or a number outside its
// bounds (checked only while the switch is on), is a Disabled state naming the variable.
func SettingsFromEnv(getenv func(string) string) (Settings, *Disabled) {
	set := Settings{Concurrency: DefaultConcurrency, Parallel: DefaultParallel, MemoryBytes: DefaultMemoryBytes}
	switch strings.ToLower(strings.TrimSpace(getenv(EnvSwitch))) {
	case "", "0", "false", "off", "no":
		return set, nil
	case "1", "true", "on", "yes":
		set.Enabled = true
	default:
		return set, &Disabled{Reason: "switch_invalid", Setting: EnvSwitch}
	}
	num := func(name string, def, lo, hi int64) (int64, bool) {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return def, true
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < lo || n > hi {
			return 0, false
		}
		return n, true
	}
	for _, f := range []struct {
		name        string
		def, lo, hi int64
		set         func(int64)
	}{
		{EnvConcurrency, DefaultConcurrency, 1, MaxConcurrency, func(n int64) { set.Concurrency = int(n) }},
		{EnvParallel, DefaultParallel, 1, MaxParallel, func(n int64) { set.Parallel = int(n) }},
		{EnvMemory, DefaultMemoryBytes, MinMemoryBytes, MaxMemoryBytes, func(n int64) { set.MemoryBytes = n }},
	} {
		n, ok := num(f.name, f.def, f.lo, f.hi)
		if !ok {
			set.Enabled = false
			return set, &Disabled{Reason: "setting_invalid", Setting: f.name}
		}
		f.set(n)
	}
	return set, nil
}

// budget is the byte reservation: the check and the add happen under one lock, release is idempotent and terminal.
type budget struct {
	mu        sync.Mutex
	cap, used int64
}

func (b *budget) reserve(n int64) (func(), bool) {
	b.mu.Lock()
	if b.used+n > b.cap {
		b.mu.Unlock()
		return nil, false
	}
	b.used += n
	metrics.ContractIdentityMemoryInUse(b.used)
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.used -= n
			metrics.ContractIdentityMemoryInUse(b.used)
			b.mu.Unlock()
		})
	}, true
}

func (b *budget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Deps are what the runtime needs from the process.
type Deps struct {
	Store    Store // the durable insert-only store (WP-S8-5's Postgres implementation); nil = no_durable_store
	Manifest *ci.Manifest
	// SourceFor returns the agreed source of a live EVM chain (lazily: the chains are built after the runtime). An error leaves that chain
	// uncaptured, counted as dropped{no_chain_reader}.
	SourceFor func(chain uint64) (AttestSource, error)
	Clock     ethproof.ReplayClock // default ethproof.WallClock
	Logf      func(string, ...interface{})
	// Deadline is the memberChainDeadline of an anchor of a chain (pkg/execution): past it its hop ticks stop. Optional.
	Deadline func(chain uint64, anchorID [32]byte) (time.Time, bool)
	// TickPoll is how often the hop tick loop looks at the head (default DefaultTickPoll); tests lower it.
	TickPoll time.Duration
}

type jobKey struct {
	station string
	chain   uint64
	tx      common.Hash
}

type job struct {
	jobKey
	bundle [32]byte
}

// Runtime is a running capture.
type Runtime struct {
	set  Settings
	d    Deps
	mem  *budget
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu     sync.Mutex
	seen   map[jobKey]bool
	order  []jobKey
	queues map[uint64]chan job
	// tickers: E1b, one tick chain per chain, started with the first attested anchor of the chain.
	tickers map[uint64]*Ticker
}

// Start starts the runtime. It returns (nil, nil) for an off switch and (nil, *Disabled) for a state it cannot run in; it never panics and
// every outcome is announced through pkg/metrics (gauge, counter, health) and logf.
func Start(ctx context.Context, set Settings, d Deps) (rt *Runtime, dis *Disabled) {
	logf := func(string, ...interface{}) {}
	if orig := d.Logf; orig != nil { // a logger that panics is no reason to stop
		logf = func(format string, args ...interface{}) {
			defer func() { _ = recover() }()
			orig(format, args...)
		}
		d.Logf = logf
	}
	defer func() {
		if r := recover(); r != nil {
			rt, dis = nil, &Disabled{Reason: "start_panicked"}
			metrics.AnnounceContractIdentityCaptureDisabled(dis.Reason, dis.Setting)
			logf("⚠️ [CONTRACT-IDENTITY] %v", dis)
		}
	}()
	if !set.Enabled {
		metrics.SetContractIdentityCapture(false, 0)
		logf("ℹ️ [CONTRACT-IDENTITY] capture is off (%s unset or off)", EnvSwitch)
		return nil, nil
	}
	switch {
	case d.Store == nil:
		dis = &Disabled{Reason: "no_durable_store"}
	case d.Manifest == nil:
		dis = &Disabled{Reason: "manifest_unavailable"}
	case d.SourceFor == nil:
		dis = &Disabled{Reason: "no_chain_reader"}
	}
	if dis != nil {
		metrics.AnnounceContractIdentityCaptureDisabled(dis.Reason, dis.Setting)
		logf("⚠️ [CONTRACT-IDENTITY] capture disabled: %v", dis)
		return nil, dis
	}
	if d.Clock == nil {
		d.Clock = ethproof.WallClock
	}
	rctx, cancel := context.WithCancel(ctx)
	rt = &Runtime{set: set, d: d, mem: &budget{cap: set.MemoryBytes}, ctx: rctx, stop: cancel, seen: map[jobKey]bool{}, queues: map[uint64]chan job{}, tickers: map[uint64]*Ticker{}}
	metrics.SetContractIdentityCapture(true, set.MemoryBytes)
	logf("✅ [CONTRACT-IDENTITY] capture on: %d captures per chain, %d provider calls at once, %d MiB budget", set.Concurrency, set.Parallel, set.MemoryBytes>>20)
	return rt, nil
}

// Stop ends the workers and waits for them.
func (r *Runtime) Stop() {
	if r == nil {
		return
	}
	r.stop()
	r.wg.Wait()
}

// MemoryInUse is the bytes reserved by running captures.
func (r *Runtime) MemoryInUse() int64 { return r.mem.inUse() }

// AttestationObserved is the E1 trigger: an attestation transaction a validator learned of. It matches the execution layer's observer
// type, never blocks, never panics and ignores a transaction it has already been told of.
func (r *Runtime) AttestationObserved(chainID int64, bundleID [32]byte, txHash common.Hash, _ uint64) {
	r.enqueue("attest", chainID, txHash, bundleID)
}

// SettlementObserved is the E2 trigger: a settlement transaction first observed (at inclusion, as the S6 capture is started).
func (r *Runtime) SettlementObserved(chainID int64, txHash common.Hash) {
	r.enqueue("settle", chainID, txHash, [32]byte{})
}

func (r *Runtime) enqueue(station string, chainID int64, tx common.Hash, bundle [32]byte) {
	defer func() { _ = recover() }()
	if r == nil || chainID <= 0 {
		return
	}
	chain := uint64(chainID)
	k := jobKey{station, chain, tx}
	r.mu.Lock()
	if r.seen[k] {
		r.mu.Unlock()
		return
	}
	if r.ctx.Err() != nil {
		r.mu.Unlock()
		return
	}
	q, ok := r.queues[chain]
	if !ok {
		q = make(chan job, queueDepth)
		r.queues[chain] = q
		for i := 0; i < r.set.Concurrency; i++ {
			r.wg.Add(1)
			go r.worker(chain, q)
		}
	}
	select {
	case q <- job{jobKey: k, bundle: bundle}:
		r.seen[k] = true
		r.order = append(r.order, k)
		if len(r.order) > seenBound { // forget the oldest: a re-trigger after that is a capture again, and the store makes it a no-op
			delete(r.seen, r.order[0])
			r.order = r.order[1:]
		}
	default:
		metrics.ContractIdentityCaptureDropped(chain, station, "queue_full")
	}
	r.mu.Unlock()
}

func (r *Runtime) worker(chain uint64, q chan job) {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case j := <-q:
			r.run(chain, j)
		}
	}
}

// run executes one job: reservation, capture, store. Every exit releases the reservation, the inflight count and recovers a panic.
func (r *Runtime) run(chain uint64, j job) {
	station := j.station
	release, ok := r.mem.reserve(WorkingSetBytes)
	if !ok {
		metrics.ContractIdentityCaptureDropped(chain, station, "memory_budget")
		return
	}
	defer release()
	metrics.ContractIdentityCaptureInflight(chain, station, 1)
	defer metrics.ContractIdentityCaptureInflight(chain, station, -1)
	start := time.Now()
	outcome := "error"
	defer func() {
		if p := recover(); p != nil {
			outcome = "panic"
			r.logf("⚠️ [CONTRACT-IDENTITY] chain %d %s capture of %s panicked: %v", chain, station, j.tx.Hex(), p)
		}
		metrics.ObserveContractIdentityCapture(chain, station, outcome, time.Since(start))
	}()
	src, err := r.d.SourceFor(chain)
	if err != nil || src == nil {
		outcome = "error"
		metrics.ContractIdentityCaptureDropped(chain, station, "no_chain_reader")
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, jobTimeout)
	defer cancel()
	cfg := r.chainConfig(chain, src)
	if station == "attest" {
		outcome = r.runAttest(ctx, cfg, j)
	} else {
		outcome = r.runSettle(ctx, cfg, j)
	}
}

func (r *Runtime) logf(format string, args ...interface{}) {
	if r.d.Logf != nil { // Start wrapped it: a panic in the logger is recovered there
		r.d.Logf(format, args...)
	}
}

// ChainBudget is the budget of one capture on a chain: Arbitrum's public proof window is about 100 blocks of 0.25 s, so its attestation
// capture must finish inside 20 s (measured 2026-10-24, see the AT-9 check-in); the other chains keep the S6 budget.
func ChainBudget(chain uint64) (budget, backoff time.Duration) {
	if chain == 421614 {
		return 20 * time.Second, 500 * time.Millisecond
	}
	return DefaultBudget, DefaultBackoff
}

func (r *Runtime) chainConfig(chain uint64, src AttestSource) Config {
	b, bo := ChainBudget(chain)
	return Config{Chain: chain, Manifest: r.d.Manifest, Source: src, Clock: r.d.Clock, Budget: b, Backoff: bo, Parallel: r.set.Parallel, Logf: r.d.Logf}
}

// outcomeOf names what a finished capture was.
func outcomeOf(stated *ci.Stated) string {
	if stated == nil {
		return "captured"
	}
	return "stated_" + stated.Reason
}

func (r *Runtime) runAttest(ctx context.Context, cfg Config, j job) string {
	res, err := CaptureAttest(ctx, cfg, AttestRequest{TxHash: j.tx, AnchorID: common.Hash(j.bundle)})
	switch {
	case errors.Is(err, ErrNotAttestation):
		return "not_attestation"
	case err != nil:
		var pe *PanicError
		r.logf("⚠️ [CONTRACT-IDENTITY] chain %d attest capture of %s: %v", cfg.Chain, j.tx.Hex(), err)
		if errors.As(err, &pe) {
			return "panic"
		}
		return "error"
	}
	if err := SaveAttest(ctx, r.d.Store, res); err != nil {
		return r.storeOutcome(cfg.Chain, "attest", res.Stated != nil, err)
	}
	if res.Stated == nil {
		r.track(cfg, res)
	}
	return outcomeOf(res.Stated)
}

// storeOutcome: a conflict on a captured row is an alarm (two honest captures disagreed), on a Stated row it means another validator
// stated first and is benign.
func (r *Runtime) storeOutcome(chain uint64, station string, stated bool, err error) string {
	if errors.Is(err, ErrCaptureConflict) {
		if stated {
			return "stated_already_stored"
		}
		r.logf("🚨 [CONTRACT-IDENTITY] chain %d %s: a captured row exists with other bytes", chain, station)
		return "conflict"
	}
	r.logf("⚠️ [CONTRACT-IDENTITY] chain %d %s: store: %v", chain, station, err)
	return "error"
}

// runSettle is E2: it needs the attestation's pubkey commitment and block, which the attestation station stored for the anchor.
func (r *Runtime) runSettle(ctx context.Context, cfg Config, j job) string {
	src := cfg.Source.(AttestSource)
	var tx = j.tx
	var facts *Facts
	deadline := r.d.Clock.Now().Add(receiptWait)
	for {
		t, found, terr := src.TransactionByHash(ctx, tx)
		if terr == nil && found {
			rc, rerr := src.TransactionReceipt(ctx, tx)
			if rerr == nil && rc != nil && rc.BlockNumber != nil {
				f, ferr := DeriveFacts(cfg.Manifest, cfg.Chain, t, rc, SettleRequest{})
				if ferr != nil {
					if errors.Is(ferr, ErrNotAccountSettlement) {
						return "not_account_settlement"
					}
					r.logf("⚠️ [CONTRACT-IDENTITY] chain %d settle %s: %v", cfg.Chain, tx.Hex(), ferr)
					return "error"
				}
				facts = f
				break
			}
		}
		if !r.d.Clock.Now().Before(deadline) || !r.d.Clock.Sleep(ctx, 2*time.Second) {
			return "error"
		}
	}
	att := r.waitAttest(ctx, cfg.Chain, facts.AnchorID)
	rcBlock, _ := src.TransactionReceipt(ctx, tx)
	if att == nil || att.Stated != nil || rcBlock == nil {
		blk := ci.BlockRef{}
		if rcBlock != nil {
			blk = ci.BlockRef{Number: rcBlock.BlockNumber.Uint64(), Hash: [32]byte(rcBlock.BlockHash)}
		}
		res := NotAttempted(cfg.Chain, facts.AnchorID, blk, "the attestation station holds no capture for the anchor")
		if err := SaveSettle(ctx, r.d.Store, res); err != nil {
			return r.storeOutcome(cfg.Chain, "settle", true, err)
		}
		return outcomeOf(res.Stated)
	}
	req := SettleRequest{TxHash: tx, PKC: att.PKC, Link: ci.LinkSpine}
	if plan, _, err := PlanLink(ctx, r.d.Store, cfg.Manifest, cfg.Chain, facts.AnchorID, att.Block, rcBlock.BlockNumber.Uint64()); err == nil {
		req.Link, req.HopNumbers = plan.Link, plan.HopNumbers
	} // out of reach: the settle part is captured without a hop read; the assembly states the attest part attest_block_out_of_reach
	res, err := CaptureSettle(ctx, cfg, req)
	if err != nil {
		r.logf("⚠️ [CONTRACT-IDENTITY] chain %d settle capture of %s: %v", cfg.Chain, tx.Hex(), err)
		var pe *PanicError
		if errors.As(err, &pe) {
			return "panic"
		}
		return "error"
	}
	if err := SaveSettle(ctx, r.d.Store, res); err != nil {
		return r.storeOutcome(cfg.Chain, "settle", res.Stated != nil, err)
	}
	r.untrack(cfg.Chain, facts.AnchorID)
	return outcomeOf(res.Stated)
}

// track hands an attested anchor to the tick chain of its chain (E1b), starting the chain's loop on first use. A chain without a tick
// chain, or a full tracker, leaves the anchor without hops: its legs beyond the window are then attest_block_out_of_reach, counted here.
func (r *Runtime) track(cfg Config, res *AttestResult) {
	defer func() { _ = recover() }()
	r.mu.Lock()
	t := r.tickers[cfg.Chain]
	if t == nil && r.ctx.Err() == nil {
		tc := TickConfig{Config: cfg, Store: r.d.Store, Poll: r.d.TickPoll, Reserve: func() (func(), bool) { return r.mem.reserve(TickWorkingSetBytes) }}
		if dl := safeDeadline(r.d.Deadline); dl != nil {
			chain := cfg.Chain
			tc.Deadline = func(a [32]byte) (time.Time, bool) { return dl(chain, a) }
		}
		nt, err := NewTicker(tc)
		if err != nil {
			r.mu.Unlock()
			metrics.ContractIdentityCaptureDropped(cfg.Chain, "tick", "no_tick_chain")
			return
		}
		t = nt
		r.tickers[cfg.Chain] = t
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() {
				if p := recover(); p != nil {
					r.logf("⚠️ [CONTRACT-IDENTITY] chain %d tick loop panicked: %v", cfg.Chain, p)
				}
			}()
			t.Run(r.ctx)
		}()
	}
	r.mu.Unlock()
	if t == nil {
		return
	}
	if err := t.Track(TrackedAnchor{AnchorID: res.AnchorID, Bv: res.Block}); err != nil {
		metrics.ContractIdentityCaptureDropped(cfg.Chain, "tick", "tracker_full")
	}
}

func (r *Runtime) untrack(chain uint64, anchorID common.Hash) {
	r.mu.Lock()
	t := r.tickers[chain]
	r.mu.Unlock()
	if t != nil {
		t.Untrack(anchorID)
	}
}

// waitAttest finds the attestation station's row for the anchor, waiting up to attestWait: E1 normally finished before the settlement.
func (r *Runtime) waitAttest(ctx context.Context, chain uint64, anchorID common.Hash) *AttestResult {
	deadline := r.d.Clock.Now().Add(attestWait)
	for {
		keys, err := r.d.Store.ListByAnchor(ctx, chain, anchorID)
		if err == nil {
			for _, k := range keys {
				if k.Item == ItemAttest {
					if res, lerr := LoadAttest(ctx, r.d.Store, chain, k.AnchorID, k.BlockHash); lerr == nil && res != nil {
						return res
					}
				}
			}
		}
		if !r.d.Clock.Now().Before(deadline) || !r.d.Clock.Sleep(ctx, time.Second) {
			// a Stated row is a row too
			for _, k := range keys {
				if k.Item == ItemAttestStated {
					if res, lerr := LoadAttest(ctx, r.d.Store, chain, k.AnchorID, k.BlockHash); lerr == nil {
						return res
					}
				}
			}
			return nil
		}
	}
}
