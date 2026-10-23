// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	"github.com/certen/independant-validator/pkg/finality/allkinds"
	arbbuild "github.com/certen/independant-validator/pkg/finality/arbfinal/build"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// LCFeed is the light-client source the wiring needs: the L1-finality part of the evidence and the beacon head slot it observed.
// The Lodestar-backed *LC of this package implements it; tests give a fixed one.
type LCFeed interface {
	FinalizedAt(ctx context.Context) (ethl1.LC, uint64, error)
}

// Env is what a kit gets to build its prover from.
type Env struct {
	Pins    *finality.Pins
	Config  Config
	LC      LCFeed
	HTTP    *http.Client
	Store   finality.CaptureStore
	Logf    func(string, ...any)
	L1Block []string // Sepolia execution endpoints
	L1Proof []string // near-head proof providers followed by the archive provider
	// Memory is the process memory budget the upgrader's builders, the gap backfill and the capture index reserve from (one budget, one process).
	Memory *finality.MemoryBudget
	// Durable is the store without the per-leg capture bound: index rows are not capture bytes.
	Durable finality.CaptureStore
}

// Deps are the process-level collaborators of the wiring.
type Deps struct {
	Registry *finality.Registry
	Store    finality.CaptureStore // the durable store (database.FinalityCaptureStore)
	Status   finality.BuilderStatusStore
	Logf     func(string, ...any)

	// Test hooks.
	HTTP  *http.Client
	LC    LCFeed
	Pins  *finality.Pins
	Clock loopClock
	Now   func() time.Time
}

// Wiring is the result of Wire: everything finality.Launch needs, and what the startup line and the health endpoint report.
type Wiring struct {
	Registry   *finality.Registry
	Pins       *finality.Pins
	PinsSource string
	PinsSHA256 string
	Store      finality.CaptureStore
	// Upgrader is the UpgraderConfig for finality.Launch: bounds from the environment, the status store, and the chains switched
	// off (their per-chain switch or a missing provider setting) with the named state that says why.
	Upgrader finality.UpgraderConfig
	// Disabled maps each chain that will not build to its named finality_upgrader_disabled state.
	Disabled map[uint64]*finality.StateError
	Config   Config
}

func disabledState(chain uint64, env, value, effect string) *finality.StateError {
	return finality.NewState(finality.CodeUpgraderDisabled, "chain", chain, "env", env, "value", value, "effect", effect)
}

// lcCache serves one light client to all builders for lcAge. The light client is untrusted input of a verifier: caching it only
// saves requests; a stale one is judged (and refused or accepted) by the verifier like any other.
type lcCache struct {
	inner LCFeed
	now   func() time.Time
	mu    sync.Mutex
	at    time.Time
	lc    ethl1.LC
	slot  uint64
	have  bool
}

func (c *lcCache) FinalizedAt(ctx context.Context) (ethl1.LC, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.have && c.now().Sub(c.at) < lcAge {
		return c.lc, c.slot, nil
	}
	lc, slot, err := c.inner.FinalizedAt(ctx)
	if err != nil {
		return ethl1.LC{}, 0, err
	}
	c.lc, c.slot, c.at, c.have = lc, slot, c.now(), true
	return lc, slot, nil
}

type lcPlain struct{ c *lcCache } // arbfinal/build.LCSource, arbposted via ArbL1

func (l lcPlain) LC(ctx context.Context) (ethl1.LC, error) {
	lc, _, err := l.c.FinalizedAt(ctx)
	return lc, err
}

// Finalized is baseposted.LCSource.
func (l lcPlain) Finalized(ctx context.Context) (ethl1.LC, error) { return l.LC(ctx) }

type lcSlot struct{ c *lcCache } // basefinal.LCSource

func (l lcSlot) Finalized(ctx context.Context) (ethl1.LC, uint64, error) { return l.c.FinalizedAt(ctx) }

// Wire builds, from cfg and the process collaborators, the provers and capturers of every live chain, registers them (and the
// verifier kinds) into d.Registry and returns the UpgraderConfig for finality.Launch. A chain whose providers are not configured,
// whose pins section cannot be read, or whose kind is not built in is returned in Wiring.Disabled with the named state, and is
// announced (log and metric) by Launch: nothing is skipped silently and nothing here panics. An error is returned only for a
// failure that makes the whole feature unsafe to start (the embedded pins fail their hash, a registration conflict).
func Wire(cfg Config, d Deps) (*Wiring, error) {
	logf := d.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf = ethrpc.RedactingLogf(logf)
	if d.Registry == nil || d.Store == nil {
		return nil, fmt.Errorf("finality runtime: a registry and a capture store are required")
	}
	cfg.RegisterRedaction()

	pins := d.Pins
	var source, sha string
	if pins == nil {
		var err error
		if pins, source, sha, err = LoadPins(cfg.PinsFile); err != nil {
			return nil, err
		}
	} else {
		sha, source = pins.Identity()
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	clock := d.Clock
	if clock.Now == nil {
		clock.Now = now
	}

	reg := d.Registry
	if err := allkinds.Register(reg); err != nil {
		return nil, err
	}

	hc := d.HTTP
	if hc == nil {
		hc = NewTransport(cfg).Client(90 * time.Second)
	}
	store := finality.CaptureStore(NewBudgetedStore(d.Store, cfg.CaptureBytes))

	var lcf LCFeed = d.LC
	if lcf == nil {
		lcf = &LC{URLs: cfg.LC, Pins: pins, HTTP: hc, Logf: logf}
	}
	cache := &lcCache{inner: lcf, now: now}
	l1Proof := cfg.proofURLs()
	mem := finality.NewMemoryBudget(cfg.MemoryBudget)
	env := Env{Pins: pins, Config: cfg, LC: cache, HTTP: hc, Store: store, Logf: logf, L1Block: cfg.L1RPC, L1Proof: l1Proof, Memory: mem, Durable: d.Store}

	w := &Wiring{Registry: reg, Pins: pins, PinsSource: source, PinsSHA256: sha, Store: store, Disabled: map[uint64]*finality.StateError{}, Config: cfg}

	// the chains whose providers are not configured
	missing := cfg.Missing()
	for chain, envs := range missing {
		w.Disabled[chain] = disabledState(chain, envs[0], "unset",
			fmt.Sprintf("no finality addenda are appended and nothing is captured for chain %d by this validator: %s names a provider this chain's builders need and it is not configured; its proofs stay at the level they were stored at", chain, envs[0]))
	}

	type setup struct {
		chain uint64
		name  string
		build func() error
	}
	setups := []setup{
		{finality.ChainAdiri, "adiri", func() error {
			return reg.RegisterProver(&adiri.Prover{Endpoints: cfg.Adiri, ProofEndpoints: cfg.AdiriPF, Client: hc, Pins: pins, Verifier: adiri.NewVerifier(),
				Now: now, BatchSize: cfg.MaxBatch})
		}},
		{finality.ChainSepolia, "ethereum-sepolia", func() error { return wireSepolia(reg, env, d) }},
		{finality.ChainBaseSepolia, "base-sepolia", func() error { return wireBase(reg, env, d, clock, logf) }},
		{finality.ChainArbitrumSepolia, "arbitrum-sepolia", func() error { return wireArb(reg, env, d, clock, logf, cache) }},
	}
	for _, s := range setups {
		if w.Disabled[s.chain] != nil {
			continue
		}
		if err := s.build(); err != nil {
			// a pins section that cannot be read, or a provider that cannot be built, switches THIS chain off by name
			w.Disabled[s.chain] = disabledState(s.chain, "pins:"+s.name, "unusable",
				fmt.Sprintf("the %s builders could not be built (%s); no finality addenda are appended for chain %d by this validator", s.name, ethrpc.RedactText(err.Error()), s.chain))
		}
	}
	// the per-chain switches (CERTEN_FINALITY_CHAIN_<id>_ENABLED) join the missing-configuration chains
	off, err := finality.DisabledChainsFromEnv(reg.Chains())
	if err != nil {
		return nil, err
	}
	disabled := map[uint64]bool{}
	reasons := map[uint64]*finality.StateError{}
	for c := range off {
		disabled[c] = true // announced as its switch (the default reason)
	}
	for c, st := range w.Disabled {
		if !disabled[c] {
			disabled[c], reasons[c] = true, st
		}
	}
	w.Upgrader = finality.UpgraderConfig{
		Concurrency: cfg.Concurrency, Interval: cfg.Interval, BuildTimeout: cfg.BuildTimeout, Memory: mem,
		Status: d.Status, DisabledChains: disabled, DisabledReasons: reasons, Logf: logf, Now: d.Now,
	}
	chains := make([]uint64, 0, len(w.Disabled))
	for c := range w.Disabled {
		chains = append(chains, c)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i] < chains[j] })
	logf("[FINALITY] runtime wiring: pins_source=%s pins_sha256=%s chains_off_by_configuration=%v config=%v", source, sha, chains, cfg.Describe())
	return w, nil
}

func wireBase(reg *finality.Registry, env Env, d Deps, clock loopClock, logf func(string, ...any)) error {
	cfg := env.Config
	bp, err := baseposted.ParsePins(env.Pins)
	if err != nil {
		return err
	}
	if cfg.IndexDisabled != nil {
		finality.AnnounceIndexDisabled(logf, cfg.IndexDisabled)
	}
	fp, err := basefinal.ParsePins(env.Pins)
	if err != nil {
		return err
	}
	l1 := &baseposted.JSONRPCSource{BlockURLs: env.L1Block, ProofURLs: env.L1Proof, Client: env.HTTP}
	cache := env.LC.(*lcCache)
	builder := &baseposted.Builder{Pins: env.Pins, Store: env.Store, L1: l1, Headers: l1,
		L2: &baseposted.L2JSONRPC{URLs: cfg.BaseL2}, LC: lcPlain{cache}, Now: d.Now,
		CursorSlack: captureSlack(cfg), HasArchive: len(cfg.Archive) > 0}
	// the capture index (RB12-INDEX-A): built as captures arrive, read by the builder; off by CERTEN_FINALITY_BASE_INDEX=off
	var indexer finality.CaptureIndexer
	if cfg.BaseIndex {
		builder.Index = baseposted.NewIndexReader(env.Store, bp, cfg.IndexGeneration)
		durable := env.Durable
		if durable == nil {
			durable = env.Store
		}
		indexer = baseposted.NewIndexer(durable, bp, cfg.IndexGeneration, baseposted.IndexConfig{BlocksPerStep: cfg.IndexBlocks, StepBudget: cfg.IndexStep, Logf: logf})
	}
	if err := reg.RegisterProver(builder); err != nil {
		return err
	}
	rpc := &basefinal.RPC{BlockURLs: env.L1Block, ProofURLs: env.L1Proof, L2URLs: cfg.BaseL2, Client: env.HTTP}
	if err := reg.RegisterProver(&basefinal.Builder{Pins: env.Pins, Store: env.Store, Games: &basefinal.LiveGames{RPC: rpc, Portal: fp.Portal},
		L1: rpc, L2: rpc, LC: lcSlot{cache}, Now: d.Now, Providers: Hosts(env.L1Proof)}); err != nil {
		return err
	}
	capt := &baseposted.Capturer{Chain: finality.ChainBaseSepolia, Pins: bp, L1: l1, Beacon: &baseposted.BeaconHTTP{Bases: cfg.Beacon, Client: env.HTTP},
		Store: env.Store, GenesisTime: capture.BeaconGenesisTime, SlotSeconds: 12}
	if err := reg.RegisterCapturer(&BasePostedLoop{Cap: capt, Store: env.Store, Status: d.Status, Pins: env.Pins, Every: cfg.CaptureEvery, MaxPerTick: cfg.CaptureBlocks,
		StartBack: 32, HasArchive: len(cfg.Archive) > 0, Logf: logf, Clock: clock, Index: indexer, Memory: env.Memory}); err != nil {
		return err
	}
	// RB12-CAPTURE-GAP: the loop that closes the recorded capture gaps with the same capture call (the providers are the same, plus the archive
	// provider when one is configured), one block at a time, inside the process memory budget
	bf := &baseposted.Backfiller{Chain: finality.ChainBaseSepolia, Store: env.Store, Capturer: baseposted.CapturerOf(capt), Providers: Hosts(cfg.Beacon),
		Policy: baseposted.DefaultBackfillPolicy(), Now: d.Now, Logf: logf}
	return reg.RegisterCapturer(&GapBackfillLoop{ChainID: finality.ChainBaseSepolia, Store: env.Store, Backfill: bf, Every: cfg.CaptureEvery, PerTick: cfg.GapBlocks,
		AuditSpacing: uint64(cfg.GapAuditSpacing), Memory: env.Memory, Logf: logf, Clock: clock})
}

// captureSlack is how many blocks before its first cursor row the Base capture loop may have started scanning: its first range ends
// at the head and reaches back by the larger of its start-back (32) and its per-tick block bound.
func captureSlack(cfg Config) uint64 {
	n := uint64(cfg.CaptureBlocks)
	if n < 32 {
		n = 32
	}
	return n
}

func wireArb(reg *finality.Registry, env Env, d Deps, clock loopClock, logf func(string, ...any), cache *lcCache) error {
	cfg := env.Config
	hdr := &baseposted.JSONRPCSource{BlockURLs: env.L1Block, ProofURLs: env.L1Proof, Client: env.HTTP}
	if err := reg.RegisterProver(&arbposted.Builder{Store: env.Store, L2: &ArbL2{URLs: cfg.ArbL2, HTTP: env.HTTP},
		L1: &ArbL1{LC: lcPlain{cache}, Headers: hdr}, Pins: env.Pins, Now: d.Now}); err != nil {
		return err
	}
	if err := reg.RegisterProver(&arbbuild.Prover{Pins: env.Pins, Store: env.Store,
		L1: &arbbuild.LiveL1{Endpoints: env.L1Block, ProofEndpoints: env.L1Proof, HTTP: env.HTTP},
		L2: &arbbuild.LiveL2{Endpoints: cfg.ArbL2, HTTP: env.HTTP}, LC: lcPlain{cache}}); err != nil {
		return err
	}
	// the capture providers: the execution endpoints first (logs, blocks), then the proof providers and the archive provider
	providers := ethrpc.ParseEndpoints(append(append([]string(nil), env.L1Block...), env.L1Proof...)...)
	l1 := capture.NewHTTPL1(providers...)
	l1.Client = env.HTTP
	bc := capture.NewHTTPBeacon(cfg.Beacon...)
	bc.Client = env.HTTP
	cp := capture.NewCapturer(env.Store, l1, bc, capture.Config{Logf: logf, StartBack: 32})
	return reg.RegisterCapturer(&ArbPostedLoop{Cap: cp, Providers: Hosts(providers), Status: d.Status, Pins: env.Pins, Every: cfg.CaptureEvery, Logf: logf, Clock: clock})
}

// wireSepolia registers the Ethereum Sepolia finalized prover: the light-client objects come from the ordered CERTEN_FINALITY_LC_URLS
// list (availability only, in order), the execution headers of the spine from the validator's Sepolia endpoints (JSON-RPC batches
// of at most MaxBatch, 429 retried with a bounded backoff by the shared transport and by the source itself), and the ledger link
// files are the embedded ones. A spine of several thousand headers takes minutes on a public endpoint: the prover runs only in the
// background upgrader pass, under the pass's BuildTimeout (CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS), never on the settlement path.
func wireSepolia(reg *finality.Registry, env Env, d Deps) error {
	cfg := env.Config
	links, err := finality.EmbeddedLedgerLinks()
	if err != nil {
		return err
	}
	srcs := make(ethsepolia.Multi, 0, len(cfg.LC))
	for _, u := range cfg.LC {
		srcs = append(srcs, &ethsepolia.HTTPSource{Base: strings.TrimRight(u, "/"), Client: env.HTTP})
	}
	return reg.RegisterProver(&ethsepolia.Prover{Source: srcs, Exec: &ethsepolia.RPCHeaders{Endpoints: env.L1Block, Client: env.HTTP, BatchSize: cfg.MaxBatch},
		Pins: env.Pins, Verifier: ethsepolia.New(), Now: d.Now, ExtraLinks: links})
}
