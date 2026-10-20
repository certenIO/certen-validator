// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// LegRef names a settled leg cheaply: its stored proof (one leg per proof_artifacts row) and the chain it settled on. The leg's
// binding D0 is computed from its Settlement block, not carried here.
type LegRef struct {
	ProofID string
	Chain   uint64
}

// LegSource lists the settled legs the worker upgrades and loads one leg's L6 evidence on demand.
type LegSource interface {
	// SettledLegs returns up to limit legs whose proof id sorts after `after` (empty for the first page), ascending by
	// proof id. A source may leave out legs that are certainly complete (a finalized addendum exists).
	SettledLegs(ctx context.Context, after string, limit int) ([]LegRef, error)
	// LegSettlement loads the leg's settlement with its L6 evidence (Settlement.Included). A leg whose L6 evidence cannot
	// be read is a Named state, not a zero value.
	LegSettlement(ctx context.Context, ref LegRef) (Settlement, error)
}

// AddendumStore is the append-only store of addenda (pkg/database.FinalityAddendaRepository). It has no update or delete.
type AddendumStore interface {
	// Append writes the next addendum of a proof's chain. If another writer appended that seq first, the error is the named
	// finality_append_conflict state.
	Append(ctx context.Context, a Addendum) error
	// Chain returns a proof's addenda, ascending by seq.
	Chain(ctx context.Context, proofID string) ([]Addendum, error)
}

// Recorder receives the upgrader's metrics; MetricsRecorder is the Prometheus one.
type Recorder interface {
	Appended(chain uint64, level Level)
	BuildFailed(chain uint64, code string)
	Pending(chain uint64, reached Level)
	ChainBroken(chain uint64)
	LegsAt(chain uint64, level Level, n int)
	Pass(d time.Duration, finished time.Time)
}

// MetricsRecorder reports to pkg/metrics (the series are listed in pkg/metrics/finality_metrics.go).
type MetricsRecorder struct{}

func (MetricsRecorder) Appended(chain uint64, l Level) {
	metrics.IncFinalityAppended(chain, l.String())
}
func (MetricsRecorder) BuildFailed(chain uint64, c string) { metrics.IncFinalityBuildFailure(chain, c) }
func (MetricsRecorder) Pending(chain uint64, l Level)      { metrics.IncFinalityPending(chain, l.String()) }
func (MetricsRecorder) ChainBroken(chain uint64)           { metrics.IncFinalityChainBroken(chain) }
func (MetricsRecorder) LegsAt(chain uint64, l Level, n int) {
	metrics.SetFinalityLegs(chain, l.String(), n)
}
func (MetricsRecorder) Pass(d time.Duration, t time.Time) { metrics.ObserveFinalityPass(d, t) }

// UpgraderConfig bounds the worker. Zero values take the defaults.
type UpgraderConfig struct {
	Concurrency  int           // legs processed at once (default 4)
	Interval     time.Duration // between passes (default 60s)
	PageSize     int           // legs listed per source call (default 200)
	BuildTimeout time.Duration // one prover's Build (default 5m); a prover that ignores its context is abandoned at this deadline
	PendingRetry time.Duration // next attempt for a leg with no ETA (default 2m)
	FailureRetry time.Duration // next attempt after a named build failure (default 5m)
	BrokenRetry  time.Duration // next attempt after a stored chain failed verification (default 1h)
	Logf         func(format string, args ...any)
	Now          func() time.Time
	Jitter       func(time.Duration) time.Duration // spreads retries across validators that share one database
	Recorder     Recorder
}

func (c UpgraderConfig) withDefaults() UpgraderConfig {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.PageSize <= 0 {
		c.PageSize = 200
	}
	def(&c.Interval, 60*time.Second)
	def(&c.BuildTimeout, 5*time.Minute)
	def(&c.PendingRetry, 2*time.Minute)
	def(&c.FailureRetry, 5*time.Minute)
	def(&c.BrokenRetry, time.Hour)
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Jitter == nil {
		c.Jitter = func(d time.Duration) time.Duration {
			if d <= 0 {
				return d
			}
			return d + time.Duration(rand.Int63n(int64(d)/5+1))
		}
	}
	if c.Recorder == nil {
		c.Recorder = MetricsRecorder{}
	}
	return c
}

// Upgrader is the background worker that appends the strongest finality level now buildable to each settled leg's addendum
// chain and re-schedules the leg until its chain reaches the chain's top level. It runs beside settlement, attestation and
// write-back and shares nothing with them: it reads stored proofs, calls provers under deadlines, and appends to its own
// table. Nothing it does can delay or fail a settlement, an attestation or a write-back, and every failure of its own is a
// named state in a log line and a metric.
type Upgrader struct {
	src   LegSource
	store AddendumStore
	reg   *Registry
	pins  *Pins
	cfg   UpgraderConfig

	mu       sync.Mutex
	next     map[string]time.Time // proof id -> earliest next attempt
	complete map[string]Level     // proof id -> level it completed at (skipped from now on)
	stand    map[string]legStand  // proof id -> where its chain stood at the last attempt, for the gauges
	noProver map[uint64]bool      // chains already announced as having no registered prover
}

type legStand struct {
	chain uint64
	level Level
}

// NewUpgrader builds the worker; it starts nothing.
func NewUpgrader(src LegSource, store AddendumStore, reg *Registry, pins *Pins, cfg UpgraderConfig) (*Upgrader, error) {
	if src == nil || store == nil || reg == nil {
		return nil, errors.New("finality: an upgrader needs a leg source, an addendum store and a registry")
	}
	return &Upgrader{
		src: src, store: store, reg: reg, pins: pins, cfg: cfg.withDefaults(),
		next: map[string]time.Time{}, complete: map[string]Level{}, stand: map[string]legStand{}, noProver: map[uint64]bool{},
	}, nil
}

// PassReport counts what one pass did.
type PassReport struct {
	Listed   int // legs the source returned
	NotDue   int // skipped: scheduled for later
	Complete int // legs at the top level of their chain (not attempted)
	Attempts int
	Appended int // addenda appended
	Pending  int // attempts that ended in finality_pending
	Failed   int // attempts that ended in another named state
	Broken   int // legs whose stored chain failed verification (nothing appended)
	Conflict int // appends another validator won
	NoProver int // legs of a chain with no registered prover: not loaded, not verified, not scheduled (logged once per chain)
	Unusable int // legs whose L6 evidence could not be loaded
	// SourceErr is a failure listing legs (the pass ended early).
	SourceErr error
}

// Run passes every Interval until ctx is cancelled, and returns when the pass in flight has stopped.
func (u *Upgrader) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep := u.RunOnce(ctx)
		if rep.SourceErr != nil && ctx.Err() == nil {
			u.cfg.Logf("[FINALITY] pass could not list settled legs: %v", rep.SourceErr)
		}
		if rep.Appended > 0 || rep.Failed > 0 || rep.Broken > 0 || rep.Unusable > 0 {
			u.cfg.Logf("[FINALITY] pass: listed=%d attempts=%d appended=%d pending=%d failed=%d broken=%d conflict=%d unusable=%d complete=%d",
				rep.Listed, rep.Attempts, rep.Appended, rep.Pending, rep.Failed, rep.Broken, rep.Conflict, rep.Unusable, rep.Complete)
		}
		t.Reset(u.cfg.Interval)
	}
}

// RunOnce makes one pass over the settled legs. It honours ctx: when it is cancelled no new leg starts and the pass returns
// as soon as the legs in flight have returned (each is bounded by BuildTimeout and by ctx).
func (u *Upgrader) RunOnce(ctx context.Context) PassReport {
	start := u.cfg.Now()
	var rep PassReport
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, u.cfg.Concurrency)

	after := ""
page:
	for ctx.Err() == nil {
		refs, err := u.src.SettledLegs(ctx, after, u.cfg.PageSize)
		if err != nil {
			rep.SourceErr = err
			break
		}
		if len(refs) == 0 {
			break
		}
		after = refs[len(refs)-1].ProofID
		for _, ref := range refs {
			rep.Listed++
			switch {
			case len(u.reg.Provers(ref.Chain)) == 0:
				// nothing can be built for this chain until a prover is registered: its L6 evidence is not reloaded and
				// re-verified on every retry. Counted in every pass and announced once per chain.
				rep.NoProver++
				u.announceNoProver(ref.Chain)
				continue
			case u.isComplete(ref.ProofID):
				rep.Complete++
				continue
			case !u.due(ref.ProofID):
				rep.NotDue++
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break page
			}
			wg.Add(1)
			go func(ref LegRef) {
				defer wg.Done()
				defer func() { <-sem }()
				res := u.upgradeLeg(ctx, ref)
				mu.Lock()
				rep.Attempts++
				rep.Appended += res.appended
				rep.Pending += b2i(res.pending != nil)
				rep.Failed += b2i(res.failed)
				rep.Broken += b2i(res.broken)
				rep.Conflict += b2i(res.conflict)
				rep.Unusable += b2i(res.unusable)
				mu.Unlock()
			}(ref)
		}
		if len(refs) < u.cfg.PageSize {
			break
		}
	}
	wg.Wait()
	u.publishGauges()
	u.cfg.Recorder.Pass(u.cfg.Now().Sub(start), u.cfg.Now())
	return rep
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (u *Upgrader) announceNoProver(chain uint64) {
	u.mu.Lock()
	seen := u.noProver[chain]
	u.noProver[chain] = true
	u.mu.Unlock()
	if !seen {
		u.cfg.Logf("[FINALITY] chain %d has no registered prover: its legs are counted as no_prover and are not loaded or attempted until one is registered", chain)
	}
}

func (u *Upgrader) isComplete(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.complete[id]
	return ok
}

func (u *Upgrader) due(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	at, ok := u.next[id]
	return !ok || !u.cfg.Now().Before(at)
}

func (u *Upgrader) schedule(id string, after time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.next[id] = u.cfg.Now().Add(u.cfg.Jitter(after))
}

func (u *Upgrader) record(id string, chain uint64, level Level, done bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stand[id] = legStand{chain, level}
	if done {
		u.complete[id] = level
		delete(u.next, id)
	}
}

// publishGauges sets certen_finality_legs for every profiled chain and level from where each known leg stands.
func (u *Upgrader) publishGauges() {
	u.mu.Lock()
	counts := map[uint64]map[Level]int{}
	for _, s := range u.stand {
		if counts[s.chain] == nil {
			counts[s.chain] = map[Level]int{}
		}
		counts[s.chain][s.level]++
	}
	u.mu.Unlock()
	for _, chain := range u.reg.Chains() {
		for _, l := range append([]Level{LevelNone}, Levels...) {
			u.cfg.Recorder.LegsAt(chain, l, counts[chain][l])
		}
	}
}

type legResult struct {
	appended int
	pending  *PendingState
	failed   bool
	broken   bool
	conflict bool
	unusable bool
}

// storedOffered are the stored levels (l1_posted, finalized) the chain's profile offers, ascending.
func storedOffered(p ChainProfile) []Level {
	var out []Level
	for _, l := range p.Levels {
		if l.Stored() {
			out = append(out, l)
		}
	}
	return out
}

// upgradeLeg appends every stored level the leg does not yet hold that a prover can build and the offline Kind confirms
// (any order, at most one addendum per level, V2_SPEC_S7 R1) and schedules the leg's next attempt. D0 is the LegBinding of
// the leg's Settlement block, recomputed on every pass; a stored chain that does not verify against it is never extended.
func (u *Upgrader) upgradeLeg(ctx context.Context, ref LegRef) (res legResult) {
	logf := u.cfg.Logf
	defer func() {
		if r := recover(); r != nil {
			res.failed = true
			u.cfg.Recorder.BuildFailed(ref.Chain, CodePanic)
			logf("[FINALITY] leg %s chain %d: %s: %v", ref.ProofID, ref.Chain, CodePanic, r)
			u.schedule(ref.ProofID, u.cfg.FailureRetry)
		}
	}()
	profile, err := u.reg.Profile(ref.Chain)
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s: %v", ref.ProofID, err)
		u.schedule(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}
	proofID, err := ParseProofID(ref.ProofID)
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s: %v", ref.ProofID, err)
		u.schedule(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}

	settlement, err := u.src.LegSettlement(ctx, ref)
	if err != nil {
		res.unusable = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s chain %d: its L6 evidence cannot be used: %v", ref.ProofID, ref.Chain, err)
		u.record(ref.ProofID, ref.Chain, LevelNone, false)
		u.schedule(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}
	// The leg's block is DERIVED from the verified L6 evidence (level 1): never taken from the source's Subject, which is a
	// stored claim. D0 is the binding of the derived block.
	block, err := DeriveIncluded(ref.Chain, settlement.Included)
	if err != nil {
		res.unusable = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s chain %d: its L6 evidence cannot be used: %v", ref.ProofID, ref.Chain, err)
		u.record(ref.ProofID, ref.Chain, LevelNone, false)
		u.schedule(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}
	d0 := LegBindingOf(block)

	chain, err := u.store.Chain(ctx, ref.ProofID)
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, "store_read")
		logf("[FINALITY] leg %s: reading its addenda: %v", ref.ProofID, err)
		u.schedule(ref.ProofID, u.cfg.FailureRetry)
		return res
	}
	if err := VerifyChain(d0, chain); err != nil {
		return u.brokenChain(ref, err)
	}
	if len(chain) > 0 && chain[0].Chain != ref.Chain {
		return u.brokenChain(ref, ChainBroken(1, CheckKind, "stored", chain[0].Chain, "settled_on", ref.Chain))
	}
	have := LevelsOf(chain)
	current := Top(chain)
	var targets []Level
	for _, l := range storedOffered(profile) {
		if !have.Has(l) {
			targets = append(targets, l)
		}
	}
	if len(targets) == 0 {
		u.record(ref.ProofID, ref.Chain, current, true)
		return res
	}

	// For each missing level, ask every prover that can still serve it; keep the earliest pending.
	var pendings []*PendingState
	failure := ""
	for _, target := range targets {
		for _, p := range u.reg.Provers(ref.Chain) {
			if c, ok := p.(Ceilinged); ok && c.Ceiling() < target {
				continue
			}
			add, pd, err := u.build(ctx, p, settlement.Included, have, target)
			if ctx.Err() != nil {
				return res // cancelled: leave the schedule alone, nothing was judged
			}
			if err != nil {
				if st, ok := AsNamed(err); ok && st.Code == CodeNotApplicable {
					continue // the chain does not have that level: nothing to build, nothing wrong
				}
				failure = codeOf(err)
				u.cfg.Recorder.BuildFailed(ref.Chain, failure)
				logf("[FINALITY] leg %s chain %d: build of %s refused: %v", ref.ProofID, ref.Chain, target, err)
				res.failed = true
				continue // a refusal claims no level
			}
			if pd != nil {
				pendings = append(pendings, pd)
			}
			if add == nil || add.Level != target {
				continue
			}
			// never append what the offline Kind does not confirm
			if _, verr := u.reg.JudgeAddendum(block, *add, u.pins); verr != nil {
				res.failed = true
				u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(verr))
				logf("[FINALITY] leg %s chain %d: built %s evidence that does not verify offline: %v", ref.ProofID, ref.Chain, target, verr)
				continue
			}
			a, err := NewAddendum(d0, proofID, chain, ref.Chain, add.Level, add.Kind, add.Evidence)
			if err != nil {
				res.failed = true
				u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
				logf("[FINALITY] leg %s chain %d: cannot form the %s addendum: %v", ref.ProofID, ref.Chain, target, err)
				continue
			}
			if err := u.store.Append(ctx, a); err != nil {
				if n, ok := AsNamed(err); ok && n.Code == CodeAppendConflict {
					res.conflict = true // another validator appended first; the next pass reads its chain
					break
				}
				res.failed = true
				u.cfg.Recorder.BuildFailed(ref.Chain, "store_write")
				logf("[FINALITY] leg %s chain %d: appending the %s addendum: %v", ref.ProofID, ref.Chain, target, err)
				continue
			}
			chain = append(chain, a)
			have = have.With(a.Level)
			if a.Level > current {
				current = a.Level
			}
			res.appended++
			u.cfg.Recorder.Appended(ref.Chain, a.Level)
			logf("[FINALITY] leg %s chain %d reached %s (addendum %d, kind %s)", ref.ProofID, ref.Chain, a.Level, a.Seq, a.Kind)
			break // one addendum per level
		}
	}

	done := true
	for _, l := range storedOffered(profile) {
		if !have.Has(l) {
			done = false
		}
	}
	u.record(ref.ProofID, ref.Chain, current, done)
	if done {
		return res
	}
	switch {
	case len(pendings) > 0:
		res.pending = pendings[0]
		u.cfg.Recorder.Pending(ref.Chain, current)
		// not before the earliest stated ETA; a pending without an ETA is retried at PendingRetry
		wait := time.Duration(-1)
		for _, pd := range pendings {
			w := u.cfg.PendingRetry
			if !pd.ETA.IsZero() {
				w = pd.ETA.Sub(u.cfg.Now())
				if w < time.Second {
					w = time.Second
				}
			}
			if wait < 0 || w < wait {
				wait = w
			}
		}
		u.schedule(ref.ProofID, wait)
	case res.failed || failure != "":
		u.schedule(ref.ProofID, u.cfg.FailureRetry)
	default:
		u.schedule(ref.ProofID, u.cfg.PendingRetry)
	}
	return res
}

func (u *Upgrader) brokenChain(ref LegRef, err error) legResult {
	u.cfg.Recorder.ChainBroken(ref.Chain)
	u.cfg.Logf("[FINALITY] leg %s chain %d: its stored addendum chain does not verify and nothing is appended to it: %v", ref.ProofID, ref.Chain, err)
	u.schedule(ref.ProofID, u.cfg.BrokenRetry)
	return legResult{broken: true}
}

// build runs one prover under BuildTimeout and recovers its panic. A prover that ignores its context is abandoned at the
// deadline: the leg is reported as a named timeout and the worker moves on, so no prover can stall the pass.
func (u *Upgrader) build(ctx context.Context, p Prover, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error) {
	bctx, cancel := context.WithTimeout(ctx, u.cfg.BuildTimeout)
	defer cancel()
	type out struct {
		add *Addendum
		pd  *PendingState
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{err: NewState(CodePanic, "chain", p.Chain(), "panic", fmt.Sprint(r))}
			}
		}()
		add, pd, err := p.Build(bctx, s, have, target)
		ch <- out{add, pd, err}
	}()
	select {
	case o := <-ch:
		return o.add, o.pd, o.err
	case <-bctx.Done():
		return nil, nil, NewState(CodeBuildTimeout, "chain", p.Chain(), "after", u.cfg.BuildTimeout, "cause", bctx.Err().Error())
	}
}

func codeOf(err error) string {
	if n, ok := AsNamed(err); ok {
		return n.Code
	}
	return "unnamed_error"
}

// ---- the enable flag ----

// EnvEnabled switches the upgrader. Unset means ON; a value that is not a switch refuses startup by name.
const EnvEnabled = "CERTEN_FINALITY_UPGRADER_ENABLED"

// Enabled reads EnvEnabled (default on).
func Enabled() (bool, error) { return envvar.Bool(EnvEnabled, true) }

// Launch starts the upgrader on its own goroutine, or, when it is switched off, reports the named state
// finality_upgrader_disabled in the log and the metric: an off switch is never a silent skip. It returns the started worker
// (nil when off). It never blocks the caller.
func Launch(ctx context.Context, enabled bool, src LegSource, store AddendumStore, reg *Registry, pins *Pins, cfg UpgraderConfig) (*Upgrader, error) {
	cfg = cfg.withDefaults()
	if !enabled {
		st := NewState(CodeUpgraderDisabled, "env", EnvEnabled, "value", "false",
			"effect", "no finality addenda are appended by this validator; proofs stay at the level they were stored at")
		cfg.Logf("[FINALITY] upgrader DISABLED: %s", st.Error())
		metrics.SetFinalityUpgraderEnabled(false)
		return nil, nil
	}
	u, err := NewUpgrader(src, store, reg, pins, cfg)
	if err != nil {
		return nil, err
	}
	metrics.SetFinalityUpgraderEnabled(true)
	cfg.Logf("[FINALITY] upgrader ENABLED (%s): concurrency=%d interval=%s chains=%v", EnvEnabled, cfg.Concurrency, cfg.Interval, reg.Chains())
	go u.Run(ctx)
	return u, nil
}
