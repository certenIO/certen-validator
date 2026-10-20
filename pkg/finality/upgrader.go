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
	"github.com/certen/independant-validator/pkg/ethrpc"
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
	// Append extends the leg's chain by one addendum, under the proof's lock, and stores it only if the registered Kind
	// verifies the evidence (V2_SPEC_S7 2.4; see PlanAppend). It returns the stored addendum. A refused build is the verifier's
	// named state and leaves nothing; a second addendum at a stored level is level_already_present; a lost race that could
	// not be retried is finality_append_conflict.
	Append(ctx context.Context, req AppendRequest) (Addendum, error)
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

// StatusRecorder is the optional half of a Recorder that counts builder status rows (certen_finality_status_total).
type StatusRecorder interface {
	Status(chain uint64, target Level, state string)
	StatusWriteFailed(chain uint64)
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
func (MetricsRecorder) Status(chain uint64, target Level, state string) {
	metrics.IncFinalityStatus(chain, target.String(), state)
}
func (MetricsRecorder) StatusWriteFailed(chain uint64) { metrics.IncFinalityStatusWriteFailure(chain) }

// MinPoll is the floor of every polling interval of the upgrader: a configured value below it is raised to it, so no
// configuration makes the worker a tight loop (V2_SPEC_S7 8.3).
const MinPoll = time.Second

// UpgraderConfig bounds the worker. Zero values take the defaults.
type UpgraderConfig struct {
	Concurrency  int           // legs processed at once (default 4)
	Interval     time.Duration // between passes (default 60s, at least MinPoll)
	PageSize     int           // legs listed per source call (default 200)
	BuildTimeout time.Duration // one prover's Build or one verified Append (default 5m); a call that ignores its context is abandoned at this deadline
	// PendingRetry is the bounded polling interval of a level whose prover states NO eta (default 2m, at least MinPoll): the
	// V2_SPEC_S7 8.3 constant that keeps such a level from being polled in a tight loop. A level WITH an eta is not asked
	// before it, whatever this value is.
	PendingRetry time.Duration
	FailureRetry time.Duration // next ask of a level after a named build failure or refusal (default 5m, at least MinPoll)
	BrokenRetry  time.Duration // next attempt after a stored chain failed verification (default 1h, at least MinPoll)
	// StoreTimeout bounds every call to the leg source, the addendum store's reads and the status store; a call that ignores
	// its context is abandoned at the deadline (default 30s), so a hung database stalls neither the pass nor shutdown.
	StoreTimeout time.Duration
	// Status receives the builder status rows (V2_SPEC_S7 2.7: pending / unavailable / refused / not applicable / verified,
	// each with the level reached, the next level and the eta). Nil keeps the status in logs and metrics only.
	Status BuilderStatusStore
	// DisabledChains are the chains whose per-chain switch is off: their legs are not loaded or attempted, announced once as
	// the named state finality_upgrader_disabled. Launch fills it from CERTEN_FINALITY_CHAIN_<id>_ENABLED when it is nil.
	DisabledChains map[uint64]bool
	// DisabledReasons names why a chain in DisabledChains is off when the cause is not its CERTEN_FINALITY_CHAIN_<id>_ENABLED
	// switch: a missing provider setting (the runtime wiring, RB11-B2B2b) is announced with its own finality_upgrader_disabled
	// state naming that setting. A chain without an entry is announced as its switch (ChainSwitchState).
	DisabledReasons map[uint64]*StateError
	Logf            func(format string, args ...any)
	Now             func() time.Time
	Jitter          func(time.Duration) time.Duration // spreads retries across validators that share one database
	Recorder        Recorder
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
	def(&c.StoreTimeout, 30*time.Second)
	def(&c.PendingRetry, 2*time.Minute)
	def(&c.FailureRetry, 5*time.Minute)
	def(&c.BrokenRetry, time.Hour)
	for _, d := range []*time.Duration{&c.Interval, &c.PendingRetry, &c.FailureRetry, &c.BrokenRetry} {
		if *d < MinPoll {
			*d = MinPoll
		}
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	// no line the worker logs carries a credential: provider and transport text reaches these lines through error values, and the
	// formatted line is redacted as a whole (pkg/ethrpc, the one sanitiser)
	c.Logf = ethrpc.RedactingLogf(c.Logf)
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
// named state in a log line, a metric and a builder status row.
//
// Scheduling (V2_SPEC_S7 8.3): each (leg, level) has its own earliest next ask. A level whose prover stated an eta is not
// asked before the eta (jitter only adds time); a level with no eta is asked at PendingRetry, a bounded interval that is
// never below MinPoll. A leg that holds one level while waiting for another is therefore not asked about the waiting level
// each time the other level's schedule falls due.
type Upgrader struct {
	src   LegSource
	store AddendumStore
	reg   *Registry
	pins  *Pins
	cfg   UpgraderConfig

	mu       sync.Mutex
	next     map[string]time.Time   // proof id -> earliest next attempt of any level
	levelAt  map[levelKey]time.Time // (proof id, target level) -> earliest next ask of the provers for that level
	disabled map[uint64]bool        // chains announced as switched off
	complete map[string]Level       // proof id -> level it completed at (skipped from now on)
	stand    map[string]legStand    // proof id -> where its chain stood at the last attempt, for the gauges
	noProver map[uint64]bool        // chains already announced as having no registered prover
}

type levelKey struct {
	id    string
	level Level
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
		next: map[string]time.Time{}, levelAt: map[levelKey]time.Time{}, disabled: map[uint64]bool{},
		complete: map[string]Level{}, stand: map[string]legStand{}, noProver: map[uint64]bool{},
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
	Disabled int // legs of a chain whose per-chain switch is off (finality_upgrader_disabled, logged once per chain)
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
// as soon as the legs in flight have returned (each is bounded by BuildTimeout, StoreTimeout and by ctx).
func (u *Upgrader) RunOnce(ctx context.Context) PassReport {
	start := u.cfg.Now()
	var rep PassReport
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, u.cfg.Concurrency)

	after := ""
page:
	for ctx.Err() == nil {
		refs, err := bounded(ctx, u.cfg.StoreTimeout, 0, "listing the settled legs", func(c context.Context) ([]LegRef, error) {
			return u.src.SettledLegs(c, after, u.cfg.PageSize)
		})
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
			case u.cfg.DisabledChains[ref.Chain]:
				rep.Disabled++
				u.announceDisabled(ref.Chain)
				continue
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

// bounded runs fn under a deadline d and abandons it when the deadline (or ctx) ends first: a store or a source that ignores
// its context can stall the one goroutine that waits for it and nothing else. A panic inside fn is recovered into the named
// finality_prover_panicked state; an abandoned call is the named finality_build_timeout. chain is 0 for a call that is about no
// chain.
func bounded[T any](ctx context.Context, d time.Duration, chain uint64, what string, fn func(context.Context) (T, error)) (T, error) {
	bctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	type out struct {
		v   T
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				var zero T
				ch <- out{zero, NewState(CodePanic, "chain", chain, "panic", fmt.Sprint(r))}
			}
		}()
		v, err := fn(bctx)
		ch <- out{v, err}
	}()
	select {
	case o := <-ch:
		return o.v, o.err
	case <-bctx.Done():
		var zero T
		return zero, NewState(CodeBuildTimeout, "chain", chain, "after", d, "cause", what+": "+bctx.Err().Error())
	}
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

// announceDisabled logs the named state finality_upgrader_disabled once per switched-off chain.
func (u *Upgrader) announceDisabled(chain uint64) {
	u.mu.Lock()
	seen := u.disabled[chain]
	u.disabled[chain] = true
	u.mu.Unlock()
	if !seen {
		AnnounceDisabled(u.cfg.Logf, chain, u.cfg.DisabledReasons[chain])
	}
}

// AnnounceDisabled logs the named state finality_upgrader_disabled of a switched-off chain (reason when given, else the chain's
// CERTEN_FINALITY_CHAIN_<id>_ENABLED switch), counts it and records it for the health endpoint. Callers announce once per chain.
func AnnounceDisabled(logf func(format string, args ...any), chain uint64, reason *StateError) {
	if reason == nil {
		reason = ChainSwitchState(chain)
	}
	env, _ := reason.Fields["env"].(string)
	logf("[FINALITY] chain %d upgrader DISABLED: %s", chain, reason.Error())
	metrics.IncFinalityUpgraderDisabled(chain, env)
	metrics.SetFinalityChainDisabledReason(chain, reason.Error())
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

// levelDue reports whether the provers may be asked about target for the leg now: the eta rule of V2_SPEC_S7 8.3.
func (u *Upgrader) levelDue(id string, target Level) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	at, ok := u.levelAt[levelKey{id, target}]
	return !ok || !u.cfg.Now().Before(at)
}

// scheduleLevel sets the earliest next ask of one level to now+after (jitter only adds time).
func (u *Upgrader) scheduleLevel(id string, target Level, after time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.levelAt[levelKey{id, target}] = u.cfg.Now().Add(u.cfg.Jitter(after))
}

// scheduleLeg sets the leg's next attempt to the earliest next ask over the levels it still lacks; a missing level with no
// schedule of its own is asked again at PendingRetry.
func (u *Upgrader) scheduleLeg(id string, missing []Level) {
	u.mu.Lock()
	defer u.mu.Unlock()
	var at time.Time
	for _, l := range missing {
		t, ok := u.levelAt[levelKey{id, l}]
		if !ok {
			t = u.cfg.Now().Add(u.cfg.Jitter(u.cfg.PendingRetry))
			u.levelAt[levelKey{id, l}] = t
		}
		if at.IsZero() || t.Before(at) {
			at = t
		}
	}
	if !at.IsZero() {
		u.next[id] = at
	}
}

// scheduleBoth sets one schedule for the leg and every missing level (a stored chain that is broken, a settlement that cannot
// be loaded): nothing is asked of any level until it falls due.
func (u *Upgrader) scheduleBoth(id string, after time.Duration) {
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
		for _, l := range Levels {
			delete(u.levelAt, levelKey{id, l})
		}
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

// putStatus records one builder status row (V2_SPEC_S7 2.7) and counts it. A status that cannot be written is logged and
// counted and never fails or delays the leg: the status table is not authoritative and the next pass writes it again.
func (u *Upgrader) putStatus(ctx context.Context, st BuilderStatus) {
	state := string(st.Class)
	if st.State != nil {
		state = st.State.Code
	}
	if sr, ok := u.cfg.Recorder.(StatusRecorder); ok {
		sr.Status(st.Chain, st.TargetLevel, state)
	}
	if u.cfg.Status == nil {
		return
	}
	st.JudgedAt = u.cfg.Now()
	_, err := bounded(ctx, u.cfg.StoreTimeout, st.Chain, "writing the builder status", func(c context.Context) (struct{}, error) {
		return struct{}{}, u.cfg.Status.UpsertStatus(c, st)
	})
	if err != nil && ctx.Err() == nil {
		if sr, ok := u.cfg.Recorder.(StatusRecorder); ok {
			sr.StatusWriteFailed(st.Chain)
		}
		u.cfg.Logf("[FINALITY] leg %s chain %d: the %s status row was not written: %v", st.ProofID, st.Chain, st.TargetLevel, err)
	}
}

// upgradeLeg appends every stored level the leg does not yet hold that a prover can build and the registered Kind confirms
// inside the store's locked transaction (any order, at most one addendum per level, V2_SPEC_S7 R1) and schedules each level's
// next ask. D0 is the LegBinding of the leg's Settlement block, recomputed on every pass and again inside Append; a stored chain
// that does not verify against it is never extended.
func (u *Upgrader) upgradeLeg(ctx context.Context, ref LegRef) (res legResult) {
	logf := u.cfg.Logf
	defer func() {
		if r := recover(); r != nil {
			res.failed = true
			u.cfg.Recorder.BuildFailed(ref.Chain, CodePanic)
			logf("[FINALITY] leg %s chain %d: %s: %v", ref.ProofID, ref.Chain, CodePanic, r)
			u.scheduleBoth(ref.ProofID, u.cfg.FailureRetry)
		}
	}()
	profile, err := u.reg.Profile(ref.Chain)
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s: %v", ref.ProofID, err)
		u.scheduleBoth(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}
	proofID, err := ParseProofID(ref.ProofID)
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s: %v", ref.ProofID, err)
		u.scheduleBoth(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}

	settlement, err := bounded(ctx, u.cfg.StoreTimeout, ref.Chain, "loading the leg's settlement", func(c context.Context) (Settlement, error) {
		return u.src.LegSettlement(c, ref)
	})
	if err != nil {
		res.unusable = true
		u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
		logf("[FINALITY] leg %s chain %d: its L6 evidence cannot be used: %v", ref.ProofID, ref.Chain, err)
		u.record(ref.ProofID, ref.Chain, LevelNone, false)
		u.scheduleBoth(ref.ProofID, u.cfg.BrokenRetry)
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
		u.scheduleBoth(ref.ProofID, u.cfg.BrokenRetry)
		return res
	}
	d0 := LegBindingOf(block)

	chain, err := bounded(ctx, u.cfg.StoreTimeout, ref.Chain, "reading the stored addenda", func(c context.Context) ([]Addendum, error) {
		return u.store.Chain(c, ref.ProofID)
	})
	if err != nil {
		res.failed = true
		u.cfg.Recorder.BuildFailed(ref.Chain, "store_read")
		logf("[FINALITY] leg %s: reading its addenda: %v", ref.ProofID, err)
		u.scheduleBoth(ref.ProofID, u.cfg.FailureRetry)
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
	reached := func() Level { // the level the leg stands at: included is derived from the verified settlement
		if current < LevelIncluded {
			return LevelIncluded
		}
		return current
	}

	// For each missing level whose eta has passed, ask every prover that can still serve it; keep the earliest pending.
	for _, target := range targets {
		if !u.levelDue(ref.ProofID, target) {
			continue // the eta rule: not asked before the stated eta (or before PendingRetry when none was stated)
		}
		wait := time.Duration(-1) // next ask of this level; <0 = the level was stored
		var status *BuilderStatus
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
					s := BuilderStatusOf(ref.ProofID, ref.Chain, target, reached(), nil, err, false, u.cfg.Now())
					status = &s
					wait = u.cfg.BrokenRetry
					continue // the chain does not have that level: nothing to build, nothing wrong
				}
				u.cfg.Recorder.BuildFailed(ref.Chain, codeOf(err))
				logf("[FINALITY] leg %s chain %d: build of %s refused: %v", ref.ProofID, ref.Chain, target, err)
				res.failed = true
				s := BuilderStatusOf(ref.ProofID, ref.Chain, target, reached(), nil, err, false, u.cfg.Now())
				status = &s
				wait = minWait(wait, u.cfg.FailureRetry)
				continue // a refusal claims no level
			}
			if pd != nil {
				if res.pending == nil {
					res.pending = pd
				}
				w := u.cfg.PendingRetry
				if !pd.ETA.IsZero() {
					w = pd.ETA.Sub(u.cfg.Now())
					if w < MinPoll {
						w = MinPoll
					}
				}
				s := BuilderStatusOf(ref.ProofID, ref.Chain, target, reached(), pd, nil, false, u.cfg.Now())
				if status == nil || status.Class != BuilderPending || w < wait || wait < 0 {
					status = &s
				}
				wait = minWait(wait, w)
			}
			if add == nil || add.Level != target {
				continue
			}
			// The store forms the link under the proof's lock, recomputes the chain under D0 of the settlement and stores the
			// addendum only if the registered Kind verifies the evidence (V2_SPEC_S7 2.4).
			req := AppendRequest{ProofID: proofID, Chain: ref.Chain, Settlement: settlement.Included, Level: add.Level, Kind: add.Kind,
				Evidence: add.Evidence, Registry: u.reg, Pins: u.pins}
			a, err := bounded(ctx, u.cfg.BuildTimeout, ref.Chain, "appending the verified addendum", func(c context.Context) (Addendum, error) {
				return u.store.Append(c, req)
			})
			if ctx.Err() != nil {
				return res
			}
			if err != nil {
				n, named := AsNamed(err)
				switch {
				case named && (n.Code == CodeAppendConflict || n.Code == CodeLevelAlreadyPresent):
					res.conflict = true // another validator appended first; the next pass reads its chain
					wait = minWait(wait, u.cfg.Interval)
				case named && n.Code != CodeBuildTimeout && n.Code != CodePanic:
					// the registered Kind (or the chain checks) refused what the prover built: nothing was stored (class R)
					res.failed = true
					u.cfg.Recorder.BuildFailed(ref.Chain, n.Code)
					logf("[FINALITY] leg %s chain %d: built %s evidence that does not verify: %v", ref.ProofID, ref.Chain, target, err)
					s := BuilderStatusOf(ref.ProofID, ref.Chain, target, reached(), nil, err, true, u.cfg.Now())
					status = &s
					wait = minWait(wait, u.cfg.FailureRetry)
				default:
					res.failed = true
					u.cfg.Recorder.BuildFailed(ref.Chain, "store_write")
					logf("[FINALITY] leg %s chain %d: appending the %s addendum: %v", ref.ProofID, ref.Chain, target, err)
					s := BuilderStatusOf(ref.ProofID, ref.Chain, target, reached(), nil, err, false, u.cfg.Now())
					status = &s
					wait = minWait(wait, u.cfg.FailureRetry)
				}
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
			v := VerifiedBuilderStatus(ref.ProofID, ref.Chain, a.Level, a.Seq, u.cfg.Now())
			status = &v
			wait = -1
			break // one addendum per level
		}
		if status != nil {
			if status.Class == BuilderPending {
				u.cfg.Recorder.Pending(ref.Chain, current)
			}
			u.putStatus(ctx, *status)
		}
		if wait >= 0 {
			u.scheduleLevel(ref.ProofID, target, wait)
		}
	}

	var missing []Level
	for _, l := range storedOffered(profile) {
		if !have.Has(l) {
			missing = append(missing, l)
		}
	}
	u.record(ref.ProofID, ref.Chain, current, len(missing) == 0)
	if len(missing) > 0 {
		u.scheduleLeg(ref.ProofID, missing)
	}
	return res
}

// minWait is the smaller of a and b, where a negative a means "no wait recorded yet".
func minWait(a, b time.Duration) time.Duration {
	if a < 0 || b < a {
		return b
	}
	return a
}

func (u *Upgrader) brokenChain(ref LegRef, err error) legResult {
	u.cfg.Recorder.ChainBroken(ref.Chain)
	u.cfg.Logf("[FINALITY] leg %s chain %d: its stored addendum chain does not verify and nothing is appended to it: %v", ref.ProofID, ref.Chain, err)
	u.scheduleBoth(ref.ProofID, u.cfg.BrokenRetry)
	return legResult{broken: true}
}

// build runs one prover under BuildTimeout and recovers its panic. A prover that ignores its context is abandoned at the
// deadline: the leg is reported as a named timeout and the worker moves on, so no prover can stall the pass.
func (u *Upgrader) build(ctx context.Context, p Prover, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error) {
	type out struct {
		add *Addendum
		pd  *PendingState
	}
	o, err := bounded(ctx, u.cfg.BuildTimeout, p.Chain(), "building the evidence", func(c context.Context) (out, error) {
		add, pd, err := p.Build(c, s, have, target)
		return out{add, pd}, err
	})
	return o.add, o.pd, err
}

func codeOf(err error) string {
	if n, ok := AsNamed(err); ok {
		return n.Code
	}
	return "unnamed_error"
}

// ---- the enable flags ----

// EnvEnabled switches the upgrader. Unset means ON; a value that is not a switch refuses startup by name.
const EnvEnabled = "CERTEN_FINALITY_UPGRADER_ENABLED"

// Enabled reads EnvEnabled (default on).
func Enabled() (bool, error) { return envvar.Bool(EnvEnabled, true) }

// ChainEnv is the per-chain switch of one chain: CERTEN_FINALITY_CHAIN_<chain id>_ENABLED (default on).
func ChainEnv(chain uint64) string { return fmt.Sprintf("CERTEN_FINALITY_CHAIN_%d_ENABLED", chain) }

// ChainSwitchState is the named state of a chain whose per-chain switch is off: finality_upgrader_disabled, naming the
// variable. Its legs keep the level they were stored at and its capture loops do not run.
func ChainSwitchState(chain uint64) *StateError {
	return NewState(CodeUpgraderDisabled, "env", ChainEnv(chain), "value", "false",
		"effect", fmt.Sprintf("no finality addenda are appended and nothing is captured for chain %d by this validator; its proofs stay at the level they were stored at", chain))
}

// DisabledChainsFromEnv reads every profiled chain's switch (default on). A value that is not a switch is an error naming the
// variable, so startup is refused rather than the chain silently left on or off.
func DisabledChainsFromEnv(chains []uint64) (map[uint64]bool, error) {
	off := map[uint64]bool{}
	for _, c := range chains {
		on, err := envvar.Bool(ChainEnv(c), true)
		if err != nil {
			return nil, err
		}
		if !on {
			off[c] = true
		}
	}
	return off, nil
}

// Launch starts the upgrader and the registered capture loops on their own goroutines, or, when it is switched off, reports
// the named state finality_upgrader_disabled in the log and the metric: an off switch is never a silent skip. Per-chain
// switches (CERTEN_FINALITY_CHAIN_<id>_ENABLED, default on) turn one chain's upgrader and capturers off the same way. It
// returns the started worker (nil when off). It never blocks the caller.
func Launch(ctx context.Context, enabled bool, src LegSource, store AddendumStore, reg *Registry, pins *Pins, cfg UpgraderConfig) (*Upgrader, error) {
	cfg = cfg.withDefaults()
	if !enabled {
		st := NewState(CodeUpgraderDisabled, "env", EnvEnabled, "value", "false",
			"effect", "no finality addenda are appended by this validator; proofs stay at the level they were stored at")
		cfg.Logf("[FINALITY] upgrader DISABLED: %s", st.Error())
		metrics.SetFinalityUpgraderEnabled(false)
		metrics.IncFinalityUpgraderDisabled(0, EnvEnabled)
		return nil, nil
	}
	// a missing registry is NewUpgrader's refusal below, not a nil dereference here
	if cfg.DisabledChains == nil && reg != nil {
		off, err := DisabledChainsFromEnv(reg.Chains())
		if err != nil {
			return nil, err
		}
		cfg.DisabledChains = off
	}
	u, err := NewUpgrader(src, store, reg, pins, cfg)
	if err != nil {
		return nil, err
	}
	metrics.SetFinalityUpgraderEnabled(true)
	for _, c := range reg.Chains() {
		metrics.SetFinalityChainEnabled(c, !cfg.DisabledChains[c])
		if cfg.DisabledChains[c] {
			// announced at launch, once, whether or not a leg of the chain exists yet; the worker does not announce it again
			u.announceDisabled(c)
		}
	}
	cfg.Logf("[FINALITY] upgrader ENABLED (%s): concurrency=%d interval=%s chains=%v switched_off=%v", EnvEnabled, cfg.Concurrency, cfg.Interval, reg.Chains(), cfg.DisabledChains)
	StartCapturers(ctx, reg, SupervisorConfig{DisabledChains: cfg.DisabledChains, DisabledReasons: cfg.DisabledReasons, Logf: cfg.Logf})
	go u.Run(ctx)
	return u, nil
}
