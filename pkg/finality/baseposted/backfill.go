// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP: the backfill. It captures the blocks of the recorded gaps with the SAME capture call as the live loop, one block at
// a time, and records what happened as new insert-only rows: a fill when the block is captured (or scanned empty), a note when it
// failed, an end when the providers have PROVED the data unavailable or its retention elapsed. It gives up on nothing else: a block
// whose state proof no provider can serve (a leg judged at it says so by name) is retried with a doubling backoff for as long as the
// gap is open.

// SepoliaBeaconGenesis is the genesis_time of the Sepolia beacon chain (slot = (timestamp - genesis) / 12).
const SepoliaBeaconGenesis uint64 = 1655733600

// BackfillPolicy is the retry and proof policy of a Backfiller.
type BackfillPolicy struct {
	BackoffBase, BackoffMax time.Duration // wait after the first failure of a block, doubling up to the cap
	GoneObservations        int           // how many failures with every beacon endpoint answering 404/410 prove a blob unavailable ...
	GoneSpan                time.Duration // ... when they span at least this long (a beacon node that is merely behind recovers inside it)
	MinGoneHosts            int           // ... and every observation was made by at least this many DISTINCT beacon hosts (default 2): one provider's 404 is not proof
	ReprobeEvery            time.Duration // a block proven unavailable is asked again this often (default 24h): the newest of each run, the rest when that one is served
	Retention               time.Duration // beacon blob retention (4096 epochs) plus one epoch of margin
	GenesisTime             uint64
	SlotSeconds             uint64
}

// DefaultBackfillPolicy is the production policy: blobs are kept 4096 epochs (about 18.2 days), a blob is proven gone by three
// all-endpoints-404/410 answers over half an hour, a block is retried after 30 s doubling to 30 min.
func DefaultBackfillPolicy() BackfillPolicy {
	return BackfillPolicy{BackoffBase: 30 * time.Second, BackoffMax: 30 * time.Minute, GoneObservations: 3, GoneSpan: 30 * time.Minute, MinGoneHosts: 2, ReprobeEvery: 24 * time.Hour,
		Retention: (4096 + 1) * 32 * 12 * time.Second, GenesisTime: SepoliaBeaconGenesis, SlotSeconds: 12}
}

func (p BackfillPolicy) withDefaults() BackfillPolicy {
	d := DefaultBackfillPolicy()
	if p.BackoffBase <= 0 {
		p.BackoffBase = d.BackoffBase
	}
	if p.BackoffMax < p.BackoffBase {
		p.BackoffMax = d.BackoffMax
		if p.BackoffMax < p.BackoffBase {
			p.BackoffMax = p.BackoffBase
		}
	}
	if p.GoneObservations <= 0 {
		p.GoneObservations = d.GoneObservations
	}
	if p.ReprobeEvery <= 0 {
		p.ReprobeEvery = d.ReprobeEvery
	}
	if p.MinGoneHosts <= 0 {
		p.MinGoneHosts = d.MinGoneHosts
	}
	if p.GoneSpan <= 0 {
		p.GoneSpan = d.GoneSpan
	}
	if p.Retention <= 0 {
		p.Retention = d.Retention
	}
	if p.GenesisTime == 0 {
		p.GenesisTime = d.GenesisTime
	}
	if p.SlotSeconds == 0 {
		p.SlotSeconds = d.SlotSeconds
	}
	return p
}

// BackfillReport is what one Step did.
type BackfillReport struct {
	Attempted, Filled, Failed, Ended, Conflicts, Skipped int
	FilledBlocks                                         []uint64 // the blocks this step captured (the capture index is told, it digests them at its next step)
	Open, UnavailableProven, RetentionExpired            uint64   // blocks still in each state after the step
	FailedByClass                                        map[string]int
	EndedByKind                                          map[string]int
	// RB12-ARCHIVE-BACKFILL
	PrefixAttempted, PrefixFilled int // attempts / fills of blocks that lie only in prefix windows (included in Attempted / Filled)
	LeaseLost, LeaseErrors        int // chunks another validator held for this bucket / claims the store could not take
}

type bfEntry struct {
	attempts  int
	next      time.Time
	goneCount int
	goneFirst time.Time
	notes     int
}

// maxNotesPerBlock bounds the provider texts one process keeps for one block (a flapping provider changes its text every time).
const maxNotesPerBlock = 3

// Backfiller fills the recorded gaps of one chain. It is single-threaded (Step holds a lock): concurrency is one block at a time.
type Backfiller struct {
	Chain     uint64
	Store     CaptureStore
	Capturer  BlockCapturer
	Providers []string // host labels of the providers the capture asks; carried by the end records and compared when the set changes
	Policy    BackfillPolicy
	Now       func() time.Time
	// Pick chooses which of n eligible open blocks to take next (default: uniformly at random, so validators sharing one database do not
	// all start at the same block). The tests pin it.
	Pick func(n int) int
	Logf func(string, ...any)
	// Lease, when set, is the cross-validator claim on chunks of prefix blocks (nil: no claims, one validator or tests).
	Lease *Lease
	// NoPrefix switches the prefix extension off for this validator (a refused prefix setting, finality_prefix_disabled): no window of the
	// capture-store prefix is taken, none is claimed, and no block that only a prefix window holds is reopened or asked again. The windows stay as
	// recorded (the rows are insert-only) for a validator whose prefix feature is on; the holes of the live range are closed as before.
	// Exception: GapsIn merges overlapping or abutting rows into one piece with the union of their classes, so a piece that a hole shares with a
	// window is a hole and its window-only blocks may still be asked (hole 500-509 + window 505-520 is one piece 500-520, blocks 510-520 included).
	NoPrefix bool
	// OnFill is told of every block the backfill closes (after its fill row is stored), so an index of the capture store can digest a block
	// that arrived out of order (RB12-ARCHIVE-BACKFILL; nil: nobody is told).
	OnFill func(block uint64, hasInbox bool)

	mu          sync.Mutex
	entries     map[uint64]*bfEntry
	reopenSet   string // the provider set the terminal blocks were last compared with
	reopen      map[uint64]bool
	reopenReady bool
	// the daily re-probe of blocks proven unavailable
	probing     map[uint64]bool
	reopenAll   bool
	claims      claimState // the claims of the step in progress
	lastReprobe time.Time
}

func (b *Backfiller) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Backfiller) logf(f string, a ...any) {
	if b.Logf != nil {
		b.Logf(f, a...)
	}
}

func (b *Backfiller) pick(n int) int {
	if b.Pick != nil {
		return b.Pick(n)
	}
	return rand.Intn(n)
}

func providerKey(ps []string) string {
	c := append([]string(nil), ps...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

// reopenTerminal finds the terminal blocks whose recorded providers do not cover the providers configured now: a provider added since may
// have the data. It runs once per provider set.
func (b *Backfiller) reopenTerminal(ctx context.Context, pieces []finality.GapRange) error {
	key := providerKey(b.Providers)
	if b.reopenReady && b.reopenSet == key {
		return nil
	}
	reopen := map[uint64]bool{}
	for _, p := range pieces {
		if p.State == finality.GapOpen {
			continue
		}
		for n := p.From; n <= p.To; n++ {
			ends, err := finality.GapEndsOf(ctx, b.Store, b.Chain, n)
			if err != nil {
				return err
			}
			asked := map[string]bool{}
			for _, e := range ends {
				for _, h := range e.Providers {
					asked[h] = true
				}
			}
			for _, h := range b.Providers {
				if !asked[ethrpc.RedactText(h)] {
					reopen[n] = true
					break
				}
			}
		}
	}
	b.reopen, b.reopenSet, b.reopenReady = reopen, key, true
	return nil
}

// Step captures at most max blocks of the recorded gaps. It returns an error only when the gap rows cannot be read: a failed capture is
// a note and a backoff, never an error.
func (b *Backfiller) Step(ctx context.Context, max int) (BackfillReport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var rep BackfillReport
	if b.entries == nil {
		b.entries = map[uint64]*bfEntry{}
	}
	pol := b.Policy.withDefaults()
	pieces, err := finality.GapsIn(ctx, b.Store, b.Chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		return rep, err
	}
	live := pieces // the pieces the reopen and the re-probe look at
	if b.NoPrefix {
		live = withoutPrefixOnly(pieces)
	}
	if err := b.reopenTerminal(ctx, live); err != nil {
		return rep, err
	}
	b.reprobe(b.now(), live, pol)
	wins, err := finality.PrefixWindowsOf(ctx, b.Store, b.Chain)
	if err != nil {
		return rep, err
	}
	if b.NoPrefix {
		wins = nil
	}
	now := b.now()
	// the blocks that must not be taken now: attempted and not yet due again
	skip := map[uint64]bool{}
	for n, e := range b.entries {
		if now.Before(e.next) {
			skip[n] = true
		}
	}
	taken := map[uint64]bool{}
	b.claims = claimState{lost: map[uint64]bool{}, held: map[uint64]bool{}}
	// the holes keep a quarter of every tick (at least one block) while one is due, so a prefix of any size, failing or not, cannot starve them
	// (V-ARCHIVE D3); what the holes do not use goes to the prefix.
	// the prefix windows of legs that predate the capture: the windows that can still complete first (oldest block first), see prefix.go
	var dead []bool
	if len(wins) > 0 {
		dead = deadWindows(pieces, wins)
	}
	// the holes of the live range: the pieces that are not open only because of a prefix request
	var holes []finality.GapRange
	for _, p := range pieces {
		if !isPrefixOnly(p) {
			holes = append(holes, p)
		}
	}
	var eligible int
	for _, p := range holes {
		if p.State != finality.GapOpen {
			continue
		}
		eligible += int(p.Blocks())
	}
	for n := range skip {
		for _, p := range holes {
			if p.State == finality.GapOpen && n >= p.From && n <= p.To {
				eligible--
				break
			}
		}
	}
	holesDue := eligible > 0
	for n := range b.reopen {
		if !skip[n] {
			holesDue = true
			break
		}
	}
	prefixCap := max
	if holesDue {
		prefixCap = max - (max+3)/4
	}
	if len(wins) > 0 {
		b.prefixPhase(ctx, pieces, wins, dead, true, skip, taken, prefixCap, pol, &rep)
	}
	for rep.Attempted < max && ctx.Err() == nil {
		var n uint64
		var ok bool
		if eligible > 0 {
			n, ok = nthEligible(holes, skip, taken, b.pick(eligible))
			if ok {
				eligible--
			}
		}
		if !ok { // nothing open is due: a terminal block whose providers have changed is tried
			for r := range b.reopen {
				if !skip[r] && !taken[r] {
					n, ok = r, true
					break
				}
			}
		}
		if !ok {
			break
		}
		taken[n] = true
		if fills, err := b.Store.ListByRange(ctx, b.Chain, n, n, finality.GapFillPrefix); err == nil && len(fills) > 0 {
			rep.Skipped++ // another validator closed it since the listing
			continue
		}
		rep.Attempted++
		b.attempt(ctx, n, pol, &rep)
	}
	if len(wins) > 0 {
		// what the holes did not use goes to the windows that can still complete, then (last, so a later archive finds the rest already
		// captured) to the windows that hold a block no provider has
		b.prefixPhase(ctx, pieces, wins, dead, true, skip, taken, max, pol, &rep)
		b.prefixPhase(ctx, pieces, wins, dead, false, skip, taken, max, pol, &rep)
	}
	// the state after the step
	after, err := finality.GapsIn(ctx, b.Store, b.Chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		return rep, err
	}
	for _, p := range after {
		switch p.State {
		case finality.GapOpen:
			rep.Open += p.Blocks()
		case finality.GapUnavailableProven:
			rep.UnavailableProven += p.Blocks()
		case finality.GapRetentionExpired:
			rep.RetentionExpired += p.Blocks()
		}
	}
	return rep, nil
}

// nthEligible is the k-th (0-based) open block that is neither skipped nor already taken in this step.
func nthEligible(pieces []finality.GapRange, skip, taken map[uint64]bool, k int) (uint64, bool) {
	for _, p := range pieces {
		if p.State != finality.GapOpen {
			continue
		}
		for n := p.From; n <= p.To; n++ {
			if skip[n] || taken[n] {
				continue
			}
			if k == 0 {
				return n, true
			}
			k--
		}
	}
	return 0, false
}

func (b *Backfiller) attempt(ctx context.Context, n uint64, pol BackfillPolicy, rep *BackfillReport) {
	e := b.entries[n]
	if e == nil {
		e = &bfEntry{}
		b.entries[n] = e
	}
	hash, inbox, err := b.Capturer.CaptureBlockHash(ctx, n)
	wasProbe := b.probing[n]
	delete(b.probing, n)
	if err == nil {
		if ferr := finality.RecordGapFill(ctx, b.Store, b.Chain, n, hash, inbox); ferr != nil {
			rep.Failed++
			b.logf("[FINALITY] gap backfill chain %d: L1 block %d captured but its fill was not recorded: %v", b.Chain, n, ethrpc.RedactError(ferr))
			return
		}
		delete(b.entries, n)
		delete(b.reopen, n)
		rep.Filled++
		if inbox {
			rep.FilledBlocks = append(rep.FilledBlocks, n) // a block with no inbox transactions has no rows and nothing to digest
		}
		if wasProbe {
			b.reopenAll = true // a block once proven unavailable is served again: every run of them is asked again
			b.logf("[FINALITY] gap backfill chain %d: L1 block %d, proven unavailable before, is served again; the blocks proven unavailable are asked again", b.Chain, n)
		}
		if b.OnFill != nil {
			b.OnFill(n, inbox)
		}
		return
	}
	if ctx.Err() != nil {
		return // the process is stopping: not a failure of the block
	}
	rep.Failed++
	class := ClassOfFailure(err)
	if rep.FailedByClass == nil {
		rep.FailedByClass = map[string]int{}
	}
	rep.FailedByClass[string(class)]++
	var cf *CaptureFailure
	if errors.As(err, &cf) && cf.State != nil && cf.State.Code == CodeCaptureRowConflict {
		rep.Conflicts++
		b.logf("[FINALITY] gap backfill chain %d: %s: the stored rows of L1 block %d differ from what the providers serve now; the gap stays open", b.Chain, cf.State.Error(), n)
	}
	if e.notes < maxNotesPerBlock {
		e.notes++
		if nerr := finality.RecordGapNote(ctx, b.Store, b.Chain, n, class, err.Error()); nerr != nil {
			b.logf("[FINALITY] gap backfill chain %d: note of L1 block %d not recorded: %v", b.Chain, n, ethrpc.RedactError(nerr))
		}
	}
	now := b.now()
	if ge, gone := BlobsGone(err); class == finality.GapBlobUnavailable && gone {
		if end, ok := b.goneVerdict(e, cf, ge.Endpoints, now, pol); ok {
			// the slot the blobs were asked at is recorded first: an end is never visible without its slot evidence
			var serr error
			if cf == nil || cf.State == nil {
				serr = errors.New("the capture failure carries no state")
			} else if v, have := cf.State.Fields["beacon_slot"].(uint64); have {
				serr = finality.RecordGapSlot(ctx, b.Store, b.Chain, n, v)
			} else {
				serr = errors.New("the capture failure names no beacon slot")
			}
			if serr != nil {
				b.logf("[FINALITY] gap backfill chain %d: the slot of L1 block %d not recorded, so its end is not recorded yet: %v", b.Chain, n, ethrpc.RedactError(serr))
			} else if rerr := finality.RecordGapEnd(ctx, b.Store, b.Chain, n, end); rerr == nil {
				rep.Ended++
				if rep.EndedByKind == nil {
					rep.EndedByKind = map[string]int{}
				}
				rep.EndedByKind[string(end.Kind)]++
				delete(b.reopen, n)
				b.logf("[FINALITY] gap backfill chain %d: L1 block %d is %s (%s; providers %s): the gap stays recorded and will not be retried by these providers",
					b.Chain, n, end.Kind, end.Reason, strings.Join(end.Providers, ","))
			} else {
				b.logf("[FINALITY] gap backfill chain %d: end of L1 block %d not recorded: %v", b.Chain, n, ethrpc.RedactError(rerr))
			}
		}
	} else {
		e.goneCount = 0
	}
	e.attempts++
	wait := pol.BackoffBase << uint(minInt(e.attempts-1, 20))
	if wait <= 0 || wait > pol.BackoffMax {
		wait = pol.BackoffMax
	}
	e.next = now.Add(wait)
}

// goneVerdict decides whether the blobs of a block are provably unavailable. Every beacon endpoint said 404/410 on this attempt; that is
// the evidence. Past the retention it is enough (the data was pruned); inside it, it must hold on GoneObservations attempts spanning
// GoneSpan, so a beacon node that is merely behind does not end a gap.
func (b *Backfiller) goneVerdict(e *bfEntry, cf *CaptureFailure, hosts int, now time.Time, pol BackfillPolicy) (finality.GapEnd, bool) {
	providers := append([]string(nil), b.Providers...)
	sort.Strings(providers)
	var slot uint64
	haveSlot := false
	if cf != nil && cf.State != nil {
		if v, ok := cf.State.Fields["beacon_slot"].(uint64); ok {
			slot, haveSlot = v, true
		}
	}
	if haveSlot {
		slotTime := time.Unix(int64(pol.GenesisTime+slot*pol.SlotSeconds), 0)
		if now.Sub(slotTime) > pol.Retention {
			return finality.GapEnd{Kind: finality.GapRetentionExpired, Reason: "blob_retention_elapsed", Providers: providers}, true
		}
	}
	if hosts < pol.MinGoneHosts {
		// One provider's 404 proves nothing about the data: the gap stays open, named by the count of hosts that answered (the note of this
		// attempt carries it too), and the observations do not accumulate toward a verdict.
		e.goneCount = 0
		b.logf("[FINALITY] gap backfill chain %d: the blobs of a block are gone on %d distinct beacon host(s) and unavailable_proven needs %d: the gap stays open", b.Chain, hosts, pol.MinGoneHosts)
		return finality.GapEnd{}, false
	}
	if e.goneCount == 0 {
		e.goneFirst = now
	}
	e.goneCount++
	if e.goneCount >= pol.GoneObservations && now.Sub(e.goneFirst) >= pol.GoneSpan {
		return finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: providers}, true
	}
	return finality.GapEnd{}, false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maxReprobes bounds the blocks asked again in one daily re-probe: the newest block of each run proven unavailable, the runs being few.
const maxReprobes = 16

// reprobe is the cadence of blocks proven unavailable: a gap that ended is not asked again by the same providers except once a day, and
// then only the NEWEST block of each run (providers prune oldest first, so if the newest is still gone every older one is). When that
// block is served, every block proven unavailable or past retention is asked again. The first step of a process starts the day.
func (b *Backfiller) reprobe(now time.Time, pieces []finality.GapRange, pol BackfillPolicy) {
	if b.reopen == nil {
		b.reopen = map[uint64]bool{}
	}
	if b.probing == nil {
		b.probing = map[uint64]bool{}
	}
	if b.reopenAll {
		b.reopenAll = false
		for _, p := range pieces {
			if p.State == finality.GapUnavailableProven || p.State == finality.GapRetentionExpired {
				for n := p.From; n <= p.To; n++ {
					b.reopen[n] = true
				}
			}
		}
		return
	}
	if b.lastReprobe.IsZero() {
		b.lastReprobe = now
		return
	}
	if now.Sub(b.lastReprobe) < pol.ReprobeEvery {
		return
	}
	b.lastReprobe = now
	probes := 0
	for i := len(pieces) - 1; i >= 0 && probes < maxReprobes; i-- {
		if p := pieces[i]; p.State == finality.GapUnavailableProven || p.State == finality.GapRetentionExpired {
			b.reopen[p.To], b.probing[p.To] = true, true
			probes++
		}
	}
}
