// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// The heartbeat of a chain whose blocks stop when it is idle (RB7 §1.1, decision D7)
// =============================================================================
//
// Telcoin Adiri builds a block only when a consensus commit carries a transaction, or closes an epoch (every 6 h). Its
// time - the time of its latest finalized block - therefore stops while nobody sends anything, and every rule that waits
// for "a finalized block past H" (a member's deadline plus its margin, a settlement window's fence, a leaf's notBefore)
// waits for traffic that may never come; the settlement-window takeover and the notBefore send deadlock outright, since
// the transaction that would advance the chain is the one waiting.
//
// So a rule blocked ONLY because no block yet passes its horizon says so (ChainClock.AwaitTime/AwaitBlock), and validator
// i - its position in the chain-confirmed roster, sorted by address - sends ONE zero-value transfer to itself on that
// chain once its wall clock is past H + 30 s + 15 s*(i-1). Before sending it reads the chain again, and stays silent when a
// block past H already exists (another validator's heartbeat, or anyone's traffic). One heartbeat serves every horizon
// below its block's time; a validator has at most one in flight, and sends at most one per heartbeatMinGap.
//
// The wall clock only TRIGGERS a heartbeat. It decides nothing:
//   - a heartbeat sent too early lands in a block whose time is not past H. That block decides nothing new, the horizon
//     stays, and the trigger re-arms;
//   - a heartbeat sent late only delays;
//   - every outcome is reached through the rule's own predicate on the chain's finalized blocks, read through the
//     chain's agreeing providers. A heartbeat block is a block like any other: the "first block past H" is a fact of the
//     chain, the same for every validator whoever's transaction made it.
//
// Without any heartbeat (every relayer unfunded, the pool refusing) the chain's own epoch-closing block passes every
// horizon within its epoch (21600 s on Adiri): the same rule, the same source, later. Every failure to send is named and
// counted (unfunded, refused, gas ceiling, key busy, unread), never silent.
//
// Only a chain whose catalogue entry says its blocks stop when idle (supportedchains.Chain.BlocksOnlyWithTraffic) has a
// heartbeat, and only with CERTEN_CHAIN_HEARTBEAT_<id>=on; the chains whose blocks never stop never heartbeat.

// heartbeatEnvPrefix names a chain's heartbeat switch: CERTEN_CHAIN_HEARTBEAT_<chainId>.
const heartbeatEnvPrefix = "CERTEN_CHAIN_HEARTBEAT_"

// ChainHeartbeatEnv is the variable that switches chainID's heartbeat on.
func ChainHeartbeatEnv(chainID int64) string {
	return heartbeatEnvPrefix + strconv.FormatInt(chainID, 10)
}

const (
	// heartbeatBaseDelay and heartbeatStagger are validator i's wait past a horizon: 30 s + 15 s*(i-1). The first
	// validator acts after half a minute, the seventh after two; each reads the chain before sending, so normally one
	// heartbeat is sent per horizon.
	heartbeatBaseDelay = 30 * time.Second
	heartbeatStagger   = 15 * time.Second
	// heartbeatMinGap is the least time between two heartbeats of this validator on one chain: one that landed too
	// early re-arms after it, never in a burst.
	heartbeatMinGap = 30 * time.Second
	// heartbeatHorizonTTL drops a horizon no rule has re-stated for this long: the rules re-state theirs on every pass
	// while blocked, so one that stopped being blocked (its member settled, its successor stopped) stops asking.
	heartbeatHorizonTTL = 10 * time.Minute
	// heartbeatTick is how often a chain's heartbeat looks at its horizons.
	heartbeatTick = 5 * time.Second
	// heartbeatGas is a plain transfer's gas.
	heartbeatGas = 21000
)

// chainHeartbeatOn reads chainID's heartbeat switch.
//
//   - A chain whose blocks stop when idle must have CERTEN_CHAIN_HEARTBEAT_<id>=on to be settled on: enabling it without
//     the heartbeat would leave its non-settlements, its window takeovers and its notBefore sends waiting on traffic
//     (refused by name at boot).
//   - A chain whose blocks never stop has no heartbeat: the variable must be unset (refused by name otherwise).
func chainHeartbeatOn(chainID int64) (bool, error) {
	env := ChainHeartbeatEnv(chainID)
	raw, set := os.LookupEnv(env)
	val := strings.ToLower(strings.TrimSpace(raw))
	c, ok := supportedchains.Lookup(chainID)
	if !ok || !c.BlocksOnlyWithTraffic {
		if set {
			return false, fmt.Errorf("%s=%q: chain %d produces blocks without traffic, so it has no heartbeat - unset it",
				env, raw, chainID)
		}
		return false, nil
	}
	if val != "on" {
		return false, fmt.Errorf("chain %d (%s) produces a block only when a transaction lands or its epoch closes: settling "+
			"on it requires its heartbeat, %s=on (it is %q). Its relayer key sends a zero-value transfer to itself when a "+
			"rule waits for a block past its horizon; without it a non-settlement, a window takeover or a notBefore send waits "+
			"for third-party traffic, or for the next epoch close", chainID, c.Name, env, raw)
	}
	return true, nil
}

var (
	heartbeatOutcomes = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "chain_heartbeat",
		Name: "rounds_total", Help: "Heartbeat rounds of a chain whose blocks stop when idle, by what the round did"},
		[]string{"chain", "outcome"})
	heartbeatPending = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "chain_heartbeat",
		Name: "pending_horizons", Help: "Horizons rules are blocked on that no finalized block of the chain has passed yet"},
		[]string{"chain"})
	heartbeatLastBlock = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "chain_heartbeat",
		Name: "last_block", Help: "The block this validator's last heartbeat landed in"}, []string{"chain"})
)

func init() {
	prometheus.MustRegister(heartbeatOutcomes, heartbeatPending, heartbeatLastBlock)
}

// HeartbeatOutcome is what one heartbeat round did.
type HeartbeatOutcome string

const (
	HeartbeatIdle       HeartbeatOutcome = "idle"        // no rule is waiting on a horizon
	HeartbeatServed     HeartbeatOutcome = "served"      // a block past every due horizon exists: nothing sent
	HeartbeatWaiting    HeartbeatOutcome = "waiting"     // a horizon is pending, this validator's turn has not come
	HeartbeatSent       HeartbeatOutcome = "sent"        // a heartbeat landed
	HeartbeatUnfunded   HeartbeatOutcome = "unfunded"    // the relayer cannot pay for it
	HeartbeatRefused    HeartbeatOutcome = "refused"     // the node refused it before it was in flight
	HeartbeatGasCeiling HeartbeatOutcome = "gas_ceiling" // the chain's gas price or cost ceiling refused it
	HeartbeatKeyBusy    HeartbeatOutcome = "key_busy"    // this key is sending something else, or has a transaction in flight
	HeartbeatUnread     HeartbeatOutcome = "unread"      // the chain, the roster or the outcome could not be read
)

// heartbeatSend sends one zero-value transfer from this validator's relayer key to itself and returns its hash and the
// block it landed in.
type heartbeatSend func(ctx context.Context) (txHash string, block uint64, err error)

// ErrHeartbeatUnfunded: the relayer's balance cannot pay for a heartbeat.
var ErrHeartbeatUnfunded = errors.New("the relayer cannot pay for a heartbeat")

// heartbeatHorizon is one horizon and the rules waiting on it.
type heartbeatHorizon struct {
	rules map[string]bool
	since time.Time // when a rule first stated it (wall clock: it triggers, it decides nothing)
	asked time.Time // when a rule last stated it
}

// chainHeartbeat is one chain's heartbeat.
type chainHeartbeat struct {
	chainID int64
	clock   *ChainClock
	// ordinal is this validator's 1-based position among the validators.
	ordinal func(ctx context.Context) (int, error)
	send    heartbeatSend
	// now is the wall clock: it only triggers.
	now  func() time.Time
	logf func(string, ...interface{})

	mu       sync.Mutex
	times    map[uint64]*heartbeatHorizon // a finalized block with time > key is awaited
	blocks   map[uint64]*heartbeatHorizon // a finalized block numbered >= key is awaited
	lastSent time.Time
	inFlight bool
}

func newChainHeartbeat(clock *ChainClock, ordinal func(context.Context) (int, error), send heartbeatSend,
	logf func(string, ...interface{})) *chainHeartbeat {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &chainHeartbeat{chainID: clock.ChainID(), clock: clock, ordinal: ordinal, send: send, now: time.Now, logf: logf,
		times: map[uint64]*heartbeatHorizon{}, blocks: map[uint64]*heartbeatHorizon{}}
}

func (h *chainHeartbeat) note(set map[uint64]*heartbeatHorizon, key uint64, rule string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	hz := set[key]
	if hz == nil {
		hz = &heartbeatHorizon{rules: map[string]bool{}, since: now}
		set[key] = hz
	}
	hz.rules[rule] = true
	hz.asked = now
	heartbeatPending.WithLabelValues(strconv.FormatInt(h.chainID, 10)).Set(float64(len(h.times) + len(h.blocks)))
}

func (h *chainHeartbeat) awaitTime(rule string, after uint64) { h.note(h.times, after, rule) }
func (h *chainHeartbeat) awaitBlock(rule string, n uint64)    { h.note(h.blocks, n, rule) }

// delay is validator i's wait past a horizon.
func heartbeatDelay(i int) time.Duration {
	if i < 1 {
		i = 1
	}
	return heartbeatBaseDelay + time.Duration(i-1)*heartbeatStagger
}

// prune drops every horizon the block fin has passed, and every one no rule has re-stated within heartbeatHorizonTTL.
// It returns the rules served.
func (h *chainHeartbeat) prune(fin *types.Header) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	var served []string
	for after, hz := range h.times {
		switch {
		case fin != nil && fin.Time > after:
			for r := range hz.rules {
				served = append(served, r)
			}
			delete(h.times, after)
		case now.Sub(hz.asked) > heartbeatHorizonTTL:
			delete(h.times, after)
		}
	}
	for n, hz := range h.blocks {
		switch {
		case fin != nil && fin.Number.Uint64() >= n:
			for r := range hz.rules {
				served = append(served, r)
			}
			delete(h.blocks, n)
		case now.Sub(hz.asked) > heartbeatHorizonTTL:
			delete(h.blocks, n)
		}
	}
	heartbeatPending.WithLabelValues(strconv.FormatInt(h.chainID, 10)).Set(float64(len(h.times) + len(h.blocks)))
	sort.Strings(served)
	return served
}

// due is the earliest pending horizon this validator's turn has come for: a time horizon H is due at H + delay, a block
// horizon at its first statement + delay. ok is false when none is pending; at is when the earliest one falls due.
func (h *chainHeartbeat) due(delay time.Duration) (after uint64, isTime bool, number uint64, at time.Time, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for a := range h.times {
		d := time.Unix(int64(a), 0).Add(delay)
		if !ok || d.Before(at) {
			after, isTime, number, at, ok = a, true, 0, d, true
		}
	}
	for n, hz := range h.blocks {
		d := hz.since.Add(delay)
		if !ok || d.Before(at) {
			after, isTime, number, at, ok = 0, false, n, d, true
		}
	}
	return
}

func (h *chainHeartbeat) pending() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.times) + len(h.blocks)
}

func (h *chainHeartbeat) count(o HeartbeatOutcome) HeartbeatOutcome {
	heartbeatOutcomes.WithLabelValues(strconv.FormatInt(h.chainID, 10), string(o)).Inc()
	return o
}

// Tick is one heartbeat round.
func (h *chainHeartbeat) Tick(ctx context.Context) (HeartbeatOutcome, error) {
	if h.pending() == 0 {
		return HeartbeatIdle, nil
	}
	fin, err := h.clock.Finalized(ctx)
	if err != nil {
		return h.count(HeartbeatUnread), err
	}
	if served := h.prune(fin); len(served) > 0 {
		h.logf("💓 [HEARTBEAT] chain %d: finalized block %d (time %d) is past the horizons of %s", h.chainID,
			fin.Number.Uint64(), fin.Time, strings.Join(served, ", "))
	}
	if h.pending() == 0 {
		return h.count(HeartbeatServed), nil
	}
	i, err := h.ordinal(ctx)
	if err != nil {
		return h.count(HeartbeatUnread), fmt.Errorf("chain %d heartbeat: this validator's position among the validators: %w", h.chainID, err)
	}
	delay := heartbeatDelay(i)
	after, isTime, number, at, ok := h.due(delay)
	now := h.now()
	if !ok || now.Before(at) {
		return HeartbeatWaiting, nil
	}
	h.mu.Lock()
	if h.inFlight || (!h.lastSent.IsZero() && now.Sub(h.lastSent) < heartbeatMinGap) {
		h.mu.Unlock()
		return HeartbeatWaiting, nil
	}
	h.inFlight = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.inFlight = false
		h.mu.Unlock()
	}()

	// Each validator reads the chain again before it sends: a block past the horizon may exist already, from another
	// validator's heartbeat or from anyone's traffic (it may not be finalized yet; then finality is what is awaited).
	head, err := h.clock.Head(ctx)
	if err != nil {
		return h.count(HeartbeatUnread), err
	}
	if (isTime && head.Time > after) || (!isTime && head.Number.Uint64() >= number) {
		return h.count(HeartbeatServed), nil
	}
	what := fmt.Sprintf("a block after time %d", after)
	if !isTime {
		what = fmt.Sprintf("block %d", number)
	}
	h.mu.Lock()
	h.lastSent = now
	h.mu.Unlock()
	tx, block, err := h.send(ctx)
	if err != nil {
		o := classifyHeartbeatFailure(err)
		h.logf("❌ [HEARTBEAT] chain %d: validator %d could not send the heartbeat awaiting %s (head %d at %d): %s: %v",
			h.chainID, i, what, head.Number.Uint64(), head.Time, o, err)
		return h.count(o), err
	}
	heartbeatLastBlock.WithLabelValues(strconv.FormatInt(h.chainID, 10)).Set(float64(block))
	h.logf("💓 [HEARTBEAT] chain %d: validator %d sent %s awaiting %s (head was %d at %d); it landed in block %d",
		h.chainID, i, tx, what, head.Number.Uint64(), head.Time, block)
	return h.count(HeartbeatSent), nil
}

// classifyHeartbeatFailure names why a heartbeat was not sent.
func classifyHeartbeatFailure(err error) HeartbeatOutcome {
	var gas *ErrGasCeilingExceeded
	var cost *ErrTxCostCeilingExceeded
	var foreign *ForeignPendingError
	var wait *ChainWaitError
	var unavailable *SenderUnavailableError
	var nb *NotBroadcastError
	switch {
	case errors.Is(err, ErrHeartbeatUnfunded) || strings.Contains(strings.ToLower(err.Error()), "insufficient funds"):
		return HeartbeatUnfunded
	case errors.Is(err, ethrpc.ErrGenesisMismatch):
		return HeartbeatRefused
	case errors.As(err, &gas) || errors.As(err, &cost):
		return HeartbeatGasCeiling
	case errors.Is(err, ErrSequenceBusy) || errors.As(err, &foreign) || errors.As(err, &wait) || errors.As(err, &unavailable):
		return HeartbeatKeyBusy
	case errors.As(err, &nb):
		return HeartbeatRefused
	case IsChainReadError(err):
		return HeartbeatUnread
	default:
		return HeartbeatRefused
	}
}

// Run is the chain's heartbeat until ctx ends.
func (h *chainHeartbeat) Run(ctx context.Context) {
	t := time.NewTicker(heartbeatTick)
	defer t.Stop()
	for {
		if _, err := h.Tick(ctx); err != nil {
			h.logf("⚠️ [HEARTBEAT] chain %d: %v", h.chainID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// =============================================================================
// The orchestrator's side: who this validator is, and the transfer itself
// =============================================================================

// heartbeatOrdinal is this validator's 1-based position in the chain-confirmed settlement roster (sorted by address, the
// order the anchor's set root commits to): the same distinct position on every validator, from the chain.
func (o *BatchOrchestrator) heartbeatOrdinal(ctx context.Context) (int, error) {
	roster, err := o.settlementRoster(ctx)
	if err != nil {
		return 0, err
	}
	me := o.ownAddress()
	for i, a := range roster {
		if a == me {
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("this validator's address %s is not in the chain-confirmed roster", me.Hex())
}

// sendHeartbeat sends one zero-value transfer from this validator's relayer key to itself, through the key's sender (its
// nonce sequence, its outbox, its gas and cost ceilings), and waits for it to land.
func (o *BatchOrchestrator) sendHeartbeat(ctx context.Context) (string, uint64, error) {
	if err := o.ecm.beginNonceSequence(ctx); err != nil {
		return "", 0, err
	}
	defer o.ecm.endNonceSequence()
	self := o.ownAddress()
	// What the sender may pay at most: twice the base fee plus the tip (its fee cap), or the legacy price.
	head, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return "", 0, readErr(fmt.Errorf("reading the head to price a heartbeat: %w", err))
	}
	var price *big.Int
	if head.BaseFee != nil {
		tip, err := o.ecm.client.SuggestGasTipCap(ctx)
		if err != nil {
			return "", 0, readErr(fmt.Errorf("reading the tip to price a heartbeat: %w", err))
		}
		price = new(big.Int).Add(tip, new(big.Int).Mul(head.BaseFee, big.NewInt(2)))
	} else if price, err = o.ecm.client.SuggestGasPrice(ctx); err != nil {
		return "", 0, readErr(fmt.Errorf("reading the gas price to price a heartbeat: %w", err))
	}
	need := new(big.Int).Mul(price, big.NewInt(heartbeatGas))
	bal, err := o.ecm.client.BalanceAt(ctx, self, nil)
	if err != nil {
		return "", 0, readErr(fmt.Errorf("reading the relayer's balance: %w", err))
	}
	if bal.Cmp(need) < 0 {
		return "", 0, fmt.Errorf("%w: %s holds %s wei, a heartbeat may cost %s wei", ErrHeartbeatUnfunded, self.Hex(), bal, need)
	}
	chainID := int64(0)
	if o.ecm.config != nil {
		chainID = o.ecm.config.ChainID
	}
	rcpt, hash, err := o.ecm.sendBatchTx(ctx, "heartbeat", fmt.Sprintf("heartbeat:%d", chainID), heartbeatGas,
		func(opts *bind.TransactOpts) (*types.Transaction, error) {
			return types.NewTx(&types.LegacyTx{Nonce: opts.Nonce.Uint64(), To: &self, Value: new(big.Int), Gas: opts.GasLimit}), nil
		}, nil)
	if err != nil {
		return hash, 0, err
	}
	return hash, rcpt.BlockNumber.Uint64(), nil
}

// attachHeartbeat gives a chain whose blocks stop when idle its heartbeat, sent by this orchestrator's key. A chain whose
// blocks never stop gets none. It returns the heartbeat, or nil.
func (o *BatchOrchestrator) attachHeartbeat(clock *ChainClock) (*chainHeartbeat, error) {
	on, err := chainHeartbeatOn(clock.ChainID())
	if err != nil || !on {
		return nil, err
	}
	b := newChainHeartbeat(clock, o.heartbeatOrdinal, o.sendHeartbeat, o.logf)
	if err := clock.setHeartbeat(b); err != nil {
		return nil, err
	}
	return b, nil
}
