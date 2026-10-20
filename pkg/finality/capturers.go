// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/metrics"
)

// Capturer is the leg-independent CAPTURE loop of one chain's kinds (V2_SPEC_S7 2.8, phase 1). It follows the parent chain's
// head and writes the bytes the attesting builders need into a CaptureStore, insert-only. It is a separate long-running loop
// from the upgrader: it is scheduled from the L1 block of the posting or resolution event and is NOT delayed by any eta
// (8.3, "the capture phase is not delayed by any eta"). The chain packages implement it (RB11-D..F) and the validator wires
// their provider configuration (RB11-B2B2b); this package owns only the interface and the scheduling seam.
type Capturer interface {
	// Chain is the ROLLUP chain id the capture serves (the chain column of the capture rows).
	Chain() uint64
	// Name identifies the loop in logs and metrics ("base-sepolia/inbox").
	Name() string
	// Run captures on every new head until ctx is cancelled and returns nil then. Any other return is a failure the
	// supervisor logs by its named state (a StateError, or the error text) and restarts after a bounded backoff.
	Run(ctx context.Context) error
}

// RegisterCapturer adds a capture loop for its chain. The chain must have a profile.
func (r *Registry) RegisterCapturer(c Capturer) error {
	if _, err := r.Profile(c.Chain()); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.capturers == nil {
		r.capturers = map[uint64][]Capturer{}
	}
	for _, e := range r.capturers[c.Chain()] {
		if e.Name() == c.Name() {
			return fmt.Errorf("finality: capturer %q of chain %d is already registered", c.Name(), c.Chain())
		}
	}
	r.capturers[c.Chain()] = append(r.capturers[c.Chain()], c)
	return nil
}

// Capturers returns every registered capture loop, ascending by chain then registration order.
func (r *Registry) Capturers() []Capturer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Capturer
	for _, chain := range r.sortedChainsLocked() {
		out = append(out, r.capturers[chain]...)
	}
	return out
}

// SupervisorConfig bounds the capture supervisor. Zero values take the defaults.
type SupervisorConfig struct {
	RestartMin     time.Duration // first wait after a failed loop (default 5s)
	RestartMax     time.Duration // longest wait (default 5m); the wait doubles from RestartMin up to this
	DisabledChains map[uint64]bool
	Logf           func(format string, args ...any)
	// Restarted is told of every restart (tests; the metric is always updated).
	Restarted func(c Capturer, err error, wait time.Duration)
}

func (c SupervisorConfig) withDefaults() SupervisorConfig {
	if c.RestartMin < MinPoll {
		c.RestartMin = 5 * time.Second
	}
	if c.RestartMax < c.RestartMin {
		c.RestartMax = 5 * time.Minute
		if c.RestartMax < c.RestartMin {
			c.RestartMax = c.RestartMin
		}
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	c.Logf = ethrpc.RedactingLogf(c.Logf) // a capture loop's failure text may carry provider text
	return c
}

// CaptureSupervisor runs every registered Capturer on its own goroutine, so a hung, failing or panicking loop affects no other
// loop, the upgrader, or settlement.
type CaptureSupervisor struct {
	wg sync.WaitGroup
}

// StartCapturers starts one goroutine per registered Capturer whose chain is not switched off, and returns at once. A chain
// whose switch is off is announced as the named state finality_upgrader_disabled and its loops do not start. A loop that
// returns anything but nil after ctx is cancelled, or panics, is restarted after RestartMin doubling to RestartMax, the
// failure logged (provider text must already be redacted by the capturer through pkg/ethrpc) and counted. Wait returns when
// ctx is cancelled and every loop has stopped.
func StartCapturers(ctx context.Context, reg *Registry, cfg SupervisorConfig) *CaptureSupervisor {
	cfg = cfg.withDefaults()
	s := &CaptureSupervisor{}
	for _, c := range reg.Capturers() {
		if cfg.DisabledChains[c.Chain()] {
			cfg.Logf("[FINALITY] capturer %s (chain %d) DISABLED: %s", c.Name(), c.Chain(), ChainSwitchState(c.Chain()).Error())
			continue
		}
		s.wg.Add(1)
		go func(c Capturer) {
			defer s.wg.Done()
			superviseCapturer(ctx, c, cfg)
		}(c)
	}
	return s
}

// Wait blocks until every capture loop has stopped (after ctx is cancelled).
func (s *CaptureSupervisor) Wait() { s.wg.Wait() }

func superviseCapturer(ctx context.Context, c Capturer, cfg SupervisorConfig) {
	wait := cfg.RestartMin
	for ctx.Err() == nil {
		started := time.Now()
		err := runCapturer(ctx, c)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > cfg.RestartMax+cfg.RestartMax {
			wait = cfg.RestartMin // it ran for a long time: this is a new failure, not a crash loop
		}
		cfg.Logf("[FINALITY] capturer %s (chain %d) stopped: %v; restarting in %s", c.Name(), c.Chain(), err, wait)
		metrics.IncFinalityCapturerRestart(c.Chain(), c.Name())
		if cfg.Restarted != nil {
			cfg.Restarted(c, err, wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if wait *= 2; wait > cfg.RestartMax {
			wait = cfg.RestartMax
		}
	}
}

func runCapturer(ctx context.Context, c Capturer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewState(CodePanic, "chain", c.Chain(), "panic", fmt.Sprint(r))
		}
	}()
	if err := c.Run(ctx); err != nil {
		return err
	}
	return fmt.Errorf("capturer returned without an error before its context ended")
}
