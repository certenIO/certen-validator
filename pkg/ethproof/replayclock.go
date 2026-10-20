// Copyright 2026 Certen Protocol

package ethproof

import (
	"context"
	"sync"
	"time"
)

// ReplayClock is the time a replay-guard capture runs on: the wall clock when it asks live providers, a replay clock
// when it re-runs over a recorded world (RB10-F9). The capture's budget, its polls and its per-request deadline are all
// measured on it, so a recorded world, whose answers come back instantly, is judged with the real budget and the real
// poll interval and reaches exactly the verdict the live capture reached.
type ReplayClock interface {
	Now() time.Time
	// Sleep waits d on this clock, or until ctx ends; false when ctx ended first.
	Sleep(ctx context.Context, d time.Duration) bool
	// WithDeadline is context.WithDeadline measured on this clock.
	WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc)
}

type wallClock struct{}

func (wallClock) Now() time.Time                                  { return time.Now() }
func (wallClock) Sleep(ctx context.Context, d time.Duration) bool { return sleepCtx(ctx, d) }
func (wallClock) WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, deadline)
}

// WallClock is the clock a live capture runs on.
var WallClock ReplayClock = wallClock{}

// VirtualClock is a replay clock: it stands still while the recorded providers answer and moves only when the capture
// sleeps, by exactly the time slept; a context deadline on it ends when the clock passes it.
type VirtualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []virtualTimer
}

type virtualTimer struct {
	at     time.Time
	cancel context.CancelFunc
}

// NewVirtualClock is a replay clock starting at start.
func NewVirtualClock(start time.Time) *VirtualClock { return &VirtualClock{now: start} }

// Now is the clock's time.
func (c *VirtualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Sleep moves the clock by d (unless ctx has already ended) and ends every deadline it passes.
func (c *VirtualClock) Sleep(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []context.CancelFunc
	kept := c.timers[:0]
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			due = append(due, t.cancel)
		} else {
			kept = append(kept, t)
		}
	}
	c.timers = kept
	c.mu.Unlock()
	for _, cancel := range due {
		cancel()
	}
	return ctx.Err() == nil
}

// WithDeadline is a context that ends when the clock reaches deadline (or when ctx ends, or cancel is called).
func (c *VirtualClock) WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	child, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	passed := !deadline.After(c.now)
	if !passed {
		c.timers = append(c.timers, virtualTimer{at: deadline, cancel: cancel})
	}
	c.mu.Unlock()
	if passed {
		cancel()
	}
	return child, cancel
}
