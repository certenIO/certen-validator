// Copyright 2026 Certen Protocol

package capture

import "time"

// DeadlineSource is where the runtime learns the deadline of an attested anchor (RB12 WP-S8-3c, D-R34-6): the chain deadline of the members the
// anchor settles (pkg/execution memberChainDeadline), past which no settlement can execute and the anchor's hop ticks stop. It is defined here,
// and implemented by the process that wires the runtime, so this package imports nothing of pkg/execution. known is false whenever the deadline
// cannot be established (no member, all members finished, a member with nothing to measure from, a store that cannot be read): the anchor is
// then followed to its reach bound (B_v + 16 ticks + W) and never beyond.
type DeadlineSource interface {
	ChainDeadline(chain uint64, anchorID [32]byte) (deadline time.Time, known bool)
}

// DeadlineFrom is src as the Deps.Deadline function; nil for a nil src.
func DeadlineFrom(src DeadlineSource) func(chain uint64, anchorID [32]byte) (time.Time, bool) {
	if src == nil {
		return nil
	}
	return func(chain uint64, anchorID [32]byte) (time.Time, bool) { return src.ChainDeadline(chain, anchorID) }
}

// safeDeadline wraps a deadline source for the tick loop. A source that panics, or answers a known deadline of the zero time (the "none known"
// value of TrackedAnchor.Deadline), has no deadline: the anchor is followed to its reach bound. Without the wrapper a panic would abort the whole
// step - every anchor of the chain - at every poll, and a zero deadline would end the anchor's ticks at once. A past deadline is a deadline: it
// ends the anchor's ticks, which affects nothing but the hops of that anchor. The source runs on the tick goroutine only, outside every lock of
// the runtime and the ticker, so a slow source delays the ticks of its chain and nothing else.
func safeDeadline(f func(chain uint64, anchorID [32]byte) (time.Time, bool)) func(chain uint64, anchorID [32]byte) (time.Time, bool) {
	if f == nil {
		return nil
	}
	return func(chain uint64, anchorID [32]byte) (d time.Time, ok bool) {
		defer func() {
			if recover() != nil {
				d, ok = time.Time{}, false
			}
		}()
		d, ok = f(chain, anchorID)
		if !ok || d.IsZero() {
			return time.Time{}, false
		}
		return d, true
	}
}
