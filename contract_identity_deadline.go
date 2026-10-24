// Copyright 2026 Certen Protocol

package main

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/execution"
)

// The S8 capture's hop tick loop stops following an attested anchor at its deadline (RB12 WP-S8-3c, D-R34-6): the instant after which none of the
// bundle's members can execute (execution.BatchStack.BundleChainDeadline). The capture reads it through capture.DeadlineSource; this is the adapter.
// The deadline is no input of any hash, message, outcome root or govRoot, and reading it changes nothing the settlement or attestation path holds.

// contractIdentityBundles is the batch stack the deadlines are read from; set when the stack is built, nil before (every answer is then "unknown").
var contractIdentityBundles atomic.Pointer[execution.BatchStack]

type bundleDeadlineAdapter struct {
	stack *atomic.Pointer[execution.BatchStack]
}

var _ capture.DeadlineSource = bundleDeadlineAdapter{}

// ChainDeadline is the latest chain deadline of the bundle's members that can still execute, and false whenever it cannot be established.
func (a bundleDeadlineAdapter) ChainDeadline(chain uint64, anchorID [32]byte) (time.Time, bool) {
	if a.stack == nil || chain > math.MaxInt64 {
		return time.Time{}, false
	}
	s := a.stack.Load()
	if s == nil {
		return time.Time{}, false
	}
	r := s.BundleChainDeadline(int64(chain), anchorID)
	if !r.Known() {
		return time.Time{}, false
	}
	return r.Latest, true
}

// contractIdentityDeadline is the Deps.Deadline of the capture runtime.
func contractIdentityDeadline() func(chain uint64, anchorID [32]byte) (time.Time, bool) {
	return capture.DeadlineFrom(bundleDeadlineAdapter{stack: &contractIdentityBundles})
}
