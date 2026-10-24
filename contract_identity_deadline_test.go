// Copyright 2026 Certen Protocol

package main

import (
	"math"
	"sync/atomic"
	"testing"

	"github.com/certen/independant-validator/pkg/execution"
)

func TestTheCaptureDeadlineSourceIsUnknownWhenItCannotBeSure(t *testing.T) {
	var stack atomic.Pointer[execution.BatchStack]
	a := bundleDeadlineAdapter{stack: &stack}
	id := [32]byte{1}
	if d, ok := a.ChainDeadline(11155111, id); ok || !d.IsZero() {
		t.Fatalf("no stack wired: %v %v", d, ok)
	}
	stack.Store(&execution.BatchStack{})
	if d, ok := a.ChainDeadline(11155111, id); ok || !d.IsZero() {
		t.Fatalf("a stack without store or mempool: %v %v", d, ok)
	}
	if d, ok := a.ChainDeadline(math.MaxUint64, id); ok || !d.IsZero() {
		t.Fatalf("a chain id that is no chain id: %v %v", d, ok)
	}
}

func TestTheCaptureRuntimeIsStartedWithTheBundleDeadlineSource(t *testing.T) {
	f := contractIdentityDeadline()
	if f == nil {
		t.Fatal("the capture is started without a deadline source: the hop ticks would stop at the reach bound only")
	}
	if d, ok := f(11155111, [32]byte{2}); ok || !d.IsZero() {
		t.Fatalf("before the stack is wired: %v %v", d, ok)
	}
}
