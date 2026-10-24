// Copyright 2026 Certen Protocol

package strategy

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func hookWait(t *testing.T) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if atomic.LoadInt32(&hookInflight) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hook calls still in flight: %d", atomic.LoadInt32(&hookInflight))
}

func TestSettlementObserversAreToldAndCannotBlockOrBreakTheObservation(t *testing.T) {
	hookMu.Lock()
	settlementObservers = nil
	hookMu.Unlock()
	tx := common.Hash{0xab}
	got := make(chan common.Hash, 1024)
	RegisterSettlementObserver(nil) // ignored
	RegisterSettlementObserver(func(c int64, h common.Hash) {
		if c == 7 {
			panic("hostile observer")
		}
		got <- h
	})
	notifySettlementObserved(7, tx) // panics inside its own goroutine
	notifySettlementObserved(11155111, tx)
	select {
	case h := <-got:
		if h != tx {
			t.Fatalf("observer got %x", h)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the observer was not told")
	}
	hookWait(t)
	release := make(chan struct{})
	RegisterSettlementObserver(func(int64, common.Hash) { <-release })
	t0 := time.Now()
	for i := 0; i < 150; i++ {
		notifySettlementObserved(1, tx)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("150 notifications took %v", d)
	}
	if n := atomic.LoadInt32(&hookInflight); n > maxHookCalls {
		t.Fatalf("%d hook calls in flight, bound %d", n, maxHookCalls)
	}
	close(release)
	hookWait(t)
}

func TestAgreedReaderRegistry(t *testing.T) {
	if _, ok := AgreedReaderFor(424242); ok {
		t.Fatal("an unknown chain has a reader")
	}
	RegisterAgreedReader(424242, nil) // ignored
	if _, ok := AgreedReaderFor(424242); ok {
		t.Fatal("a nil reader was registered")
	}
}

// The observation calls the hook right after it starts the S6 capture, and the strategy registers the reader it builds: pinned by the text.
func TestCaptureHookCallSites(t *testing.T) {
	obs, err := os.ReadFile("evm_observer.go")
	if err != nil {
		t.Fatal(err)
	}
	o := strings.ReplaceAll(string(obs), "\r\n", "\n")
	if !strings.Contains(o, "o.replay.Begin(txHash)\n\t}\n\t// The S8 contract-identity capture starts at the same moment (capture_hooks.go); it cannot delay or fail this observation.\n\tnotifySettlementObserved(o.chainID, txHash)") {
		t.Fatal("notifySettlementObserved does not follow the S6 capture start")
	}
	st, err := os.ReadFile("evm_strategy.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(st), "\r\n", "\n"), "finality = agreeing\n\t\tRegisterAgreedReader(chainID.Int64(), agreeing)") {
		t.Fatal("the strategy does not register the agreed reader it builds")
	}
}
