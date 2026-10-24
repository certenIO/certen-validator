// Copyright 2026 Certen Protocol

package execution

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const obsTx = "0x1111111111111111111111111111111111111111111111111111111111111111"

func waitInflight(t *testing.T, want int32) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if atomic.LoadInt32(&observerInflight) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("observer calls in flight = %d, want %d", atomic.LoadInt32(&observerInflight), want)
}

func TestAttestationObserverIsToldOfTheTransaction(t *testing.T) {
	s := NewBatchProofSubmitter(nil, nil)
	type got struct {
		chain  int64
		bundle [32]byte
		tx     common.Hash
		block  uint64
	}
	ch := make(chan got, 1)
	s.SetAttestationObserver(func(c int64, b [32]byte, h common.Hash, blk uint64) { ch <- got{c, b, h, blk} })
	s.notifyAttestation(84532, [32]byte{7}, obsTx, 99)
	select {
	case g := <-ch:
		if g.chain != 84532 || g.bundle != [32]byte{7} || g.tx != common.HexToHash(obsTx) || g.block != 99 {
			t.Fatalf("observer got %+v", g)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the observer was not told")
	}
	// not a transaction hash: nothing is delivered; removing the observer silences it
	s.notifyAttestation(84532, [32]byte{7}, "pending", 1)
	s.notifyAttestation(84532, [32]byte{7}, "", 1)
	s.SetAttestationObserver(nil)
	s.notifyAttestation(84532, [32]byte{7}, obsTx, 99)
	select {
	case g := <-ch:
		t.Fatalf("a call that must be ignored was delivered: %+v", g)
	case <-time.After(100 * time.Millisecond):
	}
	waitInflight(t, 0)
}

func TestAttestationObserverCannotBlockOrBreakTheAttestationPath(t *testing.T) {
	s := NewBatchProofSubmitter(nil, nil)
	// a panicking observer: the path goes on, and the next call is delivered
	var calls int32
	s.SetAttestationObserver(func(int64, [32]byte, common.Hash, uint64) {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("hostile observer")
		}
	})
	s.notifyAttestation(1, [32]byte{}, obsTx, 1)
	s.notifyAttestation(1, [32]byte{}, obsTx, 1)
	waitInflight(t, 0)
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("calls = %d", atomic.LoadInt32(&calls))
	}
	// a hung observer: 200 notifications return at once, at most maxObserverCalls goroutines hold, the rest are dropped
	release := make(chan struct{})
	var started int32
	s.SetAttestationObserver(func(int64, [32]byte, common.Hash, uint64) { atomic.AddInt32(&started, 1); <-release })
	t0 := time.Now()
	for i := 0; i < 200; i++ {
		s.notifyAttestation(1, [32]byte{}, obsTx, 1)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("200 notifications took %v", d)
	}
	waitInflight(t, maxObserverCalls)
	if n := atomic.LoadInt32(&observerInflight); n > maxObserverCalls {
		t.Fatalf("%d calls in flight, the bound is %d", n, maxObserverCalls)
	}
	close(release)
	waitInflight(t, 0)
	if n := atomic.LoadInt32(&started); n != maxObserverCalls {
		t.Fatalf("%d observer calls started, want exactly the bound %d (the other 136 were dropped)", n, maxObserverCalls)
	}
	// concurrent notifications and replacement of the observer are safe
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SetAttestationObserver(func(int64, [32]byte, common.Hash, uint64) {})
			s.notifyAttestation(1, [32]byte{}, obsTx, 1)
		}()
	}
	wg.Wait()
	waitInflight(t, 0)
}

// The two paths that learn of an attestation call the observer with their result already decided: pinned by the text of the file.
func TestAttestationObserverIsCalledAtTheTwoPathsAfterTheirResultIsKnown(t *testing.T) {
	raw, err := os.ReadFile("batch_proof_submitter.go")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, c := range []struct{ before, call string }{
		{"attestation mined tx=%s gas=%d", "s.notifyAttestation(chainID, bundleID, txHash, receipt.BlockNumber.Uint64())\n\treturn txHash, receipt.BlockNumber.Uint64()"},
		{"could not read proofExecuted for anchor", "if executed {\n\t\ts.notifyAttestation(chainID, bundleID, verifyTxHash, 0)\n\t}\n\treturn executed, nil"},
	} {
		i, j := strings.Index(src, c.before), strings.Index(src, c.call)
		if i < 0 || j < 0 || j < i {
			t.Fatalf("the observer call %q is not placed after %q", c.call[:30], c.before)
		}
	}
	if strings.Count(src, "notifyAttestation(") != 2 {
		t.Fatalf("notifyAttestation is called %d times, want the two paths", strings.Count(src, "notifyAttestation("))
	}
}
