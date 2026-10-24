// Copyright 2026 Certen Protocol

package strategy

import (
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// The hooks of the S8 contract-identity capture (RB12 WP-S8-3b). They hand the capture the two things it cannot see from outside: the agreed
// reader of each live chain, and the moment a settlement is first observed (the trigger of the S6 capture, which this sits beside). They
// change nothing the observation does: observers are called from goroutines of their own after the S6 capture has been started, a panic in
// one is recovered, at most maxHookCalls are in flight, and nothing here is an input of any attestation message, outcome root or govRoot.

const maxHookCalls = 64

var (
	hookMu              sync.RWMutex
	agreedReaders       = map[int64]*ethrpc.AgreeingReader{}
	settlementObservers []func(chainID int64, txHash common.Hash)
	hookInflight        int32
)

// RegisterAgreedReader records the agreed reader of a chain (called when the strategy builds it).
func RegisterAgreedReader(chainID int64, r *ethrpc.AgreeingReader) {
	if r == nil {
		return
	}
	hookMu.Lock()
	agreedReaders[chainID] = r
	hookMu.Unlock()
}

// AgreedReaderFor returns the agreed reader of a chain, if its strategy has built one.
func AgreedReaderFor(chainID int64) (*ethrpc.AgreeingReader, bool) {
	hookMu.RLock()
	defer hookMu.RUnlock()
	r, ok := agreedReaders[chainID]
	return r, ok
}

// RegisterSettlementObserver adds an observer told of every settlement transaction when it is first observed.
func RegisterSettlementObserver(f func(chainID int64, txHash common.Hash)) {
	if f == nil {
		return
	}
	hookMu.Lock()
	settlementObservers = append(settlementObservers, f)
	hookMu.Unlock()
}

// notifySettlementObserved tells the observers and returns at once.
func notifySettlementObserved(chainID int64, txHash common.Hash) {
	hookMu.RLock()
	fns := append([]func(int64, common.Hash){}, settlementObservers...)
	hookMu.RUnlock()
	for _, f := range fns {
		if atomic.AddInt32(&hookInflight, 1) > maxHookCalls {
			atomic.AddInt32(&hookInflight, -1)
			return
		}
		go func(f func(int64, common.Hash)) {
			defer atomic.AddInt32(&hookInflight, -1)
			defer func() { _ = recover() }()
			f(chainID, txHash)
		}(f)
	}
}
