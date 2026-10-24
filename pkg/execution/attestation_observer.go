// Copyright 2026 Certen Protocol

package execution

import (
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
)

// AttestationObserver is told of every attestation transaction (executeComprehensiveProof) this validator learns of: the one it mined itself
// (SubmitBatchQuorumProof) and the one it confirmed another validator's way (AnchorProofExecutedConfirmed). block is 0 when the caller did not
// read the receipt's block. It exists for the S8 contract-identity capture (RB12 WP-S8-3b), which must start while the attestation block is
// near the head. The observer can neither delay nor change the attestation path: it is called from a goroutine of its own, after the result
// the path returns is known, a panic in it is recovered, and at most maxObserverCalls calls are in flight (a hung observer costs those and no
// more). It is not an input of any attestation message, outcome root or govRoot.
type AttestationObserver func(chainID int64, bundleID [32]byte, txHash common.Hash, block uint64)

const maxObserverCalls = 64

var observerInflight int32

// observerSlot is the observer of one submitter.
type observerSlot struct {
	mu sync.RWMutex
	fn AttestationObserver
}

// SetAttestationObserver installs (or, with nil, removes) the submitter's observer.
func (s *BatchProofSubmitterImpl) SetAttestationObserver(f AttestationObserver) {
	s.observer.mu.Lock()
	s.observer.fn = f
	s.observer.mu.Unlock()
}

// notifyAttestation hands the transaction to the observer and returns at once.
func (s *BatchProofSubmitterImpl) notifyAttestation(chainID int64, bundleID [32]byte, txHash string, block uint64) {
	s.observer.mu.RLock()
	f := s.observer.fn
	s.observer.mu.RUnlock()
	if f == nil || !IsTransactionHash(txHash) {
		return
	}
	if atomic.AddInt32(&observerInflight, 1) > maxObserverCalls {
		atomic.AddInt32(&observerInflight, -1)
		return
	}
	go func() {
		defer atomic.AddInt32(&observerInflight, -1)
		defer func() { _ = recover() }()
		f(chainID, bundleID, common.HexToHash(txHash), block)
	}()
}
