// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/chain/strategy"
	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// S8 contract-identity capture (RB12 WP-S8-3b, V2_SPEC_S8 Q2): two stations run beside the observation. E1 starts when this validator
// learns of an attestation transaction (execution.BatchProofSubmitterImpl.SetAttestationObserver), E2 when a settlement is first observed
// (strategy.RegisterSettlementObserver), and both write the insert-only capture store. The switch CERTEN_CONTRACT_IDENTITY_CAPTURE is OFF by
// default. NO failure of this start ends the validator: a bad switch or setting, a missing durable store or manifest, a panic, is a NAMED
// disabled state (contract_identity_capture_disabled{reason,setting}: log, metric certen_contract_identity_capture_disabled_total and
// certen_contract_identity_capture_enabled 0, and the capture block of /health/detailed) and the function returns. The capture reads no
// stored data and enters no hashed input.

// contractIdentityStore returns the durable capture store. WP-S8-5 replaces it with the Postgres implementation of capture.Store (the
// conformance suite is capture/storetest); until then there is none, and a switched-on capture is the named state no_durable_store.
var contractIdentityStore = func() (capture.Store, error) {
	return nil, errors.New("the Postgres capture store is WP-S8-5")
}

// contractIdentityRuntime is the running capture, or nil.
var contractIdentityRuntime atomic.Pointer[capture.Runtime]

// contractIdentityAttested is installed as the submitter's attestation observer at construction; it forwards to the runtime once started.
func contractIdentityAttested(chainID int64, bundleID [32]byte, txHash common.Hash, block uint64) {
	if rt := contractIdentityRuntime.Load(); rt != nil {
		rt.AttestationObserved(chainID, bundleID, txHash, block)
	}
}

var settlementObserverOnce sync.Once

// startContractIdentityCapture starts the capture. It never returns an error and never panics.
func startContractIdentityCapture(ctx context.Context, logf func(string, ...any)) {
	defer func() {
		if r := recover(); r != nil {
			metrics.AnnounceContractIdentityCaptureDisabled("start_panicked", "")
			logf("⚠️ [CONTRACT-IDENTITY] capture start panicked: %v", r)
		}
	}()
	set, dis := capture.SettingsFromEnv(os.Getenv)
	if dis != nil {
		metrics.AnnounceContractIdentityCaptureDisabled(dis.Reason, dis.Setting)
		logf("⚠️ [CONTRACT-IDENTITY] capture disabled: %v (the value is not printed)", dis)
		return
	}
	var store capture.Store
	if set.Enabled {
		if s, err := contractIdentityStore(); err == nil {
			store = s
		}
	}
	man, merr := ci.Embedded()
	if merr != nil {
		man = nil
	}
	var readers sync.Map
	rt, _ := capture.Start(ctx, set, capture.Deps{Store: store, Manifest: man, Logf: logf,
		SourceFor: func(chain uint64) (capture.AttestSource, error) {
			if v, ok := readers.Load(chain); ok {
				return v.(capture.AttestSource), nil
			}
			r, ok := strategy.AgreedReaderFor(int64(chain))
			if !ok {
				return nil, errors.New("no agreed reader for the chain")
			}
			src, err := capture.NewReaderSource(r)
			if err != nil {
				return nil, err
			}
			readers.Store(chain, src)
			return src, nil
		}})
	if rt == nil {
		return
	}
	contractIdentityRuntime.Store(rt)
	settlementObserverOnce.Do(func() {
		strategy.RegisterSettlementObserver(func(chainID int64, tx common.Hash) {
			if cur := contractIdentityRuntime.Load(); cur != nil {
				cur.SettlementObserved(chainID, tx)
			}
		})
	})
}
