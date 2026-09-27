// Copyright 2026 Certen Protocol

package ledger

import (
	"errors"
	"testing"
	"time"
)

// RB3-F116: a read that FAILED is not a key that is absent. Treating it as absent re-seals the
// entitlement policy from the environment, restarts the ABCI state at height 0, resets an anchor
// target's counters, and restarts intent discovery at the chain tip.

var errDisk = errors.New("leveldb: corrupted block")

type kvStub struct {
	m    map[string][]byte
	fail bool
	sets int
}

func (k *kvStub) Get(key []byte) ([]byte, error) {
	if k.fail {
		return nil, errDisk
	}
	return k.m[string(key)], nil
}

func (k *kvStub) Set(key, value []byte) error {
	k.sets++
	k.m[string(key)] = append([]byte(nil), value...)
	return nil
}

func TestAFailedReadIsAnErrorNotAnAbsentKey(t *testing.T) {
	kv := &kvStub{m: map[string][]byte{}, fail: true}
	s := NewLedgerStore(kv)

	if st, err := s.LoadABCIState(); !errors.Is(err, errDisk) || st != nil {
		t.Errorf("LoadABCIState: (%v, %v)", st, err)
	}
	if p, err := s.LoadEntitlementPolicy(); !errors.Is(err, errDisk) || p != nil {
		t.Errorf("LoadEntitlementPolicy: (%v, %v)", p, err)
	}
	if h, err := s.LoadIntentLastBlock(); !errors.Is(err, errDisk) || h != 0 {
		t.Errorf("LoadIntentLastBlock: (%d, %v)", h, err)
	}
	if _, err := s.loadSystemLedgerMeta(); !errors.Is(err, errDisk) || errors.Is(err, ErrMetaNotFound) {
		t.Errorf("loadSystemLedgerMeta: %v", err)
	}
	if _, err := s.loadAnchorMeta(); !errors.Is(err, errDisk) || errors.Is(err, ErrAnchorMetaNotFound) {
		t.Errorf("loadAnchorMeta: %v", err)
	}
	if tgt, err := s.loadAnchorTarget("acc://x"); !errors.Is(err, errDisk) || tgt != nil {
		t.Errorf("loadAnchorTarget: (%v, %v)", tgt, err)
	}
	if _, err := s.GetSystemLedgerLatest("c"); !errors.Is(err, errDisk) {
		t.Errorf("GetSystemLedgerLatest: %v", err)
	}
	if _, err := s.GetSystemLedgerAtHeight("c", 3); !errors.Is(err, errDisk) {
		t.Errorf("GetSystemLedgerAtHeight: %v", err)
	}

	// A write that first reads must not write over state it could not read.
	if err := s.MarkAnchorProduced(7, "acc://x", "tx", time.Unix(1, 0), 0, time.Time{}); err == nil {
		t.Error("MarkAnchorProduced wrote after a failed read")
	}
	if err := s.MarkAnchorDelivered("acc://x", "tx", time.Unix(1, 0)); err == nil {
		t.Error("MarkAnchorDelivered wrote after a failed read")
	}
	if err := s.UpdateSystemLedgerOnCommit(7, "h", time.Unix(1, 0), nil, "v", nil); err == nil {
		t.Error("UpdateSystemLedgerOnCommit wrote after a failed read")
	}
	if kv.sets != 0 {
		t.Errorf("%d writes after failed reads", kv.sets)
	}
}

// Absent keys still read as absent.
func TestAnAbsentKeyStillReadsAsAbsent(t *testing.T) {
	s := NewLedgerStore(&kvStub{m: map[string][]byte{}})
	if st, err := s.LoadABCIState(); err != nil || st != nil {
		t.Errorf("LoadABCIState: (%v, %v)", st, err)
	}
	if p, err := s.LoadEntitlementPolicy(); err != nil || p != nil {
		t.Errorf("LoadEntitlementPolicy: (%v, %v)", p, err)
	}
	if h, err := s.LoadIntentLastBlock(); err != nil || h != 0 {
		t.Errorf("LoadIntentLastBlock: (%d, %v)", h, err)
	}
	if _, err := s.loadSystemLedgerMeta(); !errors.Is(err, ErrMetaNotFound) {
		t.Errorf("loadSystemLedgerMeta: %v", err)
	}
	if _, err := s.loadAnchorMeta(); !errors.Is(err, ErrAnchorMetaNotFound) {
		t.Errorf("loadAnchorMeta: %v", err)
	}
	if tgt, err := s.loadAnchorTarget("acc://x"); err != nil || tgt == nil || tgt.TargetURL != "acc://x" {
		t.Errorf("loadAnchorTarget: (%v, %v)", tgt, err)
	}
}
