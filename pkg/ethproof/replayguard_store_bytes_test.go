// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// V-R10B note: the store is bounded by bytes as well as by count; the oldest entries leave first.
func TestTheReplayGuardStoreIsBoundedByBytes(t *testing.T) {
	w := replayworld.New(t, replayworld.Opts{After: 3})
	ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: w.Proof}
	one := ethproof.ReplayEvidenceSize(ev)
	if one <= 0 {
		t.Fatalf("size %d", one)
	}
	store := ethproof.NewReplayGuardStoreBytes(1000, 3*one)
	for i := 0; i < 10; i++ {
		store.Put(replayworld.ChainID, common.BigToHash(big.NewInt(int64(i+1))), ev, true)
		if b := store.Bytes(); b > 3*one {
			t.Fatalf("after %d entries the store holds %d bytes, bound %d", i+1, b, 3*one)
		}
	}
	if _, _, ok := store.Get(replayworld.ChainID, common.BigToHash(big.NewInt(1))); ok {
		t.Fatal("the oldest entry is still held past the byte bound")
	}
	if _, _, ok := store.Get(replayworld.ChainID, common.BigToHash(big.NewInt(10))); !ok {
		t.Fatal("the newest entry was evicted")
	}
	if ethproof.DefaultReplayGuards.MaxBytes() <= 0 || ethproof.DefaultReplayGuards.MaxBytes() > 512<<20 {
		t.Fatalf("DefaultReplayGuards byte bound %d", ethproof.DefaultReplayGuards.MaxBytes())
	}
}
