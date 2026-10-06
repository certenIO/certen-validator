// Copyright 2026 Certen Protocol

package ethereum

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

// RB7 Phase A F-RPC-10: GetBlock read a full block (BlockByNumber), which go-ethereum refuses on every Telcoin Adiri block
// ("empty uncle list but block header indicates uncles"). The client reads headers; this is a real Adiri block.
func TestTheLatestAdiriHeaderIsRead(t *testing.T) {
	for _, name := range []string{"telcoin_adiri_498759", "telcoin_adiri_499961"} {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			c, err := NewClient(ethprooftest.URLs(t, &ethprooftest.Provider{F: f})[0], 2017)
			if err != nil {
				t.Fatal(err)
			}
			h, err := c.GetLatestHeader(context.Background())
			if err != nil {
				t.Fatalf("THE regression (F-RPC-10): the latest Adiri block is not read: %v", err)
			}
			want := f.Header(t)
			if h.Hash() != f.BlockHash() || h.Time != want.Time || h.Number.Cmp(want.Number) != 0 {
				t.Fatalf("read block %d %s at %d, want %d %s at %d", h.Number, h.Hash().Hex(), h.Time, want.Number, f.BlockHash().Hex(), want.Time)
			}
		})
	}
}
