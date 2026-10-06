// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// An outcome's layer-6 inclusion evidence (AgreedOutcomeChain.TransactionInclusion) is built and verified offline for
// the settlement of every captured signed-settlement block - including an Arbitrum block holding a Nitro retry (0x68)
// beside signed transactions - through agreeing providers, one of which serves no eth_getBlockReceipts.
func TestOutcomeInclusionEvidenceForEverySignedSettlementBlock(t *testing.T) {
	for _, name := range ethprooftest.Settlements {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			reader, err := ethrpc.NewAgreeingReader(context.Background(), f.ChainID,
				ethprooftest.URLs(t, &ethprooftest.Provider{F: f}, &ethprooftest.Provider{F: f, NoBlockReceipts: true}), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c := &AgreedOutcomeChain{chainID: f.ChainID, reader: reader, clock: newChainClock(f.ChainID, reader)}
			ev, hdr, err := c.TransactionInclusion(context.Background(), f.SettlementTx)
			if err != nil {
				t.Fatal(err)
			}
			if ev.Index != f.SettlementIndex() || hdr.Hash() != f.BlockHash() {
				t.Fatalf("evidence at index %d of block %s; the settlement is at %d of %s", ev.Index, hdr.Hash().Hex(),
					f.SettlementIndex(), f.BlockHash().Hex())
			}
			if _, _, rcpt, err := ev.verify(f.SettlementTx, f.BlockHash(), hdr.Number.Uint64(), name); err != nil {
				t.Fatalf("the evidence does not verify offline: %v", err)
			} else if rcpt.Status != 1 {
				t.Fatalf("the proven receipt has status %d", rcpt.Status)
			}
		})
	}
}
