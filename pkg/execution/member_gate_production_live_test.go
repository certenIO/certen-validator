//go:build live

// Copyright 2026 Certen Protocol

package execution

// The member-bound settlement gate (RB3-F77) against a production intent, end to end: the user-signed
// intent read from Kermit, its member on each chain derived exactly as the batch anchored it, and each
// member's real settlement proven on its chain. Intent 47b7e925 (2026-09-27) settled on Sepolia
// (0x9d980cdd…) and Base Sepolia (0x7a2c8522…) and was written back. Run with:
//
//	CERTEN_LIVE_ACCUMULATE_URL=https://kermit.accumulatenetwork.io \
//	CERTEN_LIVE_SEPOLIA_RPC=https://ethereum-sepolia-rpc.publicnode.com \
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org \
//	go test -tags live ./pkg/execution -run LiveProductionIntent
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

func TestLiveProductionIntent_GateBindsEachMembersSettlement(t *testing.T) {
	accURL, sepRPC, baseRPC := os.Getenv("CERTEN_LIVE_ACCUMULATE_URL"), os.Getenv("CERTEN_LIVE_SEPOLIA_RPC"), os.Getenv("CERTEN_LIVE_BASE_SEPOLIA_RPC")
	if accURL == "" || sepRPC == "" || baseRPC == "" {
		t.Fatal("the live build requires CERTEN_LIVE_ACCUMULATE_URL, CERTEN_LIVE_SEPOLIA_RPC and CERTEN_LIVE_BASE_SEPOLIA_RPC")
	}
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	adapter, err := accumulate.NewLiteClientAdapter(&accumulate.LiteClientConfig{NetworkURL: accURL, RequestTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "live", AccumulateQueryClient: adapter}}
	const (
		intentID = "47b7e925-b089-47da-abfa-5a6538db21ce"
		accTx    = "1578ff3372e0e17e2c726b5d98c4022cf44857d8df874fc4cb59cc195991c8d2"
		accData  = "acc://certen-seq-1790497115.acme/data"
		sepTx    = "0x9d980cdd503a56a0b306e3215166280cffd9ee398a27fc645f86bfa59df55f3e"
		baseTx   = "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7"
		foreign  = "0x4130a47fe1914405db2f592f627f4e8368cbb7766d948f303900f9597fcff705" // emits a WETH Approval
	)
	cycle := func(chainID string, txs ...string) *activeCycle {
		return &activeCycle{Request: &UnifiedProofCycleRequest{IntentID: intentID, TargetChain: chainID, TxHashes: txs,
			AccumulateTxHash: accTx, AccumulateAccountURL: accData}}
	}
	ctx := context.Background()

	// Each member is WETH.approve with its committed Approval: proven, effects_proven TRUE.
	for _, m := range []struct {
		chain, rpc, tx string
		effects        bool
	}{{"11155111", sepRPC, sepTx, true}, {"84532", baseRPC, baseTx, true}} {
		c := cycle(m.chain, m.tx)
		verified, err := o.verifyContractCallGate(ctx, c, observedChain{id: m.chain, rpc: m.rpc})
		if err != nil {
			t.Fatalf("chain %s: the member's production settlement must prove: %v", m.chain, err)
		}
		if !strings.EqualFold(c.SettlementTx, m.tx) || len(verified) != 1 || c.EffectsShortfall != nil {
			t.Fatalf("chain %s: settlement %q verified %d shortfall %v", m.chain, c.SettlementTx, len(verified), c.EffectsShortfall)
		}
		c.VerifiedCalls = verified // as executePhase7 records the gate's result
		p := cycleEffectsProven(c)
		if m.effects && (p == nil || !*p) || !m.effects && p != nil {
			t.Fatalf("chain %s: effects_proven %v; the member committed effects: %v", m.chain, p, m.effects)
		}
	}

	// A Base cycle naming a transaction that emits the committed event but is not the member's
	// settlement proves nothing - on its own or listed ahead of the real one.
	if _, err := o.verifyContractCallGate(ctx, cycle("84532", foreign), observedChain{id: "84532", rpc: baseRPC}); err == nil {
		t.Fatal("a foreign transaction was accepted as the Base member's settlement")
	}
	c := cycle("84532", foreign, baseTx)
	if _, err := o.verifyContractCallGate(ctx, c, observedChain{id: "84532", rpc: baseRPC}); err != nil || !strings.EqualFold(c.SettlementTx, baseTx) {
		t.Fatalf("with the member's settlement among the observations, it - and only it - is proven: %q %v", c.SettlementTx, err)
	}
}
