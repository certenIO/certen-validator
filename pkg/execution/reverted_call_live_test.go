//go:build live

// Copyright 2026 Certen Protocol

package execution

// Live proofs of the revert verifier against Base Sepolia (intent 5a2ebba0's reverted settlement,
// 2026-09-20). Run with:
//
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org go test -tags live ./pkg/execution -run LiveBaseSepolia
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/proof"
)

// The live revert against Base Sepolia, end to end through RB-2 inclusion.
func TestVerifyRevertedCall_LiveBaseSepolia(t *testing.T) {
	rpcURL := os.Getenv("CERTEN_LIVE_BASE_SEPOLIA_RPC")
	if rpcURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_BASE_SEPOLIA_RPC")
	}
	obs, err := NewExternalChainObserver(&ExternalChainObserverConfig{
		EthereumRPC: rpcURL, ChainID: 84532, ValidatorID: "test", RequiredConfirmations: 1, Timeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	blobs := liveIntentBlobs(t)
	call, _ := parseCommittedCallLegs(blobs[1])[0].committedCall()
	opBytes, _, _ := proof.ComputeCanonical4BlobHash(blobs[0], blobs[1], blobs[2], blobs[3])
	var opID [32]byte
	copy(opID[:], opBytes)
	tx := common.HexToHash("0x54562d54d6c38a858fda1bdd9cffb95cffb688b2f2f685468ba4752ddd3c8b0b")

	res, err := obs.VerifyRevertedCall(context.Background(), tx, []CommittedCall{call}, opID,
		common.HexToAddress("0xfa96ed9b2bc7139fa671e1faf53f901adeea5b32"))
	if err != nil {
		t.Fatalf("the live revert must prove: %v", err)
	}
	if res.Status != 0 {
		t.Fatalf("status %d", res.Status)
	}
	// And the success gate still refuses it, as it must.
	if _, err := obs.VerifyExecutedCall(context.Background(), tx, []CommittedLeg{{Call: call}}, opID,
		common.HexToAddress("0xfa96ed9b2bc7139fa671e1faf53f901adeea5b32")); err == nil {
		t.Fatal("the success gate accepted a reverted transaction")
	}
}

// Against Base Sepolia: the same reverted transaction is NOT this intent's failure when
// claimed for another account - the binding H1 of the review found missing.
func TestVerifyRevertedCall_LiveBaseSepolia_WrongAccountRefused(t *testing.T) {
	rpcURL := os.Getenv("CERTEN_LIVE_BASE_SEPOLIA_RPC")
	if rpcURL == "" {
		t.Fatal("the live build requires CERTEN_LIVE_BASE_SEPOLIA_RPC")
	}
	obs, err := NewExternalChainObserver(&ExternalChainObserverConfig{
		EthereumRPC: rpcURL, ChainID: 84532, ValidatorID: "test", RequiredConfirmations: 1, Timeout: 90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	blobs := liveIntentBlobs(t)
	call, _ := parseCommittedCallLegs(blobs[1])[0].committedCall()
	opBytes, _, _ := proof.ComputeCanonical4BlobHash(blobs[0], blobs[1], blobs[2], blobs[3])
	var opID [32]byte
	copy(opID[:], opBytes)
	tx := common.HexToHash("0x54562d54d6c38a858fda1bdd9cffb95cffb688b2f2f685468ba4752ddd3c8b0b")
	if _, err := obs.VerifyRevertedCall(context.Background(), tx, []CommittedCall{call}, opID,
		common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")); err == nil {
		t.Fatal("proved a revert addressed to another account")
	}
}
