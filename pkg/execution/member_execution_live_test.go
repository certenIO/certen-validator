//go:build live

// Copyright 2026 Certen Protocol

package execution

// Live proof of the member-bound settlement gate (RB3-F77) on Base Sepolia. Run with:
//
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org go test -tags live ./pkg/execution -run LiveMemberSettlement
//
// The member: intent 47b7e925's Base settlement 0x7a2c8522… (2026-09-27), account 0x184a…90A7 executing
// WETH.approve(account, 0) under its leaf and emitting WETH's Approval. The foreign transaction:
// 0x4130a47f… (block 47368812), which emits a WETH Approval too and is nothing to do with that member.
// The gate used to accept the foreign one: it only asked whether the committed event was there.
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestLiveMemberSettlement_BaseSepolia(t *testing.T) {
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
	ctx := context.Background()
	member := common.HexToHash("0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7")
	foreign := common.HexToHash("0x4130a47fe1914405db2f592f627f4e8368cbb7766d948f303900f9597fcff705")
	account := common.HexToAddress("0x184aeF98bEAcAF3E73Ca4a77c72e8F11E9B790A7")
	weth := common.HexToAddress("0x4200000000000000000000000000000000000006")
	approval := crypto.Keccak256Hash([]byte("Approval(address,address,uint256)"))

	// The committed call, encoded independently of the code under test.
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"approve","inputs":[{"name":"s","type":"address"},{"name":"v","type":"uint256"}],"outputs":[{"type":"bool"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := parsed.Pack("approve", account, big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	legs := []CommittedLeg{{Call: CommittedCall{Target: weth, Value: big.NewInt(0), Data: data},
		Events: []ExpectedEvent{{Contract: weth, Topic0: approval}}}}

	// The operationID the settlement was authorised under, read from the transaction; the binding is
	// exercised below by refusing any other.
	raw, _, err := obs.ethClient.TransactionByHash(ctx, member)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := decodeAccountExecution(raw.Data())
	if err != nil {
		t.Fatal(err)
	}
	opID := exec.OperationID

	// 1. The member's own settlement proves.
	if _, err := obs.VerifyExecutedCall(ctx, member, legs, opID, account); err != nil {
		t.Fatalf("the member's settlement must prove: %v", err)
	}

	// 2. A foreign transaction that emits the committed event is NOT the member's settlement.
	if _, err := obs.VerifyExecutedCall(ctx, foreign, legs, opID, account); err == nil {
		t.Fatal("a foreign transaction emitting the committed event was accepted as the member's settlement")
	}

	// 3. The member's settlement is not another member's: another account, another operationID, another
	//    value, or a call set with a call the transaction did not execute.
	if _, err := obs.VerifyExecutedCall(ctx, member, legs, opID, common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")); err == nil {
		t.Fatal("proved for another account")
	}
	other := opID
	other[0] ^= 0xff
	if _, err := obs.VerifyExecutedCall(ctx, member, legs, other, account); err == nil {
		t.Fatal("proved under another operationID")
	}
	valued := []CommittedLeg{{Call: CommittedCall{Target: weth, Value: big.NewInt(1), Data: data}, Events: legs[0].Events}}
	if _, err := obs.VerifyExecutedCall(ctx, member, valued, opID, account); err == nil {
		t.Fatal("proved a call with another value")
	}
	extra := append([]CommittedLeg{}, legs...)
	extra = append(extra, CommittedLeg{Call: CommittedCall{Target: account, Value: big.NewInt(5)}})
	if _, err := obs.VerifyExecutedCall(ctx, member, extra, opID, account); err == nil {
		t.Fatal("proved a member whose committed native transfer the transaction never executed")
	}
}
