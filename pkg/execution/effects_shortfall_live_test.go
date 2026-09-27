//go:build live

// Copyright 2026 Certen Protocol

package execution

// Live proof of the effects-shortfall verifier (RB3-F67) against Base Sepolia, on the real settlement of
// intent 47b7e925 (2026-09-27): account 0x184a…90A7 executed WETH.approve(account, 0) under its leaf and
// emitted WETH's Approval. Run with:
//
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org go test -tags live ./pkg/execution -run LiveEffectsShortfall
//
// Behind the `live` build tag rather than a skip (00_STANDARD §2): without the tag it is not compiled;
// effects_shortfall_test.go pins what the offline build proves.

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

func TestLiveEffectsShortfall_BaseSepolia(t *testing.T) {
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
	tx := common.HexToHash("0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7")
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
	call := CommittedCall{Target: weth, Value: big.NewInt(0), Data: data}

	// The operationID the settlement was authorised under, read from the transaction itself; the
	// binding is exercised below by refusing any other.
	raw, _, err := obs.ethClient.TransactionByHash(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := decodeAccountExecution(raw.Data())
	if err != nil {
		t.Fatal(err)
	}
	opID := exec.OperationID

	// 1. Committed effects that ARE there: no shortfall - the verifier refuses to claim one.
	legs := []ShortfallLeg{{Call: call, Events: []ExpectedEvent{{Contract: weth, Topic0: approval}}}}
	if _, _, err := obs.VerifyEffectsNotProven(ctx, tx, legs, opID, account); err == nil || !strings.Contains(err.Error(), "no shortfall") {
		t.Fatalf("a settlement whose committed event is present must not be claimed a shortfall: %v", err)
	}

	// 2. A committed effect it never produced (Transfer, which approve does not emit): a proven shortfall
	//    naming exactly that effect, bound to the member's leaf.
	transfer := crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	legs[0].Events = append(legs[0].Events, ExpectedEvent{Contract: weth, Topic0: transfer})
	res, claim, err := obs.VerifyEffectsNotProven(ctx, tx, legs, opID, account)
	if err != nil {
		t.Fatalf("the absent Transfer must prove a shortfall: %v", err)
	}
	if res.Status != 1 || len(claim.MissingEvents) != 1 || claim.MissingEvents[0] != "0:1" || len(claim.UnsetState) != 0 {
		t.Fatalf("claim %+v; want exactly event 0:1 missing", claim)
	}
	if claim.ChainID != 84532 || !strings.EqualFold(claim.Account, account.Hex()) || claim.Leaf == "" ||
		!strings.EqualFold(claim.OperationID, common.Hash(opID).Hex()) {
		t.Fatalf("claim %+v is not bound to the member", claim)
	}

	// 3. The binding: another account, another operationID, or another committed call is refused.
	if _, _, err := obs.VerifyEffectsNotProven(ctx, tx, legs, opID, common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")); err == nil {
		t.Fatal("claimed a shortfall for another account")
	}
	other := opID
	other[0] ^= 0xff
	if _, _, err := obs.VerifyEffectsNotProven(ctx, tx, legs, other, account); err == nil {
		t.Fatal("claimed a shortfall under another operationID")
	}
	wrongCall := legs
	wrongCall[0].Call = CommittedCall{Target: weth, Value: big.NewInt(1), Data: data}
	if _, _, err := obs.VerifyEffectsNotProven(ctx, tx, wrongCall, opID, account); err == nil {
		t.Fatal("claimed a shortfall for a call the transaction did not execute")
	}
}
