// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

func txTo(to *common.Address, data []byte) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: 500000, To: to, Value: big.NewInt(0), Data: data})
}

// WalletCallee is the callee the builder captures the wallet proofs for: exactly the transactions the classifier sends down the wallet
// route's decoding (a callee other than the Rollup, a wallet entry point, canonical arguments), nothing else.
func TestWalletCalleeIsExactlyTheTransactionsOfTheWalletDecoding(t *testing.T) {
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	arb, err := arbfinal.LoadPins(embedded)
	if err != nil {
		t.Fatal(err)
	}
	callee := common.HexToAddress("0x000000000000000000000000000000000000beef")
	confirm := sw.ConfirmCall(sw.SelConfirm)
	dest := []common.Address{sw.Rollup}
	for _, c := range []struct {
		name string
		sel  [4]byte
	}{{"executeTransaction", sw.SelWalletTx}, {"executeTransactions", sw.SelWalletTxs}, {"with gas refunder", sw.SelWalletTxR}, {"batch with gas refunder", sw.SelWalletTxsR}} {
		got, ok := arbfinal.WalletCallee(arb, txTo(&callee, sw.WalletInput(c.sel, [][]byte{confirm}, dest)))
		if !ok || got != callee {
			t.Errorf("%s: %s %v", c.name, got, ok)
		}
	}
	valid := sw.WalletInput(sw.SelWalletTx, [][]byte{confirm}, dest)
	for _, c := range []struct {
		name string
		tx   *types.Transaction
	}{
		{"no transaction", nil},
		{"a contract creation", txTo(nil, valid)},
		{"the Rollup as callee", txTo(&sw.Rollup, valid)},
		{"a direct confirmAssertion", txTo(&callee, confirm)},
		{"an unknown selector", txTo(&callee, []byte{0xde, 0xad, 0xbe, 0xef, 0x00})},
		{"empty calldata", txTo(&callee, nil)},
		{"three bytes", txTo(&callee, valid[:3])},
		{"a wallet selector with garbage", txTo(&callee, append(append([]byte(nil), sw.SelWalletTx[:]...), bytes.Repeat([]byte{0xab}, 40)...))},
		{"a wallet selector with a trailing byte", txTo(&callee, append(append([]byte(nil), valid...), 0x00))},
		{"arrays of different lengths", txTo(&callee, sw.WalletInputAmounts([][]byte{confirm, confirm}, []common.Address{sw.Rollup, sw.Rollup}, 1))},
	} {
		if got, ok := arbfinal.WalletCallee(arb, c.tx); ok || got != (common.Address{}) {
			t.Errorf("%s: %s %v", c.name, got, ok)
		}
	}
}

// The pinned wallet identity is exactly the real contract code the synthetic worlds use: the code hashes of the embedded pins are the
// keccak256 of the two runtime codes, the implementation slot is the EIP-1967 slot, and the template embeds its own address (so its code
// hash names one deployment) while the proxy code names no address at all (so one hash covers every wallet).
func TestThePinnedWalletIdentityIsTheRealRuntimeCode(t *testing.T) {
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	arb, err := arbfinal.LoadPins(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if arb.LogicPins[sw.WalletProxyCodeHash] != arbfinal.RoleWalletProxy || arb.LogicPins[sw.WalletLogicCodeHash] != arbfinal.RoleWalletLogic {
		t.Fatalf("the pinned roles %v do not hold the runtime code hashes %s / %s", arb.LogicPins, sw.WalletProxyCodeHash, sw.WalletLogicCodeHash)
	}
	if len(sw.WalletProxyCode) != 2147 || len(sw.WalletLogicCode) != 6864 {
		t.Fatalf("runtime code lengths %d / %d", len(sw.WalletProxyCode), len(sw.WalletLogicCode))
	}
	if arb.WalletImpl != sw.WalletImpl || arb.WalletImplSlot != sw.WalletImplSlot || arb.WalletImplSlot != arb.AdminSlot {
		t.Fatalf("impl %s slot %s, admin slot %s", arb.WalletImpl, arb.WalletImplSlot, arb.AdminSlot)
	}
	if n := bytes.Count(sw.WalletLogicCode, sw.WalletImpl[:]); n != 1 {
		t.Errorf("the template embeds its own address %d times, want once", n)
	}
	if bytes.Contains(sw.WalletProxyCode, sw.WalletImpl[:]) {
		t.Error("the proxy code names the template: it would not be one code for every wallet")
	}
	if got := sw.WalletImplWord(); !bytes.Equal(got[:12], make([]byte, 12)) || !bytes.Equal(got[12:], sw.WalletImpl[:]) {
		t.Errorf("implementation word %s", got)
	}
	if arb.LogicPins[sw.OtherProxyCodeHash] != "" || arb.LogicPins[sw.OtherTemplateCodeHash] != "" {
		t.Error("an unrelated Sepolia ValidatorWallet build is pinned")
	}
}
