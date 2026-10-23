// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// The wallet route is taken for a callee PROVEN to be a ValidatorWallet, never on the calldata alone (RB12-E1RAISE). These probes use
// only what the synthetic world offered before the wallet proofs existed (a wallet calldata sent to an address, no state for it), so
// they run unchanged against the base commit, where they fail: the base labels every such transaction "wallet" and states a force, a fast
// confirm or a missing confirm call decoded through code it never identified.
func probeIndirect(t *testing.T, name string, input []byte, mod func(*sw.Parts)) {
	t.Helper()
	p := sw.NewParts("probe/" + name)
	to := sw.ValidatorW
	p.TxTo, p.TxInput = &to, input
	if mod != nil {
		mod(&p)
	}
	w := sw.Assemble(p)
	v, err := w.Judge()
	s, named := finality.AsNamed(err)
	if err == nil || !named || s.Code != arbfinal.CodeConfirmationUnproof || s.Fields["reason"] != arbfinal.ConfirmIndirect {
		t.Errorf("%s: an unidentified callee must give confirmation_path_unproven{indirect}; got verdict %+v, error %v", name, v.Fields, err)
		return
	}
	if s.Fields["tx"] != w.TxHash || s.Fields["l1_block"] != w.K.Number {
		t.Errorf("%s: the state must carry the transaction %x and the block %d it was judged at: %v", name, w.TxHash, w.K.Number, s.Fields)
	}
}

func TestAnUnidentifiedCalleeOfEachEntryPointIsIndirect(t *testing.T) {
	confirm := sw.ConfirmCall(sw.SelConfirm)
	dest := []common.Address{sw.Rollup}
	for _, c := range []struct {
		name string
		sel  [4]byte
	}{{"execute_transaction", sw.SelWalletTx}, {"execute_transactions", sw.SelWalletTxs}, {"with_gas_refunder", sw.SelWalletTxR}, {"batch_with_gas_refunder", sw.SelWalletTxsR}} {
		probeIndirect(t, c.name, sw.WalletInput(c.sel, [][]byte{confirm}, dest), nil)
	}
}

func TestAnUnidentifiedCalleeGivesIndirectWhateverTheDecodedCallSays(t *testing.T) {
	dest := []common.Address{sw.Rollup}
	other := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	one := func(sel [4]byte) []byte { return sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall(sel)}, dest) }
	probeIndirect(t, "force", one(sw.SelForce), nil)
	probeIndirect(t, "fast", one(sw.SelFast), nil)
	probeIndirect(t, "fast_new", one(sw.SelFastNew), nil)
	probeIndirect(t, "other_selector", one([4]byte{0xde, 0xad, 0xbe, 0xef}), nil)
	probeIndirect(t, "other_target", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.ConfirmCall(sw.SelConfirm)}, []common.Address{other}), nil)
	probeIndirect(t, "fast_confirmer_set", one(sw.SelConfirm), func(p *sw.Parts) {
		p.FastConfirm = common.HexToAddress("0x00000000000000000000000000000000000fa570")
	})
	probeIndirect(t, "fast_confirmer_slot_unproven", one(sw.SelConfirm), func(p *sw.Parts) { p.NoFastProof = true })
	probeIndirect(t, "bare_selector", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.SelConfirm[:]}, dest), nil)
	probeIndirect(t, "call_data_three_bytes", sw.WalletInput(sw.SelWalletTx, [][]byte{sw.SelConfirm[:3]}, dest), nil)
}
