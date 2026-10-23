// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// set1Dir is where generate3 finds the published set 1 (the real vector's evidence, pins and leg are carried over from it). It is the
// directory relative to the vectorgen package, which is where the generator test runs.
const set1Dir = "../testdata/finality_arb_final1"

// generate3 builds the third published set, finality_arb_final3 (RB12-E1RAISE): the wallet route PROVEN. A callee takes the route only
// when its account proof under K shows the pinned ValidatorWallet proxy code, its EIP-1967 implementation slot holds the pinned
// template and the template's account shows the pinned logic code; every other callee is confirmation_path_unproven{indirect}.
func generate3(out string) error {
	mismatches = nil
	g := newGen()
	synthetic4(g)
	if err := realVector3(g); err != nil {
		return err
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("%d vectors disagree with the verifier:\n%s", len(mismatches), strings.Join(mismatches, "\n"))
	}
	return g.write3(out)
}

// realVector3 carries the REAL direct-route vector of set 1 (a real confirmed assertion of Arbitrum Sepolia, confirmed by an
// externally owned account calling the Rollup) into this set under the pins file with the wallet pins: the direct route is unchanged by
// the wallet identity rule, on real bytes.
func realVector3(g *gen) error {
	raw, err := os.ReadFile(filepath.Join(set1Dir, "vectors.json"))
	if err != nil {
		return err
	}
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	var real *vec
	for i := range f.Vectors {
		if f.Vectors[i].Name == "real_valid" {
			real = &f.Vectors[i]
		}
	}
	if real == nil {
		return fmt.Errorf("set 1 has no real_valid")
	}
	ev, err := os.ReadFile(filepath.Join(set1Dir, "evidence", real.Evidence))
	if err != nil {
		return err
	}
	pins, err := os.ReadFile(filepath.Join(set1Dir, "pins", real.Pins))
	if err != nil {
		return err
	}
	hb, err := hex.DecodeString(real.Leg.HeaderHex)
	if err != nil {
		return err
	}
	leg := finality.BlockRef{Chain: real.Leg.Chain, Number: real.Leg.Number, HeaderRLP: hb}
	copy(leg.Hash[:], mustHex(real.Leg.Hash))
	// The expected verdict is the one set 1 records for the same bytes: the direct route does not depend on the wallet pins.
	g.add("real_valid_direct_route_unchanged", "live", "the real direct-route vector of finality_arb_final1 (the Rollup called by an externally owned account) under a pins file that carries the wallet pins: its verdict is the one set 1 records",
		leg, "real.json", sw.WithWalletPins(pins), ev, real.Expect)
	return nil
}

func synthetic4(g *gen) {
	V := world("valid", nil)
	g.synth("synth_valid_direct", "synthetic", "the Rollup is called with confirmAssertion (the base of the patches of this set)", V, okText(okFields(V, "direct")))
	confirmCall := sw.ConfirmCall(sw.SelConfirm)
	other := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	proxyAt := common.HexToAddress("0x000000000000000000000000000000000000beef")
	hash := func(s string) common.Hash { return crypto.Keccak256Hash([]byte(s)) }
	wordOf := func(a common.Address) *common.Hash {
		h := common.BytesToHash(append(make([]byte, 12), a[:]...))
		return &h
	}
	valid := &sw.WalletState{}
	call := func(sel [4]byte, c []byte) []byte {
		return sw.WalletInput(sel, [][]byte{c}, []common.Address{sw.Rollup})
	}
	wallet := func(label string, input []byte, ws *sw.WalletState, mod func(*sw.Parts)) *sw.World {
		return world(label, func(p *sw.Parts) {
			t := sw.ValidatorW
			p.TxTo, p.TxInput, p.Wallet = &t, input, ws
			if mod != nil {
				mod(p)
			}
		})
	}
	A := func(name, note string, w *sw.World, expect string) { g.synth(name, "adversarial", note, w, expect) }
	unp := func(w *sw.World, r arbfinal.ConfirmReason) string {
		return st(arbfinal.CodeConfirmationUnproof, "reason", r, "tx", w.TxHash, "l1_block", w.K.Number)
	}
	forceT := func(w *sw.World, path string) string {
		return st(arbfinal.CodeConfirmedByOwner, "path", path, "tx", w.TxHash, "l1_block", w.K.Number)
	}

	// ---- a callee proven to be a ValidatorWallet takes the wallet route, through each of the four entry points ----
	w1 := wallet("wallet-tx", call(sw.SelWalletTx, confirmCall), valid, nil)
	g.synth("synth_valid_wallet_execute_transaction_proven", "synthetic", "executeTransaction -> Rollup.confirmAssertion; the callee is proven to be a ValidatorWallet (proxy code, pinned implementation slot, pinned logic code under K)", w1, okText(okFields(w1, "wallet")))
	w2 := wallet("wallet-txs", sw.WalletInput(sw.SelWalletTxs, [][]byte{{0x01, 0x02}, confirmCall}, []common.Address{other, sw.Rollup}), valid, nil)
	g.synth("synth_valid_wallet_execute_transactions_proven", "synthetic", "executeTransactions: a first call elsewhere, the second call confirms", w2, okText(okFields(w2, "wallet")))
	w3 := wallet("wallet-tx-refund", call(sw.SelWalletTxR, confirmCall), valid, nil)
	g.synth("synth_valid_wallet_execute_transaction_with_gas_refunder_proven", "synthetic", "executeTransactionWithGasRefunder", w3, okText(okFields(w3, "wallet")))
	w4 := wallet("wallet-txs-refund", call(sw.SelWalletTxsR, confirmCall), valid, nil)
	g.synth("synth_valid_wallet_execute_transactions_with_gas_refunder_proven", "synthetic", "executeTransactionsWithGasRefunder", w4, okText(okFields(w4, "wallet")))
	wSel := wallet("wallet-selector-only", call(sw.SelWalletTx, sw.SelConfirm[:]), valid, nil)
	g.synth("synth_valid_wallet_call_is_the_bare_selector_proven", "synthetic", "the wallet's call data is exactly the 4-byte confirmAssertion selector", wSel, okText(okFields(wSel, "wallet")))
	wAny := wallet("wallet-any-address", call(sw.SelWalletTx, confirmCall), valid, func(p *sw.Parts) { p.TxTo = &proxyAt })
	g.synth("synth_valid_wallet_at_another_address_proven", "synthetic", "the wallet is identified by its code and its implementation slot, not by its address: any address that proves the same identity", wAny, okText(okFields(wAny, "wallet")))
	wSame := wallet("wallet-k-equals-s", call(sw.SelWalletTx, confirmCall), valid, func(p *sw.Parts) { p.KBack = 0 })
	g.synth("synth_valid_wallet_k_equals_s_proven", "synthetic", "K = S: one state holds the Rollup and the wallet accounts", wSame, okText(okFields(wSame, "wallet")))
	direct := world("direct-with-wallet-proofs", func(p *sw.Parts) { p.Wallet = &sw.WalletState{Callee: &proxyAt} })
	g.synth("synth_valid_direct_with_unrelated_wallet_proofs", "synthetic", "a direct confirmAssertion transaction whose evidence also carries a valid wallet proof for another address: the direct route is unchanged", direct, okText(okFields(direct, "direct")))

	// ---- the callee is not proven to be a ValidatorWallet: confirmation_path_unproven{indirect}, never "wallet" ----
	ind := func(name, note string, ws *sw.WalletState, mod func(*sw.Parts)) *sw.World {
		w := wallet("w3/"+name, call(sw.SelWalletTx, confirmCall), ws, mod)
		A("adv_wallet_"+name, note, w, unp(w, arbfinal.ConfirmIndirect))
		return w
	}
	ind("callee_is_an_eoa", "the callee has an account without code", &sw.WalletState{CalleeEOA: true}, nil)
	ind("callee_account_absent", "the callee has no account: a verified exclusion proof", &sw.WalletState{CalleeAbsent: true}, nil)
	ind("callee_is_another_contract", "the callee is a contract whose code hash is not pinned", &sw.WalletState{CalleeCode: ptr(hash("another contract"))}, nil)
	ind("callee_has_the_rollup_admin_logic_code", "the callee's code hash is pinned, as another role (rollup_admin_logic)", &sw.WalletState{CalleeCode: ptr(sw.AdminCode)}, nil)
	ind("callee_has_the_wallet_logic_code", "the callee is a contract of the wallet LOGIC code (pinned as validator_wallet_logic, not validator_wallet_proxy)", &sw.WalletState{CalleeCode: ptr(sw.WalletLogicCodeHash)}, nil)
	ind("callee_is_a_proxy_of_another_build", "the callee is a TransparentUpgradeableProxy of another build (code hash 0x5680833d...)", &sw.WalletState{CalleeCode: ptr(sw.OtherProxyCodeHash)}, nil)
	ind("callee_is_the_pinned_template_itself", "the transaction calls the template (the wallet implementation) directly: its code is the logic code, not a proxy",
		&sw.WalletState{CalleeCode: ptr(sw.WalletLogicCodeHash), ImplZero: true}, func(p *sw.Parts) { t := sw.WalletImpl; p.TxTo = &t })
	ind("proxy_over_another_template", "the proxy code is right and its implementation slot names the template of another ValidatorWalletCreator (a real contract whose code hash is not pinned)",
		&sw.WalletState{ImplWord: wordOf(sw.OtherTemplate), ImplCode: ptr(sw.OtherTemplateCodeHash)}, nil)
	ind("proxy_over_another_address_with_the_logic_code", "the implementation slot names another address whose account has exactly the pinned logic code: the slot must hold the pinned address",
		&sw.WalletState{ImplWord: wordOf(other)}, nil)
	ind("implementation_slot_empty", "the implementation slot of the proxy is empty (a verified absence)", &sw.WalletState{ImplZero: true}, nil)
	dirty := common.BytesToHash(append([]byte{0x01}, append(make([]byte, 11), sw.WalletImpl[:]...)...))
	ind("implementation_slot_has_a_high_byte", "the slot word has a non-zero byte above the 20-byte pinned address", &sw.WalletState{ImplWord: &dirty}, nil)
	ind("implementation_has_other_code", "the pinned implementation address has an account whose code hash is not pinned", &sw.WalletState{ImplCode: ptr(hash("not the wallet logic"))}, nil)
	ind("implementation_has_another_pinned_role", "the pinned implementation address has an account with the code hash of another role (rollup_user_logic)", &sw.WalletState{ImplCode: ptr(sw.UserCode)}, nil)
	ind("implementation_has_the_proxy_code", "the pinned implementation address has the wallet PROXY code (a role pinned, but the wrong one)", &sw.WalletState{ImplCode: ptr(sw.WalletProxyCodeHash)}, nil)
	ind("implementation_has_no_code", "the pinned implementation address has an account without code", &sw.WalletState{ImplCode: ptr(types.EmptyCodeHash)}, nil)
	ind("implementation_account_absent", "the pinned implementation address has no account", &sw.WalletState{ImplAbsent: true}, nil)
	ind("proof_of_the_callee_account_omitted", "the callee's account proof is not carried", &sw.WalletState{Omit: []string{"account"}}, nil)
	ind("proof_of_the_implementation_slot_omitted", "the storage proof of the implementation slot is not carried", &sw.WalletState{Omit: []string{"slot"}}, nil)
	ind("proof_of_the_implementation_account_omitted", "the implementation's account proof is not carried", &sw.WalletState{Omit: []string{"impl_account"}}, nil)
	ind("proofs_are_for_another_address", "a complete valid wallet proof, for an address other than the transaction's callee", &sw.WalletState{Callee: &other}, nil)
	ind("proofs_only_in_the_state_at_s", "the wallet accounts exist in the state at S and the verifier reads K", &sw.WalletState{AtS: true}, nil)
	ind("callee_proof_only_in_the_state_at_s", "the callee and its slot are proven under S, the implementation under K", &sw.WalletState{CalleeAtS: true}, nil)
	ind("implementation_proof_only_in_the_state_at_s", "the callee and its slot are proven under K, the implementation's account under S", &sw.WalletState{ImplAtS: true}, nil)
	none := wallet("w3/none", call(sw.SelWalletTx, confirmCall), nil, nil)
	A("adv_wallet_no_wallet_proofs_at_all", "a wallet entry point sent to an address of which the evidence proves nothing", none, unp(none, arbfinal.ConfirmIndirect))
	for _, c := range []struct {
		name string
		sel  [4]byte
	}{{"execute_transactions", sw.SelWalletTxs}, {"execute_transaction_with_gas_refunder", sw.SelWalletTxR}, {"execute_transactions_with_gas_refunder", sw.SelWalletTxsR}} {
		w := wallet("w3/eoa-"+c.name, sw.WalletInput(c.sel, [][]byte{confirmCall}, []common.Address{sw.Rollup}), &sw.WalletState{CalleeEOA: true}, nil)
		A("adv_wallet_"+c.name+"_to_an_eoa", "the entry point of the name sent to an account without code", w, unp(w, arbfinal.ConfirmIndirect))
	}
	create := wallet("w3/create", call(sw.SelWalletTx, confirmCall), valid, func(p *sw.Parts) { p.TxCreate = true })
	A("adv_wallet_contract_creation_with_valid_wallet_proofs", "a contract-creation transaction whose init code decodes as a wallet call, with a valid wallet proof for the address it would have been sent to: init code is not calldata",
		create, unp(create, arbfinal.ConfirmIndirect))

	// ---- the outcome of the decoded call is read only after the identity: an unproven callee gives indirect whatever the call says ----
	unprovenOutcome := func(name, note string, input []byte, mod func(*sw.Parts)) {
		for _, c := range []struct {
			suffix string
			ws     *sw.WalletState
			why    string
		}{{"_without_wallet_proofs", nil, "no wallet proof"}, {"_to_an_eoa", &sw.WalletState{CalleeEOA: true}, "an externally owned callee"}, {"_to_another_contract", &sw.WalletState{CalleeCode: ptr(hash("another contract"))}, "another contract as callee"}} {
			w := wallet("w3/u/"+name+c.suffix, input, c.ws, mod)
			A("adv_wallet_"+name+c.suffix, note+" ("+c.why+")", w, unp(w, arbfinal.ConfirmIndirect))
		}
	}
	unprovenOutcome("force_call", "the decoded wallet call is forceConfirmAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelForce)), nil)
	unprovenOutcome("fast_call", "the decoded wallet call is fastConfirmAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelFast)), nil)
	unprovenOutcome("fast_new_call", "the decoded wallet call is fastConfirmNewAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelFastNew)), nil)
	unprovenOutcome("no_confirm_call_other_target", "the decoded wallet call has the confirm selector but targets another contract", sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{other}), nil)
	unprovenOutcome("no_confirm_call_other_selector", "the decoded wallet call targets the Rollup with another selector", call(sw.SelWalletTx, sw.ConfirmCall([4]byte{0xde, 0xad, 0xbe, 0xef})), nil)
	unprovenOutcome("fast_confirmer_set", "a wallet confirmation while anyTrustFastConfirmer is not the zero address at K", call(sw.SelWalletTx, confirmCall),
		func(p *sw.Parts) { p.FastConfirm = common.HexToAddress("0x00000000000000000000000000000000000fa570") })
	unprovenOutcome("fast_confirmer_slot_proof_missing", "a wallet confirmation without the proof of the anyTrustFastConfirmer slot", call(sw.SelWalletTx, confirmCall), func(p *sw.Parts) { p.NoFastProof = true })

	// ---- the outcome of a PROVEN wallet is unchanged ----
	pf := func(name, note string, input []byte, mod func(*sw.Parts), expect func(w *sw.World) string) {
		w := wallet("w3/p/"+name, input, valid, mod)
		A("adv_wallet_"+name+"_proven", note, w, expect(w))
	}
	pf("force_call", "a proven wallet calls forceConfirmAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelForce)), nil, func(w *sw.World) string { return forceT(w, "force") })
	pf("fast_call", "a proven wallet calls fastConfirmAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelFast)), nil, func(w *sw.World) string { return forceT(w, "fast") })
	pf("fast_new_call", "a proven wallet calls fastConfirmNewAssertion", call(sw.SelWalletTx, sw.ConfirmCall(sw.SelFastNew)), nil, func(w *sw.World) string { return forceT(w, "fast") })
	pf("force_call_in_a_batch", "a proven wallet's executeTransactions: a harmless call, then forceConfirmAssertion",
		sw.WalletInput(sw.SelWalletTxs, [][]byte{{0x01}, sw.ConfirmCall(sw.SelForce)}, []common.Address{other, sw.Rollup}), nil, func(w *sw.World) string { return forceT(w, "force") })
	pf("no_confirm_call_other_target", "a proven wallet's decoded call has the confirm selector but targets another contract", sw.WalletInput(sw.SelWalletTx, [][]byte{confirmCall}, []common.Address{other}), nil,
		func(w *sw.World) string { return unp(w, arbfinal.ConfirmWalletNoConfirm) })
	pf("no_confirm_call_other_selector", "a proven wallet's decoded call targets the Rollup with another selector", call(sw.SelWalletTx, sw.ConfirmCall([4]byte{0xde, 0xad, 0xbe, 0xef})), nil,
		func(w *sw.World) string { return unp(w, arbfinal.ConfirmWalletNoConfirm) })
	pf("call_data_three_bytes", "a proven wallet's call data to the Rollup is three bytes", call(sw.SelWalletTx, sw.SelConfirm[:3]), nil, func(w *sw.World) string { return unp(w, arbfinal.ConfirmWalletNoConfirm) })
	pf("fast_confirmer_set", "a proven wallet confirms while anyTrustFastConfirmer is not the zero address at K", call(sw.SelWalletTx, confirmCall),
		func(p *sw.Parts) { p.FastConfirm = common.HexToAddress("0x00000000000000000000000000000000000fa570") }, func(w *sw.World) string { return unp(w, arbfinal.ConfirmFastConfirmerSet) })
	pf("fast_confirmer_slot_proof_missing", "a proven wallet confirms without the proof of the anyTrustFastConfirmer slot at K", call(sw.SelWalletTx, confirmCall),
		func(p *sw.Parts) { p.NoFastProof = true }, func(w *sw.World) string { return st(arbfinal.CodeStateProofInvalid, "which", "slot") })
	pf("receipt_status_zero", "a proven wallet's transaction has receipt status 0", call(sw.SelWalletTx, confirmCall), func(p *sw.Parts) { p.RcStatus = 0 },
		func(w *sw.World) string { return unp(w, arbfinal.ConfirmReceiptStatus) })
	pf("receipt_without_log", "a proven wallet's receipt holds no log: the log is read before the route", call(sw.SelWalletTx, confirmCall), func(p *sw.Parts) { p.NoLogs = true },
		func(w *sw.World) string { return unp(w, arbfinal.ConfirmLogMissing) })
	pf("undecodable_calldata", "a proven wallet's entry point followed by bytes that are not ABI arguments: undecodable before any identity is read",
		append(append([]byte(nil), sw.SelWalletTx[:]...), bytes.Repeat([]byte{0xab}, 40)...), nil, func(w *sw.World) string { return unp(w, arbfinal.ConfirmWalletUndecodable) })
	both := []sw.Log{{Address: sw.Rollup, Topics: []common.Hash{sw.TopicConfirm, sw.ThisAssertion}}, {Address: sw.Rollup, Topics: []common.Hash{sw.TopicForce, sw.ThisAssertion}}}
	pf("confirm_with_a_force_log", "a proven wallet confirms and the receipt holds AssertionForceConfirmed", call(sw.SelWalletTx, confirmCall), func(p *sw.Parts) { p.Logs = both },
		func(w *sw.World) string { return forceT(w, "force") })
	// The force LOG is a fact about the Rollup, not about the callee: it is read before the route, so an unproven callee gives the same state.
	fl := wallet("w3/force-log-unproven-callee", call(sw.SelWalletTx, confirmCall), nil, func(p *sw.Parts) { p.Logs = both })
	A("adv_wallet_confirm_with_a_force_log_without_wallet_proofs", "the receipt holds AssertionForceConfirmed: read from the Rollup's log before the route, so the callee's identity does not change the state", fl, forceT(fl, "force"))

	// ---- the pins: the wallet pins are required, nothing has a default ----
	pinCase := func(name, note string, pins []byte, field string) {
		g.synthPins("adv_pins_"+name, note, "synth_"+name+".json", pins, V, st(arbfinal.CodePinMismatch, "field", field))
	}
	a := func(path ...string) []string { return append([]string{"arb_sepolia"}, path...) }
	impl, slot, proxyH, logicH := sw.WalletPinKeys()
	pinCase("without_wallet_pins", "the pins file of a verifier older than the wallet pins (finality_arb_final1 stores such files)", sw.WithoutWalletPins(V.Pins), "proxy_slots.wallet_impl")
	pinCase("without_wallet_impl", "confirm_path.validator_wallet_impl is absent", editPins(V.Pins, nil, a("confirm_path", "validator_wallet_impl")...), "confirm_path.validator_wallet_impl")
	pinCase("wallet_impl_zero_address", "confirm_path.validator_wallet_impl is the zero address", editPins(V.Pins, "0x"+strings.Repeat("00", 20), a("confirm_path", "validator_wallet_impl")...), "confirm_path.validator_wallet_impl")
	pinCase("wallet_impl_19_bytes", "confirm_path.validator_wallet_impl is 19 bytes", editPins(V.Pins, impl[:len(impl)-2], a("confirm_path", "validator_wallet_impl")...), "confirm_path.validator_wallet_impl")
	pinCase("wallet_impl_21_bytes", "confirm_path.validator_wallet_impl is 21 bytes", editPins(V.Pins, impl+"00", a("confirm_path", "validator_wallet_impl")...), "confirm_path.validator_wallet_impl")
	pinCase("without_wallet_impl_slot", "proxy_slots.wallet_impl is absent", editPins(V.Pins, nil, a("proxy_slots", "wallet_impl")...), "proxy_slots.wallet_impl")
	pinCase("wallet_impl_slot_31_bytes", "proxy_slots.wallet_impl is 31 bytes", editPins(V.Pins, slot[:len(slot)-2], a("proxy_slots", "wallet_impl")...), "proxy_slots.wallet_impl")
	pinCase("without_wallet_proxy_role", "no logic_pins entry has the role validator_wallet_proxy", editPins(V.Pins, nil, a("logic_pins", strings.ToLower(proxyH))...), "logic_pins.validator_wallet_proxy")
	pinCase("without_wallet_logic_role", "no logic_pins entry has the role validator_wallet_logic", editPins(V.Pins, nil, a("logic_pins", strings.ToLower(logicH))...), "logic_pins.validator_wallet_logic")
	proxyOnZero := editPins(editPins(V.Pins, nil, a("logic_pins", strings.ToLower(proxyH))...), "validator_wallet_proxy", a("logic_pins", "0x"+strings.Repeat("00", 32))...)
	pinCase("wallet_proxy_role_on_the_zero_hash", "the role validator_wallet_proxy is pinned on the zero hash", proxyOnZero, "logic_pins.validator_wallet_proxy")
	proxyOnEmpty := editPins(editPins(V.Pins, nil, a("logic_pins", strings.ToLower(proxyH))...), "validator_wallet_proxy", a("logic_pins", strings.ToLower(types.EmptyCodeHash.Hex()))...)
	pinCase("wallet_proxy_role_on_the_empty_code_hash", "the role validator_wallet_proxy is pinned on the hash of empty code (an EOA would be a wallet)", proxyOnEmpty, "logic_pins.validator_wallet_proxy")
	logicOnEmpty := editPins(editPins(V.Pins, nil, a("logic_pins", strings.ToLower(logicH))...), "validator_wallet_logic", a("logic_pins", strings.ToLower(types.EmptyCodeHash.Hex()))...)
	pinCase("wallet_logic_role_on_the_empty_code_hash", "the role validator_wallet_logic is pinned on the hash of empty code (an absent implementation would be a wallet)", logicOnEmpty, "logic_pins.validator_wallet_logic")
	logicOnZero := editPins(editPins(V.Pins, nil, a("logic_pins", strings.ToLower(logicH))...), "validator_wallet_logic", a("logic_pins", "0x"+strings.Repeat("00", 32))...)
	pinCase("wallet_logic_role_on_the_zero_hash", "the role validator_wallet_logic is pinned on the zero hash", logicOnZero, "logic_pins.validator_wallet_logic")
}

func ptr[T any](v T) *T { return &v }

// write3 writes the set: vectors.json, the evidence and pins files, the MANIFEST (vectors.json, evidence and pins only) and the README,
// which describes the set and is outside the manifest.
func (g *gen) write3(out string) error {
	if err := os.MkdirAll(filepath.Join(out, "evidence"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(out, "pins"), 0o755); err != nil {
		return err
	}
	files := map[string]string{}
	put := func(rel string, b []byte) error {
		files[rel] = fmt.Sprintf("%x", sha256.Sum256(b))
		return os.WriteFile(filepath.Join(out, filepath.FromSlash(rel)), b, 0o644)
	}
	var names []string
	for k := range g.evidence {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("evidence/"+k+".bin", g.evidence[k]); err != nil {
			return err
		}
	}
	names = nil
	for k := range g.pins {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := put("pins/"+k, g.pins[k]); err != nil {
			return err
		}
	}
	vj, err := json.MarshalIndent(map[string]any{"format": "finality_arb_final3/1", "vectors": g.vecs}, "", " ")
	if err != nil {
		return err
	}
	vj = append(vj, '\n')
	if err := put("vectors.json", vj); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "README.md"), []byte(readme3Text), 0o644); err != nil {
		return err
	}
	mj, _ := json.MarshalIndent(map[string]any{"format": "finality_arb_final3/manifest/1", "files": files}, "", " ")
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json"), mj, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(mj)
	if err := os.WriteFile(filepath.Join(out, "MANIFEST.json.sha256"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors, %d evidence files, %d pins files; MANIFEST sha256 %x\n", len(g.vecs), len(g.evidence), len(g.pins), sum)
	return nil
}
