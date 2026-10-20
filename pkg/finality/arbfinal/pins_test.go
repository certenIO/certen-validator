// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

func sel(sig string) string { return "0x" + common.Bytes2Hex(crypto.Keccak256([]byte(sig))[:4]) }
func top(sig string) string { return crypto.Keccak256Hash([]byte(sig)).Hex() }

func minusOne(label string) string {
	v := new(big.Int).SetBytes(crypto.Keccak256([]byte(label)))
	v.Sub(v, big.NewInt(1))
	return common.BigToHash(v).Hex()
}

// Every selector, topic and proxy slot in the pins file is derived here from its signature or label, so no hex constant is
// taken on trust (the code hashes of the logic contracts are measured with eth_getCode and recorded in the check-in).
func TestPinnedSelectorsTopicsAndSlotsAreDerived(t *testing.T) {
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var sec struct {
		ConfirmPath struct {
			Selectors map[string]string `json:"selectors"`
			Topics    map[string]string `json:"topics"`
		} `json:"confirm_path"`
		ProxySlots map[string]string `json:"proxy_slots"`
		Layout     map[string]any    `json:"layout"`
		LogicPins  map[string]string `json:"logic_pins"`
	}
	if err := json.Unmarshal(embedded.Sections["arb_sepolia"], &sec); err != nil {
		t.Fatal(err)
	}
	as := "((bytes32[2],uint64[2]),uint8,bytes32)"
	cfg := "(bytes32,uint256,address,uint64,uint64)"
	for name, sig := range map[string]string{
		"confirm_assertion":                             "confirmAssertion(bytes32,bytes32," + as + ",bytes32," + cfg + ",bytes32)",
		"force_confirm_assertion":                       "forceConfirmAssertion(bytes32,bytes32," + as + ",bytes32)",
		"fast_confirm_assertion":                        "fastConfirmAssertion(bytes32,bytes32," + as + ",bytes32)",
		"fast_confirm_new_assertion":                    "fastConfirmNewAssertion(((bytes32,bytes32," + cfg + ")," + as + "," + as + "),bytes32)",
		"wallet_execute_transaction":                    "executeTransaction(bytes,address,uint256)",
		"wallet_execute_transactions":                   "executeTransactions(bytes[],address[],uint256[])",
		"wallet_execute_transaction_with_gas_refunder":  "executeTransactionWithGasRefunder(address,bytes,address,uint256)",
		"wallet_execute_transactions_with_gas_refunder": "executeTransactionsWithGasRefunder(address,bytes[],address[],uint256[])",
	} {
		if got := sec.ConfirmPath.Selectors[name]; got != sel(sig) {
			t.Errorf("selector %s = %s, keccak(%s)[:4] = %s", name, got, sig, sel(sig))
		}
	}
	for name, sig := range map[string]string{
		"assertion_confirmed":       "AssertionConfirmed(bytes32,bytes32,bytes32)",
		"assertion_force_confirmed": "AssertionForceConfirmed(bytes32)",
	} {
		if got := sec.ConfirmPath.Topics[name]; got != top(sig) {
			t.Errorf("topic %s = %s, keccak(%s) = %s", name, got, sig, top(sig))
		}
	}
	if got := sec.ProxySlots["admin_logic"]; got != minusOne("eip1967.proxy.implementation") {
		t.Errorf("admin_logic slot %s, EIP-1967 implementation slot %s", got, minusOne("eip1967.proxy.implementation"))
	}
	if got := sec.ProxySlots["user_logic"]; got != minusOne("eip1967.proxy.implementation.secondary") {
		t.Errorf("user_logic slot %s, secondary slot %s", got, minusOne("eip1967.proxy.implementation.secondary"))
	}
	a, err := arbfinal.LoadPins(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if a.Layout.AssertionsSlot != 117 || a.Layout.StatusShiftBits != 200 || a.Layout.ConfigSlotOffset != 1 || a.MaxHeaderChain != 32768 || a.BoldGenesisL2Block != 105880604 {
		t.Fatalf("layout %+v", a)
	}
	if arbfinal.StatusOf(common.BigToHash(new(big.Int).Lsh(big.NewInt(2), 200)), a.Layout.StatusShiftBits) != 2 {
		t.Fatal("status byte")
	}
	if len(sec.LogicPins) < 2 {
		t.Fatalf("logic_pins %v", sec.LogicPins)
	}
}

// Section 5.7 O3: the hashes are those of annex A2, reproduced on constants that are independent of the verifier's own flow.
func TestAssertionHashPreimages(t *testing.T) {
	z := [32]byte{}
	a := arbfinal.AfterState{BlockHash: [32]byte{1}, SendRoot: [32]byte{2}, InboxPosition: 3, PositionInMessage: 4, MachineStatus: 1, EndHistoryRoot: [32]byte{5}}
	var pre []byte
	for _, w := range [][]byte{a.BlockHash[:], a.SendRoot[:], common.BigToHash(big.NewInt(3)).Bytes(), common.BigToHash(big.NewInt(4)).Bytes(), common.BigToHash(big.NewInt(1)).Bytes(), a.EndHistoryRoot[:]} {
		pre = append(pre, w...)
	}
	if arbfinal.AfterStateHash(a) != [32]byte(crypto.Keccak256Hash(pre)) {
		t.Fatal("afterStateHash is not keccak256 of six words")
	}
	ah := arbfinal.AfterStateHash(a)
	if arbfinal.AssertionHash(z, a, [32]byte{9}) != [32]byte(crypto.Keccak256Hash(z[:], ah[:], append([]byte{9}, make([]byte, 31)...))) {
		t.Fatal("assertionHash preimage")
	}
	c := arbfinal.ParentConfig{WasmModuleRoot: [32]byte{1}, RequiredStake: [32]byte{2}, ChallengeManager: [20]byte{3}, ConfirmPeriodBlocks: 20, NextInboxPosition: 7}
	var cp []byte
	cp = append(cp, c.WasmModuleRoot[:]...)
	cp = append(cp, c.RequiredStake[:]...)
	cp = append(cp, c.ChallengeManager[:]...)
	cp = append(cp, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 7)
	if len(cp) != 100 || arbfinal.ConfigHash(c) != [32]byte(crypto.Keccak256Hash(cp)) {
		t.Fatal("configHash preimage")
	}
	// node slot and config slot: keccak256(h || w(117)) and that plus one
	h := [32]byte{0xaa}
	ns := crypto.Keccak256Hash(h[:], common.BigToHash(big.NewInt(117)).Bytes())
	if arbfinal.NodeSlot(h, 117) != ns {
		t.Fatal("node slot")
	}
	if arbfinal.ConfigSlot(h, 117, 1) != common.BigToHash(new(big.Int).Add(new(big.Int).SetBytes(ns[:]), big.NewInt(1))) {
		t.Fatal("config slot")
	}
}

// editSection returns the pins with the arb_sepolia value at path replaced (nil deletes the key).
func editSection(t *testing.T, path []string, val any) *finality.Pins {
	t.Helper()
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(embedded.Sections["arb_sepolia"], &doc); err != nil {
		t.Fatal(err)
	}
	cur := doc
	for _, k := range path[:len(path)-1] {
		cur = cur[k].(map[string]any)
	}
	if val == nil {
		delete(cur, path[len(path)-1])
	} else {
		cur[path[len(path)-1]] = val
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &finality.Pins{Format: embedded.Format, Sections: map[string]json.RawMessage{"arb_sepolia": raw}}
}

// Every domain check of the arb_sepolia section refuses with pin_mismatch naming the field.
func TestEveryPinDomainCheckNamesItsField(t *testing.T) {
	cases := []struct {
		name  string
		path  []string
		val   any
		field string
	}{
		{"chain id", []string{"chain_id"}, 421615, "chain_id"},
		{"parent chain id", []string{"parent_chain_id"}, 1, "parent_chain_id"},
		{"rollup not hex", []string{"rollup"}, "0x12", "rollup"},
		{"rollup no prefix", []string{"rollup"}, "042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4aa", "rollup"},
		{"layout name", []string{"layout", "name"}, "x", "layout"},
		{"assertions slot zero", []string{"layout", "assertions_slot"}, 0, "layout"},
		{"status shift zero", []string{"layout", "status_shift_bits"}, 0, "layout"},
		{"status shift above 248", []string{"layout", "status_shift_bits"}, 249, "layout"},
		{"config offset zero", []string{"layout", "config_slot_offset"}, 0, "layout"},
		{"fast confirmer slot zero", []string{"layout", "fast_confirmer_slot"}, 0, "layout"},
		{"fast confirmer shift above 96", []string{"layout", "fast_confirmer_shift_bits"}, 97, "layout"},
		{"max header chain zero", []string{"max_header_chain"}, 0, "max_header_chain"},
		{"max header chain negative", []string{"max_header_chain"}, -1, "max_header_chain"},
		{"bold genesis zero", []string{"bold_genesis_l2_block"}, 0, "bold_genesis_l2_block"},
		{"admin slot short", []string{"proxy_slots", "admin_logic"}, "0x1234", "proxy_slots.admin_logic"},
		{"user slot short", []string{"proxy_slots", "user_logic"}, "0x1234", "proxy_slots.user_logic"},
		{"logic pin key short", []string{"logic_pins"}, map[string]any{"0x12": "rollup_admin_logic"}, "logic_pins"},
		{"selector short", []string{"confirm_path", "selectors", "confirm_assertion"}, "0x1234", "confirm_path.selectors.confirm_assertion"},
		{"selector zero", []string{"confirm_path", "selectors", "wallet_execute_transaction"}, "0x00000000", "confirm_path.selectors.wallet_execute_transaction"},
		{"selector missing", []string{"confirm_path", "selectors", "fast_confirm_assertion"}, nil, "confirm_path.selectors.fast_confirm_assertion"},
		{"wallet selector missing", []string{"confirm_path", "selectors", "wallet_execute_transactions_with_gas_refunder"}, nil, "confirm_path.selectors.wallet_execute_transactions_with_gas_refunder"},
		{"topic short", []string{"confirm_path", "topics", "assertion_confirmed"}, "0x12", "confirm_path.topics.assertion_confirmed"},
		{"topic missing", []string{"confirm_path", "topics", "assertion_force_confirmed"}, nil, "confirm_path.topics.assertion_force_confirmed"},
		{"unknown key", []string{"surprise"}, 1, "section"},
	}
	for _, c := range cases {
		_, err := arbfinal.LoadPins(editSection(t, c.path, c.val))
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != arbfinal.CodePinMismatch || s.Fields["field"] != c.field {
			t.Errorf("%s: got %v, want pin_mismatch{field:%s}", c.name, err, c.field)
		}
	}
	if _, err := arbfinal.LoadPins(nil); err == nil {
		t.Fatal("nil pins accepted")
	}
	if _, err := arbfinal.LoadPins(&finality.Pins{}); err == nil {
		t.Fatal("pins without the section accepted")
	}
	// the embedded section itself parses, and carries the two pinned logic roles.
	embedded, _ := finality.EmbeddedPins()
	a, err := arbfinal.LoadPins(embedded)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, r := range a.LogicPins {
		roles[r] = true
	}
	if !roles[arbfinal.RoleAdminLogic] || !roles[arbfinal.RoleUserLogic] {
		t.Fatalf("logic pins %v", a.LogicPins)
	}
}

// The accepted edge of each numeric pin domain, and the conversion of a ledger entry that carries a block root.
func TestPinDomainEdgesAreAcceptedAndTheL1ConversionKeepsBlockRoots(t *testing.T) {
	for _, c := range []struct {
		path []string
		val  any
	}{
		{[]string{"layout", "status_shift_bits"}, 248},
		{[]string{"layout", "fast_confirmer_shift_bits"}, 96},
		{[]string{"layout", "fast_confirmer_shift_bits"}, 0},
		{[]string{"max_header_chain"}, 1},
		{[]string{"bold_genesis_l2_block"}, 1},
	} {
		if _, err := arbfinal.LoadPins(editSection(t, c.path, c.val)); err != nil {
			t.Errorf("%v = %v: %v", c.path, c.val, err)
		}
	}
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	p := *embedded
	e := *embedded.EthSepolia
	root := "0x" + common.Bytes2Hex(bytes.Repeat([]byte{0x42}, 32))
	e.Anchors = []finality.AnchorPin{
		{Period: 5, CommitteeRoot: root, BlockRoot: root, WspEpochs: 279},
		{Period: 6, CommitteeRoot: root, WspEpochs: 279},
	}
	p.EthSepolia = &e
	out, err := arbfinal.EthL1Pins(&p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Anchors) != 2 || out.Anchors[0].BlockRoot == nil || out.Anchors[1].BlockRoot != nil || *out.Anchors[0].BlockRoot != [32]byte(bytes.Repeat([]byte{0x42}, 32)) {
		t.Fatalf("anchors %+v", out.Anchors)
	}
	if _, err := arbfinal.EthL1Pins(&finality.Pins{}); err == nil {
		t.Fatal("pins without the Sepolia section converted")
	}
}
