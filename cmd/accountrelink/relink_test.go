package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/consensus"
)

func relinkInventory() *Inventory {
	return &Inventory{ChainID: 84532, FactoryV10: common.HexToAddress("0xaE0466c64b562cC623e1CcF142719d51Dd8EEa82"),
		EntryPoint: common.HexToAddress("0x0000000071727De22E5E9d8BAf0edAc6f37da032"), Block: 100,
		BlockTime: time.Unix(1_790_000_000, 0).UTC(),
		Entries: []Entry{
			{Account: common.HexToAddress("0x1111111111111111111111111111111111111111"), ADIURL: "acc://funded.acme",
				GoverningBook: "acc://funded.acme/book", NativeWei: "5000",
				Tokens: []TokenBalance{{Token: common.HexToAddress("0x2222222222222222222222222222222222222222"), Balance: "7"}}},
			{Account: common.HexToAddress("0x3333333333333333333333333333333333333333"), ADIURL: "acc://empty.acme",
				GoverningBook: "acc://empty.acme/book", NativeWei: "0"},
		}}
}

// The V11 address is the factory's CREATE2 derivation: salt keccak256(adiURL), init code the creation code followed by
// abi.encode(entryPoint, keyless owner, adiURL, governingBook).
func TestAccountAddressIsTheFactorysDerivation(t *testing.T) {
	factory := common.HexToAddress("0x00000000000000000000000000000000000000f1")
	ep := common.HexToAddress("0x00000000000000000000000000000000000000e9")
	code := []byte{0x60, 0x80, 0x60, 0x40}
	got, err := AccountAddress(factory, ep, "acc://a.acme", "acc://a.acme/book", code)
	if err != nil {
		t.Fatal(err)
	}
	// Built by hand, word by word.
	word := func(b []byte) []byte { w := make([]byte, 32); copy(w[32-len(b):], b); return w }
	str := func(s string) []byte {
		out := word(big.NewInt(int64(len(s))).Bytes())
		pad := make([]byte, (len(s)+31)/32*32)
		copy(pad, s)
		return append(out, pad...)
	}
	owner := crypto.Keccak256([]byte("acc://a.acme"))[12:]
	enc := append(append(append(append(word(ep.Bytes()), word(owner)...), word(big.NewInt(128).Bytes())...),
		word(big.NewInt(128+64).Bytes())...), append(str("acc://a.acme"), str("acc://a.acme/book")...)...)
	var salt [32]byte
	copy(salt[:], crypto.Keccak256([]byte("acc://a.acme")))
	want := crypto.CreateAddress2(factory, salt, crypto.Keccak256(append(code, enc...)))
	if got != want {
		t.Fatalf("derived %s, by hand %s", got, want)
	}
	// Another governing book is another account.
	other, _ := AccountAddress(factory, ep, "acc://a.acme", "acc://a.acme/ops", code)
	if other == got {
		t.Fatal("the governing book is not part of the address")
	}
}

// A funded account gets an unsigned relink whose legs the validator reads as this account's member on the chain: its
// native balance and every token balance, to its V11 address. An empty one gets none.
func TestThePlanRelinksEveryFundedAccountAndOnlyThose(t *testing.T) {
	// A token relink is a contract call: settled only where contract calls are enabled.
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	inv := relinkInventory()
	plan, err := MakePlan(inv, common.HexToAddress("0x00000000000000000000000000000000000000f2"), []byte{0x60, 0x80},
		inv.BlockTime.Add(24*time.Hour), "base sepolia")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Entries[1].UnsignedIntent != nil {
		t.Fatal("an empty account was given a relink")
	}
	pe := plan.Entries[0]
	if pe.UnsignedIntent == nil || pe.V11Account == (common.Address{}) || pe.V11Account == pe.Account {
		t.Fatalf("funded entry %+v", pe)
	}
	ccd, err := json.Marshal(pe.UnsignedIntent.CrossChainData)
	if err != nil {
		t.Fatal(err)
	}
	ci := &consensus.CertenIntent{IntentID: "relink", IntentData: []byte(`{"intent_id":"relink","kind":"CERTEN_INTENT"}`),
		CrossChainData: ccd, GovernanceData: []byte(`{"authority":"acc://funded.acme/book"}`), ReplayData: []byte(`{"nonce":"1"}`)}
	legs, chainID, account, _, err := consensus.MemberLegsForChain(ci, 84532)
	if err != nil {
		t.Fatalf("the validator does not read the relink: %v", err)
	}
	if chainID != 84532 || common.Address(account) != pe.Account || len(legs) != 2 {
		t.Fatalf("member on %d from %x with %d legs", chainID, account, len(legs))
	}
	if common.Address(legs[0].Target) != pe.V11Account || legs[0].Value.String() != "5000" {
		t.Fatalf("native leg to %x of %s", legs[0].Target, legs[0].Value)
	}
	wantData := "a9059cbb" + strings.Repeat("0", 24) + strings.ToLower(pe.V11Account.Hex()[2:]) + strings.Repeat("0", 63) + "7"
	if common.Address(legs[1].Target) != common.HexToAddress("0x2222222222222222222222222222222222222222") ||
		common.Bytes2Hex(legs[1].Data) != wantData {
		t.Fatalf("token leg to %x data %x", legs[1].Target, legs[1].Data)
	}
	if legs[0].Deadline != inv.BlockTime.Add(24*time.Hour).Unix() {
		t.Fatalf("deadline %d", legs[0].Deadline)
	}
	if _, err := MakePlan(inv, common.Address{}, nil, inv.BlockTime.Add(-time.Hour), "x"); err == nil {
		t.Fatal("a relink deadline before the inventory was accepted")
	}
}

// At cut-over, every account the verification did not find relinked is retired by name with its balance and block;
// a relinked or empty one is not.
func TestRetireNamesEveryAccountNotRelinked(t *testing.T) {
	inv := relinkInventory()
	inv.Entries = append(inv.Entries, Entry{Account: common.HexToAddress("0x4444444444444444444444444444444444444444"),
		ADIURL: "acc://moved.acme", GoverningBook: "acc://moved.acme/book", NativeWei: "9"})
	plan, err := MakePlan(inv, common.HexToAddress("0xf2"), []byte{0x60}, inv.BlockTime.Add(time.Hour), "base sepolia")
	if err != nil {
		t.Fatal(err)
	}
	v := &Verification{Block: 200, BlockHash: common.HexToHash("0xbb"), Statuses: []Status{
		{Account: plan.Entries[0].Account, State: "not relinked", V10Native: "5000", Detail: "the V10 account still holds 5000 wei"},
		{Account: plan.Entries[1].Account, State: "nothing to move", V10Native: "0"},
		{Account: plan.Entries[2].Account, State: "relinked", V10Native: "0"},
	}}
	r := Retire(plan, v, 84532)
	if len(r) != 1 || r[0].Account != plan.Entries[0].Account || r[0].NativeWei != "5000" || r[0].Block != 200 ||
		!strings.Contains(r[0].Reason, "not relinked before chain 84532 switched to account leaf v4") {
		t.Fatalf("retired %+v", r)
	}
}

// A provider's rate refusal is retried as the same read; any other error is returned at once.
func TestRateLimitedRetriesOnlyARateRefusal(t *testing.T) {
	n := 0
	err := rateLimited(context.Background(), func() error {
		n++
		if n < 3 {
			return errors.New(`429 Too Many Requests: {"code":-32007}`)
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("%v after %d reads", err, n)
	}
	n = 0
	err = rateLimited(context.Background(), func() error { n++; return errors.New("execution reverted") })
	if err == nil || n != 1 {
		t.Fatalf("a non-rate error was retried (%d reads): %v", n, err)
	}
}
