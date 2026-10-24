// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func lowHash(h common.Hash) string { return strings.ToLower(h.Hex()) }

// The owner pin judges V03 against the rows of the VERIFIER role of policy.owner, not against the anchor rows (the embedded manifest has the
// same owner in both roles, so the world alone cannot tell them apart: an extension gives the verifier a new owner).
func TestC2OwnerPinJudgesTheVerifierAgainstItsOwnRows(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	newOwner := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	m2, err := m.WithExtension(extensionDoc(map[string]any{"owner": map[string]any{"11155111": []any{map[string]any{
		"role": "verifier", "address": newOwner.Hex(), "validFromBlock": 12000000, "validToBlock": nil, "evidence": map[string]any{"basis": "test"}}}}}, nil, nil, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	const block = 12000001
	anchorOwner := common.HexToAddress(m2.OwnerCovering(11155111, "anchor", block)[0].Address)
	if got := m2.OwnerCovering(11155111, "verifier", block); len(got) != 1 || common.HexToAddress(got[0].Address) != newOwner {
		t.Fatalf("the extension did not retire the old verifier owner: %v", got)
	}
	env := &Env{Manifest: m2, Ctx: LegContext{Chain: 11155111}, Facts: &Facts{}}
	env.Facts.B2.IB = IBResult{Evaluated: true, Verified: true}
	st := func(verifierOwner common.Address) *c2Station {
		return &c2Station{W: map[string]common.Hash{"A16": a2Word(anchorOwner), "V03": a2Word(verifierOwner)}}
	}
	if p, err := c2OwnerPin(env, st(newOwner), st(newOwner), block); err != nil || p != nil {
		t.Fatalf("the verifier's own owner row was not accepted: %v %v", p, err)
	}
	p, err := c2OwnerPin(env, st(anchorOwner), st(anchorOwner), block)
	if err != nil || p == nil || p.Status != StatusRefused || p.State.Fields["field"] != "verifier_owner" || p.State.Fields["want"] != newOwner {
		t.Fatalf("the anchor owner as verifier owner after the verifier owner changed: %v %v", p, err)
	}
}

// The manifest_history conditions at their boundaries, on synthetic stations: pkcList of exactly 256 entries passes, 257 is too large; a list
// shorter than pkcCount is a count mismatch even when pkcCount equals slot 5.
func TestC2HistoryListBounds(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	root := common.HexToHash("0x1234")
	addrs := []common.Address{common.HexToAddress("0x01"), common.HexToAddress("0x02")}
	keys := [][]byte{bytes.Repeat([]byte{1}, 96), bytes.Repeat([]byte{2}, 96)}
	run := func(count uint64, entries int, slot5 uint64) (bool, []OpenEntry) {
		list := make([]string, entries)
		w := map[string]common.Hash{"A12": common.BigToHash(big.NewInt(2)), "A13": common.BigToHash(big.NewInt(3)), "A14": root, "A07": common.BigToHash(new(big.Int).SetUint64(slot5))}
		for i := range list {
			c := common.BigToHash(big.NewInt(int64(i + 1)))
			list[i] = lowHash(c)
			w["A06:"+lowHash(c)] = common.BigToHash(big.NewInt(1))
		}
		row := map[string]any{"chainId": uint64(11155111), "root": lowHash(root), "validFromBlock": 12000000, "validToBlock": nil,
			"thresholdNumerator": 2, "thresholdDenominator": 3, "keysDigest": lowHash(c2KeysDigest(addrs, keys)), "pkcCount": count, "pkcList": list}
		m2, err := m.WithExtension(extensionDoc(map[string]any{"setRootHistory": []any{row}}, nil, nil, nil, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		vals := []c2Val{{Addr: addrs[0], KeyHash: crypto.Keccak256Hash(keys[0])}, {Addr: addrs[1], KeyHash: crypto.Keccak256Hash(keys[1])}}
		st := &c2Station{W: w, N: 2, Vals: vals}
		ok, open, err := c2History(&Env{Manifest: m2, Ctx: LegContext{Chain: 11155111}, Facts: &Facts{}}, st, st, 12000001, keys)
		if err != nil {
			t.Fatal(err)
		}
		return ok, open
	}
	if ok, open := run(256, 256, 256); !ok || len(open) != 0 {
		t.Fatalf("256 entries: %v %v", ok, open)
	}
	if ok, open := run(257, 257, 257); ok || len(open) != 1 || open[0].State.Fields["reason"] != "pkc_list_too_large" || open[0].State.Fields["count"] != uint64(257) || open[0].State.Fields["limit"] != uint64(256) {
		t.Fatalf("257 entries: %v %v", ok, open)
	}
	if ok, open := run(29, 28, 29); ok || len(open) != 1 || open[0].State.Fields["reason"] != "pkc_count_mismatch" || open[0].State.Fields["want"] != uint64(29) || open[0].State.Fields["got"] != uint64(28) {
		t.Fatalf("28 entries for pkcCount 29: %v %v", ok, open)
	}
}
