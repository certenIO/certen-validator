// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// RB12-OPS-A1 item 1 (BETA finding B-ARB-1): LoadPins judged the logic_pins keys and the confirm_path selectors and topics by ranging over
// Go maps, so two spellings of one code hash that name different roles, and several bad selector or topic pins, were answered in a
// random order. The TS twin sorts; this loader now does too. Every case below is loaded 1,000 times and answers the same every time.

const (
	walletProxyHash = "0x8736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8"
	walletLogicHash = "0x41aae8a0f910daa7a04450a94f864df487c0226c75e1809298c297d7f9e2f33a"
	detRuns         = 1000
)

func upperHash(h string) string { return "0x" + strings.ToUpper(strings.TrimPrefix(h, "0x")) }

// pinsEdits returns the embedded arb_sepolia section with every (path, value) edit applied (nil deletes).
func pinsEdits(t *testing.T, edits ...edit) *finality.Pins {
	t.Helper()
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var sec map[string]any
	if err := json.Unmarshal(embedded.Sections["arb_sepolia"], &sec); err != nil {
		t.Fatal(err)
	}
	for _, e := range edits {
		cur := sec
		for _, k := range e.path[:len(e.path)-1] {
			cur = cur[k].(map[string]any)
		}
		if e.val == nil {
			delete(cur, e.path[len(e.path)-1])
		} else {
			cur[e.path[len(e.path)-1]] = e.val
		}
	}
	raw, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	return &finality.Pins{Format: embedded.Format, Sections: map[string]json.RawMessage{"arb_sepolia": raw}}
}

type edit struct {
	path []string
	val  any
}

func answer(p *finality.Pins) string {
	a, err := arbfinal.LoadPins(p)
	if err != nil {
		return err.Error()
	}
	return "ok " + a.Rollup.Hex()
}

func mustAnswerAlways(t *testing.T, name string, p *finality.Pins, want string) {
	t.Helper()
	for i := 0; i < detRuns; i++ {
		if got := answer(p); got != want {
			t.Fatalf("%s, load %d: got %s, want %s", name, i, got, want)
		}
	}
}

// Two spellings of one code hash that name different roles are pin_mismatch{logic_pins}: before, whichever the map visited last decided
// whether the wallet proxy was pinned at all.
func TestConflictingRolesUnderTwoSpellingsOfOneHashAreRefusedEveryTime(t *testing.T) {
	want := arbfinal.PinMismatch("logic_pins").Error()
	// the upper-case spelling of the proxy hash names the LOGIC role: if it won, the proxy role would be gone (pin_mismatch on
	// logic_pins.validator_wallet_proxy); if the real one won, the file would load. Both are wrong answers to this file.
	mustAnswerAlways(t, "proxy hash under both roles", pinsEdits(t, edit{[]string{"logic_pins", upperHash(walletProxyHash)}, arbfinal.RoleWalletLogic}), want)
	mustAnswerAlways(t, "logic hash under both roles", pinsEdits(t, edit{[]string{"logic_pins", upperHash(walletLogicHash)}, arbfinal.RoleWalletProxy}), want)
	// a third spelling that agrees with one of two that conflict does not make the set consistent
	mixed := "0x" + strings.ToUpper(walletProxyHash[2:34]) + walletProxyHash[34:]
	mustAnswerAlways(t, "three spellings, two roles", pinsEdits(t,
		edit{[]string{"logic_pins", upperHash(walletProxyHash)}, arbfinal.RoleWalletProxy},
		edit{[]string{"logic_pins", mixed}, arbfinal.RoleWalletLogic}), want)
}

// The same role under two spellings is one entry (what the TS twin does as well): the file loads, and the table has one row for the hash.
func TestTheSameRoleUnderTwoSpellingsOfOneHashIsOneEntry(t *testing.T) {
	p := pinsEdits(t, edit{[]string{"logic_pins", upperHash(walletProxyHash)}, arbfinal.RoleWalletProxy})
	var rollup string
	for i := 0; i < detRuns; i++ {
		a, err := arbfinal.LoadPins(p)
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if rollup == "" {
			rollup = a.Rollup.Hex()
		}
		h := common.HexToHash(walletProxyHash)
		if got := a.LogicPins[h]; got != arbfinal.RoleWalletProxy {
			t.Fatalf("load %d: role of the proxy hash %q", i, got)
		}
		n := 0
		for _, r := range a.LogicPins {
			if r == arbfinal.RoleWalletProxy {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("load %d: %d entries with the proxy role, want 1", i, n)
		}
	}
}

// Several bad selector pins: the refusal names the first one by NAME. Each case removes the one the previous case named.
func TestSeveralBadSelectorPinsAreNamedInSortedOrder(t *testing.T) {
	order := []string{"confirm_assertion", "fast_confirm_new_assertion", "force_confirm_assertion", "wallet_execute_transactions"}
	for i, named := range order {
		var edits []edit
		for j, name := range order[i:] {
			// three different ways to be bad, in turn: short, zero and absent
			edits = append(edits, edit{[]string{"confirm_path", "selectors", name}, []any{"0x1234", "0x00000000", nil}[j%3]})
		}
		mustAnswerAlways(t, "selectors from "+named, pinsEdits(t, edits...), arbfinal.PinMismatch("confirm_path.selectors."+named).Error())
	}
}

func TestSeveralBadTopicPinsAreNamedInSortedOrder(t *testing.T) {
	both := pinsEdits(t, edit{[]string{"confirm_path", "topics", "assertion_force_confirmed"}, "0x12"}, edit{[]string{"confirm_path", "topics", "assertion_confirmed"}, nil})
	mustAnswerAlways(t, "both topics bad", both, arbfinal.PinMismatch("confirm_path.topics.assertion_confirmed").Error())
	// the selectors are judged before the topics, so one bad selector and two bad topics name the selector
	withSelector := pinsEdits(t, edit{[]string{"confirm_path", "topics", "assertion_force_confirmed"}, "0x12"}, edit{[]string{"confirm_path", "topics", "assertion_confirmed"}, nil},
		edit{[]string{"confirm_path", "selectors", "wallet_execute_transaction"}, "0x00000000"})
	mustAnswerAlways(t, "bad selector and bad topics", withSelector, arbfinal.PinMismatch("confirm_path.selectors.wallet_execute_transaction").Error())
}

// The embedded section is untouched by all of this.
func TestTheEmbeddedArbSepoliaSectionStillLoadsTheSameEveryTime(t *testing.T) {
	embedded, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	first := answer(embedded)
	if !strings.HasPrefix(first, "ok ") {
		t.Fatalf("the embedded section does not load: %s", first)
	}
	mustAnswerAlways(t, "embedded", embedded, first)
}
