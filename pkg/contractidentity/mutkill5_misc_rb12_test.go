// Copyright 2026 Certen Protocol

package contractidentity

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for txtrie.go, types.go, vocab.go, vectors.go, steps_2c.go and step_2a_settle.go sites.

func TestMutKill5TxErrorText(t *testing.T) {
	cases := []struct {
		e    TxError
		want string
	}{
		{TxError{Kind: TxTooMany, Index: 3, Got: 5, Limit: 4}, "block transactions: too_many_transactions (index 3): 5 against 4"},
		{TxError{Kind: TxTooLarge, Index: 1, Got: 9, Limit: 8}, "block transactions: transactions_too_large (index 1): 9 against 8"},
		{TxError{Kind: TxEmpty, Index: 2, Got: 9, Limit: 8}, "block transactions: empty_transaction (index 2)"},
		{TxError{Kind: TxBadEnvelope, Index: 0, Detail: "why"}, "block transactions: bad_envelope (index 0): why"},
		{TxError{Kind: TxTooMany, Index: 0, Got: 2, Limit: 1, Detail: "d"}, "block transactions: too_many_transactions (index 0): 2 against 1: d"},
	}
	for _, c := range cases {
		e := c.e
		if got := e.Error(); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

func TestMutKill5IsCoreJudgedPartUnknown(t *testing.T) {
	for _, r9 := range []bool{false, true} {
		if IsCoreJudgedPart("no_such_part", r9) {
			t.Errorf("an unknown part is not a core judged part (registry9 %v)", r9)
		}
	}
}

func TestMutKill5FindingObjectsOrder(t *testing.T) {
	st := func(code string, x int) *StateError { return &StateError{Code: code, Fields: map[string]any{"x": x}} }
	out := findingObjects([]Finding{{Part: "p", State: st("b", 1)}, {Part: "p", State: st("a", 2)}, {Part: "p", State: st("a", 1)}, {Part: "o", State: st("z", 1)}})
	want := [][3]any{{"o", "z", 1}, {"p", "a", 1}, {"p", "a", 2}, {"p", "b", 1}}
	for i, w := range want {
		o := out[i].(map[string]any)
		if o["part"] != w[0] || o["code"] != w[1] || o["fields"].(map[string]any)["x"] != w[2] {
			t.Errorf("findingObjects[%d] = %v", i, o)
		}
	}
}

func TestMutKill5VocabularyLevelNumberWithoutTheSet(t *testing.T) {
	if n, ok := (&Vocabulary{}).LevelNumber("ADMIN"); ok || n != 0 {
		t.Errorf("a vocabulary without authority_level: %d %v", n, ok)
	}
}

func TestMutKill5CanonicalJSONEqualWithAnUnencodableSide(t *testing.T) {
	bad := map[string]any{"x": make(chan int)}
	if canonicalJSONEqual(bad, map[string]any{}) || canonicalJSONEqual(map[string]any{}, bad) {
		t.Error("a map that cannot be encoded equals nothing")
	}
	if !canonicalJSONEqual(map[string]any{"a": 1}, map[string]any{"a": 1}) {
		t.Error("equal maps")
	}
}

func TestMutKill5C2FinalizedStatus(t *testing.T) {
	rep := func(s finality.Status, st *finality.StateError) *finality.Report {
		return &finality.Report{Levels: map[finality.Level]finality.LevelStatus{finality.LevelFinalized: {Status: s, State: st}}}
	}
	cases := []struct {
		r    *finality.Report
		want string
	}{
		{rep(finality.StatusRefused, nil), S7StatusRefusedPrefix + "unnamed"},
		{rep(finality.StatusRefused, &finality.StateError{Code: "some_code"}), S7StatusRefusedPrefix + "some_code"},
		{rep(finality.Status("no_such_status"), nil), S7StatusAbsent},
		{&finality.Report{}, S7StatusAbsent},
	}
	for i, c := range cases {
		if got, ok := c2FinalizedStatus(c.r, BlockRef{}); got != c.want || ok {
			t.Errorf("case %d: %q %v", i, got, ok)
		}
	}
}

func TestMutKill5A2LoggedLevelWithoutAMatch(t *testing.T) {
	m, err := parseManifest(embeddedManifest)
	if err != nil {
		t.Fatal(err)
	}
	acc := common.Address{9}
	opT := m.AccountEventTopics()["GovernanceOperationExecuted"]
	env := func(m *Manifest, logs ...*types.Log) *Env {
		e := &Env{Facts: &Facts{}, Manifest: m, Ctx: LegContext{Receipt: &ethproof.ReceiptLeaf{Logs: logs}}}
		e.Facts.A.Account = acc
		return e
	}
	if lv, ok := a2LoggedLevel(env(m), &SettlementCall{}); ok {
		t.Errorf("no legs, no logs, no batch: %d %v", lv, ok)
	}
	wrongTarget := &types.Log{Address: acc, Topics: []common.Hash{a2Hash(opT.Topic0), {1}, a2Word(common.Address{2})}}
	if lv, ok := a2LoggedLevel(env(m, wrongTarget), &SettlementCall{Legs: []Leg{{Target: common.Address{1}}}}); ok || lv != 0 {
		t.Errorf("an operation log for another target: %d %v", lv, ok)
	}
	if lv, ok := a2LoggedLevel(env(m), &SettlementCall{Batch: true}); ok || lv != 0 {
		t.Errorf("a batch call without a batch log: %d %v", lv, ok)
	}
	doc := mk5Doc(t)
	tp := map[string]json.RawMessage{}
	if err := json.Unmarshal(doc["topics"], &tp); err != nil {
		t.Fatal(err)
	}
	tp["accountEvents"] = json.RawMessage(`{"events":{}}`)
	doc["topics"] = mk5Bytes(t, tp)
	bare, err := parseManifest(mk5Bytes(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if lv, ok := a2LoggedLevel(env(bare, wrongTarget), &SettlementCall{}); ok || lv != 0 {
		t.Errorf("a manifest without the governance events: %d %v", lv, ok)
	}
}
