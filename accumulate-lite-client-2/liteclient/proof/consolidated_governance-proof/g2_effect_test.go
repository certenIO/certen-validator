package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const effectTx = "5bdf6a32ed74947cfdc6415bb262be82ed7166f061a4e27640c74a935a4f3ff6"

// loadEffectRecord is Kermit's record of the WriteData that production proof e1e34338 governs.
func loadEffectRecord(t *testing.T) *recordedEffect {
	t.Helper()
	raw, err := os.ReadFile("testdata/g2_effect_record_5bdf6a32.json")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := decodeRecordedEffect(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// RB5-F27: the effect is what Accumulate recorded the transaction doing, and it must be exactly the approved body's.
func TestTheRecordedEffectIsTheApprovedOne(t *testing.T) {
	rec := loadEffectRecord(t)
	v := verifyRecordedEffect(rec, effectTx, nil)
	if !v.Verified || v.EffectType != EffectTypeRecordedWriteData {
		t.Fatalf("the real record: %+v", v)
	}
	if *v.ExpectedValue != "f350f4cc25d0d5e7a99fae97832236a4d436f06a7e234b91cefdd3a14f5a1094" {
		t.Fatalf("the approved body's entry hashes to %s", *v.ExpectedValue)
	}
	right := "0x" + *v.ExpectedValue
	if v := verifyRecordedEffect(rec, effectTx, &right); !v.Verified {
		t.Fatalf("with the right expected entry: %+v", v.Details)
	}
}

func TestAnEffectThatIsNotTheApprovedOneIsRefused(t *testing.T) {
	wrong := strings.Repeat("ab", 32)
	for name, c := range map[string]struct {
		mut    func(r *recordedEffect)
		tx     string
		expect *string
	}{
		"another transaction":         {func(*recordedEffect) {}, strings.Repeat("cd", 32), nil},
		"another entry recorded":      {func(r *recordedEffect) { r.Result.EntryHash = wrong }, effectTx, nil},
		"recorded on another account": {func(r *recordedEffect) { r.Result.AccountURL = "acc://someone-else.acme/data" }, effectTx, nil},
		"another result type":         {func(r *recordedEffect) { r.Result.Type = "sendTokens" }, effectTx, nil},
		"not delivered":               {func(r *recordedEffect) { r.Status, r.StatusNo = "failed", 400 }, effectTx, nil},
		"pending":                     {func(r *recordedEffect) { r.Status, r.StatusNo = "pending", 0 }, effectTx, nil},
		"another expected entry":      {func(*recordedEffect) {}, effectTx, &wrong},
	} {
		rec := loadEffectRecord(t)
		c.mut(rec)
		if v := verifyRecordedEffect(rec, c.tx, c.expect); v.Verified {
			t.Errorf("%s: verified", name)
		}
	}
	if v := verifyRecordedEffect(nil, effectTx, nil); v.Verified {
		t.Error("no record: verified")
	}
	// The old --expect-entry path compared a TRANSACTION hash with an ENTRY hash; the transaction hash is no entry.
	tx := effectTx
	if v := verifyRecordedEffect(loadEffectRecord(t), effectTx, &tx); v.Verified {
		t.Error("a transaction hash accepted as the expected entry")
	}
}

// A transaction whose effect this check cannot establish does not get G2.
func TestATransactionOfAnotherKindHasNoEffectG2CanClaim(t *testing.T) {
	raw, _ := os.ReadFile("testdata/g2_effect_record_5bdf6a32.json")
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	body := m["message"].(map[string]interface{})["transaction"].(map[string]interface{})["body"].(map[string]interface{})
	for k := range body {
		delete(body, k)
	}
	body["type"] = "burnTokens"
	body["amount"] = "1"
	b, _ := json.Marshal(m)
	rec, err := decodeRecordedEffect(b)
	if err != nil {
		t.Fatal(err)
	}
	if v := verifyRecordedEffect(rec, effectTx, nil); v.Verified {
		t.Fatal("a non-WriteData transaction's effect verified")
	}
}
