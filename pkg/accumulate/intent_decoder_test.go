package accumulate

import (
	"encoding/hex"
	"testing"
	"time"
)

// RB3-F36: one decoder reads an intent's four blobs - the v3 entry's value.message.transaction. A second,
// positional "fallback" read a top-level transaction body and wrote over the same keys.
func TestOnlyTheV3DecoderStatesTheIntent(t *testing.T) {
	blob := func(s string) string { return hex.EncodeToString([]byte(s)) }
	entry := BlockEntry{Type: "transaction", Data: map[string]interface{}{
		"type": "transaction", "entry": "aa",
		"value": map[string]interface{}{"message": map[string]interface{}{"transaction": map[string]interface{}{
			"header": map[string]interface{}{"principal": "acc://user.acme/data", "memo": "CERTEN_INTENT"},
			"body": map[string]interface{}{"type": "writeData", "entry": map[string]interface{}{
				"type": "doubleHash", "data": []interface{}{blob(`{"intent":"signed"}`)}}},
		}}},
		// A body at the top level, as the fallback read it, saying something else.
		"transaction": map[string]interface{}{"body": map[string]interface{}{"entry": map[string]interface{}{
			"data": []interface{}{blob(`{"intent":"other"}`), "0a"}}}},
	}}
	l := &LiteClientAdapter{}
	tx := l.parseCertenTransaction(entry, &MinorBlock{Height: 5, Time: time.Unix(1, 0)}, "acc://dn.acme")
	got, _ := tx.IntentData["intentData"].(map[string]interface{})
	if got["intent"] != "signed" {
		t.Fatalf("intentData %v; want the signed intent from the v3 entry", tx.IntentData["intentData"])
	}
	if _, ok := tx.IntentData["rawElement_1"]; ok {
		t.Fatal("a second decoder added elements")
	}
}
