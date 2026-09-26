// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// G0's execution receipt must recompute to the anchor that becomes EXEC_WITNESS.
// Checking only that the receipt starts at the entry accepted any anchor at all.
func TestG0_ReceiptPathMustRecompute(t *testing.T) {
	prove := func(t *testing.T, mutate func(receipt map[string]interface{})) error {
		t.Helper()
		am, err := NewArtifactManager(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		resp := loadRecordedResponse(t, "g0_inclusion.json")
		receipt := resp["result"].(map[string]interface{})["receipt"].(map[string]interface{})
		if mutate != nil {
			mutate(receipt)
		}
		client := NewMockRPCClient()
		client.AddMockResponse(recordedAccount, resp)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = NewG0Layer(client, am).ProveG0(ctx, G0Request{
			Account: recordedAccount, TxHash: recordedTxHash, Chain: "main", WorkDir: t.TempDir(),
		})
		return err
	}

	if err := prove(t, nil); err != nil {
		t.Fatalf("the recorded genuine receipt must prove: %v", err)
	}

	t.Run("a path step altered", func(t *testing.T) {
		err := prove(t, func(r map[string]interface{}) {
			step := r["entries"].([]interface{})[0].(map[string]interface{})
			h := step["hash"].(string)
			step["hash"] = strings.Repeat("0", 2) + h[2:]
		})
		if err == nil || !strings.Contains(err.Error(), "G0 execution receipt") {
			t.Fatalf("an altered merkle path was accepted: %v", err)
		}
	})

	t.Run("the anchor replaced", func(t *testing.T) {
		err := prove(t, func(r map[string]interface{}) {
			r["anchor"] = strings.Repeat("11", 32)
		})
		if err == nil || !strings.Contains(err.Error(), "G0 execution receipt") {
			t.Fatalf("a receipt ending at an arbitrary anchor was accepted: %v", err)
		}
	})
}
