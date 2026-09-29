package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/execution"
)

// RB4-F55 repair: the command hands the request to the running validator through its data directory and prints its
// answer; with no running validator serving repairs it says so rather than waiting on nothing.
func TestTheRepairCommandHandsTheRequestToTheRunningValidator(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "member_repairs")
	req := execution.MemberRepairRequest{IntentID: "000ac79a", ChainID: 84532, SettlementTx: "0xc409", Apply: true}

	if _, err := requestMemberRepair(dir, req, time.Second, 10*time.Millisecond); err == nil || !strings.Contains(err.Error(), "running validator") {
		t.Fatalf("no validator serving repairs: %v", err)
	}

	for _, d := range []string{"requests", "results"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The running validator: answer the request it finds.
	go func() {
		for i := 0; i < 200; i++ {
			entries, _ := os.ReadDir(filepath.Join(dir, "requests"))
			for _, e := range entries {
				raw, _ := os.ReadFile(filepath.Join(dir, "requests", e.Name()))
				var got execution.MemberRepairRequest
				if json.Unmarshal(raw, &got) != nil {
					continue
				}
				blob, _ := json.Marshal(execution.MemberRepairResult{Request: got, Outcome: execution.MemberRepairRepaired})
				os.WriteFile(filepath.Join(dir, "results", got.ID+".json"), blob, 0o600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	res, err := requestMemberRepair(dir, req, 5*time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != execution.MemberRepairRepaired || res.Request.IntentID != "000ac79a" || res.Request.ChainID != 84532 ||
		res.Request.SettlementTx != "0xc409" || !res.Request.Apply || res.Request.ID == "" || res.Request.RequestedAt.IsZero() {
		t.Fatalf("the request reached the validator as %+v", res.Request)
	}
}
