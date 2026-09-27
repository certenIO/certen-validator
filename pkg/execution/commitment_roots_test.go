// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// RB3-F105: a governanceRoot or operationCommitment the commitment carries and that does not decode as
// exactly 32 bytes refuses the proof cycle, by name. It used to leave a zero root (bad hex) or a
// different root (truncated or padded) in the request.
func TestACommitmentRootThatDoesNotDecodeRefusesTheCycle(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	for key, bad := range map[string]string{
		"governanceRoot":      "0xnothex",
		"operationCommitment": "0x" + strings.Repeat("ab", 33),
	} {
		id := "f105-" + key + "-" + run
		s1Seed(ctx, t, db, id)
		func(id string) {
			t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
		}(id)
		err := NewUnifiedOrchestratorAdapter(o).StartProofCycleWithAccumulateRef(ctx, id, "", [32]byte{1},
			[]string{"0x" + strings.Repeat("cd", 32)},
			map[string]interface{}{"targetChain": "11155111", "memberChains": []int64{11155111}, "memberLegs": 1,
				"proofClass": "on_cadence", key: bad},
			"acc://harbor.acme/data", strings.Repeat("ef", 32), "bvn1")
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s=%q: the cycle was not refused by name (%v)", key, bad, err)
		}
	}
	if _, err := hexStringToBytes32("0x" + strings.Repeat("ab", 31)); err == nil {
		t.Error("a 31-byte value was padded into a root")
	}
	if r, err := hexStringToBytes32("0x" + strings.Repeat("ab", 32)); err != nil || r[0] != 0xab || r[31] != 0xab {
		t.Errorf("a 32-byte root was not read as itself: %x %v", r, err)
	}
}
