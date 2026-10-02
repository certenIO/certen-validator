package consensus

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

// RB5-F38. The round that queues a member names who settles it, and it names the lane's own election: measured live
// 2026-10-02, intent af16e11d, the round logged "validator-4 is ELECTED EXECUTOR ... queued for batch settlement" -
// from an election over a hard-coded list of seven names that decided nothing - while the on-demand leader,
// validator-1, anchored, attested and settled it.

func leadershipLog(t *testing.T, proofClass string, chains ...int64) (string, *batchPlan) {
	t.Helper()
	ci := batchableIntent(t, "i-lead-"+proofClass, chains...)
	ci.IntentData = []byte(fmt.Sprintf(`{"intent_id":%q,"proof_class":%q}`, ci.IntentID, proofClass))
	var buf bytes.Buffer
	bv := refusalValidator(newFakeEnqueuer())
	bv.logger = log.New(&buf, "", 0)
	plan, err := bv.planBatch(ci, 7)
	if err != nil {
		t.Fatalf("planning: %v", err)
	}
	if err := enqueue(bv, ci); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return buf.String(), plan
}

func TestAQueuedOnDemandMemberNamesItsOnDemandLeader(t *testing.T) {
	t.Setenv("ON_DEMAND_INTENT_KEYED", "true")
	t.Setenv("BATCH_LEADER_VALIDATORS", "validator-1,validator-2,validator-3,validator-4,validator-5,validator-6,validator-7")
	out, plan := leadershipLog(t, "on_demand", 84532)
	if len(plan.members) != 1 || !plan.members[0].onDemand {
		t.Fatalf("the plan is not one on-demand member: %+v", plan.members)
	}
	m := plan.members[0]
	roster := batchLeaderRoster()
	want := roster[OnDemandLeaderIndex(m.chainID, m.opID, len(roster))]
	if !strings.Contains(out, "[SETTLEMENT-LEAD]") || !strings.Contains(out, "chain 84532: on-demand leader "+want+",") {
		t.Fatalf("the round does not name the on-demand leader %s:\n%s", want, out)
	}
	if strings.Contains(out, "ELECTED EXECUTOR") {
		t.Fatalf("the round still claims an elected executor:\n%s", out)
	}
}

func TestAQueuedCadenceMemberNamesThePeriodLeader(t *testing.T) {
	t.Setenv("ON_DEMAND_INTENT_KEYED", "true")
	out, _ := leadershipLog(t, "on_cadence", 84532)
	if !strings.Contains(out, "chain 84532: the batch period leader of the period it falls in, elected when that period is flushed") {
		t.Fatalf("the round does not name the cadence lane's leader:\n%s", out)
	}
}

// Each member of a multi-chain intent is named with its own chain's leader - the chain is in the election key.
func TestEveryMemberOfAMultiChainIntentIsNamed(t *testing.T) {
	t.Setenv("ON_DEMAND_INTENT_KEYED", "true")
	out, plan := leadershipLog(t, "on_demand", 84532, 11155111)
	roster := batchLeaderRoster()
	for _, m := range plan.members {
		want := fmt.Sprintf("chain %d: on-demand leader %s", m.chainID, roster[OnDemandLeaderIndex(m.chainID, m.opID, len(roster))])
		if !strings.Contains(out, want) {
			t.Fatalf("member on chain %d is not named (%q):\n%s", m.chainID, want, out)
		}
	}
}
