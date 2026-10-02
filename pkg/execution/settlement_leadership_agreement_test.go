package execution

import (
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

// RB5-F38: one election. The leader the round names when it queues a member (consensus.OnDemandLeaderIndex) is the
// validator this submitter lets settle it, for every operation and chain - and for the period lane's settlement
// window, which places the leader's turn first.
func TestTheSubmitterSettlesOnTheLeaderTheRoundNames(t *testing.T) {
	roster := odRoster()
	for i := 0; i < 300; i++ {
		for _, chain := range []int64{84532, 11155111, 421614} {
			member := odMember(byte(i), chain, uint64(100+i))
			named := roster[consensus.OnDemandLeaderIndex(member.ChainID, member.OperationID, len(roster))]
			for _, id := range roster {
				if leads := odSubmitter(t, id).isLeaderFor(member, 0); leads != (id == named) {
					t.Fatalf("chain %d op %x: the round names %s, but %s leads=%v", chain, member.OperationID[:4], named, id, leads)
				}
			}
		}
	}
}
