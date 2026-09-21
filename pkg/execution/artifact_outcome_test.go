package execution

import (
	"reflect"
	"testing"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// The proof artifact records what the proven execution did. An artifact exists for a reverted
// settlement as well as a successful one, and the gateway completed any intent that had an artifact -
// so without the outcome, a proven failure read as a success.
func TestExecutionOutcomeRecordsWhatTheProvenExecutionDid(t *testing.T) {
	ok := func(tx string) *chain.ObservationResult {
		return &chain.ObservationResult{TxHash: tx, IsFinalized: true, Status: 1}
	}
	reverted := func(tx string) *chain.ObservationResult {
		return &chain.ObservationResult{TxHash: tx, IsFinalized: true, Status: 0}
	}
	pending := &chain.ObservationResult{TxHash: "0xp", IsFinalized: false, Status: 0}

	cases := []struct {
		name    string
		obs     []*chain.ObservationResult
		outcome string
		txs     []string
	}{
		{"a success", []*chain.ObservationResult{ok("0xa")}, "succeeded", []string{"0xa"}},
		{"the live revert (5d92a476, receipt status 0)", []*chain.ObservationResult{reverted("0x5c10")}, "reverted", []string{"0x5c10"}},
		{"every member succeeded", []*chain.ObservationResult{ok("0xa"), ok("0xb")}, "succeeded", []string{"0xa", "0xb"}},
		{"every member reverted", []*chain.ObservationResult{reverted("0xa"), reverted("0xb")}, "reverted", []string{"0xa", "0xb"}},
		{"members that disagree have no single outcome", []*chain.ObservationResult{ok("0xa"), reverted("0xb")}, "", nil},
		{"an execution that is not final says nothing", []*chain.ObservationResult{ok("0xa"), pending}, "", nil},
		{"nothing observed says nothing", nil, "", nil},
	}
	for _, c := range cases {
		outcome, txs := executionOutcome(c.obs)
		if outcome != c.outcome || (c.txs != nil && !reflect.DeepEqual(txs, c.txs)) {
			t.Errorf("%s: got %q %v, want %q %v", c.name, outcome, txs, c.outcome, c.txs)
		}
	}
}
