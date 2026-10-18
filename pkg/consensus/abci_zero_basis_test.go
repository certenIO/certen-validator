package consensus

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// PV2-F3 at the consensus rule. The chain is already deciding blocks as v14 (an anchor set is in force), and v14 counts a
// listed cost basis of zero as a price. The v15 reading - zero is no bound, the chain is unpriced - must therefore reach a
// block only through the committed fact that moves the chain to v15, the cross-partition activation, never through the
// binary: the same bytes are decided the v14 way until the block after the activation and the v15 way from it, on every
// node and on replay.
func TestABlockOverAZeroCostBasisIsDecidedByTheCommittedActivation(t *testing.T) {
	f := newRotationFixture()
	cfg, ev := pricedFixture(t,
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000, PerLegMicroUSD: 500},
		entitlement.ChainCostBasis{ChainID: 421614}) // listed at zero, as the live epoch listed Adiri
	policy := *f.policy
	policy.Mode = string(EntitlementEnforce)
	policy.Keys = map[string]string{"k1": hex.EncodeToString(cfg.Keys["k1"])}
	pf := *f
	pf.policy = &policy
	app, _ := rotationApp(t, &pf)
	zero := []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum)}
	priced := []ChainTarget{target(84532, liveAnchorBaseAndSepolia)}
	check := func(tx []byte) *abcitypes.ResponseCheckTx {
		t.Helper()
		r, err := app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Block 1, no anchor set: the ceiling is skipped, as it always was.
	v14Step(t, app, 1, []uint32{0}, anchoredBlockJSON(t, "op-1", "validator-1", zero, ev))
	// Block 2: the anchor set. From block 3 rules v14 bind the ceiling.
	v14Step(t, app, 2, []uint32{0}, rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")))

	// Block 3, v14: a listed zero is a price. The block is admitted, exactly as v14 decided it when the anchor set began.
	v14Step(t, app, 3, []uint32{0, 0}, anchoredBlockJSON(t, "op-3", "validator-1", zero, ev),
		anchoredBlockJSON(t, "op-4", "validator-1", priced, ev))
	if r := check(anchoredBlockJSON(t, "op-5", "validator-1", zero, ev)); r.Code != 0 {
		t.Fatalf("CheckTx applied the v15 reading before the activation: %d %s", r.Code, r.Log)
	}

	// Block 4: the activation, accepted. In force from block 5. Block 4 itself is still v14.
	v14Step(t, app, 4, []uint32{0, 0}, rotJSON(t, liveG1Activation(f, "ops-1", "ops-2")),
		anchoredBlockJSON(t, "op-6", "validator-1", zero, ev))

	// Block 5, v15: the zero chain is unpriced and named; a block priced throughout is decided as before.
	resp := v14Step(t, app, 5, []uint32{4, 0}, anchoredBlockJSON(t, "op-7", "validator-1", zero, ev),
		anchoredBlockJSON(t, "op-8", "validator-1", priced, ev))
	if log := resp.TxResults[0].Log; !strings.Contains(log, entitlement.ReasonUnpriced) || !strings.Contains(log, "421614") {
		t.Fatalf("the refusal does not name ENTITLEMENT_UNPRICED and the chain: %q", log)
	}
	if r := check(anchoredBlockJSON(t, "op-9", "validator-1", zero, ev)); r.Code != 4 || !strings.Contains(r.Log, entitlement.ReasonUnpriced) {
		t.Fatalf("CheckTx does not filter the unpriced block once the activation is in force: %d %s", r.Code, r.Log)
	}
	if r := check(anchoredBlockJSON(t, "op-10", "validator-1", priced, ev)); r.Code != 0 {
		t.Fatalf("CheckTx refused a block priced throughout: %d %s", r.Code, r.Log)
	}
}
