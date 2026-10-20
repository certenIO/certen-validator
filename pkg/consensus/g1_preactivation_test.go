package consensus

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/ethereum/go-ethereum/common"
)

// preActivationRun finalizes a fixed history through a fresh rotation fixture app and returns, per block, the txs' result
// codes and the block's app hash. It uses only what the v14 binary has: the sequence covers every kind of decision v14 makes
// that a rules change could disturb - a ValidatorBlock naming any anchor with no anchor set (the v13 verdict), a refused and an
// accepted anchor set (the v14 activation), the anchor rule's refusals and acceptances after it, a refused admin rotation, a
// refused registry - and ends with the stamped rules version.
func preActivationRun(t *testing.T) string {
	t.Helper()
	f := newRotationFixture()
	app, _ := rotationApp(t, f)
	wrong := common.HexToAddress("0x8398d7ebb7de3bb1d9a6f7e7aec7e2ac2c1e5339").Hex()
	right := []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum)}
	blocks := [][][]byte{
		{anchoredBlockJSON(t, "op-pre-1", "validator-1", []ChainTarget{target(84532, wrong)}, nil)},
		{rotJSON(t, adminRotation(1, genesisSetID(f), setB(f), 2).signedBy(f.admins, "ops-1")),
			rotJSON(t, liveAnchorSet(f, 1, "ops-1")), rotJSON(t, liveAnchorSet(f, 1, "ops-1", "ops-2")),
			anchoredBlockJSON(t, "op-pre-2", "validator-1", []ChainTarget{target(84532, wrong)}, nil)},
		{anchoredBlockJSON(t, "op-pre-3", "validator-1", []ChainTarget{target(84532, wrong)}, nil),
			anchoredBlockJSON(t, "op-pre-4", "validator-1", []ChainTarget{target(1, liveAnchorBaseAndSepolia)}, nil),
			anchoredBlockJSON(t, "op-pre-5", "validator-1", right, nil)},
		{rotJSON(t, liveAnchorSet(f, 1, "ops-2", "ops-3")), anchoredBlockJSON(t, "op-pre-6", "validator-1", right, nil)},
	}
	var sb strings.Builder
	for i, txs := range blocks {
		h := int64(i + 1)
		resp := finalize(t, app, h, abcitypes.CommitInfo{}, txs...)
		fmt.Fprintf(&sb, "%d:", h)
		for _, r := range resp.TxResults {
			fmt.Fprintf(&sb, "%d,", r.Code)
		}
		fmt.Fprintf(&sb, ":%s\n", hex.EncodeToString(resp.AppHash))
		if _, err := app.Commit(context.Background(), &abcitypes.RequestCommit{}); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Fprintf(&sb, "stamp:%d\n", app.committedRulesVersion())
	return sb.String()
}

// The app hashes and result codes of preActivationRun, measured at the rules v14 head (d20f693, the detached worktree
// whose output is recorded in checkins/RB9-C2.md) and asserted here by the v15 binary: before the cross-partition activation
// this binary decides every block, results and app hash, as v14 did. A change to any decision before the activation changes
// a hash here; the activation itself is the only act that may.
const preActivationV14 = `1:0,:cf0a4e63fc9a4f3e6db2b478658e8936265d21f5a669a53ed344f9adfcf45fad
2:12,16,0,0,:dcdf7480e5f0963769de33c6851dcbd357755734503e400448b0f9b565987a45
3:17,17,0,:6def21d8d7ce45b073825604de2cd5ffcecc991401ef8a939066e2c0dd522797
4:16,0,:7ecaf694378feba26099cf3c3cec62ae6f3940959bef4affd44730c7dae70322
stamp:14
`

func TestRulesV15PreActivationDecisionsAreV14s(t *testing.T) {
	got := preActivationRun(t)
	t.Logf("pre-activation history:\n%s", got)
	if got != preActivationV14 {
		t.Fatalf("this binary decided the pre-activation history differently from the v14 head.\n got:\n%s\nwant:\n%s", got, preActivationV14)
	}
}
