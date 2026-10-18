package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The rules v14 -> v15 upgrade REHEARSED on a real CometBFT network of four in-process validators running this
// ValidatorApp, driven by the operator's own tool (`validator-rotate`, built from this tree) over each node's CometBFT RPC,
// with throwaway admin keys (sealed at genesis: ops-1..3, threshold 2):
//
//  1. The chain as the v14 binary leaves it: a refused admin rotation (the state is stamped v12), a block naming a retired
//     anchor accepted (the v13 verdict), then the anchor set through the tool - the v14 activation - after which a retired
//     anchor is refused with code 17 and the committed anchors are accepted. This binary decides all of that exactly as v14
//     did: its v15 rules begin at the cross-partition activation, which is not yet committed (the state is stamped v14).
//  2. The upgrade: every node's ledger is put back exactly as the v14 binary wrote it (its history-check watermark is v14's,
//     checks 4, and none of v15's), the whole fleet stops, every node runs the boot history check this binary runs before
//     CometBFT's handshake (IndexCommittedHistory over its own block and state stores) - it re-checks the whole chain under
//     history-check v5 - and the fleet starts again: app version 15, state still stamped v14 (a rollback stays open), the same
//     app hash on every node. `history-check --rules 15` passes on the live chain; `g1-activate status` says the activation is
//     not committed; blocks are decided as before (code 17 for a retired anchor, accepted for the committed ones).
//  3. The activation, through the tool: propose (first admin), a NO-GO preflight with one approval, sign (second admin), a NO-GO
//     preflight while the chain has no spine (proof v3 not required, F8), the registry and the spine through the v13 tools, a GO
//     preflight against every node, submit - every node records it at the same height, and the state is stamped v15.
//  4. From the next height: the activation cannot be submitted again (NO-GO by name, refused by `propose --rpc`), blocks
//     are decided as before (an uncertified ValidatorBlock carries no proof v2 and is refused by the certificate rule, as under v14, so nothing of evidence 2.1 reaches it; the
//     certificate rule itself - a 2.0 certificate refused at H+1, a 2.1 one accepted, the same blocks at H and below decided as
//     v14 decided them - is TestAppJudgesTheCertificateByTheActivationInForceAtItsHeight and
//     TestACertificateOverEvidence21IsAcceptedFromTheNextHeight), and `history-check --rules 15` passes with the activation
//     found in its record.
//  5. The whole fleet restarts: one chain, stamped v15, app version 15, every node answering the activation log identically.
func TestRulesV15UpgradeAndG1ActivationRehearsalOnALiveNetwork(t *testing.T) {
	fx := newSpineFixture(t) // the rotation fixture, a BLS registry and Kermit's real genesis and major blocks (RB9-VB, F8)
	f := fx.rotationFixture
	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+f.policy.AdminKeys[id])
	}
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "off")
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", strings.Join(adminEnv, ","))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	t.Setenv("CERTEN_BLOCK_RETENTION", "0")

	dir := t.TempDir()
	tool := filepath.Join(dir, "validator-rotate")
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", tool, "github.com/certen/independant-validator/cmd/validator-rotate").CombinedOutput(); err != nil {
		t.Fatalf("build validator-rotate: %v\n%s", err, out)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(tool, args...).CombinedOutput()
		return string(out), err
	}
	mustRun := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("validator-rotate %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	secret := map[string]string{}
	for i, id := range []string{"ops-1", "ops-2", "ops-3"} {
		p := filepath.Join(dir, id+".seed")
		if err := os.WriteFile(p, []byte(strings.Repeat(fmt.Sprintf("%02x", 0xA1+i), 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secret[id] = "@" + p
	}

	const size = 4
	nodes, genesis, _, tick := startRehearsalNetworkWith(t, f, size, true)
	var rpcs []string
	for _, n := range nodes {
		rpcs = append(rpcs, n.rpcURL)
	}
	all := strings.Join(rpcs, ",")
	everyNode := func(what string, h int64) {
		t.Helper()
		waitNetwork(t, what, 90*time.Second, func() bool {
			for _, n := range nodes {
				if n.height() < h {
					return false
				}
			}
			return true
		})
	}
	connected := func(what string) {
		t.Helper()
		waitNetwork(t, what, 90*time.Second, func() bool {
			for _, n := range nodes {
				if n.node.Switch().Peers().Size() < size-1 {
					return false
				}
			}
			return true
		})
	}
	submit := func(via *rehearsalNode, tx []byte) (uint32, string, int64) {
		t.Helper()
		res, err := via.client.BroadcastTxCommit(context.Background(), cmttypes.Tx(tx))
		if err != nil {
			t.Fatalf("broadcast: %v", err)
		}
		if res.CheckTx.Code != 0 {
			return res.CheckTx.Code, res.CheckTx.Log, 0
		}
		return res.TxResult.Code, res.TxResult.Log, res.Height
	}
	retired := "0x8398D7EBb7De3BB1d9A6F7e7aEc7E2aC2c1E5339"
	op := 0
	vbWith := func(targets ...ChainTarget) []byte {
		op++
		return anchoredBlockJSON(t, fmt.Sprintf("op-g1-%d", op), "validator-1", targets, nil)
	}
	committedTargets := func() []ChainTarget {
		return []ChainTarget{target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum), target(11155111, liveAnchorBaseAndSepolia)}
	}
	// decidedAsV14 is what a v14 chain decides about a ValidatorBlock: a retired anchor is refused at the mempool with code
	// 17, the committed anchors are accepted.
	decidedAsV14 := func(what string, via *rehearsalNode) {
		t.Helper()
		if code, log, _ := submit(via, vbWith(target(84532, retired))); code != codeAnchorNotCommitted || !strings.Contains(log, ReasonAnchorNotCommitted) {
			t.Fatalf("%s: a block naming a retired anchor: %d %s", what, code, log)
		}
		if code, log, _ := submit(via, vbWith(committedTargets()...)); code != 0 {
			t.Fatalf("%s: a block naming the committed anchors: %d %s", what, code, log)
		}
	}

	// 1. The chain as the v14 binary leaves it.
	refusedRotation := adminRotation(1, genesisSetID(f), setB(f), 2).signedBy(f.admins, "ops-1")
	if code, log, _ := submit(nodes[0], rotJSON(t, refusedRotation)); code != codeAdminRotateRefused {
		t.Fatalf("an admin rotation with one approval: %d %s", code, log)
	}
	if code, log, _ := submit(nodes[1], vbWith(target(84532, retired))); code != 0 {
		t.Fatalf("v13 verdict: a block naming a retired anchor, with no anchor set: %d %s", code, log)
	}
	eth := fakeEthChains(t, map[int64]string{11155111: liveAnchorBaseAndSepolia, 84532: liveAnchorBaseAndSepolia, 421614: liveAnchorArbitrum})
	set := filepath.Join(dir, "anchor-set.json")
	anchors := "11155111=" + liveAnchorBaseAndSepolia + ",84532=" + liveAnchorBaseAndSepolia + ",421614=" + liveAnchorArbitrum
	mustRun("anchor-set", "propose", "--rpc", rpcs[0], "--anchor", anchors, "--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", set)
	mustRun("anchor-set", "sign", "--tx", set, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"])
	out := mustRun("anchor-set", "submit", "--tx", set, "--rpc", all, "--eth-rpc", eth)
	if m := regexp.MustCompile(`ACCEPTED at height (\d+)`).FindStringSubmatch(out); m == nil {
		t.Fatalf("the anchor set (v14's activation): %s", out)
	}
	tick(nodes[0], 2)
	decidedAsV14("the v14 chain", nodes[2])
	tick(nodes[0], 2)
	top := nodes[0].height()
	everyNode("every node to commit the v14 history", top)

	// 2. The upgrade. Every node's ledger as the v14 binary wrote it: its history-check watermark under v14's key (checks 4),
	// and none of v15's. Then the whole fleet stops, every node runs the boot check this binary runs, and the fleet starts again.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != executionRulesV14 {
			t.Fatalf("%s: before the upgrade the state is stamped (%+v, %v), want v14", n.name, st, err)
		}
		at, err := ledger.NewLedgerStore(n.kv).KindsCheckedThrough(CurrentExecutionRulesVersion, CommittedHistoryCheckVersion)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.kv.Set([]byte(fmt.Sprintf("abci:kinds_checked_through:v%d:checks%d", CurrentExecutionRulesVersion, CommittedHistoryCheckVersion)), nil); err != nil {
			t.Fatal(err)
		}
		prior := make([]byte, 8)
		for i := 0; i < 8; i++ {
			prior[7-i] = byte(at >> (8 * i))
		}
		if err := n.kv.Set([]byte("abci:kinds_checked_through:v14:checks4"), prior); err != nil {
			t.Fatal(err)
		}
		app := NewValidatorApp(ledger.NewLedgerStore(n.kv), "validator-chain-"+n.name)
		app.logger = log.New(io.Discard, "", 0)
		if err := app.SetGenesis(genesis); err != nil {
			t.Fatal(err)
		}
		if err := app.IndexCommittedHistory(storeHistory{blocks: store.NewBlockStore(n.dbs["blockstore"]),
			results: sm.NewStore(n.dbs["state"], sm.StoreOptions{})}); err != nil {
			t.Fatalf("%s: the v15 boot history check refused the v14 chain: %v", n.name, err)
		}
		if through, err := app.ledgerStore.KindsCheckedThrough(CurrentExecutionRulesVersion, CommittedHistoryCheckVersion); err != nil || through != at {
			t.Fatalf("%s: the boot check covered heights through %d (%v), want %d", n.name, through, err, at)
		}
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt := nodes[0].height()
	connected("the upgraded fleet to connect")
	tick(nodes[0], 2)
	everyNode("the upgraded fleet to commit", restartedAt+2)
	for _, n := range nodes {
		info, err := n.client.ABCIInfo(context.Background())
		if err != nil || info.Response.AppVersion != executionRulesV15 {
			t.Fatalf("%s: app version (%+v, %v), want 15", n.name, info, err)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != executionRulesV14 {
			t.Fatalf("%s: with no activation the state is stamped v%d, want v14 (a rollback stays open)", n.name, st.ExecutionRulesVersion)
		}
	}
	out = mustRun("history-check", "--rules", "15", "--rpc", rpcs[0])
	if !strings.Contains(out, "v15 continues this chain's history exactly") {
		t.Fatalf("history-check: %s", out)
	}
	if out := mustRun("g1-activate", "status", "--rpc", all); !strings.Contains(out, "rules v15 not yet activated") {
		t.Fatalf("status: %s", out)
	}
	decidedAsV14("the upgraded fleet before the activation", nodes[1])

	// 3. The activation, through the tool.
	req := filepath.Join(dir, "g1-activation.json")
	mustRun("g1-activate", "propose", "--rpc", rpcs[0], "--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", req)
	if out, err := run("g1-activate", "preflight", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "NO-GO") {
		t.Fatalf("preflight with one approval: %v\n%s", err, out)
	}
	mustRun("g1-activate", "sign", "--tx", req, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"])
	// F8: a fully signed activation on a chain that does not require proof v3 yet (no registry, no spine) is a NO-GO naming it.
	if out, err := run("g1-activate", "preflight", "--tx", req, "--rpc", all); err == nil || strings.Count(out, "does not require proof v3") != size {
		t.Fatalf("preflight on a chain with no spine: %v\n%s", err, out)
	}
	// The chain then requires proof v3 by the v13 procedure of TestTheSpineOnALiveNetwork: the admins commit the BLS registry under Kermit's
	// incarnation, then the spine genesis through the tool, and the archive's major blocks extend the spine. From the registry on, a
	// ValidatorBlock without an intent certificate is refused by the certificate rule (code 10), as v14 refuses it.
	evidence := "../proof/testdata/incarnation/kermit.json"
	spineReq := filepath.Join(dir, "spine-genesis.json")
	mustRun("spine-genesis", "propose", "--chain-id", rotChain, "--evidence", evidence, "--incarnation", "0x"+kermitIncarnationHex,
		"--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", spineReq)
	if code, log, _ := submit(nodes[1], rotJSON(t, fx.registry(1, "ops-1", "ops-2"))); code != 0 {
		t.Fatalf("the BLS registry: %d %s", code, log)
	}
	mustRun("spine-genesis", "sign", "--tx", spineReq, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"])
	mustRun("spine-genesis", "preflight", "--tx", spineReq, "--rpc", all)
	if out := mustRun("spine-genesis", "submit", "--tx", spineReq, "--rpc", all); !strings.Contains(out, "ACCEPTED at height") {
		t.Fatalf("the spine genesis: %s", out)
	}
	lastSpine := int64(0)
	for i, first := 0, 1; first <= len(fx.records); i, first = i+1, first+maxSpineExtensionRecords {
		end := min(first+maxSpineExtensionRecords-1, len(fx.records))
		code, log, h := submit(nodes[1+i%3], fx.extend(t, first, end))
		if code != 0 {
			t.Fatalf("major blocks %d-%d: %d %s", first, end, code, log)
		}
		lastSpine = h
	}
	tick(nodes[0], 2)
	everyNode("every node to commit past the spine", lastSpine+2)
	if code, log, _ := submit(nodes[2], vbWith(committedTargets()...)); code != codeIntentCertificateRefused {
		t.Fatalf("an uncertified block with the registry in force: %d %s", code, log)
	}
	mustRun("g1-activate", "preflight", "--tx", req, "--rpc", all)
	out = mustRun("g1-activate", "submit", "--tx", req, "--rpc", all)
	m := regexp.MustCompile(`ACCEPTED at height (\d+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "Evidence 2.1 is required from height") {
		t.Fatalf("submit: %s", out)
	}
	hs, _ := strconv.ParseInt(m[1], 10, 64)
	tick(nodes[0], 2)
	everyNode("every node to commit past the activation", hs+2)
	var activationID string
	for _, n := range nodes {
		l, err := ledger.NewLedgerStore(n.kv).LoadG1Activation()
		if err != nil || len(l.Activations) != 1 || l.Activations[0].Height != hs || l.Activations[0].Version != 1 {
			t.Fatalf("%s's activation log: (%+v, %v)", n.name, l, err)
		}
		if activationID == "" {
			activationID = l.Activations[0].ID
		} else if l.Activations[0].ID != activationID {
			t.Fatalf("%s records %s, another node %s", n.name, l.Activations[0].ID, activationID)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != executionRulesV15 {
			t.Fatalf("%s: after the activation the state is stamped v%d", n.name, st.ExecutionRulesVersion)
		}
		if got := n.app.g1ActivationInForce(hs); got != nil {
			t.Fatalf("%s: the activation is in force in its own block (%d)", n.name, hs)
		}
		if got := n.app.g1ActivationInForce(hs + 1); got == nil || got.Height != hs {
			t.Fatalf("%s: the activation is not in force at %d: %+v", n.name, hs+1, got)
		}
	}

	// 4. From the next height.
	if out, err := run("g1-activate", "submit", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "NO-GO") ||
		!strings.Contains(out, "already records the cross-partition activation") {
		t.Fatalf("a second activation: %v\n%s", err, out)
	}
	if out, err := run("g1-activate", "propose", "--rpc", rpcs[1], "--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"],
		"--out", filepath.Join(dir, "second.json")); err == nil || !strings.Contains(out, "activates once") {
		t.Fatalf("a second proposal: %v\n%s", err, out)
	}
	if code, log, _ := submit(nodes[2], rotJSON(t, liveG1Activation(f, "ops-1", "ops-3"))); code != codeG1ActivationRefused {
		t.Fatalf("the same activation again, by other admins, in a later block: %d %s", code, log)
	}
	// Blocks are decided as before: with the registry in force an uncertified block is refused by the certificate rule exactly as v14 refuses it
	// (the refusal does not mention evidence 2.1: nothing of it reaches a block with no certificate).
	if code, log, _ := submit(nodes[3], vbWith(committedTargets()...)); code != codeIntentCertificateRefused || strings.Contains(log, "2.1") {
		t.Fatalf("the fleet after the activation, an uncertified block: %d %s", code, log)
	}
	out = mustRun("history-check", "--rules", "15", "--rpc", rpcs[1])
	if !strings.Contains(out, "v15 continues this chain's history exactly") || !strings.Contains(out, G1ActivationKind) {
		t.Fatalf("history-check after the activation: %s", out)
	}
	if out := mustRun("g1-activate", "status", "--rpc", all); !strings.Contains(out, fmt.Sprintf("activated at height %d", hs)) ||
		strings.Contains(out, "DISAGREE") {
		t.Fatalf("status: %s", out)
	}

	// 5. A whole-fleet restart.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt = nodes[0].height()
	connected("the restarted fleet to connect")
	tick(nodes[0], 3)
	everyNode("the restarted fleet to commit", restartedAt+3)
	waitNetwork(t, "every node at one height", 30*time.Second, func() bool {
		top := nodes[0].height()
		for _, n := range nodes {
			if n.height() != top {
				return false
			}
		}
		return true
	})
	var first string
	for i, n := range nodes {
		info, err := n.client.ABCIInfo(context.Background())
		if err != nil || info.Response.AppVersion != executionRulesV15 {
			t.Fatalf("%s: app version (%+v, %v)", n.name, info, err)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != executionRulesV15 {
			t.Fatalf("%s: stamped v%d after the restart", n.name, st.ExecutionRulesVersion)
		}
		got := hex.EncodeToString(info.Response.LastBlockAppHash)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s's app hash %s is not %s's %s", n.name, got, nodes[0].name, first)
		}
		q, err := n.app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/g1_activation"})
		if err != nil || q.Code != 0 {
			t.Fatalf("%s: activation query (%+v, %v)", n.name, q, err)
		}
		var l ledger.G1ActivationLog
		if err := json.Unmarshal(q.Value, &l); err != nil || len(l.Activations) != 1 || l.Activations[0].ID != activationID || l.Activations[0].Height != hs {
			t.Fatalf("%s answers %s", n.name, q.Value)
		}
	}
}
