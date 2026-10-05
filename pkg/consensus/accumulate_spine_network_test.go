package consensus

import (
	"context"
	"encoding/hex"
	"fmt"
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
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The rules v13 spine on a real CometBFT network of four in-process validators running this ValidatorApp, on Kermit's
// real genesis and major blocks. Sealed at genesis with ops-1..3 (threshold 2):
//
//  1. a spine genesis before any BLS registry is refused, by the chain and by the preflight; the admins commit the
//     registry under Kermit's incarnation;
//  2. the owner's procedure through `validator-rotate spine-genesis`: propose from Kermit's incarnation evidence (refused
//     against another incarnation), one admin's approval refused by the chain and the preflight, the second admin signs,
//     preflight GO, submit; then the archive's major blocks through the other nodes, an extension per transaction, in
//     sequence; a stale extension is refused with its own code;
//  3. every node holds the same spine log, reaches the same app hash, is stamped v13 and passes the history check every
//     node runs at start - and the operator's `history-check --rules 13` over RPC;
//  4. restarted as a whole fleet, the network comes back on one chain, still v13, every node answering the same spine.
func TestTheSpineOnALiveNetwork(t *testing.T) {
	fx := newSpineFixture(t)
	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+fx.policy.AdminKeys[id])
	}
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "off")
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_KEYS", strings.Join(adminEnv, ","))
	t.Setenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD", "2")
	t.Setenv("CERTEN_BLOCK_RETENTION", "0")

	// The operator's tool, built from this tree.
	dir := t.TempDir()
	tool := filepath.Join(dir, "validator-rotate")
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", tool, "github.com/certen/independant-validator/cmd/validator-rotate").CombinedOutput(); err != nil {
		t.Fatalf("build validator-rotate: %v\n%s", err, out)
	}

	const size = 4
	nodes, genesis, _, tick := startRehearsalNetworkWith(t, fx.rotationFixture, size, true)
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

	// The operator's procedure, through the tool: the admins' secrets in files as the owner keeps them.
	run := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command(tool, args...).CombinedOutput()
		return string(out), err
	}
	secret := map[string]string{}
	for i, id := range []string{"ops-1", "ops-2", "ops-3"} {
		p := filepath.Join(dir, id+".seed")
		if err := os.WriteFile(p, []byte(strings.Repeat(fmt.Sprintf("%02x", 0xA1+i), 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secret[id] = "@" + p
	}
	var rpcs []string
	for _, nd := range nodes {
		rpcs = append(rpcs, nd.rpcURL)
	}
	all := strings.Join(rpcs, ",")
	evidence := "../proof/testdata/incarnation/kermit.json"
	req := filepath.Join(dir, "spine-genesis.json")
	if out, err := run("spine-genesis", "propose", "--chain-id", rotChain, "--evidence", evidence, "--incarnation", "0x"+strings.Repeat("ab", 32),
		"--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", req); err == nil || !strings.Contains(out, "recomputes incarnation 0x"+kermitIncarnationHex) {
		t.Fatalf("propose against another incarnation: %v\n%s", err, out)
	}
	if out, err := run("spine-genesis", "propose", "--chain-id", rotChain, "--evidence", evidence, "--incarnation", "0x"+kermitIncarnationHex,
		"--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", req); err != nil {
		t.Fatalf("propose: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(req)
	if err != nil {
		t.Fatal(err)
	}

	// 1. No registry, no genesis - by the chain, signed or not, and by the preflight; then the registry.
	if code, log, _ := submit(nodes[0], fx.genesis(t)); code != codeSpineGenesisRefused || !strings.Contains(log, "no BLS registry") {
		t.Fatalf("a genesis before the registry: %d %s", code, log)
	}
	if out, err := run("spine-genesis", "preflight", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "no BLS registry is in force") {
		t.Fatalf("preflight before the registry: %v\n%s", err, out)
	}
	if code, log, _ := submit(nodes[1], rotJSON(t, fx.registry(1, "ops-1", "ops-2"))); code != 0 {
		t.Fatalf("the registry: %d %s", code, log)
	}

	// 2. One admin's approval is not the quorum: the chain refuses it and the preflight says NO-GO. The second admin
	// signs; the tool preflights and commits it. Then the archive in sequence through the other nodes.
	if code, log, _ := submit(nodes[2], raw); code != codeSpineGenesisRefused || !strings.Contains(log, "Accumulate spine genesis") {
		t.Fatalf("a genesis one admin signed: %d %s", code, log)
	}
	if out, err := run("spine-genesis", "preflight", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "NO-GO") {
		t.Fatalf("preflight with one approval: %v\n%s", err, out)
	}
	if out, err := run("spine-genesis", "sign", "--tx", req, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"]); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	if out, err := run("spine-genesis", "preflight", "--tx", req, "--rpc", all); err != nil {
		t.Fatalf("preflight: %v\n%s", err, out)
	}
	out, err := run("spine-genesis", "submit", "--tx", req, "--rpc", all)
	m := regexp.MustCompile(`ACCEPTED at height (\d+)`).FindStringSubmatch(out)
	if err != nil || m == nil {
		t.Fatalf("submit: %v\n%s", err, out)
	}
	hg, _ := strconv.ParseInt(m[1], 10, 64)
	if out, err := run("spine-genesis", "preflight", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "is replaced only when") {
		t.Fatalf("preflight after the genesis: %v\n%s", err, out)
	}
	n := len(fx.records)
	last := hg
	for i, first := 0, 1; first <= n; i, first = i+1, first+maxSpineExtensionRecords {
		end := min(first+maxSpineExtensionRecords-1, n)
		code, log, h := submit(nodes[1+i%3], fx.extend(t, first, end))
		if code != 0 {
			t.Fatalf("major blocks %d-%d: %d %s", first, end, code, log)
		}
		last = h
	}
	if code, log, _ := submit(nodes[0], fx.extend(t, n-4, n)); code != codeSpineExtendStale {
		t.Fatalf("a stale extension: %d %s", code, log)
	}
	tick(nodes[0], 2)
	everyNode("every node to commit past the spine", last+2)

	// 3. One spine, one app hash, v13 everywhere; the history check every node runs, and the operator's.
	var want *ledger.AccumulateSpineLog
	for _, nd := range nodes {
		l, err := ledger.NewLedgerStore(nd.kv).LoadAccumulateSpine()
		if err != nil || l.Genesis == nil || l.Genesis.Height != hg || len(l.Checkpoints) != n {
			t.Fatalf("%s's spine: (%d checkpoints, %v)", nd.name, len(l.Checkpoints), err)
		}
		if want == nil {
			want = l
		} else if rotJSONString(t, l) != rotJSONString(t, want) {
			t.Fatalf("%s's spine log differs from %s's", nd.name, nodes[0].name)
		}
		if got := checkLiveHistory(t, nd); got != 1 {
			t.Fatalf("%s: %d accepted registries found in their records, want 1", nd.name, got)
		}
	}
	out, err = run("history-check", "--rules", "13", "--rpc", nodes[3].rpcURL)
	if err != nil || !strings.Contains(out, "v13 continues this chain's history exactly") ||
		!strings.Contains(out, AccumulateSpineExtendKind) || !strings.Contains(out, AccumulateSpineGenesisKind) {
		t.Fatalf("history-check --rules 13: %v\n%s", err, out)
	}
	sameHashV13(t, nodes)

	// 4. The whole fleet restarts and carries on, its state v13's.
	for _, nd := range nodes {
		nd.stop(t)
	}
	for _, nd := range nodes {
		nd.start(t, genesis)
	}
	restartedAt := nodes[0].height()
	waitNetwork(t, "the restarted fleet to connect", 90*time.Second, func() bool {
		for _, nd := range nodes {
			if nd.node.Switch().Peers().Size() < size-1 {
				return false
			}
		}
		return true
	})
	tick(nodes[0], 3)
	everyNode("the restarted fleet to commit", restartedAt+3)
	for _, nd := range nodes {
		res, err := nd.app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/accumulate_spine"})
		if err != nil || res.Code != 0 || string(res.Value) != rotJSONString(t, want) {
			t.Fatalf("%s answers another spine after the restart (%v)", nd.name, err)
		}
	}
	sameHashV13(t, nodes)
}

func rotJSONString(t *testing.T, v any) string { return string(rotJSON(t, v)) }

// sameHashV13 waits for every node to reach one height, then requires one app hash, the binary's rules version reported
// and the committed state stamped v13.
func sameHashV13(t *testing.T, nodes []*rehearsalNode) {
	t.Helper()
	waitNetwork(t, "every node at one height", 30*time.Second, func() bool {
		top := nodes[0].height()
		for _, nd := range nodes {
			if nd.height() != top {
				return false
			}
		}
		return true
	})
	var first string
	for i, nd := range nodes {
		info, err := nd.client.ABCIInfo(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.Response.AppVersion != executionRulesV13 {
			t.Fatalf("%s reports app version %d", nd.name, info.Response.AppVersion)
		}
		st, err := ledger.NewLedgerStore(nd.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != executionRulesV13 {
			t.Fatalf("%s: state stamped (%+v, %v); want v13", nd.name, st, err)
		}
		got := hex.EncodeToString(info.Response.LastBlockAppHash)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s's app hash %s is not %s's %s", nd.name, got, nodes[0].name, first)
		}
	}
}
