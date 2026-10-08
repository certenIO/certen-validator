package consensus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The rules v13 -> v14 upgrade REHEARSED on a real CometBFT network of four in-process validators running this
// ValidatorApp, driven by the operator's own tool (`validator-rotate`, built from this tree) over each node's CometBFT
// RPC, with throwaway admin keys (sealed at genesis: ops-1..3, threshold 2). It runs twice:
//
//   - TestRulesV14UpgradeAndAnchorSetRehearsalOnALiveNetwork starts from a v13 chain WITH a committed spine - the
//     production chain's condition: the BLS registry, then the Accumulate spine genesis, so the state is stamped v13.
//   - TestRulesV14UpgradeFromAV13ChainWithoutASpine starts from a v13 binary's chain that never committed a spine
//     transaction (stamped v12), which is where a ValidatorBlock can still be built without an intent certificate - so
//     it also exercises the anchor rule in FinalizeBlock on every node, by a proposer that skips the mempool.
//
// The steps:
//
//  1. The chain as the v13 binary left it: a refused admin rotation (a verdict only v12 reaches, so the state is stamped
//     v12), and a ValidatorBlock naming a retired anchor ACCEPTED - nothing in consensus checked anchors. With a spine:
//     the registry and the spine genesis through the tool, so the state is stamped v13.
//  2. The upgrade: every node's ledger is put back exactly as the v13 binary wrote it (its history-check watermark is
//     v13's, keyed `v13:checks3`, and none of v14's), the whole fleet stops, every node runs the boot history check the
//     v14 binary runs before CometBFT's handshake (IndexCommittedHistory over its own block and state stores) - it
//     re-checks the whole chain under history-check v4 - and the fleet starts again: app version 14, state still stamped
//     as it was, the same app hash on every node. `history-check --rules 14` passes on the live chain; `anchor-set
//     status` says no anchor set is in force.
//  3. The anchor set, through the tool: propose (first admin), a NO-GO preflight with one approval, sign (second
//     admin), a GO preflight against every node and every chain (fake JSON-RPC endpoints answering eth_chainId and
//     eth_getCode), submit - every node records it at the same height, and the state is stamped v14.
//  4. From the next height: a ValidatorBlock naming a retired anchor is refused at the mempool (CheckTx, code 17); without
//     a spine, one a proposer that skips admission and the mempool puts straight into its block is refused by EVERY node's
//     FinalizeBlock (code 17, ANCHOR_NOT_COMMITTED); one naming the committed anchors is accepted.
//  5. `history-check --rules 14` passes again, with the anchor set found in its record; restarted as a whole fleet, the
//     network comes back on one chain, stamped v14, app version 14, every node answering the anchor set.
func TestRulesV14UpgradeAndAnchorSetRehearsalOnALiveNetwork(t *testing.T) {
	anchorSetRehearsal(t, true)
}

func TestRulesV14UpgradeFromAV13ChainWithoutASpine(t *testing.T) {
	anchorSetRehearsal(t, false)
}

func anchorSetRehearsal(t *testing.T, spine bool) {
	f := newRotationFixture()
	var fx *spineFixture
	if spine {
		fx = newSpineFixture(t)
		f = fx.rotationFixture
	}
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
		return anchoredBlockJSON(t, fmt.Sprintf("op-net-%d", op), "validator-1", targets, nil)
	}

	// 1. The chain as the v13 binary left it.
	refusedRotation := adminRotation(1, genesisSetID(f), setB(f), 2).signedBy(f.admins, "ops-1")
	if code, log, _ := submit(nodes[0], rotJSON(t, refusedRotation)); code != codeAdminRotateRefused {
		t.Fatalf("an admin rotation with one approval: %d %s", code, log)
	}
	if code, log, _ := submit(nodes[1], vbWith(target(84532, retired))); code != 0 {
		t.Fatalf("v13 verdict: a block naming a retired anchor, with no anchor set: %d %s", code, log)
	}
	wantStamp := uint64(executionRulesV12)
	if spine {
		// The production chain's condition: the BLS registry, then the Accumulate spine genesis, through the tool.
		if code, log, _ := submit(nodes[1], rotJSON(t, fx.registry(1, "ops-1", "ops-2"))); code != 0 {
			t.Fatalf("the registry: %d %s", code, log)
		}
		req := filepath.Join(dir, "spine-genesis.json")
		mustRun("spine-genesis", "propose", "--chain-id", rotChain, "--evidence", "../proof/testdata/incarnation/kermit.json",
			"--incarnation", "0x"+kermitIncarnationHex, "--admin-key-id", "ops-1", "--admin-secret", secret["ops-1"], "--out", req)
		mustRun("spine-genesis", "sign", "--tx", req, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"])
		if out := mustRun("spine-genesis", "submit", "--tx", req, "--rpc", all); !strings.Contains(out, "ACCEPTED at height") {
			t.Fatalf("the spine genesis: %s", out)
		}
		wantStamp = executionRulesV13
	}
	tick(nodes[0], 2)
	top := nodes[0].height()
	everyNode("every node to commit the v13 history", top)

	// 2. The upgrade. Every node's ledger as the v13 binary wrote it: its history-check watermark under v13's key, and
	// none of v14's. Then the whole fleet stops, every node runs v14's boot history check, and the fleet starts again.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != wantStamp {
			t.Fatalf("%s: before the upgrade the state is stamped (%+v, %v), want v%d", n.name, st, err, wantStamp)
		}
		at, err := ledger.NewLedgerStore(n.kv).KindsCheckedThrough(executionRulesV14, CommittedHistoryCheckVersion)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.kv.Set([]byte(fmt.Sprintf("abci:kinds_checked_through:v14:checks%d", CommittedHistoryCheckVersion)), nil); err != nil {
			t.Fatal(err)
		}
		v13 := make([]byte, 8)
		for i := 0; i < 8; i++ {
			v13[7-i] = byte(at >> (8 * i))
		}
		if err := n.kv.Set([]byte("abci:kinds_checked_through:v13:checks3"), v13); err != nil {
			t.Fatal(err)
		}
		// The v14 binary's boot check, before the handshake, over this node's own stores.
		app := NewValidatorApp(ledger.NewLedgerStore(n.kv), "validator-chain-"+n.name)
		app.logger = log.New(io.Discard, "", 0)
		if err := app.SetGenesis(genesis); err != nil {
			t.Fatal(err)
		}
		if err := app.IndexCommittedHistory(storeHistory{blocks: store.NewBlockStore(n.dbs["blockstore"]),
			results: sm.NewStore(n.dbs["state"], sm.StoreOptions{})}); err != nil {
			t.Fatalf("%s: the v14 boot history check refused the v13 chain: %v", n.name, err)
		}
		if through, err := app.ledgerStore.KindsCheckedThrough(executionRulesV14, CommittedHistoryCheckVersion); err != nil || through != at {
			t.Fatalf("%s: the boot check covered heights through %d (%v), want %d", n.name, through, err, at)
		}
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt := nodes[0].height()
	waitNetwork(t, "the upgraded fleet to connect", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.node.Switch().Peers().Size() < size-1 {
				return false
			}
		}
		return true
	})
	tick(nodes[0], 2)
	everyNode("the upgraded fleet to commit", restartedAt+2)
	for _, n := range nodes {
		info, err := n.client.ABCIInfo(context.Background())
		if err != nil || info.Response.AppVersion != executionRulesV14 {
			t.Fatalf("%s: app version (%+v, %v), want 14", n.name, info, err)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != wantStamp {
			t.Fatalf("%s: with no anchor set the state is stamped v%d, want v%d (a rollback stays open)", n.name, st.ExecutionRulesVersion, wantStamp)
		}
	}
	out := mustRun("history-check", "--rules", "14", "--rpc", rpcs[0])
	if !strings.Contains(out, "v14 continues this chain's history exactly") {
		t.Fatalf("history-check: %s", out)
	}
	if out := mustRun("anchor-set", "status", "--rpc", rpcs[2]); !strings.Contains(out, "NO anchor set is in force") ||
		!strings.Contains(out, "next anchor set carries version 1") {
		t.Fatalf("status: %s", out)
	}
	if !spine {
		// With a registry and a spine every ValidatorBlock needs an intent certificate, so only the chain without one can
		// show an uncertified block still decided the v13 way.
		if code, log, _ := submit(nodes[2], vbWith(target(84532, retired))); code != 0 {
			t.Fatalf("before the anchor set the v14 binary decides as v13 did: %d %s", code, log)
		}
	}

	// 3. The anchor set, through the tool.
	eth := fakeEthChains(t, map[int64]string{11155111: liveAnchorBaseAndSepolia, 84532: liveAnchorBaseAndSepolia, 421614: liveAnchorArbitrum})
	set := filepath.Join(dir, "anchor-set.json")
	anchors := "11155111=" + liveAnchorBaseAndSepolia + ",84532=" + liveAnchorBaseAndSepolia + ",421614=" + liveAnchorArbitrum
	mustRun("anchor-set", "propose", "--rpc", rpcs[0], "--anchor", anchors, "--admin-key-id", "ops-1",
		"--admin-secret", secret["ops-1"], "--out", set)
	if out, err := run("anchor-set", "preflight", "--tx", set, "--rpc", all, "--eth-rpc", eth); err == nil || !strings.Contains(out, "NO-GO") {
		t.Fatalf("preflight with one approval: %v\n%s", err, out)
	}
	mustRun("anchor-set", "sign", "--tx", set, "--admin-key-id", "ops-2", "--admin-secret", secret["ops-2"])
	wrongChain := fakeEthChains(t, map[int64]string{11155111: liveAnchorArbitrum, 84532: liveAnchorBaseAndSepolia, 421614: liveAnchorArbitrum})
	if out, err := run("anchor-set", "preflight", "--tx", set, "--rpc", all, "--eth-rpc", wrongChain); err == nil ||
		!strings.Contains(out, "holds no code") {
		t.Fatalf("preflight with an anchor that is no contract on its chain: %v\n%s", err, out)
	}
	mustRun("anchor-set", "preflight", "--tx", set, "--rpc", all, "--eth-rpc", eth)
	out = mustRun("anchor-set", "submit", "--tx", set, "--rpc", all, "--eth-rpc", eth)
	m := regexp.MustCompile(`ACCEPTED at height (\d+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("submit: %s", out)
	}
	hs, _ := strconv.ParseInt(m[1], 10, 64)
	tick(nodes[0], 2)
	everyNode("every node to commit past the anchor set", hs+2)
	var setID string
	for _, n := range nodes {
		l, err := ledger.NewLedgerStore(n.kv).LoadAnchorSet()
		if err != nil || len(l.Versions) != 1 || l.Versions[0].Height != hs {
			t.Fatalf("%s's anchor set log: (%+v, %v)", n.name, l, err)
		}
		if setID == "" {
			setID = l.Versions[0].ID
		} else if l.Versions[0].ID != setID {
			t.Fatalf("%s records %s, another node %s", n.name, l.Versions[0].ID, setID)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != executionRulesV14 {
			t.Fatalf("%s: after the anchor set the state is stamped v%d", n.name, st.ExecutionRulesVersion)
		}
	}

	// 4. From the next height. The mempool refuses a retired anchor.
	if code, log, _ := submit(nodes[3], vbWith(target(84532, retired))); code != codeAnchorNotCommitted ||
		!strings.Contains(log, ReasonAnchorNotCommitted) {
		t.Fatalf("CheckTx after the anchor set: %d %s", code, log)
	}
	if !spine {
		// A proposer that skips admission and the mempool puts one straight into its block: every node's FinalizeBlock
		// refuses it. The fleet restarts with every node able to act as that proposer for exactly one block.
		injected := vbWith(target(421614, retired), target(84532, liveAnchorBaseAndSepolia))
		var armed atomic.Bool
		for _, n := range nodes {
			n.stop(t)
		}
		for _, n := range nodes {
			n.wrap = func(app *ValidatorApp) abcitypes.Application {
				return &injectingProposer{ValidatorApp: app, armed: &armed, tx: injected}
			}
			n.start(t, genesis)
		}
		waitNetwork(t, "the fleet to reconnect", 90*time.Second, func() bool {
			for _, n := range nodes {
				if n.node.Switch().Peers().Size() < size-1 {
					return false
				}
			}
			return true
		})
		armed.Store(true)
		before := nodes[0].height()
		tick(nodes[0], 2)
		everyNode("every node to commit the injected block", before+2)
		if armed.Load() {
			t.Fatal("no proposer included the injected block")
		}
		refusedAt := int64(0)
		upTo := before + 2 // every node has committed at least this far
		for _, n := range nodes {
			found := false
			for h := before + 1; h <= upTo; h++ {
				blk, err := n.client.Block(context.Background(), &h)
				if err != nil {
					t.Fatal(err)
				}
				// A block is in the block store just before CometBFT stores its results: wait for them.
				var res *coretypes.ResultBlockResults
				waitNetwork(t, fmt.Sprintf("%s's results of block %d", n.name, h), 30*time.Second, func() bool {
					res, err = n.client.BlockResults(context.Background(), &h)
					return err == nil
				})
				for i, tx := range blk.Block.Txs {
					if string(tx) != string(injected) {
						continue
					}
					found = true
					if r := res.TxsResults[i]; r.Code != codeAnchorNotCommitted || !strings.Contains(r.Log, "chain target 0 (chain 421614)") {
						t.Fatalf("%s: the injected block at height %d was decided %d %q", n.name, h, r.Code, r.Log)
					}
					if refusedAt == 0 {
						refusedAt = h
					} else if refusedAt != h {
						t.Fatalf("%s holds the injected block at %d, another node at %d", n.name, h, refusedAt)
					}
				}
			}
			if !found {
				t.Fatalf("%s holds no injected block", n.name)
			}
		}
		if code, log, _ := submit(nodes[1], vbWith(target(84532, liveAnchorBaseAndSepolia), target(421614, liveAnchorArbitrum),
			target(11155111, liveAnchorBaseAndSepolia))); code != 0 {
			t.Fatalf("a block naming the committed anchors: %d %s", code, log)
		}
	}

	// 5. The live chain as v14 judges it, and a whole-fleet restart.
	out = mustRun("history-check", "--rules", "14", "--rpc", rpcs[1])
	if !strings.Contains(out, "v14 continues this chain's history exactly") || !strings.Contains(out, AnchorSetKind) {
		t.Fatalf("history-check after the anchor set: %s", out)
	}
	if out := mustRun("anchor-set", "status", "--rpc", rpcs[3]); !strings.Contains(out, "anchor set v1 in force") ||
		!strings.Contains(out, liveAnchorArbitrum) {
		t.Fatalf("status: %s", out)
	}
	for _, n := range nodes {
		n.stop(t)
		n.wrap = nil
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt = nodes[0].height()
	waitNetwork(t, "the restarted fleet to connect", 90*time.Second, func() bool {
		for _, n := range nodes {
			if n.node.Switch().Peers().Size() < size-1 {
				return false
			}
		}
		return true
	})
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
		if err != nil || info.Response.AppVersion != executionRulesV14 {
			t.Fatalf("%s: app version (%+v, %v)", n.name, info, err)
		}
		if st, _ := ledger.NewLedgerStore(n.kv).LoadABCIState(); st.ExecutionRulesVersion != executionRulesV14 {
			t.Fatalf("%s: stamped v%d after the restart", n.name, st.ExecutionRulesVersion)
		}
		got := hex.EncodeToString(info.Response.LastBlockAppHash)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s's app hash %s is not %s's %s", n.name, got, nodes[0].name, first)
		}
		q, err := n.app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/anchor_set"})
		if err != nil || q.Code != 0 {
			t.Fatalf("%s: anchor set query (%+v, %v)", n.name, q, err)
		}
		var l ledger.AnchorSetLog
		if err := json.Unmarshal(q.Value, &l); err != nil || len(l.Versions) != 1 || l.Versions[0].ID != setID {
			t.Fatalf("%s answers %s", n.name, q.Value)
		}
	}
}

// injectingProposer is a proposer that skips admission and the mempool: while armed, the first block it proposes
// carries tx. Every verdict is still its ValidatorApp's.
type injectingProposer struct {
	*ValidatorApp
	armed *atomic.Bool
	tx    []byte
}

func (p *injectingProposer) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	resp, err := p.ValidatorApp.PrepareProposal(ctx, req)
	if err != nil || !p.armed.CompareAndSwap(true, false) {
		return resp, err
	}
	resp.Txs = append([][]byte{p.tx}, resp.Txs...)
	return resp, nil
}

// fakeEthChains serves one JSON-RPC endpoint per chain answering eth_chainId with the chain and eth_getCode with code at
// exactly the address given for it, and returns the --eth-rpc flag naming them.
func fakeEthChains(t *testing.T, anchorOf map[int64]string) string {
	t.Helper()
	var parts []string
	for chainID, anchor := range anchorOf {
		chainID, anchor := chainID, anchor
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			var result string
			switch req.Method {
			case "eth_chainId":
				result = "0x" + strconv.FormatInt(chainID, 16)
			case "eth_getCode":
				var addr string
				_ = json.Unmarshal(req.Params[0], &addr)
				result = "0x"
				if strings.EqualFold(addr, anchor) {
					result = "0x6080604052"
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		}))
		t.Cleanup(srv.Close)
		parts = append(parts, fmt.Sprintf("%d=%s", chainID, srv.URL))
	}
	return strings.Join(parts, ",")
}
