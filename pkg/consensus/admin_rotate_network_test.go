package consensus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The rules v12 admin rotation REHEARSED on a real CometBFT network of four in-process validators running this
// ValidatorApp, driven by the operator's own tool (`validator-rotate admin-rotate`, built from this tree) over each
// node's CometBFT RPC - the owner's procedure, with throwaway keys. Sealed at genesis with ops-1..3 (threshold 2):
//
//  1. keygen makes two throwaway admin keys; request reads the chain, the next sequence and the set in force from a
//     node; every new key proves possession; ops-1 and ops-2 approve offline; preflight checks all four nodes; submit
//     commits it and confirms the record - every node records it at the same height;
//  2. from the next height a BLS registry and a policy update signed by the OLD admins are refused and the same signed
//     by the NEW admins are accepted, on every node;
//  3. the rotation again (in other bytes) is refused by its sequence;
//  4. the new set rotates again (sequence 2) through the tool, after which the second set is refused in turn;
//  5. history-check --rules 12 passes on the live chain;
//  6. restarted as a whole fleet, the network comes back on one chain, stamped v12, every node answering the last set.
func TestAdminRotationRehearsalOnALiveNetwork(t *testing.T) {
	f := newRegistryFixture(t)
	var adminEnv []string
	for _, id := range []string{"ops-1", "ops-2", "ops-3"} {
		adminEnv = append(adminEnv, id+":"+f.policy.AdminKeys[id])
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
	run := func(args ...string) (string, error) {
		t.Helper()
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
	// The sealed admins' secrets, in files as the owner keeps them.
	secret := map[string]string{}
	for i, id := range []string{"ops-1", "ops-2", "ops-3"} {
		p := filepath.Join(dir, id+".seed")
		if err := os.WriteFile(p, []byte(hex.EncodeToString(bytes.Repeat([]byte{byte(0xA1 + i)}, 32))+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		secret[id] = "@" + p
	}

	const size = 4
	nodes, genesis, _, tick := startRehearsalNetworkWith(t, f.rotationFixture, size, true)
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
	accepted := regexp.MustCompile(`ACCEPTED at height (\d+)`)
	pubOfSeedFile := regexp.MustCompile(`admin public key \(hex\): ([0-9a-f]{64})`)

	// rotate runs the owner's procedure: keygen for each new key named in fresh, the request from node 0, possession by
	// every new key, approval by approvers, preflight, submit. It returns the height and the new set's private keys.
	rotate := func(newSet map[string]string, fresh []string, holders map[string]string, approvers ...string) (int64, map[string]ed25519.PrivateKey) {
		t.Helper()
		keys := map[string]ed25519.PrivateKey{}
		for _, id := range fresh {
			p := filepath.Join(dir, id+".seed")
			out := mustRun("admin-rotate", "keygen", "--out", p)
			m := pubOfSeedFile.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("keygen printed no public key: %s", out)
			}
			raw, _ := os.ReadFile(p)
			if strings.Contains(out, strings.TrimSpace(string(raw))) {
				t.Fatal("keygen printed the secret")
			}
			seed, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
			keys[id] = ed25519.NewKeyFromSeed(seed)
			newSet[id] = m[1]
			holders[id] = "@" + p
		}
		setFile := filepath.Join(dir, "new-set-"+strings.Join(fresh, "-")+".json")
		b, _ := json.Marshal(map[string]any{"admin_keys": newSet, "threshold": 2})
		if err := os.WriteFile(setFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
		req := filepath.Join(dir, "req-"+strings.Join(fresh, "-")+".json")
		mustRun("admin-rotate", "request", "--rpc", rpcs[0], "--new-set", setFile, "--out", req)
		for id := range newSet {
			mustRun("admin-rotate", "possess", "--tx", req, "--key-id", id, "--secret", holders[id])
		}
		mustRun("admin-rotate", "sign", "--tx", req, "--admin-key-id", approvers[0], "--admin-secret", holders[approvers[0]])
		if out, err := run("admin-rotate", "preflight", "--tx", req, "--rpc", all); err == nil || !strings.Contains(out, "NO-GO") {
			t.Fatalf("preflight with one approval: %v\n%s", err, out)
		}
		mustRun("admin-rotate", "sign", "--tx", req, "--admin-key-id", approvers[1], "--admin-secret", holders[approvers[1]])
		mustRun("admin-rotate", "preflight", "--tx", req, "--rpc", all)
		out := mustRun("admin-rotate", "submit", "--tx", req, "--rpc", all)
		m := accepted.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("submit: %s", out)
		}
		h, _ := strconv.ParseInt(m[1], 10, 64)
		return h, keys
	}

	// 1. The first rotation: ops-1, ops-2 approve {new-a, new-b, ops-3}, threshold 2.
	holders := map[string]string{"ops-1": secret["ops-1"], "ops-2": secret["ops-2"], "ops-3": secret["ops-3"]}
	setB := map[string]string{"ops-3": f.policy.AdminKeys["ops-3"]}
	h, newKeys := rotate(setB, []string{"new-a", "new-b"}, holders, "ops-1", "ops-2")
	tick(nodes[0], 2)
	everyNode("every node to commit past the rotation", h+2)
	firstID := ""
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadEntitlementPolicy()
		if err != nil || len(st.AdminReseals) != 1 || st.AdminReseals[0].Height != h || st.AdminReseals[0].Kind != AdminRotateKind ||
			st.AdminReseals[0].Sequence != 1 {
			t.Fatalf("%s's admin record: (%+v, %v)", n.name, st, err)
		}
		if keys, th := AdminSetAt(st, h+1); !sameKeysAndThreshold(keys, th, setB, 2) {
			t.Fatalf("%s: the set in force after the rotation is not the new one", n.name)
		}
		if firstID == "" {
			firstID = st.AdminReseals[0].ID
		}
	}

	// 2. The old admins are refused; the new ones authorise - a registry and a policy update.
	byNew := func(tx *BLSRegistryTx, keys map[string]ed25519.PrivateKey, ids ...string) []byte {
		tx.Signatures = nil
		for _, id := range ids {
			tx.Signatures = append(tx.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], tx.SigningBytes()))})
		}
		return rotJSON(t, tx)
	}
	if code, log, _ := submit(nodes[1], rotJSON(t, f.registry(1, "ops-1", "ops-2"))); code != codeBLSRegistryRefused {
		t.Fatalf("a registry signed by the old admins: %d %s", code, log)
	}
	code, log, hr := submit(nodes[2], byNew(f.registry(1), newKeys, "new-a", "new-b"))
	if code != 0 {
		t.Fatalf("a registry signed by the new admins: %d %s", code, log)
	}
	policyUpdate := func(keys map[string]ed25519.PrivateKey, ids ...string) []byte {
		u := &PolicyUpdateTx{Kind: PolicyUpdateKind, ChainID: rotChain, Mode: string(EntitlementOff),
			ActivationUnix: time.Now().Unix() + 3600, Version: 2} // the genesis seal is version 1
		for _, id := range ids {
			u.Signatures = append(u.Signatures, PolicySignature{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(keys[id], u.SigningBytes()))})
		}
		return rotJSON(t, u)
	}
	if code, log, _ := submit(nodes[3], policyUpdate(f.admins, "ops-1", "ops-2")); code != 5 {
		t.Fatalf("a policy update signed by the old admins: %d %s", code, log)
	}
	if code, log, _ := submit(nodes[0], policyUpdate(newKeys, "new-a", "new-b")); code != 0 {
		t.Fatalf("a policy update signed by the new admins: %d %s", code, log)
	}
	tick(nodes[0], 2)
	everyNode("every node to commit past the registry", hr+2)
	for _, n := range nodes {
		l, err := ledger.NewLedgerStore(n.kv).LoadBLSRegistry()
		if err != nil || len(l.Versions) != 1 || l.Versions[0].Height != hr {
			t.Fatalf("%s's registry log: (%+v, %v)", n.name, l, err)
		}
	}

	// 3. The first rotation again, in other bytes (the identical bytes stop at CometBFT's cache): refused by sequence.
	raw, err := os.ReadFile(filepath.Join(dir, "req-new-a-new-b.json"))
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	if code, log, _ := submit(nodes[1], append(compact.Bytes(), ' ')); code != codeAdminRotateRefused || !strings.Contains(log, "sequence 1 is not the next") {
		t.Fatalf("the rotation replayed: %d %s", code, log)
	}

	// 4. The new set rotates again, through the tool: new-a and ops-3 approve {c-1, c-2, c-3}.
	h2, cKeys := rotate(map[string]string{}, []string{"c-1", "c-2", "c-3"}, holders, "new-a", "ops-3")
	tick(nodes[0], 2)
	everyNode("every node to commit past the second rotation", h2+2)
	if code, log, _ := submit(nodes[2], byNew(f.registry(2), newKeys, "new-a", "new-b")); code != codeBLSRegistryRefused {
		t.Fatalf("a registry signed by the second set after it was rotated out: %d %s", code, log)
	}
	if code, log, _ := submit(nodes[3], byNew(f.registry(2), cKeys, "c-1", "c-3")); code != 0 {
		t.Fatalf("a registry signed by the third set: %d %s", code, log)
	}

	// 5. The live chain's history, as v12 judges it.
	out := mustRun("history-check", "--rules", "12", "--rpc", rpcs[0])
	if !strings.Contains(out, "v12 continues this chain's history exactly") || !strings.Contains(out, AdminRotateKind) {
		t.Fatalf("history-check: %s", out)
	}
	status := mustRun("admin-rotate", "status", "--rpc", rpcs[3])
	if !strings.Contains(status, "next admin rotation carries sequence 3") || !strings.Contains(status, "c-2") {
		t.Fatalf("status: %s", status)
	}

	// Every node's whole committed chain passes the record check v12 runs at start: two admin rotations and two
	// registries accepted, each found in its record.
	waitNetwork(t, "every node to commit the last registry", 30*time.Second, func() bool {
		for _, n := range nodes {
			if n.height() < nodes[0].height() {
				return false
			}
		}
		return true
	})
	for _, n := range nodes {
		if got := checkLiveHistory(t, n); got != 4 {
			t.Fatalf("%s: %d accepted registries and admin rotations found in their records, want 4", n.name, got)
		}
	}

	// 6. The whole fleet restarts and carries on, its state v12's, every node answering the third set.
	for _, n := range nodes {
		n.stop(t)
	}
	for _, n := range nodes {
		n.start(t, genesis)
	}
	restartedAt := nodes[0].height()
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
	cSet := map[string]string{}
	for id, k := range cKeys {
		cSet[id] = hex.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	for _, n := range nodes {
		st, err := ledger.NewLedgerStore(n.kv).LoadABCIState()
		if err != nil || st.ExecutionRulesVersion != executionRulesV12 {
			t.Fatalf("%s: state after the rotation is stamped (%+v, %v); want v12", n.name, st, err)
		}
		res, err := n.app.Query(context.Background(), &abcitypes.RequestQuery{Path: "/certen/admin_set"})
		if err != nil || res.Code != 0 {
			t.Fatalf("%s: admin set query (%+v, %v)", n.name, res, err)
		}
		var v AdminSetView
		if err := json.Unmarshal(res.Value, &v); err != nil {
			t.Fatal(err)
		}
		if v.InForceSetID != AdminSetID(cSet, 2) || v.NextSequence != 3 || len(v.Changes) != 2 || v.Changes[0].ID != firstID {
			t.Fatalf("%s answers %+v", n.name, v)
		}
	}
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
		if err != nil {
			t.Fatal(err)
		}
		if info.Response.AppVersion != CurrentExecutionRulesVersion {
			t.Fatalf("%s reports app version %d", n.name, info.Response.AppVersion)
		}
		got := hex.EncodeToString(info.Response.LastBlockAppHash)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("%s's app hash %s is not %s's %s", n.name, got, nodes[0].name, first)
		}
	}
}

// checkLiveHistory runs the history check every v12 node runs at start over a rehearsal node's whole committed chain -
// its block store, the result codes CometBFT stored, and the node's committed records - and returns how many accepted
// registries, re-seals and admin rotations it found in their records. Nothing may be refused or left unread.
func checkLiveHistory(t *testing.T, n *rehearsalNode) int {
	t.Helper()
	store := ledger.NewLedgerStore(n.kv)
	policy, err := store.LoadEntitlementPolicy()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := store.LoadBLSRegistry()
	if err != nil {
		t.Fatal(err)
	}
	spine, err := store.LoadAccumulateSpine()
	if err != nil {
		t.Fatal(err)
	}
	records := &CommittedRecords{Policy: policy, Registry: registry, Spine: spine}
	hist := storeHistory{blocks: n.node.BlockStore(), results: sm.NewStore(n.dbs["state"], sm.StoreOptions{})}
	// A block is in the block store just before CometBFT stores its results: wait until the newest one has them.
	waitNetwork(t, n.name+"'s newest block to have its results", 30*time.Second, func() bool {
		_, err := hist.ResultCodes(hist.Height())
		return err == nil
	})
	accepted := 0
	for h := hist.Base(); h <= hist.Height(); h++ {
		txs, _, err := hist.Block(h)
		if err != nil {
			t.Fatal(err)
		}
		codes, err := hist.ResultCodes(h)
		if err != nil {
			t.Fatalf("%s: results of block %d: %v", n.name, h, err)
		}
		v, u, err := CommittedBlockViolations(h, txs, codes, records)
		if err != nil || len(v) != 0 || len(u) != 0 {
			t.Fatalf("%s: block %d: %v %v %v", n.name, h, v, u, err)
		}
		for i, tx := range txs {
			_, isRegistry := DecodeBLSRegistry(tx)
			_, isReseal := DecodeAdminReseal(tx)
			_, isRotation := DecodeAdminRotate(tx)
			if codes[i] == 0 && (isRegistry || isReseal || isRotation) {
				accepted++
			}
		}
	}
	return accepted
}
