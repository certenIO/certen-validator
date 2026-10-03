package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// fakeAdminNode is one validator's RPC for the admin-rotate tests: its rules version, chain, height, admin record,
// and what broadcast_tx_commit answers (recording the rotation it commits, as the chain does).
type fakeAdminNode struct {
	mu         sync.Mutex
	appVersion string
	chainID    string
	height     int64
	policy     *ledger.EntitlementPolicyState
	registry   *ledger.BLSRegistryLog // /certen/bls_registry; nil serves an empty log
	// noRegistryQuery models a node of the first v12 release (f15ffe5), which serves /certen/admin_set but not
	// /certen/bls_registry.
	noRegistryQuery bool
	validators      int
	reply           string // broadcast_tx_commit's result; "" = accept at height+1 and record the rotation
	broadcasts      int
	blocks          map[int64][][]byte
	codes           map[int64][]uint32
}

func (n *fakeAdminNode) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string            `json:"method"`
			Params map[string]string `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		write := func(v any) {
			b, _ := json.Marshal(map[string]any{"result": v})
			_, _ = w.Write(b)
		}
		switch req.Method {
		case "abci_info":
			write(map[string]any{"response": map[string]string{"app_version": n.appVersion}})
		case "status":
			write(map[string]any{"node_info": map[string]string{"network": n.chainID},
				"sync_info": map[string]string{"latest_block_height": fmt.Sprint(n.height), "earliest_block_height": "1"}})
		case "validators":
			var vals []map[string]any
			for i := 0; i < n.validators; i++ {
				vals = append(vals, map[string]any{"pub_key": map[string]string{"type": "tendermint/PubKeyEd25519",
					"value": base64.StdEncoding.EncodeToString(pubOf(byte(0x20 + i)))}, "voting_power": "10"})
			}
			write(map[string]any{"validators": vals})
		case "abci_query":
			var value []byte
			switch req.Params["path"] {
			case "/certen/bls_registry":
				if n.appVersion < "12" || n.noRegistryQuery {
					write(map[string]any{"response": map[string]any{"code": 2, "log": "unknown query path: /certen/bls_registry"}})
					return
				}
				l := n.registry
				if l == nil {
					l = &ledger.BLSRegistryLog{}
				}
				value, _ = json.Marshal(l)
			case "/certen/validator_rotations":
				value, _ = json.Marshal(ledger.ValidatorRotationLog{})
			case "/certen/admin_set":
				if n.appVersion < "12" {
					write(map[string]any{"response": map[string]any{"code": 2, "log": "unknown query path: /certen/admin_set"}})
					return
				}
				value, _ = json.Marshal(consensus.NewAdminSetView(n.policy, n.height))
			}
			write(map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(value)}})
		case "broadcast_tx_commit":
			n.broadcasts++
			if n.reply != "" {
				_, _ = w.Write([]byte(n.reply))
				return
			}
			raw, _ := base64.StdEncoding.DecodeString(req.Params["tx"])
			tx, ok := consensus.DecodeAdminRotate(raw)
			if !ok {
				t.Errorf("broadcast a non-rotation: %s", raw)
				return
			}
			n.height++
			next := *n.policy
			next.AdminReseals = append(append([]ledger.AdminReseal(nil), n.policy.AdminReseals...), ledger.AdminReseal{Height: n.height,
				ID: tx.RotationID(), Keys: tx.NewAdminKeys, Threshold: tx.NewThreshold, Kind: consensus.AdminRotateKind, Sequence: tx.Sequence})
			n.policy = &next
			write(map[string]any{"check_tx": map[string]any{"code": 0}, "tx_result": map[string]any{"code": 0}, "height": fmt.Sprint(n.height)})
		case "block":
			var txs []string
			for _, tx := range n.blocks[parseHeight(req.Params["height"])] {
				txs = append(txs, base64.StdEncoding.EncodeToString(tx))
			}
			write(map[string]any{"block": map[string]any{"data": map[string]any{"txs": txs}}})
		case "block_results":
			var rs []map[string]any
			for _, c := range n.codes[parseHeight(req.Params["height"])] {
				rs = append(rs, map[string]any{"code": c})
			}
			write(map[string]any{"txs_results": rs})
		default:
			t.Errorf("method %s", req.Method)
		}
	}))
}

func parseHeight(s string) int64 {
	var h int64
	fmt.Sscanf(s, "%d", &h)
	return h
}

// adminSeedFile writes an admin's seed to a file as the owner keeps it, and returns @path and the key.
func adminSeedFile(t *testing.T, dir, name string, b byte) (string, ed25519.PrivateKey) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed(b))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return "@" + p, ed25519.NewKeyFromSeed(seed(b))
}

// captureOutput runs fn and returns what it wrote to stdout and stderr.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := fn()
	w.Close()
	os.Stdout, os.Stderr = stdout, stderr
	return <-done, ferr
}

// The owner's procedure end to end against a fleet of fake nodes: keygen, request from the chain, possession by every
// new key, approvals offline, preflight, submit - and no secret is ever printed.
func TestTheAdminRotationProcedure(t *testing.T) {
	dir := t.TempDir()
	ops := map[string]string{}
	opsKeys := map[string]ed25519.PrivateKey{}
	policy := &ledger.EntitlementPolicyState{Mode: "off", AdminKeys: map[string]string{}, AdminThreshold: 2}
	for i, id := range []string{"ops-1", "ops-2", "ops-3"} {
		ops[id], opsKeys[id] = adminSeedFile(t, dir, id+".seed", byte(0xA1+i))
		policy.AdminKeys[id] = hex.EncodeToString(opsKeys[id].Public().(ed25519.PublicKey))
	}
	nodes := []*fakeAdminNode{}
	var rpcs []string
	for i := 0; i < 3; i++ {
		n := &fakeAdminNode{appVersion: "12", chainID: chain, height: 60, policy: policy, validators: 3}
		srv := n.serve(t)
		defer srv.Close()
		nodes = append(nodes, n)
		rpcs = append(rpcs, srv.URL)
	}
	c := http.DefaultClient

	// keygen: two new keys; the output names the public key and never the secret.
	newKeys := map[string]string{}
	for _, id := range []string{"new-a", "new-b"} {
		path := filepath.Join(dir, id+".seed")
		out, err := captureOutput(t, func() error { return adminRotate([]string{"keygen", "--out", path}, c) })
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		secret := strings.TrimSpace(string(raw))
		k, err := loadAdmin("@" + path)
		if err != nil {
			t.Fatal(err)
		}
		newKeys[id] = hex.EncodeToString(k.Public().(ed25519.PublicKey))
		if strings.Contains(out, secret) || !strings.Contains(out, newKeys[id]) {
			t.Fatalf("keygen output: %q", out)
		}
		if err := adminRotate([]string{"keygen", "--out", path}, c); err == nil {
			t.Fatal("keygen overwrote an existing secret")
		}
	}
	newKeys["ops-3"] = policy.AdminKeys["ops-3"]

	// request: from the chain; a threshold with no loss tolerance needs saying so.
	setFile := filepath.Join(dir, "new-set.json")
	write := func(keys map[string]string, threshold int) {
		b, _ := json.Marshal(newSetFile{AdminKeys: keys, Threshold: threshold})
		if err := os.WriteFile(setFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	req := filepath.Join(dir, "req.json")
	write(newKeys, 3)
	if err := adminRotate([]string{"request", "--rpc", rpcs[0], "--new-set", setFile, "--out", req}, c); err == nil ||
		!strings.Contains(err.Error(), "accept-no-loss-tolerance") {
		t.Fatalf("3 of 3 without saying so: %v", err)
	}
	write(newKeys, 1)
	if err := adminRotate([]string{"request", "--rpc", rpcs[0], "--new-set", setFile, "--out", req}, c); err == nil {
		t.Fatal("one key of three acting alone was requested")
	}
	write(newKeys, 2)
	if err := adminRotate([]string{"request", "--rpc", rpcs[0], "--new-set", setFile, "--out", req}, c); err != nil {
		t.Fatal(err)
	}
	tx, err := readAdminRotate(req)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Sequence != 1 || tx.CurrentSetID != consensus.AdminSetID(policy.AdminKeys, 2) || tx.ChainID != chain {
		t.Fatalf("request %+v", tx)
	}

	// possess: each new key's holder; the wrong secret is refused.
	if err := adminRotate([]string{"possess", "--tx", req, "--key-id", "new-a", "--secret", "@" + filepath.Join(dir, "new-b.seed")}, c); err == nil {
		t.Fatal("another key proved new-a's possession")
	}
	for id, secret := range map[string]string{"new-a": "@" + filepath.Join(dir, "new-a.seed"), "new-b": "@" + filepath.Join(dir, "new-b.seed"), "ops-3": ops["ops-3"]} {
		raw, _ := os.ReadFile(strings.TrimPrefix(secret, "@"))
		out, err := captureOutput(t, func() error {
			return adminRotate([]string{"possess", "--tx", req, "--key-id", id, "--secret", secret}, c)
		})
		if err != nil {
			t.Fatalf("possess %s: %v", id, err)
		}
		if strings.Contains(out, strings.TrimSpace(string(raw))) {
			t.Fatalf("possess printed %s's secret", id)
		}
	}
	if err := adminRotate([]string{"possess", "--tx", req, "--key-id", "new-a", "--secret", "@" + filepath.Join(dir, "new-a.seed")}, c); err == nil {
		t.Fatal("new-a proved possession twice")
	}

	// One approval: NO-GO, and nothing broadcast.
	out, err := captureOutput(t, func() error {
		return adminRotate([]string{"sign", "--tx", req, "--admin-key-id", "ops-1", "--admin-secret", ops["ops-1"]}, c)
	})
	if err != nil || strings.Contains(out, hex.EncodeToString(seed(0xA1))) || !strings.Contains(out, tx.ChainID) {
		t.Fatalf("sign: %v %q", err, out)
	}
	if err := adminRotate([]string{"sign", "--tx", req, "--admin-key-id", "ops-1", "--admin-secret", ops["ops-1"]}, c); err == nil {
		t.Fatal("ops-1 signed twice")
	}
	all := strings.Join(rpcs, ",")
	if err := adminRotate([]string{"preflight", "--tx", req, "--rpc", all}, c); err == nil || !strings.Contains(err.Error(), "NO-GO") {
		t.Fatalf("one approval of two: %v", err)
	}
	// Two approvals: GO.
	if err := adminRotate([]string{"sign", "--tx", req, "--admin-key-id", "ops-2", "--admin-secret", ops["ops-2"]}, c); err != nil {
		t.Fatal(err)
	}
	if err := adminRotate([]string{"preflight", "--tx", req, "--rpc", all}, c); err != nil {
		t.Fatalf("ready: %v", err)
	}
	// Not every validator, a node on v11, a node on another chain, a node disagreeing about the admins: NO-GO.
	if err := adminRotate([]string{"preflight", "--tx", req, "--rpc", rpcs[0] + "," + rpcs[1]}, c); err == nil {
		t.Fatal("two of three validators passed")
	}
	for name, mutate := range map[string]func(n *fakeAdminNode){
		"a node on v11":            func(n *fakeAdminNode) { n.appVersion = "11" },
		"a node on another chain":  func(n *fakeAdminNode) { n.chainID = "another-chain" },
		"a node with other admins": func(n *fakeAdminNode) { p := *n.policy; p.AdminThreshold = 3; n.policy = &p },
		"a node far behind":        func(n *fakeAdminNode) { n.height = 50 },
	} {
		appVersion, chainID, policy, height := nodes[2].appVersion, nodes[2].chainID, nodes[2].policy, nodes[2].height
		mutate(nodes[2])
		if err := adminRotate([]string{"submit", "--tx", req, "--rpc", all}, c); err == nil {
			t.Errorf("%s: submitted", name)
		}
		nodes[2].appVersion, nodes[2].chainID, nodes[2].policy, nodes[2].height = appVersion, chainID, policy, height
	}
	if err := adminRotate([]string{"submit", "--dry-run", "--tx", req, "--rpc", all}, c); err != nil || nodes[0].broadcasts != 0 {
		t.Fatalf("dry run: %v, %d broadcasts", err, nodes[0].broadcasts)
	}
	// A refusal is reported as one.
	nodes[0].reply = `{"result":{"check_tx":{"code":0},"tx_result":{"code":12,"log":"admin rotation refused: x"},"height":"61"}}`
	if err := adminRotate([]string{"submit", "--tx", req, "--rpc", all}, c); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a refusal: %v", err)
	}
	// Accepted, and confirmed in the node's record.
	nodes[0].reply = ""
	if err := adminRotate([]string{"submit", "--tx", req, "--rpc", all}, c); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if v := consensus.NewAdminSetView(nodes[0].policy, nodes[0].height); v.InForceSetID != tx.NewSetID() || v.NextSequence != 2 {
		t.Fatalf("after submit: %+v", v)
	}
}

// history-check --rules 12 judges the chain as a v12 node does before it starts.
func TestHistoryCheckForV12(t *testing.T) {
	rot := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":%q,"sequence":1}`, consensus.AdminRotateKind, chain))
	n := &fakeAdminNode{appVersion: "11", chainID: chain, height: 2, validators: 1,
		blocks: map[int64][][]byte{1: {[]byte(`{"validator_id":"v"}`)}, 2: {rot}},
		codes:  map[int64][]uint32{1: {0}, 2: {2}}}
	srv := n.serve(t)
	defer srv.Close()
	if err := historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()); err == nil {
		t.Fatal("an admin rotation v11 judged as a ValidatorBlock passed")
	}
	n.codes[2] = []uint32{12}
	if err := historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()); err != nil {
		t.Fatalf("history v12 decides as it was decided: %v", err)
	}
	if err := historyCheck([]string{"--rules", "10", "--rpc", srv.URL}, srv.Client()); err == nil {
		t.Fatal("an unknown --rules was accepted")
	}
}

// history-check --rules 12 finds a policy update accepted again in a later block from the blocks alone.
func TestHistoryCheckFindsAPolicyAcceptedAgain(t *testing.T) {
	update := []byte(fmt.Sprintf(`{"kind":%q,"chain_id":%q,"mode":"off","activation_unix":1800000700,"version":2}`, consensus.PolicyUpdateKind, chain))
	n := &fakeAdminNode{appVersion: "11", chainID: chain, height: 2, validators: 1,
		blocks: map[int64][][]byte{1: {update, update}, 2: {update}}, codes: map[int64][]uint32{1: {0, 0}, 2: {0}}}
	srv := n.serve(t)
	defer srv.Close()
	if err := historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()); err == nil {
		t.Fatal("a policy update accepted again a block later passed")
	}
	n.codes[2] = []uint32{5}
	if err := historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()); err != nil {
		t.Fatalf("refused a block later, and accepted twice within its own block: %v", err)
	}
}

// An accepted BLS registry with no record in the committed registry log is FOUND against a v12 node; with its record it
// passes; against a v11 node, which serves no records, it is listed as not read and the check exits incomplete (3) -
// never reported as checked.
func TestHistoryCheckRequiresTheRecordOfEveryAcceptance(t *testing.T) {
	reg := &consensus.BLSRegistryTx{Kind: consensus.BLSRegistryKind, ChainID: chain, Version: 1, ThresholdNumerator: 2,
		ThresholdDenominator: 3, AccumulateIncarnation: "0x" + strings.Repeat("ab", 32)}
	raw, _ := json.Marshal(reg)
	policy := &ledger.EntitlementPolicyState{Mode: "off", AdminKeys: map[string]string{"ops-1": strings.Repeat("11", 32)}, AdminThreshold: 1}
	n := &fakeAdminNode{appVersion: "12", chainID: chain, height: 1, validators: 1, policy: policy,
		blocks: map[int64][][]byte{1: {raw}}, codes: map[int64][]uint32{1: {0}}}
	srv := n.serve(t)
	defer srv.Close()
	out, err := captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if err == nil || !strings.Contains(out, "holds no record of it") {
		t.Fatalf("an accepted registry without its record: %v\n%s", err, out)
	}
	n.registry = &ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{{Version: 1, Height: 1, ID: reg.RegistryID()}}}
	out, err = captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if err != nil || !strings.Contains(out, "v12 continues this chain's history exactly") {
		t.Fatalf("an accepted registry with its record: %v\n%s", err, out)
	}
	n.appVersion = "11"
	out, err = captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if historyExit(err) != 3 || !strings.Contains(out, "RECORD NOT READ") || strings.Contains(out, "history exactly") {
		t.Fatalf("against a v11 node: %v\n%s", err, out)
	}
}

// historyExit is the exit code a history-check error carries (0 for none).
func historyExit(err error) int {
	if err == nil {
		return 0
	}
	var ce *checkExit
	if errors.As(err, &ce) {
		return ce.code
	}
	return 1
}

// A node of the first v12 release serves /certen/admin_set but not /certen/bls_registry. The check still runs:
// re-seals and admin rotations are judged against the admin record - a re-seal without its record is FOUND (exit 4) -
// every accepted registry is listed by name as RECORD NOT READ with the reason, the "exactly" line is withheld, and the
// tool exits 3: incomplete, nothing found wrong. Never 0, and never the failure exit.
func TestHistoryCheckAgainstAV12NodeWithoutTheRegistryQuery(t *testing.T) {
	reg := &consensus.BLSRegistryTx{Kind: consensus.BLSRegistryKind, ChainID: chain, Version: 1, ThresholdNumerator: 2,
		ThresholdDenominator: 3, AccumulateIncarnation: "0x" + strings.Repeat("ab", 32)}
	regRaw, _ := json.Marshal(reg)
	reseal := consensus.NewAdminResealTx(chain)
	resealRaw, _ := json.Marshal(reseal)
	policy := &ledger.EntitlementPolicyState{Mode: "off", AdminKeys: map[string]string{"ops-1": strings.Repeat("11", 32)}, AdminThreshold: 1,
		AdminReseals: []ledger.AdminReseal{{Height: 1, ID: reseal.ResealID(), Keys: reseal.AdminKeys, Threshold: reseal.AdminThreshold}}}
	n := &fakeAdminNode{appVersion: "12", chainID: chain, height: 2, validators: 1, policy: policy, noRegistryQuery: true,
		blocks: map[int64][][]byte{1: {resealRaw}, 2: {regRaw}}, codes: map[int64][]uint32{1: {0}, 2: {0}}}
	srv := n.serve(t)
	defer srv.Close()
	out, err := captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if historyExit(err) != 3 || !strings.Contains(out, "RECORD NOT READ") || !strings.Contains(out, "BLS registry (version 1)") ||
		!strings.Contains(out, "predates the registry query") || strings.Contains(out, "history exactly") || strings.Contains(out, "FOUND") {
		t.Fatalf("a v12 node without the registry query: exit %d (%v)\n%s", historyExit(err), err, out)
	}
	// The re-seal is still checked against the admin record: without its record it is FOUND, the failure exit.
	bare := *policy
	bare.AdminReseals = nil
	n.policy = &bare
	out, err = captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if historyExit(err) != 4 || !strings.Contains(out, "FOUND") || !strings.Contains(out, "admin re-seal that was accepted") {
		t.Fatalf("a re-seal without its record on that node: exit %d (%v)\n%s", historyExit(err), err, out)
	}
	// A node that serves both queries and holds both records: verified, exit 0.
	n.policy, n.noRegistryQuery = policy, false
	n.registry = &ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{{Version: 1, Height: 2, ID: reg.RegistryID()}}}
	out, err = captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if historyExit(err) != 0 || !strings.Contains(out, "v12 continues this chain's history exactly") {
		t.Fatalf("a node with both records: exit %d (%v)\n%s", historyExit(err), err, out)
	}
	// A v11 node serves no records: incomplete (3), never verified.
	n.appVersion = "11"
	out, err = captureOutput(t, func() error { return historyCheck([]string{"--rules", "12", "--rpc", srv.URL}, srv.Client()) })
	if historyExit(err) != 3 || strings.Contains(out, "history exactly") || !strings.Contains(out, "serves no committed records") {
		t.Fatalf("a v11 node: exit %d (%v)\n%s", historyExit(err), err, out)
	}
}
