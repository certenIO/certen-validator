package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

// g1Admins is a 2-of-3 admin set: the secrets (as @file), and the policy the chain judges them by.
func g1Admins(t *testing.T) (dir string, secrets map[string]string, policy *ledger.EntitlementPolicyState) {
	t.Helper()
	dir = t.TempDir()
	secrets = map[string]string{}
	policy = &ledger.EntitlementPolicyState{Mode: "off", AdminThreshold: 2, AdminKeys: map[string]string{}}
	for i, id := range []string{"ops-1", "ops-2", "ops-3"} {
		admin := ed25519.NewKeyFromSeed(seed(byte(0xC1 + i)))
		f := filepath.Join(dir, id+".secret")
		if err := os.WriteFile(f, []byte(hex.EncodeToString(seed(byte(0xC1+i)))), 0o600); err != nil {
			t.Fatal(err)
		}
		secrets[id] = "@" + f
		policy.AdminKeys[id] = hex.EncodeToString(admin.Public().(ed25519.PublicKey))
	}
	return dir, secrets, policy
}

// The tool builds, offline, the activation the chain's own rule accepts once two of three admins sign.
func TestG1ActivateToolBuildsAnActivationTheChainAccepts(t *testing.T) {
	dir, admins, policy := g1Admins(t)
	out := filepath.Join(dir, "activate.json")
	if err := g1ActivatePropose([]string{"--chain-id", chain, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"],
		"--out", out}, nil); err != nil {
		t.Fatal(err)
	}
	tx, err := readG1Activation(out)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Kind != consensus.G1ActivationKind || tx.ChainID != chain || tx.Version != 1 || len(tx.Signatures) != 1 {
		t.Fatalf("the proposed activation is %+v", tx)
	}
	if _, err := consensus.VerifyG1Activation(tx, chain, policy, nil, 10); err == nil {
		t.Fatal("one approval of a threshold of two was enough")
	}
	if err := g1ActivateSign([]string{"--tx", out, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"]}); err == nil {
		t.Fatal("the same admin signed twice")
	}
	if err := g1ActivateSign([]string{"--tx", out, "--admin-key-id", "ops-3", "--admin-secret", admins["ops-3"]}); err != nil {
		t.Fatal(err)
	}
	if tx, err = readG1Activation(out); err != nil {
		t.Fatal(err)
	}
	rec, err := consensus.VerifyG1Activation(tx, chain, policy, nil, 10)
	if err != nil {
		t.Fatalf("the chain would refuse the activation the tool built: %v", err)
	}
	if rec.Version != 1 || rec.Height != 10 || rec.ID != tx.ActivationID() {
		t.Fatalf("record %+v", rec)
	}
	// It is for its own chain only, and only once.
	if _, err := consensus.VerifyG1Activation(tx, "other", policy, nil, 10); err == nil {
		t.Fatal("accepted on another chain")
	}
	if _, err := consensus.VerifyG1Activation(tx, chain, policy, &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{rec0(5)}}, 10); err == nil {
		t.Fatal("a second activation was accepted")
	}

	// Without admin flags the payload is written unsigned and the chain refuses it; one flag without the other is a mistake.
	unsigned := filepath.Join(dir, "unsigned.json")
	if err := g1ActivatePropose([]string{"--chain-id", chain, "--out", unsigned}, nil); err != nil {
		t.Fatal(err)
	}
	utx, err := readG1Activation(unsigned)
	if err != nil || len(utx.Signatures) != 0 {
		t.Fatalf("unsigned payload %+v: %v", utx, err)
	}
	if _, err := consensus.VerifyG1Activation(utx, chain, policy, nil, 10); err == nil {
		t.Fatal("an unsigned activation was accepted")
	}
	if err := g1ActivatePropose([]string{"--chain-id", chain, "--admin-key-id", "ops-1", "--out", filepath.Join(dir, "x.json")}, nil); err == nil {
		t.Fatal("a key id without its secret was accepted")
	}
	if err := g1ActivatePropose([]string{"--out", filepath.Join(dir, "y.json")}, nil); err == nil {
		t.Fatal("neither --rpc nor --chain-id was accepted")
	}
	// A version other than 1 is not an activation the chain would take, and sign refuses it before anyone signs.
	bad := &consensus.G1ActivationTx{Kind: consensus.G1ActivationKind, ChainID: chain, Version: 2}
	badPath := filepath.Join(dir, "bad.json")
	if err := writeG1Activation(bad, badPath, false); err != nil {
		t.Fatal(err)
	}
	if err := g1ActivateSign([]string{"--tx", badPath, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"]}); err == nil ||
		!strings.Contains(err.Error(), "would be refused") {
		t.Fatalf("signed a version-2 activation: %v", err)
	}
}

func rec0(h int64) ledger.G1ActivationRecord {
	return ledger.G1ActivationRecord{Version: 1, Height: h, ID: "g1-activation:" + strings.Repeat("ab", 32)}
}

// g1Fleet is n nodes at the same height on the same chain and admin set, every one on rules v15 with no activation.
func g1Fleet(t *testing.T, policy *ledger.EntitlementPolicyState, n int) []g1ActivateNode {
	t.Helper()
	var out []g1ActivateNode
	for i := 0; i < n; i++ {
		v := &nodeView{rpc: "http://v" + string(rune('1'+i)), chainID: chain, height: 100, appVersion: g1ActivateRulesVersion,
			set: map[string]int64{}, rotations: &ledger.ValidatorRotationLog{}}
		for j := 0; j < n; j++ {
			v.set[hex.EncodeToString(pubOf(byte(0x20+j)))] = 10
		}
		spine, registry := proofV3Logs(50)
		out = append(out, g1ActivateNode{nodeView: v, admin: consensus.NewAdminSetView(policy, 100), activations: &ledger.G1ActivationLog{},
			spine: spine, registry: registry})
	}
	return out
}

// proofV3Logs are a spine with one verified checkpoint and the registry in force from the given height, both of one Accumulate incarnation:
// the chain requires the v3 intent certificate (consensus.ProofV3Required).
func proofV3Logs(registryHeight int64) (*ledger.AccumulateSpineLog, *ledger.BLSRegistryLog) {
	const inc = "0x" + "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"
	return &ledger.AccumulateSpineLog{Genesis: &ledger.AccumulateSpineGenesis{Incarnation: inc, Height: registryHeight},
			Checkpoints: []ledger.AccumulateSpineCheckpoint{{Major: 1, Height: registryHeight + 1}}},
		&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{{Version: 1, Height: registryHeight, AccumulateIncarnation: inc}}}
}

func signedG1Activation(t *testing.T, admins map[string]string, ids ...string) *consensus.G1ActivationTx {
	t.Helper()
	tx := &consensus.G1ActivationTx{Kind: consensus.G1ActivationKind, ChainID: chain, Version: 1}
	for _, id := range ids {
		a, err := loadAdmin(admins[id])
		if err != nil {
			t.Fatal(err)
		}
		if err := signG1Activation(tx, id, a); err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

// Preflight is GO only when every node runs rules v15 and agrees, none records an activation, and the chain's rule accepts it.
func TestG1ActivatePreflightIsGoOnlyWhenEverythingHolds(t *testing.T) {
	_, admins, policy := g1Admins(t)
	tx := signedG1Activation(t, admins, "ops-1", "ops-2")
	if nogo := g1ActivatePreflight(tx, g1Fleet(t, policy, 7)); len(nogo) != 0 {
		t.Fatalf("a ready fleet: %v", nogo)
	}
	cases := map[string]struct {
		mutate func([]g1ActivateNode) []g1ActivateNode
		tx     *consensus.G1ActivationTx
		want   string
	}{
		"one node still on rules v14": {func(n []g1ActivateNode) []g1ActivateNode {
			n[4].appVersion = 14
			return n
		}, tx, "execution rules v14"},
		"nodes on different rules": {func(n []g1ActivateNode) []g1ActivateNode {
			n[2].appVersion = 16
			return n
		}, tx, "whole fleet must run the same rules"},
		"nodes disagree about the admin set": {func(n []g1ActivateNode) []g1ActivateNode {
			v := *n[3].admin
			v.InForceSetID = "other-set"
			n[3].admin = &v
			return n
		}, tx, "disagrees about its admins"},
		"nodes disagree about the activation": {func(n []g1ActivateNode) []g1ActivateNode {
			n[5].activations = &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{rec0(77)}}
			return n
		}, tx, "disagrees about the activation"},
		"an activation already exists on every node": {func(n []g1ActivateNode) []g1ActivateNode {
			for i := range n {
				n[i].activations = &ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{rec0(77)}}
			}
			return n
		}, tx, "activates once"},
		"below the admin threshold": {func(n []g1ActivateNode) []g1ActivateNode { return n }, signedG1Activation(t, admins, "ops-1"),
			"the chain would refuse it"},
		"an unsigned activation": {func(n []g1ActivateNode) []g1ActivateNode { return n }, signedG1Activation(t, admins),
			"the chain would refuse it"},
		"a node on another chain": {func(n []g1ActivateNode) []g1ActivateNode {
			n[1].chainID = "other"
			return n
		}, tx, "is on chain"},
		"an activation for another chain": {func(n []g1ActivateNode) []g1ActivateNode { return n },
			&consensus.G1ActivationTx{Kind: consensus.G1ActivationKind, ChainID: "other", Version: 1, Signatures: tx.Signatures}, "is on chain"},
		"not every validator checked": {func(n []g1ActivateNode) []g1ActivateNode { return n[:6] }, tx, "preflight every validator"},
		"a lagging validator": {func(n []g1ActivateNode) []g1ActivateNode {
			n[6].height = 90
			return n
		}, tx, "caught up"},
	}
	for name, c := range cases {
		nogo := g1ActivatePreflight(c.tx, c.mutate(g1Fleet(t, policy, 7)))
		if len(nogo) == 0 {
			t.Errorf("%s: preflight said GO", name)
			continue
		}
		if !strings.Contains(strings.Join(nogo, "\n"), c.want) {
			t.Errorf("%s: NO-GO did not say %q: %v", name, c.want, nogo)
		}
	}
	if nogo := g1ActivatePreflight(tx, nil); len(nogo) != 1 {
		t.Errorf("no nodes: %v", nogo)
	}
}

// g1Node is a fake validator's CometBFT RPC: it answers what the tool reads, and records an activation when one is committed.
type g1Node struct {
	mu          sync.Mutex
	appVersion  string
	height      int64
	admin       *consensus.AdminSetView
	log         ledger.G1ActivationLog
	servesLog   bool
	commitAt    int64
	broadcasts  int
	srv         *httptest.Server
	spine       ledger.AccumulateSpineLog
	registry    ledger.BLSRegistryLog
	historyTxs  map[int64]string // height -> base64 tx, for the history check
	historyCode map[int64]uint32
}

func newG1Node(t *testing.T, admin *consensus.AdminSetView, appVersion string) *g1Node {
	n := &g1Node{appVersion: appVersion, height: 60, admin: admin, servesLog: true, commitAt: 70}
	sp, rg := proofV3Logs(10)
	n.spine, n.registry = *sp, *rg
	n.srv = httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *g1Node) serve(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &req)
	reply := func(s string) { _, _ = w.Write([]byte(s)) }
	query := func(code uint32, log string, v any) {
		raw, _ := json.Marshal(v)
		reply(fmt.Sprintf(`{"result":{"response":{"code":%d,"log":%q,"value":%q}}}`, code, log, base64.StdEncoding.EncodeToString(raw)))
	}
	switch req.Method {
	case "abci_info":
		reply(`{"result":{"response":{"app_version":"` + n.appVersion + `"}}}`)
	case "status":
		reply(`{"result":{"node_info":{"network":"` + chain + `"},"sync_info":{"latest_block_height":"` + strconv.FormatInt(n.height, 10) +
			`","earliest_block_height":"1"}}}`)
	case "validators":
		var vals []string
		for j := 0; j < 3; j++ {
			vals = append(vals, `{"pub_key":{"type":"tendermint/PubKeyEd25519","value":"`+base64.StdEncoding.EncodeToString(pubOf(byte(0x20+j)))+
				`"},"voting_power":"10"}`)
		}
		reply(`{"result":{"validators":[` + strings.Join(vals, ",") + `]}}`)
	case "abci_query":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(req.Params, &p)
		switch p.Path {
		case "/certen/validator_rotations":
			query(0, "", ledger.ValidatorRotationLog{})
		case "/certen/admin_set":
			query(0, "", n.admin)
		case "/certen/bls_registry":
			query(0, "", n.registry)
		case "/certen/accumulate_spine":
			query(0, "", n.spine)
		case "/certen/anchor_set":
			query(0, "", ledger.AnchorSetLog{})
		case "/certen/g1_activation":
			if !n.servesLog {
				reply(`{"result":{"response":{"code":2,"log":"unknown query path: /certen/g1_activation"}}}`)
				return
			}
			query(0, "", n.log)
		default:
			reply(`{"result":{"response":{"code":2,"log":"unknown query path: ` + p.Path + `"}}}`)
		}
	case "block":
		var p struct {
			Height string `json:"height"`
		}
		_ = json.Unmarshal(req.Params, &p)
		h, _ := strconv.ParseInt(p.Height, 10, 64)
		txs := `[]`
		if tx, ok := n.historyTxs[h]; ok {
			txs = `["` + tx + `"]`
		}
		reply(`{"result":{"block":{"data":{"txs":` + txs + `}}}}`)
	case "block_results":
		var p struct {
			Height string `json:"height"`
		}
		_ = json.Unmarshal(req.Params, &p)
		h, _ := strconv.ParseInt(p.Height, 10, 64)
		if _, ok := n.historyTxs[h]; ok {
			reply(fmt.Sprintf(`{"result":{"txs_results":[{"code":%d}]}}`, n.historyCode[h]))
		} else {
			reply(`{"result":{"txs_results":[]}}`)
		}
	case "broadcast_tx_commit":
		n.broadcasts++
		var p struct {
			Tx string `json:"tx"`
		}
		_ = json.Unmarshal(req.Params, &p)
		raw, _ := base64.StdEncoding.DecodeString(p.Tx)
		if tx, ok := consensus.DecodeG1Activation(raw); ok {
			n.log.Activations = append(n.log.Activations, ledger.G1ActivationRecord{Version: tx.Version, Height: n.commitAt, ID: tx.ActivationID()})
		}
		reply(`{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"height":"` + strconv.FormatInt(n.commitAt, 10) + `"}}`)
	default:
		reply(`{"error":{"message":"unknown method ` + req.Method + `"}}`)
	}
}

func writeActivation(t *testing.T, dir string, tx *consensus.G1ActivationTx) string {
	t.Helper()
	path := filepath.Join(dir, "activate.json")
	if err := writeG1Activation(tx, path, true); err != nil {
		t.Fatal(err)
	}
	return path
}

// Submit commits only after a GO, reports a refusal as one, and confirms what the node recorded; status says none, then H.
func TestG1ActivateStatusPreflightAndSubmitAgainstNodes(t *testing.T) {
	dir, admins, policy := g1Admins(t)
	view := consensus.NewAdminSetView(policy, 60)
	var nodes []*g1Node
	var rpcs []string
	for i := 0; i < 3; i++ {
		n := newG1Node(t, view, "15")
		nodes = append(nodes, n)
		rpcs = append(rpcs, n.srv.URL)
	}
	all := strings.Join(rpcs, ",")
	c := http.DefaultClient

	var status bytes.Buffer
	if err := g1ActivateStatus(&status, []string{"--rpc", all}, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.String(), "rules v15 not yet activated") || strings.Contains(status.String(), "DISAGREE") ||
		strings.Count(status.String(), "cross-partition activation: none") != 3 {
		t.Fatalf("status before the activation:\n%s", status.String())
	}

	good := signedG1Activation(t, admins, "ops-1", "ops-2")
	goodPath := writeActivation(t, dir, good)
	short := signedG1Activation(t, admins, "ops-2")

	// Below the threshold: NO-GO, and nothing is broadcast.
	var out bytes.Buffer
	shortPath := filepath.Join(dir, "short.json")
	if err := writeG1Activation(short, shortPath, true); err != nil {
		t.Fatal(err)
	}
	if err := g1ActivateSubmit(&out, []string{"--tx", shortPath, "--rpc", all}, c, "submit"); err == nil || !strings.Contains(err.Error(), "NO-GO") {
		t.Fatalf("submit below the threshold: %v\n%s", err, out.String())
	}

	// One node still on rules v14 (it does not serve the log): NO-GO, nothing broadcast.
	nodes[1].appVersion, nodes[1].servesLog = "14", false
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all}, c, "submit"); err == nil || !strings.Contains(err.Error(), "NO-GO") {
		t.Fatalf("submit with a v14 node: %v\n%s", err, out.String())
	}
	// ...and a node on v14 that does answer is a NO-GO naming its rules.
	nodes[1].servesLog = true
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all}, c, "submit"); err == nil ||
		!strings.Contains(out.String(), "NO-GO: "+nodes[1].srv.URL+" runs execution rules v14") {
		t.Fatalf("submit with a v14 node that answers: %v\n%s", err, out.String())
	}
	for i, n := range nodes {
		if n.broadcasts != 0 {
			t.Fatalf("node %d was sent a transaction after a NO-GO", i)
		}
	}
	nodes[1].appVersion = "15"

	// A chain that does not require proof v3 (a node reporting no spine) is a NO-GO naming it; nothing is broadcast.
	savedSpine := nodes[2].spine
	nodes[2].spine = ledger.AccumulateSpineLog{}
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all}, c, "submit"); err == nil ||
		!strings.Contains(out.String(), "NO-GO: "+nodes[2].srv.URL+" does not require proof v3") {
		t.Fatalf("submit with a node that requires no proof v3: %v\n%s", err, out.String())
	}
	for i, n := range nodes {
		if n.broadcasts != 0 {
			t.Fatalf("node %d was sent a transaction after a NO-GO (no proof v3)", i)
		}
	}
	nodes[2].spine = savedSpine

	// A GO as a dry run commits nothing.
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all, "--dry-run"}, c, "preflight"); err != nil ||
		!strings.Contains(out.String(), "GO: every validator runs rules v15") || !strings.Contains(out.String(), "dry run") {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	if nodes[0].broadcasts != 0 {
		t.Fatal("a dry run committed")
	}

	// The real submit commits through the first node and confirms what it recorded.
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all}, c, "submit"); err != nil {
		t.Fatalf("submit: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "ACCEPTED at height 70") || !strings.Contains(out.String(), "Evidence 2.1 is required from height 71") {
		t.Fatalf("submit output:\n%s", out.String())
	}
	if nodes[0].broadcasts != 1 || nodes[1].broadcasts != 0 {
		t.Fatalf("broadcasts %d/%d", nodes[0].broadcasts, nodes[1].broadcasts)
	}

	// The other nodes catch up; status says H. Once any node records it, a second submit is a NO-GO.
	for _, n := range nodes[1:] {
		n.log = nodes[0].log
	}
	status.Reset()
	if err := g1ActivateStatus(&status, []string{"--rpc", all}, c); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status.String(), "accepted at height 70") || !strings.Contains(status.String(), "evidence 2.1 is required from height 71") ||
		strings.Contains(status.String(), "DISAGREE") {
		t.Fatalf("status after the activation:\n%s", status.String())
	}
	out.Reset()
	if err := g1ActivateSubmit(&out, []string{"--tx", goodPath, "--rpc", all}, c, "submit"); err == nil ||
		!strings.Contains(out.String(), "activates once") || nodes[0].broadcasts != 1 {
		t.Fatalf("a second activation: %v\n%s", err, out.String())
	}
	// A node that lags in recording it is a disagreement status reports.
	nodes[2].log = ledger.G1ActivationLog{}
	status.Reset()
	if err := g1ActivateStatus(&status, []string{"--rpc", all}, c); err != nil || !strings.Contains(status.String(), "DISAGREE") {
		t.Fatalf("status with a lagging node: %v\n%s", err, status.String())
	}

	// propose --rpc reads the chain id, and refuses once the chain recorded the activation.
	if err := g1ActivatePropose([]string{"--rpc", rpcs[0], "--out", filepath.Join(dir, "again.json")}, c); err == nil ||
		!strings.Contains(err.Error(), "activates once") {
		t.Fatalf("propose after the activation: %v", err)
	}
	fresh := newG1Node(t, view, "15")
	fromNode := filepath.Join(dir, "from-node.json")
	if err := g1ActivatePropose([]string{"--rpc", fresh.srv.URL, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", fromNode}, c); err != nil {
		t.Fatal(err)
	}
	if tx, err := readG1Activation(fromNode); err != nil || tx.ChainID != chain || len(tx.Signatures) != 1 {
		t.Fatalf("proposed from a node: %+v %v", tx, err)
	}
}

// history-check --rules 15 reads the activation log: an accepted activation with its record is checked, one without is FOUND.
func TestG1ActivateHistoryCheckFindsAnActivationWithoutItsRecord(t *testing.T) {
	_, admins, policy := g1Admins(t)
	view := consensus.NewAdminSetView(policy, 60)
	tx := signedG1Activation(t, admins, "ops-1", "ops-2")
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	n := newG1Node(t, view, "15")
	n.height = 3
	n.historyTxs = map[int64]string{2: base64.StdEncoding.EncodeToString(raw)}
	n.historyCode = map[int64]uint32{2: 0}

	// Accepted at height 2 and recorded there: history is what v15 decides.
	n.log = ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{{Version: 1, Height: 2, ID: tx.ActivationID()}}}
	if err := historyCheckRules(n.srv.URL, http.DefaultClient, 15); err != nil {
		t.Fatalf("an accepted activation with its record: %v", err)
	}
	// Accepted but unrecorded: FOUND (a checkExit with the FOUND code).
	n.log = ledger.G1ActivationLog{}
	err = historyCheckRules(n.srv.URL, http.DefaultClient, 15)
	ce, ok := err.(*checkExit)
	if !ok || ce.code != exitHistoryFound {
		t.Fatalf("an accepted activation without its record: %v", err)
	}
	// Refused by v15 (code 18) is the verdict v15 reproduces.
	n.historyCode[2] = 18
	if err := historyCheckRules(n.srv.URL, http.DefaultClient, 15); err != nil {
		t.Fatalf("a refused activation: %v", err)
	}
	// Judged as a ValidatorBlock by an earlier version (code 0 with no record is above; any other code) is FOUND.
	n.historyCode[2] = 2
	if ce, ok := historyCheckRules(n.srv.URL, http.DefaultClient, 15).(*checkExit); !ok || ce.code != exitHistoryFound {
		t.Fatal("an activation decided with a ValidatorBlock's code was not FOUND")
	}
}

// F8: an activation accepted on a chain that does not require the v3 intent certificate yet (no verified Accumulate spine of the registry's
// incarnation) would record a height at which nothing is judged and would be effective only once a spine appears, at a time no one chose.
// The preflight refuses it on every node that reports it: NO-GO naming proof v3.
func TestG1ActivatePreflightRefusesWhenProofV3IsNotRequired(t *testing.T) {
	_, admins, policy := g1Admins(t)
	tx := signedG1Activation(t, admins, "ops-1", "ops-2")
	if nogo := g1ActivatePreflight(tx, g1Fleet(t, policy, 7)); len(nogo) != 0 {
		t.Fatalf("a fleet that requires proof v3: %v", nogo)
	}
	otherInc := "0x" + strings.Repeat("ab", 32)
	for name, mutate := range map[string]func(n *g1ActivateNode){
		"no spine at all":                     func(n *g1ActivateNode) { n.spine = &ledger.AccumulateSpineLog{} },
		"a nil spine":                         func(n *g1ActivateNode) { n.spine = nil },
		"a spine with no verified checkpoint": func(n *g1ActivateNode) { n.spine.Checkpoints = nil },
		"a spine of another incarnation than the registry's": func(n *g1ActivateNode) {
			g := *n.spine.Genesis
			g.Incarnation = otherInc
			n.spine.Genesis = &g
		},
		"no registry": func(n *g1ActivateNode) { n.registry = &ledger.BLSRegistryLog{} },
		"a registry that starts above the next block": func(n *g1ActivateNode) { n.registry.Versions[0].Height = n.height + 1 },
	} {
		nodes := g1Fleet(t, policy, 7)
		mutate(&nodes[3])
		nogo := g1ActivatePreflight(tx, nodes)
		if len(nogo) == 0 {
			t.Errorf("%s: preflight said GO", name)
			continue
		}
		if joined := strings.Join(nogo, "\n"); !strings.Contains(joined, nodes[3].rpc+" does not require proof v3") {
			t.Errorf("%s: NO-GO did not name the node and proof v3: %v", name, nogo)
		}
	}
}
