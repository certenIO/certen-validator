package main

import (
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
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ledger"
)

const kermitInc = "0xcac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

// registryFixture writes three validators' BLS key files and their member entries, and two admins' secrets.
func registryFixture(t *testing.T) (dir string, members []string, adminSecrets map[string]string, policy *ledger.EntitlementPolicyState) {
	t.Helper()
	dir = t.TempDir()
	for i := 0; i < 3; i++ {
		s := make([]byte, 32)
		s[0], s[31] = 0xD1, byte(i+1)
		sk, _, err := bls.GenerateKeyPairFromSeed(s)
		if err != nil {
			t.Fatal(err)
		}
		keyFile := filepath.Join(dir, fmt.Sprintf("bls_key_validator-%d.hex", i+1))
		if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(sk.Bytes())), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, fmt.Sprintf("member-%d.json", i+1))
		if err := blsPossession([]string{"--chain-id", chain, "--validator-id", fmt.Sprintf("validator-%d", i+1),
			"--evm-address", fmt.Sprintf("0x%040x", 0x2000+i), "--power", "100", "--bls-key", keyFile, "--out", out}); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(out)
		if strings.Contains(string(raw), hex.EncodeToString(sk.Bytes())) {
			t.Fatal("the member entry carries the private key")
		}
		members = append(members, out)
	}
	adminSecrets = map[string]string{}
	policy = &ledger.EntitlementPolicyState{Mode: "off", AdminThreshold: 2, AdminKeys: map[string]string{}}
	for i, id := range []string{"ops-1", "ops-2"} {
		admin := ed25519.NewKeyFromSeed(seed(byte(0xE1 + i)))
		f := filepath.Join(dir, id+".secret")
		if err := os.WriteFile(f, []byte(hex.EncodeToString(seed(byte(0xE1+i)))), 0o600); err != nil {
			t.Fatal(err)
		}
		adminSecrets[id] = "@" + f
		policy.AdminKeys[id] = hex.EncodeToString(admin.Public().(ed25519.PublicKey))
	}
	return
}

// The tool builds, from each validator's own key file, a registry the chain accepts.
func TestTheToolBuildsARegistryTheChainAccepts(t *testing.T) {
	dir, members, admins, policy := registryFixture(t)
	reg := filepath.Join(dir, "reg.json")
	if err := blsRegistryPropose([]string{"--chain-id", chain, "--version", "1", "--threshold", "2/3", "--incarnation", kermitInc,
		"--members", strings.Join(members, ","), "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", reg}); err != nil {
		t.Fatal(err)
	}
	if err := blsRegistrySign([]string{"--tx", reg, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"]}); err == nil {
		t.Fatal("the same admin signed twice")
	}
	if err := blsRegistrySign([]string{"--tx", reg, "--admin-key-id", "ops-2", "--admin-secret", admins["ops-2"]}); err != nil {
		t.Fatal(err)
	}
	tx, err := readRegistry(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.VerifyBLSRegistry(tx, chain, policy, &ledger.BLSRegistryLog{}, 5); err != nil {
		t.Fatalf("the chain refuses what the tool built: %v", err)
	}

	// A member entry carrying another key's possession is refused before anyone signs.
	var e consensus.BLSRegistryEntry
	raw, _ := os.ReadFile(members[1])
	_ = json.Unmarshal(raw, &e)
	var other consensus.BLSRegistryEntry
	raw0, _ := os.ReadFile(members[0])
	_ = json.Unmarshal(raw0, &other)
	e.Possession = other.Possession
	forged := filepath.Join(dir, "forged.json")
	b, _ := json.Marshal(e)
	_ = os.WriteFile(forged, b, 0o600)
	if err := blsRegistryPropose([]string{"--chain-id", chain, "--version", "1", "--threshold", "2/3", "--incarnation", kermitInc,
		"--members", strings.Join([]string{members[0], forged, members[2]}, ","), "--admin-key-id", "ops-1",
		"--admin-secret", admins["ops-1"], "--out", filepath.Join(dir, "reg2.json")}); err == nil {
		t.Fatal("a forged possession was assembled")
	}
}

// Preflight is GO only when every node runs rules v10 on the registry's chain and every anchor commits its root;
// submit reports a refusal as one.
func TestRegistryPreflightAndSubmit(t *testing.T) {
	dir, members, admins, _ := registryFixture(t)
	reg := filepath.Join(dir, "reg.json")
	if err := blsRegistryPropose([]string{"--chain-id", chain, "--version", "1", "--threshold", "2/3", "--incarnation", kermitInc,
		"--members", strings.Join(members, ","), "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", reg}); err != nil {
		t.Fatal(err)
	}
	tx, _ := readRegistry(reg)
	var ms []ledger.BLSRegistryMember
	for _, e := range tx.Members {
		ms = append(ms, e.BLSRegistryMember)
	}
	root, _ := consensus.RegistryCertenSetRoot(ms, 2, 3)
	anchorRoot, appVersion, txReply := "0x"+hex.EncodeToString(root[:]), "10", `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"height":"70"}}`
	logJSON, _ := json.Marshal(ledger.ValidatorRotationLog{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "abci_info":
			_, _ = w.Write([]byte(`{"result":{"response":{"app_version":"` + appVersion + `"}}}`))
		case "status":
			_, _ = w.Write([]byte(`{"result":{"node_info":{"network":"` + chain + `"},"sync_info":{"latest_block_height":"60"}}}`))
		case "validators":
			_, _ = w.Write([]byte(`{"result":{"validators":[{"pub_key":{"type":"tendermint/PubKeyEd25519","value":"` +
				base64.StdEncoding.EncodeToString(pubOf(0x20)) + `"},"voting_power":"10"}]}}`))
		case "abci_query":
			_, _ = w.Write([]byte(`{"result":{"response":{"code":0,"value":"` + base64.StdEncoding.EncodeToString(logJSON) + `"}}}`))
		case "eth_call":
			_, _ = w.Write([]byte(`{"result":"` + anchorRoot + `"}`))
		case "broadcast_tx_commit":
			_, _ = w.Write([]byte(txReply))
		default:
			t.Errorf("method %s", req.Method)
		}
	}))
	defer srv.Close()
	pre := func() error {
		return blsRegistryPreflight([]string{"--tx", reg, "--rpc", srv.URL, "--eth-rpc", srv.URL, "--anchor",
			"0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c"}, srv.Client())
	}
	if err := pre(); err != nil {
		t.Fatalf("everything holds: %v", err)
	}
	anchorRoot = "0x" + strings.Repeat("ab", 32)
	if err := pre(); err == nil || !strings.Contains(err.Error(), "NO-GO") {
		t.Fatalf("an anchor committing another set: %v", err)
	}
	anchorRoot, appVersion = "0x"+hex.EncodeToString(root[:]), "9"
	if err := pre(); err == nil {
		t.Fatal("a node on rules v9 passed preflight")
	}
	if err := blsRegistrySubmit([]string{"--tx", reg, "--rpc", srv.URL}, srv.Client()); err != nil {
		t.Fatalf("accepted: %v", err)
	}
	txReply = `{"result":{"check_tx":{"code":0},"tx_result":{"code":9,"log":"BLS registry refused: x"},"height":"70"}}`
	if err := blsRegistrySubmit([]string{"--tx", reg, "--rpc", srv.URL}, srv.Client()); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a refusal: %v", err)
	}
}
