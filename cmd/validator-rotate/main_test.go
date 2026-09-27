package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/ledger"
)

const chain = "certen-testnet"

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func pubOf(b byte) []byte { return consensus.CometPrivvalKeyFromSeed(seed(b)).PubKey().Bytes() }

// A fleet of seven with equal power, every node on the rotation rules, no rotation yet.
func views(n int) []*nodeView {
	var out []*nodeView
	for i := 0; i < n; i++ {
		v := &nodeView{rpc: "http://v" + string(rune('1'+i)), chainID: chain, appVersion: rotationRulesVersion,
			set: map[string]int64{}, rotations: &ledger.ValidatorRotationLog{}}
		for j := 0; j < 7; j++ {
			v.set[hex.EncodeToString(pubOf(byte(0x20+j)))] = 10
		}
		out = append(out, v)
	}
	return out
}

func rotationFor(t *testing.T, version uint64) *consensus.ValidatorRotationTx {
	t.Helper()
	tx, err := buildRotation(chain, version, pubOf(0x22), seed(0x99))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestTheToolBuildsWhatTheChainVerifies(t *testing.T) {
	tx := rotationFor(t, 1)
	admin := ed25519.NewKeyFromSeed(seed(0xA1))
	if err := addSignature(tx, "ops-1", admin); err != nil {
		t.Fatal(err)
	}
	if err := addSignature(tx, "ops-1", admin); err == nil {
		t.Fatal("the same admin signed twice")
	}
	policy := &ledger.EntitlementPolicyState{Mode: "off", AdminThreshold: 1,
		AdminKeys: map[string]string{"ops-1": hex.EncodeToString(admin.Public().(ed25519.PublicKey))}}
	var genesis []consensus.GenesisValidator
	for j := 0; j < 7; j++ {
		genesis = append(genesis, consensus.GenesisValidator{PubKey: pubOf(byte(0x20 + j)), Power: 10})
	}
	if _, err := consensus.VerifyValidatorRotation(tx, chain, policy, genesis, &ledger.ValidatorRotationLog{}, 100); err != nil {
		t.Fatalf("the chain refuses what the tool built: %v", err)
	}
	// The new key is the one a node started with that seed runs.
	if tx.NewPubKey != hex.EncodeToString(pubOf(0x99)) {
		t.Fatal("the rotation names a key other than the seed's")
	}
	if _, err := buildRotation(chain, 1, pubOf(0x99), seed(0x99)); err == nil {
		t.Fatal("rotated a key to itself")
	}
}

func TestPreflightIsGoOnlyWhenEverythingHolds(t *testing.T) {
	tx := rotationFor(t, 1)
	if nogo := preflightChecks(tx, views(7)); len(nogo) != 0 {
		t.Fatalf("a ready fleet: %v", nogo)
	}
	cases := map[string]func([]*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx){
		"a node on the old rules": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			v[4].appVersion = 7
			return v, tx
		},
		"a node on another chain": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			v[1].chainID = "other"
			return v, tx
		},
		"the old key not in the set": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			r, _ := buildRotation(chain, 1, pubOf(0x55), seed(0x99))
			return v, r
		},
		"the new key already in the set": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			r, _ := buildRotation(chain, 1, pubOf(0x22), seed(0x23))
			for _, n := range v {
				n.set[r.NewPubKey] = 10
			}
			return v, r
		},
		"a skipped version": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			return v, rotationFor(t, 2)
		},
		"an earlier rotation not adopted": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			for _, n := range v {
				n.rotations.Rotations = []ledger.ValidatorRotationRecord{{Version: 1, Height: 9,
					OldPubKey: hex.EncodeToString(pubOf(0x30)), NewPubKey: hex.EncodeToString(pubOf(0x21))}}
			}
			return v, rotationFor(t, 2)
		},
		"not every validator checked": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			return v[:6], tx
		},
		"too little power left": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			for _, n := range v {
				n.set[tx.OldPubKey] = 40
			}
			return v, tx
		},
		"a formula key": func(v []*nodeView) ([]*nodeView, *consensus.ValidatorRotationTx) {
			r := rotationFor(t, 1)
			r.NewPubKey = hex.EncodeToString(formulaPub(t, "validator-3"))
			return v, r
		},
	}
	for name, mutate := range cases {
		v, r := mutate(views(7))
		if nogo := preflightChecks(r, v); len(nogo) == 0 {
			t.Errorf("%s: GO", name)
		}
	}
	// Re-rotating the pending slot is allowed.
	v := views(7)
	for _, n := range v {
		n.rotations.Rotations = []ledger.ValidatorRotationRecord{{Version: 1, Height: 9,
			OldPubKey: hex.EncodeToString(pubOf(0x30)), NewPubKey: tx.OldPubKey}}
	}
	if nogo := preflightChecks(rotationFor(t, 2), v); len(nogo) != 0 {
		t.Fatalf("re-rotating the pending slot: %v", nogo)
	}
}

// formulaPub is validator-N's public-formula key on chain (sha256 of the public formula, as seed).
func formulaPub(t *testing.T, id string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte("certen-validator-key-" + chain + "-" + id))
	pub := ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)
	if got, ok := consensus.IsFormulaKey(chain, pub, formulaIDs); !ok || got != id {
		t.Fatalf("the formula key is not recognised: %v %v", got, ok)
	}
	return pub
}

func TestKeygenWritesASecretOnceAndNeverPrintsIt(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "v3.seed")
	stdout := captureStdout(t, func() {
		if err := keygen([]string{"--kind", "consensus", "--out", out}); err != nil {
			t.Fatal(err)
		}
	})
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSpace(string(raw))
	if len(s) != 64 || strings.Contains(stdout, s) {
		t.Fatalf("seed file %q, printed %q", s, stdout)
	}
	sd, _ := hex.DecodeString(s)
	if !strings.Contains(stdout, hex.EncodeToString(consensus.CometPrivvalKeyFromSeed(sd).PubKey().Bytes())) {
		t.Fatal("the printed public key is not the seed's")
	}
	if err := keygen([]string{"--kind", "consensus", "--out", out}); err == nil {
		t.Fatal("an existing seed file was overwritten")
	}
	if again, _ := os.ReadFile(out); !bytes.Equal(again, raw) {
		t.Fatal("the seed file changed")
	}
}

func TestSubmitReportsARefusalAsARefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tx.json")
	if err := writeTx(rotationFor(t, 1), path, false); err != nil {
		t.Fatal(err)
	}
	reply := `{"result":{"check_tx":{"code":0},"tx_result":{"code":6,"log":"validator rotation refused: x"},"height":"44"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method != "broadcast_tx_commit" {
			t.Errorf("method %s", req.Method)
		}
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()
	if err := submit([]string{"--tx", path, "--rpc", srv.URL}, srv.Client()); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a refused rotation: %v", err)
	}
	reply = `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"height":"44"}}`
	if err := submit([]string{"--tx", path, "--rpc", srv.URL}, srv.Client()); err != nil {
		t.Fatalf("an accepted rotation: %v", err)
	}
}

// readNode reads what preflight judges from a node's RPC.
func TestReadNodeReadsTheFleetView(t *testing.T) {
	logJSON, _ := json.Marshal(ledger.ValidatorRotationLog{Rotations: []ledger.ValidatorRotationRecord{{Version: 1, Height: 5}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "abci_info":
			_, _ = w.Write([]byte(`{"result":{"response":{"app_version":"8"}}}`))
		case "status":
			_, _ = w.Write([]byte(`{"result":{"node_info":{"network":"certen-testnet"},"sync_info":{"latest_block_height":"77"}}}`))
		case "validators":
			_, _ = w.Write([]byte(`{"result":{"validators":[{"pub_key":{"type":"tendermint/PubKeyEd25519","value":"` +
				base64.StdEncoding.EncodeToString(pubOf(0x20)) + `"},"voting_power":"10"}]}}`))
		case "abci_query":
			_, _ = w.Write([]byte(`{"result":{"response":{"code":0,"value":"` + base64.StdEncoding.EncodeToString(logJSON) + `"}}}`))
		}
	}))
	defer srv.Close()
	v, err := readNode(srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if v.appVersion != 8 || v.chainID != chain || v.height != 77 || v.set[hex.EncodeToString(pubOf(0x20))] != 10 || len(v.rotations.Rotations) != 1 {
		t.Fatalf("view %+v", v)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}
