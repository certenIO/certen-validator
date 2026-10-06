package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

const (
	liveSepoliaAndBase = "0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c"
	liveArbitrum       = "0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6"
	liveAnchorsFlag    = "11155111=" + liveSepoliaAndBase + ",84532=" + liveSepoliaAndBase + ",421614=" + liveArbitrum
)

// The tool builds, offline, the anchor set the runbook commits, and the chain's own rule accepts it once two admins sign.
func TestTheToolBuildsAnAnchorSetTheChainAccepts(t *testing.T) {
	dir, _, admins, policy := registryFixture(t)
	out := filepath.Join(dir, "set.json")
	if err := anchorSetPropose([]string{"--chain-id", chain, "--version", "1", "--anchor", liveAnchorsFlag,
		"--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", out}, nil); err != nil {
		t.Fatal(err)
	}
	tx, err := readAnchorSet(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consensus.VerifyAnchorSet(tx, chain, policy, nil, 10); err == nil {
		t.Fatal("one approval was enough")
	}
	if err := anchorSetSign([]string{"--tx", out, "--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"]}); err == nil {
		t.Fatal("the same admin signed twice")
	}
	if err := anchorSetSign([]string{"--tx", out, "--admin-key-id", "ops-2", "--admin-secret", admins["ops-2"]}); err != nil {
		t.Fatal(err)
	}
	if tx, err = readAnchorSet(out); err != nil {
		t.Fatal(err)
	}
	rec, err := consensus.VerifyAnchorSet(tx, chain, policy, nil, 10)
	if err != nil {
		t.Fatalf("the chain would refuse the set the tool built: %v", err)
	}
	if len(rec.Anchors) != 3 || rec.Anchors[0].Anchor != liveSepoliaAndBase || rec.Anchors[1].Anchor != liveArbitrum {
		t.Fatalf("record %+v", rec)
	}

	// A set may leave a catalogued chain out (the catalogue grows; a chain joins through a later version), and the tool
	// names what it leaves out before anyone signs it. A chain the catalogue does not hold is refused.
	partial := filepath.Join(dir, "partial.json")
	if err := anchorSetPropose([]string{"--chain-id", chain, "--version", "1", "--anchor", "84532=" + liveSepoliaAndBase,
		"--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", partial}, nil); err != nil {
		t.Fatalf("a partial set: %v", err)
	}
	pb, err := os.ReadFile(partial)
	if err != nil {
		t.Fatal(err)
	}
	var ptx consensus.AnchorSetTx
	if err := json.Unmarshal(pb, &ptx); err != nil {
		t.Fatal(err)
	}
	left := strings.Join(omittedChains(&ptx), ",")
	if !strings.Contains(left, "ethereum-sepolia (11155111)") || !strings.Contains(left, "arbitrum-sepolia (421614)") ||
		strings.Contains(left, "(84532)") {
		t.Fatalf("a set naming only Base Sepolia reports it omits %q", left)
	}
	err = anchorSetPropose([]string{"--chain-id", chain, "--version", "1", "--anchor", "1=" + liveSepoliaAndBase,
		"--admin-key-id", "ops-1", "--admin-secret", admins["ops-1"], "--out", filepath.Join(dir, "unknown.json")}, nil)
	if err == nil || !strings.Contains(err.Error(), "not a settlement chain") {
		t.Fatalf("a set naming a chain no catalogue holds: %v", err)
	}
	for _, bad := range []string{"84532", "base=0x830cfB484b6e5606687e00f64C40aeb9c7c84E3c", "84532=830cfB484b6e5606687e00f64C40aeb9c7c84E3c"} {
		if _, err := parseAnchors(bad); err == nil {
			t.Fatalf("--anchor %q was accepted", bad)
		}
	}
}

// Every anchor is checked against its own chain: the endpoint serves that chain, and the address holds code there.
func TestEveryAnchorIsAContractOnItsChain(t *testing.T) {
	serve := func(chainID int64, codeAt string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string            `json:"method"`
				Params []json.RawMessage `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			result := "0x"
			switch req.Method {
			case "eth_chainId":
				result = "0x" + strconv.FormatInt(chainID, 16)
			case "eth_getCode":
				var a string
				_ = json.Unmarshal(req.Params[0], &a)
				if strings.EqualFold(a, codeAt) {
					result = "0x6080"
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	entries, err := parseAnchors(liveAnchorsFlag)
	if err != nil {
		t.Fatal(err)
	}
	tx := &consensus.AnchorSetTx{Kind: consensus.AnchorSetKind, ChainID: chain, Version: 1, Anchors: entries}
	good := map[int64]string{11155111: serve(11155111, liveSepoliaAndBase), 84532: serve(84532, liveSepoliaAndBase),
		421614: serve(421614, liveArbitrum)}
	if p := anchorOnChainProblems(http.DefaultClient, tx, good); len(p) != 0 {
		t.Fatalf("the live anchors: %v", p)
	}
	swapped := map[int64]string{11155111: good[84532], 84532: good[84532], 421614: good[421614]}
	if p := anchorOnChainProblems(http.DefaultClient, tx, swapped); len(p) != 1 || !strings.Contains(p[0], "serves chain 0x14a34") {
		t.Fatalf("an endpoint of another chain: %v", p)
	}
	noCode := map[int64]string{11155111: good[11155111], 84532: good[84532], 421614: serve(421614, liveSepoliaAndBase)}
	if p := anchorOnChainProblems(http.DefaultClient, tx, noCode); len(p) != 1 || !strings.Contains(p[0], "holds no code") {
		t.Fatalf("an address with no code: %v", p)
	}
	missing := map[int64]string{84532: good[84532], 421614: good[421614]}
	if p := anchorOnChainProblems(http.DefaultClient, tx, missing); len(p) != 1 || !strings.Contains(p[0], "unchecked") {
		t.Fatalf("a chain with no endpoint: %v", p)
	}
}
