// Phase 4 probe: how much does a ValidatorSetProof actually add to a stored
// proof? Builds the real JSON from live data and measures it.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type step struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right,omitempty"`
}
type receipt struct {
	Start   string `json:"start"`
	Anchor  string `json:"anchor"`
	Entries []step `json:"entries"`
}
type chainRoot struct {
	Name   string `json:"name"`
	Count  uint64 `json:"count"`
	Anchor string `json:"anchor"`
}
type validatorSetProof struct {
	Incarnation            string      `json:"incarnation"`
	AccountState           string      `json:"accountState"`
	StateReceipt           receipt     `json:"stateReceipt"`
	Chains                 []chainRoot `json:"chains"`
	BoundToStateTreeAnchor string      `json:"boundToStateTreeAnchor"`
	MainChainHeight        uint64      `json:"mainChainHeight"`
}

func rpc(server string, params any) json.RawMessage {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "query", "params": params})
	resp, err := http.Post(server, "application/json", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var r struct {
		Result json.RawMessage  `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if r.Error != nil {
		panic(string(*r.Error))
	}
	return r.Result
}

func main() {
	net := "kermit"
	if len(os.Args) > 1 {
		net = os.Args[1]
	}
	server := fmt.Sprintf("https://%s.accumulatenetwork.io/v3", net)

	raw := rpc(server, map[string]any{
		"scope": "acc://dn.acme/network",
		"query": map[string]any{"queryType": "default", "includeReceipt": true},
	})
	var ar struct {
		Account json.RawMessage `json:"account"`
		Receipt receipt         `json:"receipt"`
	}
	json.Unmarshal(raw, &ar)
	acct, err := protocol.UnmarshalAccountJSON(ar.Account)
	if err != nil {
		panic(err)
	}
	state, _ := acct.MarshalBinary()
	leaf := sha256.Sum256(state)

	raw = rpc(server, map[string]any{
		"scope": "acc://dn.acme/network",
		"query": map[string]any{"queryType": "chain"},
	})
	var cr struct {
		Records []struct {
			Name  string    `json:"name"`
			Count uint64    `json:"count"`
			State []*string `json:"state"`
		} `json:"records"`
	}
	json.Unmarshal(raw, &cr)

	vsp := validatorSetProof{
		Incarnation:            "e3f3119213a1ead44647659d67e47f4269a2affb13f150aa87b20baacf93cf81",
		AccountState:           hex.EncodeToString(state),
		StateReceipt:           ar.Receipt,
		BoundToStateTreeAnchor: ar.Receipt.Anchor,
	}
	for _, c := range cr.Records {
		a := ""
		for _, s := range c.State {
			if s != nil {
				a = *s
			}
		}
		vsp.Chains = append(vsp.Chains, chainRoot{Name: c.Name, Count: c.Count, Anchor: a})
		if c.Name == "main" {
			vsp.MainChainHeight = c.Count
		}
	}

	b, _ := json.Marshal(vsp)
	pretty, _ := json.MarshalIndent(vsp, "", "  ")

	fmt.Printf("=== %s : ValidatorSetProof, built from live data ===\n", net)
	fmt.Printf("  leaf derivable            : %v\n", hex.EncodeToString(leaf[:]) == ar.Receipt.Start)
	fmt.Printf("  BPT path steps            : %d\n", len(ar.Receipt.Entries))
	fmt.Printf("  main chain height         : %d  -> %s\n", vsp.MainChainHeight,
		map[bool]string{true: "BASE CASE: set has NEVER changed", false: "updates required"}[vsp.MainChainHeight == 1])
	fmt.Printf("  accountState (hex)        : %d chars\n", len(vsp.AccountState))
	fmt.Printf("  ValidatorSetProof compact : %d B\n", len(b))
	fmt.Printf("  ValidatorSetProof indented: %d B\n", len(pretty))
	fmt.Printf("  current stored proof      : 18784 B (testdata/proof_bvn1.json)\n")
	fmt.Printf("  GROWTH (compact, 1 leg)   : +%.1f%%\n", 100*float64(len(b))/18784)
	fmt.Printf("  GROWTH (compact, 2 legs)  : +%.1f%%\n", 100*float64(2*len(b))/18784)
}
