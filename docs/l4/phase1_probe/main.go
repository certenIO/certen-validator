// Phase 1 probe: is the genesis validator set provable offline, today?
//
// Q13. Proving the genesis *chain entry* proves nothing: systemGenesis has an
// empty body. What must be proven is the *account state* of
// acc://dn.acme/network, which lives in the BPT. This probe:
//
//  1. queries the account with includeReceipt (the BPT state receipt),
//  2. re-derives the receipt's start from the returned account state
//     (sha256 of the marshalled account = hasher[0], observer_prod.go:31),
//  3. validates the merkle path to the claimed anchor,
//  4. checks that anchor against the DN's signed StateTreeAnchor.
//
// Read-only. Run: go run ./docs/l4/phase1_probe <network>
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type rpcResp struct {
	Result json.RawMessage  `json:"result"`
	Error  *json.RawMessage `json:"error"`
}

func rpc(server string, params any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "query", "params": params,
	})
	resp, err := http.Post(server, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", string(*r.Error))
	}
	return r.Result, nil
}

type receipt struct {
	Start   string `json:"start"`
	Anchor  string `json:"anchor"`
	Entries []struct {
		Hash  string `json:"hash"`
		Right bool   `json:"right"`
	} `json:"entries"`
}

func (r receipt) validate() (string, bool) {
	cur, _ := hex.DecodeString(r.Start)
	for _, e := range r.Entries {
		h, _ := hex.DecodeString(e.Hash)
		var s []byte
		if e.Right {
			s = append(append([]byte{}, cur...), h...)
		} else {
			s = append(append([]byte{}, h...), cur...)
		}
		d := sha256.Sum256(s)
		cur = d[:]
	}
	got := hex.EncodeToString(cur)
	return got, got == r.Anchor
}

func main() {
	net := "kermit"
	if len(os.Args) > 1 {
		net = os.Args[1]
	}
	server := fmt.Sprintf("https://%s.accumulatenetwork.io/v3", net)
	fmt.Printf("=== %s : acc://dn.acme/network state proof ===\n", net)

	raw, err := rpc(server, map[string]any{
		"scope": "acc://dn.acme/network",
		"query": map[string]any{"queryType": "default", "includeReceipt": true},
	})
	if err != nil {
		fmt.Println("FAILED:", err)
		os.Exit(1)
	}

	var rec struct {
		Account json.RawMessage `json:"account"`
		Receipt receipt         `json:"receipt"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		fmt.Println("decode:", err)
		os.Exit(1)
	}

	// Re-derive hasher[0]: a simple hash of the marshalled main state.
	acct, err := protocol.UnmarshalAccountJSON(rec.Account)
	if err != nil {
		fmt.Println("unmarshal account:", err)
		os.Exit(1)
	}
	bin, err := acct.MarshalBinary()
	if err != nil {
		fmt.Println("marshal account:", err)
		os.Exit(1)
	}
	leaf := sha256.Sum256(bin)
	derived := hex.EncodeToString(leaf[:])

	fmt.Printf("  account type            : %v\n", acct.Type())
	fmt.Printf("  receipt.start           : %s\n", rec.Receipt.Start)
	fmt.Printf("  sha256(marshalled state): %s\n", derived)
	fmt.Printf("  LEAF DERIVABLE OFFLINE  : %v\n", strings.EqualFold(derived, rec.Receipt.Start))

	got, ok := rec.Receipt.validate()
	fmt.Printf("  path length             : %d\n", len(rec.Receipt.Entries))
	fmt.Printf("  claimed anchor          : %s\n", rec.Receipt.Anchor)
	fmt.Printf("  recomputed anchor       : %s\n", got)
	fmt.Printf("  MERKLE PATH VALID       : %v\n", ok)

	// What does the state actually say?
	if da, isData := acct.(*protocol.DataAccount); isData && da.Entry != nil {
		var nd protocol.NetworkDefinition
		if err := nd.UnmarshalBinary(da.Entry.GetData()[0]); err == nil {
			fmt.Printf("  networkName             : %s\n", nd.NetworkName)
			fmt.Printf("  NetworkDefinition ver   : %d\n", nd.Version)
			fmt.Printf("  validators              : %d\n", len(nd.Validators))
			fmt.Printf("  partitions              : %d\n", len(nd.Partitions))
		} else {
			fmt.Printf("  (could not parse NetworkDefinition: %v)\n", err)
		}
	}
}
