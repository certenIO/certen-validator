// Live end-to-end validation of the ValidatorSetProof chain-height binding.
//
// The state hasher is [main, secondaryState, chains, pending], so the receipt's
// second step is H(chains || pending). Neither component is returned directly by
// the API. This checks that a client can DERIVE both and have the derivation
// confirmed by the receipt - which is what makes the chain heights bound rather
// than asserted.
//
//	secondaryState : 32 zero bytes for a plain data account
//	chains         : merkle over each chain's DAG root, itself folded from the
//	                 chain query's "state" (the merkle State.Pending list)
//	pending        : 32 zero bytes when the account has no pending transactions
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

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

func h2b(s string) []byte { b, _ := hex.DecodeString(s); return b }

func comb(l, r []byte) []byte {
	d := sha256.Sum256(append(append([]byte{}, l...), r...))
	return d[:]
}

// stateAnchor mirrors merkle.State.Anchor: fold Pending, v on the left.
func stateAnchor(pending []*string) []byte {
	var anchor []byte
	for _, v := range pending {
		if anchor == nil {
			if v != nil {
				anchor = h2b(*v)
			}
			continue
		}
		if v != nil {
			anchor = comb(h2b(*v), anchor)
		}
	}
	return anchor
}

// merkleHash mirrors merkle.Hasher.MerkleHash: build a State, then Anchor.
func merkleHash(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return make([]byte, 32)
	}
	var pend [][]byte
	for _, l := range leaves {
		cur := l
		for i := 0; ; i++ {
			if i == len(pend) {
				pend = append(pend, cur)
				break
			}
			if pend[i] == nil {
				pend[i] = cur
				break
			}
			cur = comb(pend[i], cur)
			pend[i] = nil
		}
	}
	var out []byte
	for _, h := range pend {
		if h == nil {
			continue
		}
		if out == nil {
			out = h
			continue
		}
		out = comb(h, out)
	}
	if out == nil {
		return make([]byte, 32)
	}
	return out
}

func main() {
	net := "kermit"
	if len(os.Args) > 1 {
		net = os.Args[1]
	}
	server := fmt.Sprintf("https://%s.accumulatenetwork.io/v3", net)
	allOK := true

	for _, acct := range []string{"acc://dn.acme/network", "acc://dn.acme/globals"} {
		raw := rpc(server, map[string]any{
			"scope": acct,
			"query": map[string]any{"queryType": "default", "includeReceipt": true},
		})
		var rec struct {
			Receipt struct {
				Entries []struct {
					Hash  string `json:"hash"`
					Right bool   `json:"right"`
				} `json:"entries"`
			} `json:"receipt"`
			Pending struct {
				Total int `json:"total"`
			} `json:"pending"`
		}
		json.Unmarshal(raw, &rec)

		chains := rpc(server, map[string]any{"scope": acct, "query": map[string]any{"queryType": "chain"}})
		var cr struct {
			Records []struct {
				Name  string    `json:"name"`
				Count uint64    `json:"count"`
				State []*string `json:"state"`
			} `json:"records"`
		}
		json.Unmarshal(chains, &cr)

		var leaves [][]byte
		for _, c := range cr.Records {
			if c.Count == 0 {
				leaves = append(leaves, make([]byte, 32))
				continue
			}
			leaves = append(leaves, stateAnchor(c.State))
		}
		chainsComp := merkleHash(leaves)
		pendingHash := make([]byte, 32) // no pending transactions
		computed := comb(chainsComp, pendingHash)

		fmt.Printf("=== %s : %s ===\n", net, acct)
		fmt.Printf("  chains            : %d, pending total %d\n", len(cr.Records), rec.Pending.Total)
		fmt.Printf("  secondary sibling : %s\n", rec.Receipt.Entries[0].Hash)
		fmt.Printf("    derivable as 32 zero bytes: %v\n",
			rec.Receipt.Entries[0].Hash == hex.EncodeToString(make([]byte, 32)))
		fmt.Printf("  chains component  : %x\n", chainsComp)
		fmt.Printf("  H(chains||pending): %x\n", computed)
		fmt.Printf("  receipt step[1]   : %s\n", rec.Receipt.Entries[1].Hash)
		ok := hex.EncodeToString(computed) == rec.Receipt.Entries[1].Hash
		fmt.Printf("  CHAIN HEIGHTS BOUND: %v\n\n", ok)
		allOK = allOK && ok
	}
	fmt.Printf("RESULT: the chain-height binding is derivable and confirmed by the receipt: %v\n", allOK)
	if !allOK {
		os.Exit(1)
	}
}
