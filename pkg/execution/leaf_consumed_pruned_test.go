// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB4-F65. A sequential successor is released when its predecessor's leaf is consumed as of the predecessor chain's
// FINALIZED block, and that was read with an eth_call at the finalized block. Arbitrum Sepolia's finalized block
// trails its head by ~18 minutes (~4,500 blocks) and the configured node serves no state that old: every read failed
// "historical state … is not available", and intent 728ce961's ethereum member waited on its arbitrum predecessor
// forever (2026-09-29, from 12:38:00 every minute). A leaf once consumed stays consumed and every consumption emits
// LeafConsumed(anchorId, leaf, operationID): it is consumed as of block N exactly when it is consumed now and no
// LeafConsumed for it was emitted after N. Neither needs historical state.

// prunedNode answers like a node that keeps only recent state: headers and logs for any block, contract state only at
// the head.
type prunedNode struct {
	head       uint64
	hasCode    bool
	consumed   bool   // isLeafConsumed at the head
	consumedAt uint64 // the block its LeafConsumed was emitted in (0: none)
	leaf       [32]byte
	logsErr    bool
	callErr    bool     // eth_call fails at the head too
	stateCalls []string // the block each eth_call asked for
}

func (p *prunedNode) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(result string) { _, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result) }
		fail := func(msg string) {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":%q}}`, req.ID, msg)
		}
		blockArg := func(i int) string {
			if len(req.Params) <= i {
				return "latest"
			}
			var s string
			_ = json.Unmarshal(req.Params[i], &s)
			return s
		}
		isHead := func(b string) bool { return b == "latest" || b == fmt.Sprintf("0x%x", p.head) }
		switch req.Method {
		case "eth_getBlockByNumber", "eth_getHeaderByNumber":
			n := p.head
			if b := blockArg(0); b != "latest" && b != "finalized" {
				fmt.Sscanf(b, "0x%x", &n)
			}
			reply(fmt.Sprintf(`{"number":"0x%x","hash":"0x%064x","parentHash":"0x%064x","sha3Uncles":"0x%064x","miner":"0x%040x",`+
				`"stateRoot":"0x%064x","transactionsRoot":"0x%064x","receiptsRoot":"0x%064x","logsBloom":"0x%0512x","difficulty":"0x0",`+
				`"gasLimit":"0x1","gasUsed":"0x0","timestamp":"0x%x","extraData":"0x","mixHash":"0x%064x","nonce":"0x0000000000000000",`+
				`"baseFeePerGas":"0x1","transactions":[],"uncles":[]}`, n, n, 0, 0, 0, 0, 0, 0, 0, 1790680000+n, 0))
		case "eth_call":
			b := blockArg(1)
			p.stateCalls = append(p.stateCalls, b)
			if p.callErr {
				fail("header not found")
				return
			}
			if !isHead(b) {
				fail("historical state bff50abba4636530db13cafd199e7bc67432b1e07b19fc716db0406a0e87ebb4 is not available")
				return
			}
			if !p.hasCode {
				reply(`"0x"`)
				return
			}
			v := "0"
			if p.consumed {
				v = "1"
			}
			reply(`"0x` + fmt.Sprintf("%064s", v) + `"`)
		case "eth_getCode":
			if !isHead(blockArg(1)) {
				fail("historical state bff50abba4636530db13cafd199e7bc67432b1e07b19fc716db0406a0e87ebb4 is not available")
				return
			}
			if p.hasCode {
				reply(`"0x6080"`)
			} else {
				reply(`"0x"`)
			}
		case "eth_getLogs":
			if p.logsErr {
				fail("eth_getLogs unavailable")
				return
			}
			var q struct {
				FromBlock string `json:"fromBlock"`
				ToBlock   string `json:"toBlock"`
			}
			_ = json.Unmarshal(req.Params[0], &q)
			var from, to uint64
			fmt.Sscanf(q.FromBlock, "0x%x", &from)
			fmt.Sscanf(q.ToBlock, "0x%x", &to)
			if p.consumedAt == 0 || p.consumedAt < from || p.consumedAt > to {
				reply(`[]`)
				return
			}
			reply(fmt.Sprintf(`[{"address":"0x1d423de969ad0188a9b6e080e13cfeee8d0cd777","topics":["%s","0x%064x","0x%x"],`+
				`"data":"0x%064x","blockNumber":"0x%x","transactionHash":"0x%064x","transactionIndex":"0x0","blockHash":"0x%064x",`+
				`"logIndex":"0x0","removed":false}]`, crypto.Keccak256Hash([]byte("LeafConsumed(bytes32,bytes32,bytes32)")).Hex(), 1, p.leaf, 2, p.consumedAt, 3, p.consumedAt))
		default:
			fail("not stubbed: " + req.Method)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestALeafIsReadAsOfTheFinalizedBlockWithoutItsHistoricalState(t *testing.T) {
	account, leaf := common.HexToAddress("0x1d423DE969aD0188a9b6E080e13cFEee8d0CD777"), [32]byte{0xbe, 0xef}
	const finalized, head = uint64(313948905), uint64(313953395)
	ctx := context.Background()

	// Consumed before the finalized block: consumed as of it.
	p := &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: finalized - 100, leaf: leaf}
	consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized)
	if err != nil || !consumed {
		t.Fatalf("THE regression: a leaf consumed before the finalized block read as consumed=%v err=%v", consumed, err)
	}
	for _, b := range p.stateCalls {
		if b != "latest" && b != fmt.Sprintf("0x%x", head) {
			t.Fatalf("contract state was read at block %s, which the node does not keep", b)
		}
	}

	// Consumed after it: not yet as of the finalized block.
	p = &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: finalized + 10, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized); err != nil || consumed {
		t.Fatalf("a leaf consumed after the finalized block: consumed=%v err=%v; want not yet", consumed, err)
	}

	// Not consumed now: not consumed then.
	p = &prunedNode{head: head, hasCode: true, consumed: false, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized); err != nil || consumed {
		t.Fatalf("an unconsumed leaf: consumed=%v err=%v", consumed, err)
	}

	// No account now: nothing consumed (RB3-F63's rule, read at the head).
	p = &prunedNode{head: head, hasCode: false, leaf: leaf}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized); err != nil || consumed {
		t.Fatalf("no account: consumed=%v err=%v", consumed, err)
	}

	// Logs that cannot be read decide nothing.
	p = &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: finalized - 100, leaf: leaf, logsErr: true}
	if _, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized); err == nil || !strings.Contains(err.Error(), "LeafConsumed") {
		t.Fatalf("unreadable logs must stay an error naming what could not be read: %v", err)
	}

	// A call that fails at the head decides nothing either.
	p = &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: finalized - 100, leaf: leaf, callErr: true}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, finalized); err == nil || consumed {
		t.Fatalf("a failed call must stay an error: consumed=%v err=%v", consumed, err)
	}

	// Asked as of the head itself, the head's state is the answer: no logs are needed.
	p = &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: head, leaf: leaf, logsErr: true}
	if consumed, err := leafConsumedAt(ctx, p.serve(t), account, leaf, head); err != nil || !consumed {
		t.Fatalf("as of the head: consumed=%v err=%v", consumed, err)
	}

	// A block the node has not reached is not answered.
	p = &prunedNode{head: head, hasCode: true, consumed: true, consumedAt: finalized - 100, leaf: leaf}
	if _, err := leafConsumedAt(ctx, p.serve(t), account, leaf, head+1); err == nil || !strings.Contains(err.Error(), "past the chain head") {
		t.Fatalf("a block past the head must be refused by name: %v", err)
	}
}
