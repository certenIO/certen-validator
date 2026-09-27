// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// accountRPC is a JSON-RPC stub for one account: with code, eth_call answers isLeafConsumed with
// consumed; without code, eth_call returns nothing and eth_getCode says there is no contract - the
// shape a real node gives for an account not yet deployed at the requested block.
func accountRPC(t *testing.T, hasCode, consumed bool, callErr bool) *ethclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(result string) {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result)
		}
		switch {
		case req.Method == "eth_call" && callErr:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"header not found"}}`, req.ID)
		case req.Method == "eth_call" && !hasCode:
			reply(`"0x"`)
		case req.Method == "eth_call":
			v := "0"
			if consumed {
				v = "1"
			}
			reply(`"0x` + fmt.Sprintf("%064s", v) + `"`)
		case req.Method == "eth_getCode" && hasCode:
			reply(`"0x6080"`)
		case req.Method == "eth_getCode":
			reply(`"0x"`)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed"}}`, req.ID)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// RB3-F63: a leaf read at a block where the account has no code is "not consumed", not a failed read.
// Seen live on intent 3b990fe3: the Base member's leader read its Sepolia predecessor at the finalized
// block 11792066, before the account was deployed at 11792092, and logged a read failure every pass.
func TestLeafConsumedAtABlockWithoutTheAccountIsNotConsumed(t *testing.T) {
	account, leaf := common.HexToAddress("0x58F490700e8bEB42a282b4EE83C7542335CEd455"), [32]byte{0xaa}

	consumed, err := leafConsumedAt(context.Background(), accountRPC(t, false, false, false), account, leaf, 11792066)
	if err != nil || consumed {
		t.Fatalf("no code at the block: consumed=%v err=%v; want not consumed and no error", consumed, err)
	}
	if consumed, err := leafConsumedAt(context.Background(), accountRPC(t, true, true, false), account, leaf, 11792152); err != nil || !consumed {
		t.Fatalf("deployed and consumed: consumed=%v err=%v", consumed, err)
	}
	if consumed, err := leafConsumedAt(context.Background(), accountRPC(t, true, false, false), account, leaf, 11792152); err != nil || consumed {
		t.Fatalf("deployed, not consumed: consumed=%v err=%v", consumed, err)
	}
	// A read that genuinely fails still decides nothing.
	if _, err := leafConsumedAt(context.Background(), accountRPC(t, true, false, true), account, leaf, 11792152); err == nil {
		t.Fatal("a failed call must stay an error")
	}
}
