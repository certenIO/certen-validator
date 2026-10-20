// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// fakeProvider answers JSON-RPC from a fixed table; a method it does not know is a 500 whose body carries a secret.
func fakeProvider(t *testing.T, h *types.Header, proofNodes []string) *httptest.Server {
	t.Helper()
	hdrJSON, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var blk map[string]any
	_ = json.Unmarshal(hdrJSON, &blk)
	blk["transactions"] = []any{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "eth_blockNumber":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x3e8"}`))
		case "eth_getBlockByNumber", "eth_getBlockByHash":
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": blk})
			w.Write(out)
		case "eth_getProof":
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
				"accountProof": proofNodes,
				"storageProof": []any{map[string]any{"key": "0x67", "value": "0x01", "proof": proofNodes}},
			}})
			w.Write(out)
		default:
			w.WriteHeader(500)
			w.Write([]byte("secret-provider-body https://user:supersecretkey@node.example/v2/abcdef0123456789"))
		}
	}))
}

func TestJSONRPCSourceAgainstAFakeProviderRedactsAndNeverEchoesABody(t *testing.T) {
	h := &types.Header{Number: big.NewInt(1000), ParentHash: common.Hash{1}, Root: common.Hash{2}, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
		UncleHash: types.EmptyUncleHash, Difficulty: big.NewInt(0), Time: 1700000000, GasLimit: 30000000, BaseFee: big.NewInt(7)}
	srv := fakeProvider(t, h, []string{"0x80", "0x81"})
	defer srv.Close()
	s := &JSONRPCSource{BlockURLs: []string{srv.URL}, ProofURLs: []string{srv.URL}}
	ctx := context.Background()
	if n, err := s.Head(ctx); err != nil || n != 1000 {
		t.Fatalf("head %d %v", n, err)
	}
	blk, err := s.Block(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if blk.Hash != [32]byte(h.Hash()) || blk.Number != 1000 || blk.Timestamp != 1700000000 || len(blk.TxRaw) != 0 {
		t.Fatalf("%+v", blk)
	}
	raw, parent, num, err := s.HeaderByHash(ctx, blk.Hash)
	if err != nil || num != 1000 || parent != [32]byte(h.ParentHash) || len(raw) == 0 {
		t.Fatalf("header by hash: %v %d", err, num)
	}
	if _, _, _, err := s.HeaderByHash(ctx, [32]byte{9}); err == nil {
		t.Fatal("a header that does not hash to the request must be refused")
	}
	sp, err := s.Proof(ctx, [20]byte{1}, [][32]byte{batcherHashSlot}, 1000)
	if err != nil || len(sp.Nodes) != 4 {
		t.Fatalf("proof: %v %d", err, len(sp.Nodes))
	}
	// an unknown method: the provider's body (with a credential in it) is never part of the error
	_, err = s.call(ctx, srv.URL, "eth_unknown")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, leak := range []string{"supersecretkey", "secret-provider-body", "abcdef0123456789"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error echoes provider text: %v", err)
		}
	}
	// a transport failure goes through the redactor too
	srv.Close()
	if _, err := s.Head(ctx); err == nil || strings.Contains(err.Error(), srv.URL+"/") {
		t.Fatalf("transport error %v", err)
	}
}

func TestBeaconHTTPFallsBackToSidecarsAndReportsOnlyTheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/blobs/"):
			w.WriteHeader(404)
			w.Write([]byte("no such route: secret-beacon-body"))
		case strings.Contains(r.URL.Path, "/blob_sidecars/7"):
			w.Write([]byte(`{"data":[{"blob":"0x0102"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	bc := &BeaconHTTP{Bases: []string{srv.URL}}
	got, err := bc.Blobs(context.Background(), 7)
	if err != nil || len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	_, err = bc.Blobs(context.Background(), 8)
	var se *StatusError
	if err == nil || !asStatus(err, &se) || se.Status != 404 || strings.Contains(err.Error(), "secret-beacon-body") {
		t.Fatalf("%v", err)
	}
}

func asStatus(err error, out **StatusError) bool {
	s, ok := err.(*StatusError)
	if ok {
		*out = s
	}
	return ok
}
