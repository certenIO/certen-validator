// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

const secretToken = "0123456789abcdef0123456789abcdef"

func rpcServer(t *testing.T, handler func(method string, params []json.RawMessage) (any, *struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}, int)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, rerr, status := handler(req.Method, req.Params)
		if status != 0 && status != 200 {
			w.WriteHeader(status)
			fmt.Fprintf(w, "internal body with %s that must never be echoed", secretToken)
			return
		}
		out := map[string]any{"jsonrpc": "2.0", "id": 1}
		if rerr != nil {
			out["error"] = rerr
		} else {
			out["result"] = res
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

type rpcErr = struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func blockJSON(number uint64, parent string) map[string]any {
	m := map[string]any{
		"parentHash": parent, "sha3Uncles": "0x" + strings.Repeat("11", 32), "miner": "0x" + strings.Repeat("22", 20),
		"stateRoot": "0x" + strings.Repeat("33", 32), "transactionsRoot": "0x" + strings.Repeat("44", 32), "receiptsRoot": "0x" + strings.Repeat("55", 32),
		"logsBloom": "0x" + strings.Repeat("00", 256), "difficulty": "0x0", "number": fmt.Sprintf("0x%x", number), "gasLimit": "0x1c9c380",
		"gasUsed": "0x5208", "timestamp": "0x6553f100", "extraData": "0x", "mixHash": "0x" + strings.Repeat("66", 32), "nonce": "0x0000000000000000",
		"baseFeePerGas": "0x7", "withdrawalsRoot": "0x" + strings.Repeat("77", 32), "blobGasUsed": "0x0", "excessBlobGas": "0x0",
		"parentBeaconBlockRoot": "0x" + strings.Repeat("88", 32), "requestsHash": "0x" + strings.Repeat("99", 32),
	}
	raw, err := headerRLP(m)
	if err != nil {
		panic(err)
	}
	m["hash"] = "0x" + hex.EncodeToString(crypto.Keccak256(raw))
	return m
}

func TestHTTPL1TriesProvidersInOrderAndNeverEchoesABodyOrASecret(t *testing.T) {
	bad := rpcServer(t, func(string, []json.RawMessage) (any, *rpcErr, int) { return nil, nil, 500 })
	defer bad.Close()
	rpcFail := rpcServer(t, func(string, []json.RawMessage) (any, *rpcErr, int) {
		return nil, &rpcErr{Code: -32602, Message: "distance to target block exceeds maximum proof window at " + secretURL}, 0
	})
	defer rpcFail.Close()
	good := rpcServer(t, func(m string, p []json.RawMessage) (any, *rpcErr, int) {
		switch m {
		case "eth_blockNumber":
			return "0x10", nil, 0
		case "eth_getBlockByNumber":
			return blockJSON(16, "0x"+strings.Repeat("ab", 32)), nil, 0
		}
		return nil, &rpcErr{Code: -1, Message: "unexpected"}, 0
	})
	defer good.Close()

	h := NewHTTPL1(bad.URL, rpcFail.URL, good.URL)
	head, err := h.HeadNumber(context.Background())
	if err != nil || head != 16 {
		t.Fatalf("head %d %v", head, err)
	}
	hd, err := h.Header(context.Background(), 16)
	if err != nil || hd.Number != 16 || crypto.Keccak256Hash(hd.RLP) != hd.Hash {
		t.Fatalf("header %+v %v", hd, err)
	}

	// every provider fails: the error names hosts and statuses, never a body or the secret
	all := NewHTTPL1(bad.URL, rpcFail.URL)
	_, err = all.GetProof(context.Background(), [20]byte{1}, nil, 5, nil)
	var pe *ProviderErrors
	if !errors.As(err, &pe) || len(pe.Failures) != 2 {
		t.Fatalf("error %v", err)
	}
	for _, s := range append(pe.Strings(), err.Error()) {
		if strings.Contains(s, secretToken) || strings.Contains(s, "internal body") {
			t.Fatalf("provider text leaked: %q", s)
		}
	}
	if !strings.Contains(pe.Strings()[0], "http 500") || !strings.Contains(pe.Strings()[1], "proof window") {
		t.Fatalf("failures do not say what happened: %v", pe.Strings())
	}
}

func TestHTTPL1RefusesAHeaderThatDoesNotHashToTheStatedHash(t *testing.T) {
	srv := rpcServer(t, func(m string, _ []json.RawMessage) (any, *rpcErr, int) {
		b := blockJSON(7, "0x"+strings.Repeat("ab", 32))
		b["hash"] = "0x" + strings.Repeat("00", 32)
		return b, nil, 0
	})
	defer srv.Close()
	if _, err := NewHTTPL1(srv.URL).Header(context.Background(), 7); err == nil || !strings.Contains(err.Error(), "does not hash") {
		t.Fatalf("a header with a wrong stated hash was accepted: %v", err)
	}
	// a provider that answers another block is refused too
	srv2 := rpcServer(t, func(string, []json.RawMessage) (any, *rpcErr, int) {
		return blockJSON(8, "0x"+strings.Repeat("ab", 32)), nil, 0
	})
	defer srv2.Close()
	if _, err := NewHTTPL1(srv2.URL).Header(context.Background(), 7); err == nil {
		t.Fatal("a provider that answered another block was accepted")
	}
}

func TestHTTPL1GetProofAppliesTheAcceptorToEachProvider(t *testing.T) {
	answer := func(value string) *httptest.Server {
		return rpcServer(t, func(string, []json.RawMessage) (any, *rpcErr, int) {
			return map[string]any{
				"accountProof": []string{"0xc0"}, "storageHash": "0x" + strings.Repeat("11", 32), "codeHash": "0x" + strings.Repeat("22", 32),
				"storageProof": []map[string]any{{"key": "0x01", "value": value, "proof": []string{"0xc0"}}},
			}, nil, 0
		})
	}
	first, second := answer("0x1"), answer("0x2")
	defer first.Close()
	defer second.Close()
	h := NewHTTPL1(first.URL, second.URL)
	p, err := h.GetProof(context.Background(), [20]byte{1}, [][32]byte{{1}}, 3, func(p *Proof) error {
		if p.Slots[0].Value[31] != 2 {
			return errors.New("not the value we verified")
		}
		return nil
	})
	if err != nil || p.Slots[0].Value[31] != 2 {
		t.Fatalf("the acceptor did not move on to the second provider: %v", err)
	}
	if _, err := h.GetProof(context.Background(), [20]byte{1}, [][32]byte{{1}, {2}}, 3, nil); err == nil {
		t.Fatal("an answer for a different slot list was accepted")
	}
}

func TestHTTPBeaconSelectsByVersionedHashAndTheProofVerifies(t *testing.T) {
	mk := func(seed byte) []byte {
		b := make([]byte, BlobBytes)
		for i := 0; i < BlobBytes; i += 32 {
			b[i+31] = seed
			b[i+30] = byte(i >> 5)
		}
		return b
	}
	b1, b2 := mk(1), mk(2)
	var blob2 kzg4844.Blob
	copy(blob2[:], b2)
	c2, err := kzg4844.BlobToCommitment(&blob2)
	if err != nil {
		t.Fatal(err)
	}
	var c [48]byte
	copy(c[:], c2[:])
	want := VersionedHash(c)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eth/v1/beacon/blobs/100":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []string{"0x" + hex.EncodeToString(b1), "0x" + hex.EncodeToString(b2)}})
		case "/eth/v1/beacon/blobs/101":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []string{}})
		default:
			w.WriteHeader(404)
			fmt.Fprintf(w, "body %s", secretToken)
		}
	}))
	defer srv.Close()
	bc := NewHTTPBeacon(srv.URL)
	got, err := bc.Sidecars(context.Background(), 100, [][32]byte{want})
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	sc := got[want]
	if string(sc.Blob) != string(b2) || sc.Commitment != c {
		t.Fatal("the blob selected is not the one whose commitment hashes to the versioned hash")
	}
	var cm kzg4844.Commitment
	var pf kzg4844.Proof
	copy(cm[:], sc.Commitment[:])
	copy(pf[:], sc.Proof[:])
	if err := kzg4844.VerifyBlobProof(&blob2, cm, pf); err != nil {
		t.Fatalf("the proof the beacon source computed does not verify: %v", err)
	}
	// a wanted hash the block does not hold
	if _, err := bc.Sidecars(context.Background(), 100, [][32]byte{{0x01, 0xff}}); err == nil {
		t.Fatal("a missing versioned hash was not an error")
	}
	if _, err := bc.Sidecars(context.Background(), 101, [][32]byte{want}); err == nil {
		t.Fatal("an empty block answered a wanted hash")
	}
	_, err = bc.Sidecars(context.Background(), 5, [][32]byte{want})
	var be *BeaconError
	if !errors.As(err, &be) || be.Status != 404 || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("%v", err)
	}
}
