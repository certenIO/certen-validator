// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// maxResponse bounds any provider answer read into memory.
const maxResponse = 64 << 20

// RPC is the live JSON-RPC source of the builder. BlockURLs serve L1 blocks, the head and calls (any full node); ProofURLs serve
// eth_getProof (public providers hold proofs only near the head: 0xrpc.io/sep serves head-100); L2URLs serve Base Sepolia
// blocks (not windowed). Provider text never leaves this type unredacted (ethrpc.RedactError) and an answer body is never echoed.
type RPC struct {
	BlockURLs []string
	ProofURLs []string
	L2URLs    []string
	Client    *http.Client
}

func (s *RPC) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func redact(err error) error { return ethrpc.RedactError(err) }

func (s *RPC) call(ctx context.Context, url, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, redact(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, redact(err)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: HTTP %d, answer is not JSON-RPC", method, resp.StatusCode)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: provider error code %d", method, out.Error.Code)
	}
	if len(out.Result) == 0 || string(out.Result) == "null" {
		return nil, fmt.Errorf("%s: no result", method)
	}
	return out.Result, nil
}

func (s *RPC) first(ctx context.Context, urls []string, method string, params ...any) (json.RawMessage, error) {
	var last error
	for _, u := range urls {
		r, err := s.call(ctx, u, method, params...)
		if err == nil {
			return r, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("%s: no provider configured", method)
	}
	return nil, last
}

func unhexBytes(s string) []byte {
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return b
}

func bigOf(s string) *big.Int {
	v, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if v == nil {
		return new(big.Int)
	}
	return v
}

// headerFromBlock re-encodes the header RLP positionally from the provider JSON, in the order go-ethereum and the consensus
// layer append fields; the caller checks keccak(rlp) equals the block hash, so a field the encoder lacks is a refusal.
func headerFromBlock(m map[string]any) ([]byte, error) {
	s := func(k string) string { v, _ := m[k].(string); return v }
	has := func(k string) bool { _, ok := m[k].(string); return ok } // a JSON null is an absent field
	items := []any{
		unhexBytes(s("parentHash")), unhexBytes(s("sha3Uncles")), unhexBytes(s("miner")), unhexBytes(s("stateRoot")), unhexBytes(s("transactionsRoot")),
		unhexBytes(s("receiptsRoot")), unhexBytes(s("logsBloom")), bigOf(s("difficulty")), bigOf(s("number")), bigOf(s("gasLimit")),
		bigOf(s("gasUsed")), bigOf(s("timestamp")), unhexBytes(s("extraData")), unhexBytes(s("mixHash")), unhexBytes(s("nonce")),
	}
	if has("baseFeePerGas") {
		items = append(items, bigOf(s("baseFeePerGas")))
	}
	if has("withdrawalsRoot") {
		items = append(items, unhexBytes(s("withdrawalsRoot")))
	}
	for _, k := range []string{"blobGasUsed", "excessBlobGas"} {
		if has(k) {
			items = append(items, bigOf(s(k)))
		}
	}
	for _, k := range []string{"parentBeaconBlockRoot", "requestsHash", "blockAccessListHash"} {
		if has(k) {
			items = append(items, unhexBytes(s(k)))
		}
	}
	if has("slotNumber") {
		items = append(items, bigOf(s("slotNumber")))
	}
	return rlp.EncodeToBytes(items)
}

// HeaderInfo is one header read from a provider, re-encoded positionally and checked to hash to the provider's block hash.
type HeaderInfo struct {
	Raw       []byte
	Hash      [32]byte
	Parent    [32]byte
	Number    uint64
	Timestamp uint64
	StateRoot [32]byte
}

func (s *RPC) header(ctx context.Context, urls []string, method string, param any) (HeaderInfo, error) {
	var out HeaderInfo
	// public providers answer an occasional null for a block they serve a second later: retry a few times before refusing
	var r json.RawMessage
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if r, err = s.first(ctx, urls, method, param, false); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		return out, err
	}
	var m map[string]any
	if err := json.Unmarshal(r, &m); err != nil {
		return out, fmt.Errorf("%s: answer is not a block", method)
	}
	raw, err := headerFromBlock(m)
	if err != nil {
		return out, err
	}
	out.Raw = raw
	out.Hash = [32]byte(crypto.Keccak256Hash(raw))
	if want, _ := m["hash"].(string); "0x"+hex.EncodeToString(out.Hash[:]) != strings.ToLower(want) {
		return out, fmt.Errorf("the re-encoded header does not hash to the provider's block hash")
	}
	str := func(k string) string { v, _ := m[k].(string); return v }
	copy(out.Parent[:], unhexBytes(str("parentHash")))
	copy(out.StateRoot[:], unhexBytes(str("stateRoot")))
	out.Number, out.Timestamp = bigOf(str("number")).Uint64(), bigOf(str("timestamp")).Uint64()
	return out, nil
}

// L1Head is the current head number of the L1 block providers.
func (s *RPC) L1Head(ctx context.Context) (uint64, error) { return s.head(ctx, s.BlockURLs) }

// ProofHead is the current head number of the proof providers (the near-head window is relative to it).
func (s *RPC) ProofHead(ctx context.Context) (uint64, error) { return s.head(ctx, s.ProofURLs) }

func (s *RPC) head(ctx context.Context, urls []string) (uint64, error) {
	r, err := s.first(ctx, urls, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	var h string
	if err := json.Unmarshal(r, &h); err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimPrefix(h, "0x"), 16, 64)
}

// L1HeaderByNumber / L1HeaderByHash / L2HeaderByNumber read one header.
func (s *RPC) L1HeaderByNumber(ctx context.Context, n uint64) (HeaderInfo, error) {
	return s.header(ctx, s.BlockURLs, "eth_getBlockByNumber", fmt.Sprintf("0x%x", n))
}
func (s *RPC) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	return s.header(ctx, s.BlockURLs, "eth_getBlockByHash", "0x"+hex.EncodeToString(h[:]))
}
func (s *RPC) L2HeaderByNumber(ctx context.Context, n uint64) (HeaderInfo, error) {
	return s.header(ctx, s.L2URLs, "eth_getBlockByNumber", fmt.Sprintf("0x%x", n))
}

// Code reads the runtime code of an account at an L1 block (proof providers first: they hold the recent state).
func (s *RPC) Code(ctx context.Context, addr [20]byte, block uint64) ([]byte, error) {
	r, err := s.first(ctx, append(append([]string{}, s.ProofURLs...), s.BlockURLs...), "eth_getCode", "0x"+hex.EncodeToString(addr[:]), fmt.Sprintf("0x%x", block))
	if err != nil {
		return nil, err
	}
	var h string
	if err := json.Unmarshal(r, &h); err != nil {
		return nil, err
	}
	return unhexBytes(h), nil
}

// StorageAtLatest reads one slot at the latest block (not windowed; used for builder-side status, never as evidence).
func (s *RPC) StorageAtLatest(ctx context.Context, addr [20]byte, slot [32]byte) ([32]byte, error) {
	var out [32]byte
	r, err := s.first(ctx, s.BlockURLs, "eth_getStorageAt", "0x"+hex.EncodeToString(addr[:]), "0x"+hex.EncodeToString(slot[:]), "latest")
	if err != nil {
		return out, err
	}
	var h string
	if err := json.Unmarshal(r, &h); err != nil {
		return out, err
	}
	b := unhexBytes(h)
	if len(b) > 32 {
		return out, fmt.Errorf("storage word longer than 32 bytes")
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// CallLatest runs a read-only call at the latest block (builder-side discovery only, never evidence).
func (s *RPC) CallLatest(ctx context.Context, to [20]byte, data []byte) ([]byte, error) {
	r, err := s.first(ctx, s.BlockURLs, "eth_call", map[string]string{"to": "0x" + hex.EncodeToString(to[:]), "data": "0x" + hex.EncodeToString(data)}, "latest")
	if err != nil {
		return nil, err
	}
	var h string
	if err := json.Unmarshal(r, &h); err != nil {
		return nil, err
	}
	return unhexBytes(h), nil
}

// StateProof is one eth_getProof answer: the union of the account proof and every requested slot's storage proof.
type StateProof struct {
	Nodes    [][]byte
	CodeHash [32]byte
	Values   map[[32]byte][32]byte
}

// Proof reads eth_getProof for an account and slots at an L1 block from the proof providers.
func (s *RPC) Proof(ctx context.Context, addr [20]byte, slots [][32]byte, block uint64) (StateProof, error) {
	var sp StateProof
	ss := make([]string, len(slots))
	for i, x := range slots {
		ss[i] = "0x" + hex.EncodeToString(x[:])
	}
	r, err := s.first(ctx, s.ProofURLs, "eth_getProof", "0x"+hex.EncodeToString(addr[:]), ss, fmt.Sprintf("0x%x", block))
	if err != nil {
		return sp, err
	}
	var p struct {
		CodeHash     string   `json:"codeHash"`
		AccountProof []string `json:"accountProof"`
		StorageProof []struct {
			Key   string   `json:"key"`
			Value string   `json:"value"`
			Proof []string `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(r, &p); err != nil {
		return sp, fmt.Errorf("eth_getProof: answer is not a proof")
	}
	copy(sp.CodeHash[:], unhexBytes(p.CodeHash))
	for _, n := range p.AccountProof {
		sp.Nodes = append(sp.Nodes, unhexBytes(n))
	}
	sp.Values = map[[32]byte][32]byte{}
	for _, sl := range p.StorageProof {
		for _, n := range sl.Proof {
			sp.Nodes = append(sp.Nodes, unhexBytes(n))
		}
		var k, v [32]byte
		kb, vb := unhexBytes(sl.Key), bigOf(sl.Value).Bytes()
		copy(k[32-len(kb):], kb)
		copy(v[32-len(vb):], vb)
		sp.Values[k] = v
	}
	return sp, nil
}
