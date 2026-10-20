// Copyright 2026 Certen Protocol

package baseposted

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

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// maxResponse bounds any provider answer read into memory (a full Sepolia block with blob transactions is well below it).
const maxResponse = 64 << 20

// JSONRPCSource is the live L1Source over JSON-RPC providers: BlockURLs serve blocks and the head (any full node),
// ProofURLs serve eth_getProof (providers hold proofs only near the head: 0xrpc.io/sep serves head-100, publicnode head-2).
// Provider text never leaves this type unredacted (ethrpc.RedactText) and an answer body is never echoed.
type JSONRPCSource struct {
	BlockURLs []string
	ProofURLs []string
	Client    *http.Client
}

func (s *JSONRPCSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func redact(err error) error { return ethrpc.RedactError(err) }

func (s *JSONRPCSource) call(ctx context.Context, url, method string, params ...any) (json.RawMessage, error) {
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
			Code int `json:"code"`
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

func (s *JSONRPCSource) first(ctx context.Context, urls []string, method string, params ...any) (json.RawMessage, error) {
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

func (s *JSONRPCSource) Head(ctx context.Context) (uint64, error) {
	r, err := s.first(ctx, s.BlockURLs, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	var h string
	if err := json.Unmarshal(r, &h); err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimPrefix(h, "0x"), 16, 64)
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

func (s *JSONRPCSource) Block(ctx context.Context, number uint64) (L1BlockData, error) {
	var out L1BlockData
	r, err := s.first(ctx, s.BlockURLs, "eth_getBlockByNumber", fmt.Sprintf("0x%x", number), true)
	if err != nil {
		return out, err
	}
	var m map[string]any
	if err := json.Unmarshal(r, &m); err != nil {
		return out, err
	}
	hdr, err := headerFromBlock(m)
	if err != nil {
		return out, err
	}
	out.HeaderRLP = hdr
	out.Hash = [32]byte(crypto.Keccak256Hash(hdr))
	if want, _ := m["hash"].(string); "0x"+hex.EncodeToString(out.Hash[:]) != strings.ToLower(want) {
		return out, fmt.Errorf("block %d: the re-encoded header does not hash to the provider's block hash", number)
	}
	out.Number = number
	out.Timestamp = bigOf(m["timestamp"].(string)).Uint64()
	var txs struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(r, &txs); err != nil {
		return out, err
	}
	for i, raw := range txs.Transactions {
		enc, _, err := ethproof.EncodeTxJSON(raw)
		if err != nil {
			return out, fmt.Errorf("block %d tx %d: %v", number, i, err)
		}
		var t struct {
			To                  *string  `json:"to"`
			BlobVersionedHashes []string `json:"blobVersionedHashes"`
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			return out, err
		}
		out.TxRaw = append(out.TxRaw, enc)
		var to [20]byte
		has := t.To != nil
		if has {
			copy(to[:], unhexBytes(*t.To))
		}
		out.TxTo = append(out.TxTo, to)
		out.TxHasTo = append(out.TxHasTo, has)
		var hs [][32]byte
		for _, h := range t.BlobVersionedHashes {
			var a [32]byte
			copy(a[:], unhexBytes(h))
			hs = append(hs, a)
		}
		out.TxBlobHash = append(out.TxBlobHash, hs)
	}
	return out, nil
}

func (s *JSONRPCSource) Proof(ctx context.Context, address [20]byte, slots [][32]byte, block uint64) (StateProof, error) {
	var sp StateProof
	ss := make([]string, len(slots))
	for i, x := range slots {
		ss[i] = "0x" + hex.EncodeToString(x[:])
	}
	r, err := s.first(ctx, s.ProofURLs, "eth_getProof", "0x"+hex.EncodeToString(address[:]), ss, fmt.Sprintf("0x%x", block))
	if err != nil {
		return sp, err
	}
	var p struct {
		AccountProof []string `json:"accountProof"`
		StorageProof []struct {
			Key   string   `json:"key"`
			Value string   `json:"value"`
			Proof []string `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(r, &p); err != nil {
		return sp, err
	}
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

// BeaconHTTP is the live BeaconSource: GET {Base}/eth/v1/beacon/blobs/{slot} (Gloas: blob_sidecars is gone), falling back to
// /eth/v1/beacon/blob_sidecars/{slot} on a non-200. A non-200 is reported with its status only.
type BeaconHTTP struct {
	Bases  []string
	Client *http.Client
}

// StatusError carries the HTTP status of a beacon answer (the http_status field of l1_blob_unavailable).
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("beacon blob answer HTTP %d", e.Status) }

func (b *BeaconHTTP) Blobs(ctx context.Context, slot uint64) ([][]byte, error) {
	cl := b.Client
	if cl == nil {
		cl = &http.Client{Timeout: 120 * time.Second}
	}
	var last error = fmt.Errorf("no beacon endpoint configured")
	for _, base := range b.Bases {
		for _, path := range []string{"/eth/v1/beacon/blobs/%d", "/eth/v1/beacon/blob_sidecars/%d"} {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+fmt.Sprintf(path, slot), nil)
			if err != nil {
				last = redact(err)
				continue
			}
			resp, err := cl.Do(req)
			if err != nil {
				last = redact(err)
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
			resp.Body.Close()
			if err != nil {
				last = redact(err)
				continue
			}
			if resp.StatusCode != 200 {
				last = &StatusError{resp.StatusCode}
				continue
			}
			var d struct {
				Data []json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(body, &d); err != nil {
				last = fmt.Errorf("beacon blob answer is not JSON")
				continue
			}
			var out [][]byte
			for _, e := range d.Data {
				var s string
				if json.Unmarshal(e, &s) == nil {
					out = append(out, unhexBytes(s))
					continue
				}
				var sc struct {
					Blob string `json:"blob"`
				}
				if json.Unmarshal(e, &sc) == nil && sc.Blob != "" {
					out = append(out, unhexBytes(sc.Blob))
				}
			}
			if len(out) > 0 {
				return out, nil
			}
			last = fmt.Errorf("beacon blob answer carries no blobs")
		}
	}
	return nil, last
}

// HeaderByHash is HeaderSource: one L1 header by hash, re-encoded positionally and checked to hash to the request.
func (s *JSONRPCSource) HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, [32]byte, uint64, error) {
	var parent [32]byte
	r, err := s.first(ctx, s.BlockURLs, "eth_getBlockByHash", "0x"+hex.EncodeToString(hash[:]), false)
	if err != nil {
		return nil, parent, 0, err
	}
	var m map[string]any
	if err := json.Unmarshal(r, &m); err != nil {
		return nil, parent, 0, err
	}
	raw, err := headerFromBlock(m)
	if err != nil {
		return nil, parent, 0, err
	}
	if [32]byte(crypto.Keccak256Hash(raw)) != hash {
		return nil, parent, 0, fmt.Errorf("the re-encoded header does not hash to the requested hash")
	}
	copy(parent[:], unhexBytes(m["parentHash"].(string)))
	return raw, parent, bigOf(m["number"].(string)).Uint64(), nil
}

// L2JSONRPC is the live L2Source.
type L2JSONRPC struct{ URLs []string }

func (l *L2JSONRPC) Block(ctx context.Context, number uint64) (L2BlockData, error) {
	s := &JSONRPCSource{BlockURLs: l.URLs}
	r, err := s.first(ctx, l.URLs, "eth_getBlockByNumber", fmt.Sprintf("0x%x", number), true)
	if err != nil {
		return L2BlockData{}, err
	}
	var blk struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(r, &blk); err != nil {
		return L2BlockData{}, err
	}
	out := L2BlockData{Number: number}
	for i, raw := range blk.Transactions {
		enc, _, err := ethproof.EncodeTxJSON(raw)
		if err != nil {
			return out, fmt.Errorf("L2 block %d tx %d: %v", number, i, err)
		}
		out.Txs = append(out.Txs, enc)
	}
	return out, nil
}

// HeaderByNumber reads one block header of the chain the BlockURLs serve (the L2 for a Base provider), re-encoded positionally.
func (s *JSONRPCSource) HeaderByNumber(ctx context.Context, number uint64) (raw []byte, hash [32]byte, ts uint64, err error) {
	r, err := s.first(ctx, s.BlockURLs, "eth_getBlockByNumber", fmt.Sprintf("0x%x", number), false)
	if err != nil {
		return nil, hash, 0, err
	}
	var m map[string]any
	if err := json.Unmarshal(r, &m); err != nil {
		return nil, hash, 0, err
	}
	raw, err = headerFromBlock(m)
	if err != nil {
		return nil, hash, 0, err
	}
	hash = [32]byte(crypto.Keccak256Hash(raw))
	if want, _ := m["hash"].(string); "0x"+hex.EncodeToString(hash[:]) != strings.ToLower(want) {
		return nil, hash, 0, fmt.Errorf("block %d: the re-encoded header does not hash to the provider's block hash", number)
	}
	return raw, hash, bigOf(m["timestamp"].(string)).Uint64(), nil
}
