// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// HeaderSource serves the RAW consensus RLP of execution headers. The bytes are hashed and read positionally by the verifier;
// a source never decodes a header into a typed struct (a future field would make a typed decode fail while the hash still
// holds, spec section 0).
type HeaderSource interface {
	HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error)
	// HeadersByNumber returns the headers of blocks from..to inclusive, ascending.
	HeadersByNumber(ctx context.Context, from, to uint64) ([][]byte, error)
}

// headerFields is the consensus order of the execution header's RLP items as the JSON-RPC names them. The first fifteen are in
// every header; the rest are present from the fork that introduced them (the Sepolia header has 23 items since 2026-10-06:
// ... requestsHash, blockAccessListHash, slotNumber).
var headerFields = []struct {
	name string
	kind byte // 'h' bytes, 'q' quantity
	opt  bool
}{
	{"parentHash", 'h', false}, {"sha3Uncles", 'h', false}, {"miner", 'h', false}, {"stateRoot", 'h', false},
	{"transactionsRoot", 'h', false}, {"receiptsRoot", 'h', false}, {"logsBloom", 'h', false}, {"difficulty", 'q', false},
	{"number", 'q', false}, {"gasLimit", 'q', false}, {"gasUsed", 'q', false}, {"timestamp", 'q', false},
	{"extraData", 'h', false}, {"mixHash", 'h', false}, {"nonce", 'h', false}, {"baseFeePerGas", 'q', true},
	{"withdrawalsRoot", 'h', true}, {"blobGasUsed", 'q', true}, {"excessBlobGas", 'q', true},
	{"parentBeaconBlockRoot", 'h', true}, {"requestsHash", 'h', true}, {"blockAccessListHash", 'h', true}, {"slotNumber", 'q', true},
}

// HeaderRLPFromJSON rebuilds the raw consensus RLP of an eth_getBlock* result from its JSON fields, in the consensus order,
// and requires keccak256 of it to equal the "hash" the node reported: a node field this list does not know therefore cannot
// pass silently (the hash would differ). The result is never decoded into a typed header.
func HeaderRLPFromJSON(raw json.RawMessage) ([]byte, [32]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, [32]byte{}, fmt.Errorf("the block is not a JSON object")
	}
	var items []any
	for _, f := range headerFields {
		v, present := m[f.name]
		if !present {
			if f.opt {
				continue
			}
			return nil, [32]byte{}, fmt.Errorf("the block has no %s", f.name)
		}
		s, ok := v.(string)
		if !ok {
			return nil, [32]byte{}, fmt.Errorf("%s is not a string", f.name)
		}
		s = strings.TrimPrefix(s, "0x")
		if f.kind == 'q' {
			n, ok := new(big.Int).SetString(s, 16)
			if !ok {
				return nil, [32]byte{}, fmt.Errorf("%s is not a hex quantity", f.name)
			}
			items = append(items, n)
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, [32]byte{}, fmt.Errorf("%s is not hex", f.name)
		}
		items = append(items, b)
	}
	enc, err := rlp.EncodeToBytes(items)
	if err != nil {
		return nil, [32]byte{}, err
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(enc)
	var got [32]byte
	h.Sum(got[:0])
	named, _ := m["hash"].(string)
	want, err := hex.DecodeString(strings.TrimPrefix(named, "0x"))
	if err != nil || len(want) != 32 || !bytes.Equal(want, got[:]) {
		return nil, [32]byte{}, fmt.Errorf("the rebuilt header does not hash to the hash the node reported (a field this verifier does not know?)")
	}
	return enc, got, nil
}

// RPCHeaders is a HeaderSource over JSON-RPC endpoints tried in order for availability only: a header is self-authenticating
// (it hashes to the hash asked for, or chains by hash to the finalized head in Verify), so no agreement between endpoints is
// needed or taken as evidence.
type RPCHeaders struct {
	Endpoints []string
	Client    *http.Client
	BatchSize int
}

var _ HeaderSource = (*RPCHeaders)(nil)

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (r *RPCHeaders) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (r *RPCHeaders) post(ctx context.Context, url string, reqs []rpcReq) ([]rpcResp, error) {
	body, _ := json.Marshal(reqs)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := r.client().Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out []rpcResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the batch answer does not parse")
	}
	byID := map[int]rpcResp{}
	for _, o := range out {
		byID[o.ID] = o
	}
	ordered := make([]rpcResp, len(reqs))
	for i, q := range reqs {
		a, ok := byID[q.ID]
		if !ok {
			return nil, fmt.Errorf("the batch answer lacks id %d", q.ID)
		}
		ordered[i] = a
	}
	return ordered, nil
}

func (r *RPCHeaders) batch(ctx context.Context, reqs []rpcReq) ([][]byte, error) {
	var fails []EndpointFailure
	for _, ep := range r.Endpoints {
		rs, err := r.post(ctx, ep, reqs)
		name := (&HTTPSource{Base: ep}).Name()
		if err != nil {
			fails = append(fails, EndpointFailure{Endpoint: name, Op: "headers", Reason: ethrpc.RedactText(err.Error())})
			continue
		}
		out := make([][]byte, len(rs))
		bad := ""
		for i, a := range rs {
			if a.Error != nil || len(a.Result) == 0 || string(a.Result) == "null" {
				msg := "no such block"
				if a.Error != nil {
					msg = a.Error.Message
				}
				bad = ethrpc.RedactText(msg)
				break
			}
			enc, _, err := HeaderRLPFromJSON(a.Result)
			if err != nil {
				bad = ethrpc.RedactText(err.Error())
				break
			}
			out[i] = enc
		}
		if bad != "" {
			fails = append(fails, EndpointFailure{Endpoint: name, Op: "headers", Reason: bad})
			continue
		}
		return out, nil
	}
	if len(fails) == 0 {
		fails = []EndpointFailure{{Endpoint: "(none configured)", Op: "headers", Reason: "no execution endpoint is configured"}}
	}
	return nil, &SourceError{Failures: fails}
}

// HeaderByHash implements HeaderSource and requires the returned header to hash to the hash asked for.
func (r *RPCHeaders) HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	out, err := r.batch(ctx, []rpcReq{{JSONRPC: "2.0", ID: 1, Method: "eth_getBlockByHash", Params: []any{"0x" + hex.EncodeToString(hash[:]), false}}})
	if err != nil {
		return nil, err
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(out[0])
	if !bytes.Equal(h.Sum(nil), hash[:]) {
		return nil, &SourceError{Failures: []EndpointFailure{{Op: "headers", Reason: "the endpoint served a different block for the hash asked"}}}
	}
	return out[0], nil
}

// HeadersByNumber implements HeaderSource in batches.
func (r *RPCHeaders) HeadersByNumber(ctx context.Context, from, to uint64) ([][]byte, error) {
	bs := r.BatchSize
	if bs <= 0 {
		bs = 100
	}
	var out [][]byte
	for f := from; f <= to; f += uint64(bs) {
		t := f + uint64(bs) - 1
		if t > to {
			t = to
		}
		reqs := make([]rpcReq, 0, t-f+1)
		for n := f; n <= t; n++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(n-f) + 1, Method: "eth_getBlockByNumber", Params: []any{fmt.Sprintf("0x%x", n), false}})
		}
		part, err := r.batch(ctx, reqs)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}
