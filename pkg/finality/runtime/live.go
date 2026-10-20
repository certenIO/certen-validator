// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// maxAnswer bounds one provider answer read into memory.
const maxAnswer = 64 << 20

// rpcFirst sends one JSON-RPC call to each URL in order and returns the first result. Provider text reaches the returned error
// only through ethrpc.RedactText; an answer body is never echoed.
func rpcFirst(ctx context.Context, hc *http.Client, urls []string, method string, params ...any) (json.RawMessage, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("%s: no provider configured", method)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	var last error
	for _, u := range urls {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		if err != nil {
			last = errors.New("bad request")
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			last = fmt.Errorf("%s via %s: %s", method, HostLabel(u), ethrpc.RedactText(err.Error()))
			continue
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
		resp.Body.Close()
		if rerr != nil {
			last = fmt.Errorf("%s via %s: %s", method, HostLabel(u), ethrpc.RedactText(rerr.Error()))
			continue
		}
		var out struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		switch jerr := json.Unmarshal(raw, &out); {
		case jerr == nil && out.Error != nil:
			last = fmt.Errorf("%s via %s: rpc error %d: %s", method, HostLabel(u), out.Error.Code, ethrpc.RedactText(out.Error.Message))
		case resp.StatusCode != http.StatusOK:
			last = fmt.Errorf("%s via %s: HTTP %d", method, HostLabel(u), resp.StatusCode)
		case jerr != nil:
			last = fmt.Errorf("%s via %s: the answer is not JSON-RPC", method, HostLabel(u))
		case len(out.Result) == 0 || string(out.Result) == "null":
			last = fmt.Errorf("%s via %s: no result", method, HostLabel(u))
		default:
			return out.Result, nil
		}
	}
	return nil, last
}

// ArbL2 is the live arbposted.L2Source: the consensus encodings of ALL transactions of an Arbitrum Sepolia block, by block hash.
// Nothing it returns is trusted: the kind's verifier recomputes the transaction trie against the leg's header.
type ArbL2 struct {
	URLs []string
	HTTP *http.Client
}

// BlockTxs implements arbposted.L2Source.
func (a *ArbL2) BlockTxs(ctx context.Context, blockHash [32]byte) ([][]byte, error) {
	r, err := rpcFirst(ctx, a.HTTP, a.URLs, "eth_getBlockByHash", "0x"+hex.EncodeToString(blockHash[:]), true)
	if err != nil {
		return nil, err
	}
	var blk struct {
		Hash         string            `json:"hash"`
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(r, &blk); err != nil {
		return nil, errors.New("the Arbitrum block answer is not a block")
	}
	if !strings.EqualFold(blk.Hash, "0x"+hex.EncodeToString(blockHash[:])) {
		return nil, errors.New("the provider answered another block than the one asked for")
	}
	out := make([][]byte, 0, len(blk.Transactions))
	for i, raw := range blk.Transactions {
		enc, _, err := ethproof.EncodeTxJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("Arbitrum block transaction %d: %s", i, ethrpc.RedactText(err.Error()))
		}
		out = append(out, enc)
	}
	return out, nil
}

// ArbL1 is the live arbposted.L1Chain: the light-client evidence of the finalized head (from the LC source) and the L1
// execution headers that connect it down to the proof block. None of it is trusted: the builder runs the verifier on what it gets.
type ArbL1 struct {
	LC interface {
		LC(context.Context) (ethl1.LC, error)
	}
	Headers *baseposted.JSONRPCSource
}

// LightClient implements arbposted.L1Chain.
func (a *ArbL1) LightClient(ctx context.Context) (ethl1.LC, error) { return a.LC.LC(ctx) }

// HeaderRLP implements arbposted.L1Chain: the header of L1 block `number`, re-encoded positionally and hash-checked.
func (a *ArbL1) HeaderRLP(ctx context.Context, number uint64) ([]byte, error) {
	raw, _, _, err := a.Headers.HeaderByNumber(ctx, number)
	return raw, err
}

// HeaderRLPByHash implements arbposted.L1Chain.
func (a *ArbL1) HeaderRLPByHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	raw, _, _, err := a.Headers.HeaderByHash(ctx, hash)
	if err == nil && [32]byte(crypto.Keccak256Hash(raw)) != hash {
		return nil, errors.New("the header does not hash to the requested hash")
	}
	return raw, err
}

// CaptureStatusProofID is the pseudo proof id under which a capture loop records its named unavailability states in the
// status table (the table is keyed by proof and level, a capturer has no leg): ffffffff-ffff-4fff-8fff-<chain as 12 hex>. No
// stored proof has this prefix (uuid v4 ids are random); readers of the status table recognise capture rows by it.
func CaptureStatusProofID(chain uint64) string {
	return fmt.Sprintf("ffffffff-ffff-4fff-8fff-%012x", chain)
}

// IsCaptureStatusProofID reports whether id is a capture loop's pseudo proof id.
func IsCaptureStatusProofID(id string) bool { return strings.HasPrefix(id, "ffffffff-ffff-4fff-8fff-") }

// lcAge is how long a fetched light client may be reused by the builders of one pass: the finality update changes every slot
// batch, and rebuilding it for each of many legs would hammer the endpoints. Never evidence: the verifier judges what is used.
const lcAge = 30 * time.Second
