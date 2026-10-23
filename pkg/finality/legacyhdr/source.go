// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethsepolia"
)

// HeaderSource serves block headers by hash. An implementation is availability only: what it returns must hash to the hash asked
// for (HeaderByHash checks it and Leg.Verify checks it again), and when it cannot serve it returns *Unserved.
type HeaderSource interface {
	HeaderByHash(ctx context.Context, chain uint64, hash common.Hash) ([]byte, error)
}

// Unserved is the answer of a source that tried every provider it has for the chain and none served the block. It holds counts only:
// provider text and URLs never reach a state, a log line or a status row.
type Unserved struct {
	Chain uint64
	Hash  common.Hash
	// Asked is the number of providers tried. NotServed answered that the block is unknown or its history is pruned (a JSON-RPC
	// error or a null result); Unreachable did not answer with a usable JSON-RPC response (transport error, HTTP status, not JSON);
	// WrongBlock served a block that does not hash to the hash asked for; Oversized answered past the response bound.
	Asked, NotServed, Unreachable, WrongBlock, Oversized int
}

func (u *Unserved) Error() string {
	return fmt.Sprintf("no provider served block %x on chain %d: asked %d, not served %d, unreachable %d, wrong block %d, oversized %d",
		u.Hash[:4], u.Chain, u.Asked, u.NotServed, u.Unreachable, u.WrongBlock, u.Oversized)
}

// State is finality_included_unavailable{legacy_header_unserved} for the leg: the chain and block it was judged at and how each
// provider failed.
func (u *Unserved) State(l Leg) *finality.StateError {
	return finality.IncludedUnavailable(finality.IncludedLegacyHeaderUnserved, "proof_id", l.ProofID, "chain", l.Chain, "block", l.BlockNumber,
		"asked", u.Asked, "not_served", u.NotServed, "unreachable", u.Unreachable, "wrong_block", u.WrongBlock, "oversized", u.Oversized)
}

// DefaultMaxResponse bounds one provider response: eth_getBlockByHash(hash, false) is the header fields plus one 32-byte hash per
// transaction (a few hundred KiB at most); anything larger is refused unread.
const DefaultMaxResponse = 4 << 20

// RPCSource is a HeaderSource over JSON-RPC providers: eth_getBlockByHash(hash, false), every configured provider of the chain tried in
// turn (a pruning primary is an availability miss, not a verdict). The header is rebuilt from the JSON fields in consensus order and
// must hash to the hash asked for; nothing else a provider says is used.
type RPCSource struct {
	// URLs are the providers per chain id, in the order they are tried. A chain with none is an empty Unserved (Asked 0).
	URLs        map[uint64][]string
	Client      *http.Client
	MaxResponse int64
}

var _ HeaderSource = (*RPCSource)(nil)

type providerClass int

const (
	classServed providerClass = iota
	classNotServed
	classUnreachable
	classWrongBlock
	classOversized
)

// HeaderByHash implements HeaderSource.
func (s *RPCSource) HeaderByHash(ctx context.Context, chain uint64, hash common.Hash) ([]byte, error) {
	u := &Unserved{Chain: chain, Hash: hash}
	for _, url := range s.URLs[chain] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		u.Asked++
		hdr, class := s.fetch(ctx, url, hash)
		switch class {
		case classServed:
			return hdr, nil
		case classNotServed:
			u.NotServed++
		case classUnreachable:
			u.Unreachable++
		case classWrongBlock:
			u.WrongBlock++
		case classOversized:
			u.Oversized++
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, u
}

func (s *RPCSource) fetch(ctx context.Context, url string, hash common.Hash) ([]byte, providerClass) {
	limit := s.MaxResponse
	if limit <= 0 {
		limit = DefaultMaxResponse
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByHash", "params": []any{hash.Hex(), false}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, classUnreachable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, classUnreachable
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, classUnreachable
	}
	if int64(len(raw)) > limit {
		return nil, classOversized
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, classUnreachable // an HTTP error page, a rate-limit text, a truncated body
	}
	if len(out.Error) > 0 && string(out.Error) != "null" {
		return nil, classNotServed // "pruned history unavailable", "block not found", ...: the provider does not hold the block
	}
	if len(out.Result) == 0 || string(bytes.TrimSpace(out.Result)) == "null" {
		return nil, classNotServed
	}
	hdr, got, err := ethsepolia.HeaderRLPFromJSON(out.Result)
	if err != nil || common.Hash(got) != hash || len(hdr) > MaxHeaderRLP {
		return nil, classWrongBlock
	}
	return hdr, classServed
}

// redactedCause is the provider-safe text of a source error for logs: Unserved is counts only, anything else goes through the shared
// redaction.
func redactedCause(err error) string {
	if _, ok := err.(*Unserved); ok {
		return err.Error()
	}
	return ethrpc.RedactError(err).Error()
}

// Describe is the log-safe text of a header source failure.
func Describe(err error) string { return redactedCause(err) }
