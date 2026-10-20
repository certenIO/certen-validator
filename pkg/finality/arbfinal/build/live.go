// Copyright 2026 Certen Protocol

package build

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// This file holds the live providers: JSON-RPC over HTTP for L1 and L2, and the beacon-API client of the L1-finality part. Every
// error text that reaches a caller passes through ethrpc.RedactText; the provider names handed to the unavailability states are
// scheme and host only (a key in a path or query never reaches a state).

// providerLabel is the redacted "scheme://host" of an endpoint.
func providerLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ethrpc.RedactText(raw)
	}
	return ethrpc.RedactText(u.Scheme + "://" + u.Host)
}

func labels(urls []string) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = providerLabel(u)
	}
	return out
}

type rpcClient struct {
	urls []string
	hc   *http.Client
}

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
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// post sends one request to u and retries a rate limit (429), a gateway error (502-504) and a transport failure with exponential
// backoff (0.5 s .. 8 s, five retries): the public providers rate-limit bursts, and a build must not fail on a burst.
func (c *rpcClient) post(ctx context.Context, u string, body []byte) ([]byte, int, error) {
	var b []byte
	var status int
	var err error
	for try := 0; try <= 5; try++ {
		if try > 0 {
			select {
			case <-ctx.Done():
				return b, status, ctx.Err()
			case <-time.After(time.Duration(500<<uint(try-1)) * time.Millisecond):
			}
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		if rerr != nil {
			return nil, 0, rerr
		}
		req.Header.Set("Content-Type", "application/json")
		resp, derr := c.client().Do(req)
		if derr != nil {
			b, status, err = nil, 0, derr
			continue
		}
		b, err = io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		status = resp.StatusCode
		if err == nil && status != http.StatusTooManyRequests && status != http.StatusBadGateway && status != http.StatusServiceUnavailable && status != http.StatusGatewayTimeout {
			return b, status, nil
		}
	}
	return b, status, err
}

func (c *rpcClient) client() *http.Client {
	if c.hc != nil {
		return c.hc
	}
	return &http.Client{Timeout: 90 * time.Second}
}

func redacted(format string, a ...any) error {
	return ethrpc.RedactError(fmt.Errorf(format, a...))
}

// batch sends reqs to each endpoint in turn and returns the first answer in which every request has a result.
func (c *rpcClient) batch(ctx context.Context, urls []string, reqs []rpcReq) ([]json.RawMessage, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(reqs)
	if err != nil {
		return nil, err
	}
	var last error
	for _, u := range urls {
		b, status, perr := c.post(ctx, u, body)
		if perr != nil || status != http.StatusOK {
			last = redacted("%s: status %d: %v: %.200s", providerLabel(u), status, perr, b)
			continue
		}
		var out []rpcResp
		if len(reqs) == 1 && len(b) > 0 && b[0] == '{' {
			var one rpcResp
			if err := json.Unmarshal(b, &one); err != nil {
				last = redacted("%s: %v: %.200s", providerLabel(u), err, b)
				continue
			}
			out = []rpcResp{one}
		} else if err := json.Unmarshal(b, &out); err != nil {
			last = redacted("%s: %v: %.200s", providerLabel(u), err, b)
			continue
		}
		res := make([]json.RawMessage, len(reqs))
		ok := true
		for _, r := range out {
			if r.ID < 1 || r.ID > len(reqs) {
				ok = false
				break
			}
			if r.Error != nil {
				last = redacted("%s: %s: code %d: %s", providerLabel(u), reqs[r.ID-1].Method, r.Error.Code, r.Error.Message)
				ok = false
				break
			}
			res[r.ID-1] = r.Result
		}
		if !ok {
			continue
		}
		for i := range res {
			if len(res[i]) == 0 || string(res[i]) == "null" {
				last = redacted("%s: %s: empty result", providerLabel(u), reqs[i].Method)
				ok = false
				break
			}
		}
		if ok {
			return res, nil
		}
	}
	if last == nil {
		last = fmt.Errorf("no endpoint configured")
	}
	return nil, last
}

func (c *rpcClient) call(ctx context.Context, urls []string, method string, params ...any) (json.RawMessage, error) {
	r, err := c.batch(ctx, urls, []rpcReq{{JSONRPC: "2.0", ID: 1, Method: method, Params: params}})
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

func hexU(v uint64) string { return fmt.Sprintf("0x%x", v) }

func unhex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func bigOf(s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad quantity %q", s)
	}
	return v, nil
}

// HeaderRLPFromJSON rebuilds the raw RLP header from a block's JSON (every field the node serves, in consensus order) and checks
// keccak256(rlp) against the block hash the node states, which proves the field list complete.
func HeaderRLPFromJSON(m map[string]any) ([]byte, [32]byte, error) {
	s := func(k string) string { v, _ := m[k].(string); return v }
	var firstErr error
	hb := func(k string) []byte {
		b, err := unhex(s(k))
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("header field %s: %v", k, err)
		}
		return b
	}
	bi := func(k string) *big.Int {
		v, err := bigOf(s(k))
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("header field %s: %v", k, err)
			return new(big.Int)
		}
		return v
	}
	items := []any{hb("parentHash"), hb("sha3Uncles"), hb("miner"), hb("stateRoot"), hb("transactionsRoot"), hb("receiptsRoot"),
		hb("logsBloom"), bi("difficulty"), bi("number"), bi("gasLimit"), bi("gasUsed"), bi("timestamp"), hb("extraData"), hb("mixHash"), hb("nonce")}
	if _, ok := m["baseFeePerGas"]; ok {
		items = append(items, bi("baseFeePerGas"))
	}
	if _, ok := m["withdrawalsRoot"]; ok {
		items = append(items, hb("withdrawalsRoot"))
	}
	for _, k := range []string{"blobGasUsed", "excessBlobGas"} {
		if _, ok := m[k]; ok {
			items = append(items, bi(k))
		}
	}
	for _, k := range []string{"parentBeaconBlockRoot", "requestsHash", "blockAccessListHash"} {
		if _, ok := m[k]; ok {
			items = append(items, hb(k))
		}
	}
	if _, ok := m["slotNumber"]; ok {
		items = append(items, bi("slotNumber"))
	}
	if firstErr != nil {
		return nil, [32]byte{}, firstErr
	}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		return nil, [32]byte{}, err
	}
	h := crypto.Keccak256Hash(raw)
	if want := s("hash"); want != "" && !strings.EqualFold(want, h.Hex()) {
		return nil, [32]byte{}, fmt.Errorf("the header rebuilt from the block JSON hashes to %x, the node states %s", h[:4], want[:10])
	}
	return raw, h, nil
}

func headerOfResult(raw json.RawMessage) ([]byte, [32]byte, map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, [32]byte{}, nil, redacted("block is not served: %v", err)
	}
	h, hash, err := HeaderRLPFromJSON(m)
	return h, hash, m, err
}

// headersRange reads blocks from..to in JSON-RPC batches of 100 and checks the parent links.
func headersRange(ctx context.Context, c *rpcClient, urls []string, from, to, batch uint64) ([][]byte, error) {
	var out [][]byte
	var prev [32]byte
	for lo := from; lo <= to; lo += batch {
		hi := lo + batch - 1
		if hi > to {
			hi = to
		}
		reqs := make([]rpcReq, 0, hi-lo+1)
		for n := lo; n <= hi; n++ {
			reqs = append(reqs, rpcReq{JSONRPC: "2.0", ID: int(n-lo) + 1, Method: "eth_getBlockByNumber", Params: []any{hexU(n), false}})
		}
		res, err := c.batch(ctx, urls, reqs)
		if err != nil {
			return nil, err
		}
		for i, r := range res {
			raw, hash, m, err := headerOfResult(r)
			if err != nil {
				return nil, err
			}
			num, _ := bigOf(fmt.Sprint(m["number"]))
			if num == nil || num.Uint64() != lo+uint64(i) {
				return nil, redacted("block %d: the node answered another block", lo+uint64(i))
			}
			if len(out) > 0 {
				ph, _ := unhex(fmt.Sprint(m["parentHash"]))
				if !bytes.Equal(ph, prev[:]) {
					return nil, redacted("block %d: parent hash does not link to block %d", lo+uint64(i), lo+uint64(i)-1)
				}
			}
			prev = hash
			out = append(out, raw)
		}
	}
	return out, nil
}

// LiveL1 is the JSON-RPC L1 source. Endpoints serve everything but proofs; ProofEndpoints are asked for eth_getProof (public
// providers serve it only near the head: research R11-base-030 M4).
type LiveL1 struct {
	Endpoints      []string
	ProofEndpoints []string
	HTTP           *http.Client
}

func (l *LiveL1) c() *rpcClient { return &rpcClient{hc: l.HTTP} }

var _ L1 = (*LiveL1)(nil)

// Providers implements L1.
func (l *LiveL1) Providers() []string {
	return labels(append(append([]string(nil), l.Endpoints...), l.ProofEndpoints...))
}

// Head implements L1.
func (l *LiveL1) Head(ctx context.Context) (uint64, error) {
	r, err := l.c().call(ctx, l.Endpoints, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	var s string
	if err := json.Unmarshal(r, &s); err != nil {
		return 0, redacted("eth_blockNumber: %v", err)
	}
	v, err := bigOf(s)
	if err != nil {
		return 0, err
	}
	return v.Uint64(), nil
}

// Headers implements L1.
func (l *LiveL1) Headers(ctx context.Context, from, to uint64) ([][]byte, error) {
	return headersRange(ctx, l.c(), l.Endpoints, from, to, 100)
}

// HeaderByHash implements L1.
func (l *LiveL1) HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	r, err := l.c().call(ctx, l.Endpoints, "eth_getBlockByHash", "0x"+hex.EncodeToString(hash[:]), false)
	if err != nil {
		return nil, err
	}
	raw, got, _, err := headerOfResult(r)
	if err != nil {
		return nil, err
	}
	if got != hash {
		return nil, redacted("the node answered another block for %x", hash[:4])
	}
	return raw, nil
}

// Logs implements L1.
func (l *LiveL1) Logs(ctx context.Context, addr common.Address, topics [][]common.Hash, from, to uint64) ([]Log, error) {
	ts := make([]any, len(topics))
	for i, alts := range topics {
		switch len(alts) {
		case 0:
			ts[i] = nil
		case 1:
			ts[i] = alts[0].Hex()
		default:
			hs := make([]string, len(alts))
			for j, a := range alts {
				hs[j] = a.Hex()
			}
			ts[i] = hs
		}
	}
	r, err := l.c().call(ctx, l.Endpoints, "eth_getLogs", map[string]any{"address": addr.Hex(), "topics": ts, "fromBlock": hexU(from), "toBlock": hexU(to)})
	if err != nil {
		return nil, err
	}
	var raw []struct {
		BlockNumber string   `json:"blockNumber"`
		BlockHash   string   `json:"blockHash"`
		TxHash      string   `json:"transactionHash"`
		TxIndex     string   `json:"transactionIndex"`
		Topics      []string `json:"topics"`
		Data        string   `json:"data"`
	}
	if err := json.Unmarshal(r, &raw); err != nil {
		return nil, redacted("eth_getLogs: %v", err)
	}
	var out []Log
	for _, x := range raw {
		bn, e1 := bigOf(x.BlockNumber)
		ti, e2 := bigOf(x.TxIndex)
		bh, e3 := unhex(x.BlockHash)
		th, e4 := unhex(x.TxHash)
		d, e5 := unhex(x.Data)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(bh) != 32 || len(th) != 32 {
			return nil, redacted("eth_getLogs: a log does not parse")
		}
		lg := Log{Block: bn.Uint64(), TxIndex: ti.Uint64(), Data: d}
		copy(lg.BlockHash[:], bh)
		copy(lg.TxHash[:], th)
		for _, t := range x.Topics {
			tb, err := unhex(t)
			if err != nil || len(tb) != 32 {
				return nil, redacted("eth_getLogs: a topic does not parse")
			}
			lg.Topics = append(lg.Topics, common.BytesToHash(tb))
		}
		out = append(out, lg)
	}
	return out, nil
}

// Block implements L1: the block with the consensus encodings of its transactions and receipts. The encodings are checked
// against the transaction hashes the node states; the caller checks the trie roots against the header.
func (l *LiveL1) Block(ctx context.Context, number uint64) (*L1Block, error) {
	r, err := l.c().call(ctx, l.Endpoints, "eth_getBlockByNumber", hexU(number), true)
	if err != nil {
		return nil, err
	}
	raw, hash, m, err := headerOfResult(r)
	if err != nil {
		return nil, err
	}
	var txs struct {
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := json.Unmarshal(r, &txs); err != nil {
		return nil, redacted("block %d: %v", number, err)
	}
	_ = m
	b := &L1Block{Number: number, Hash: hash, HeaderRLP: raw}
	for i, t := range txs.Transactions {
		enc, h, err := ethproof.EncodeTxJSON(t)
		if err != nil {
			return nil, redacted("block %d tx %d: %v", number, i, err)
		}
		if crypto.Keccak256Hash(enc) != h {
			return nil, redacted("block %d tx %d: the consensus encoding does not hash to the stated hash", number, i)
		}
		b.Txs = append(b.Txs, enc)
	}
	rr, err := l.c().call(ctx, l.Endpoints, "eth_getBlockReceipts", hexU(number))
	if err != nil {
		return nil, err
	}
	var rs []json.RawMessage
	if err := json.Unmarshal(rr, &rs); err != nil || len(rs) != len(b.Txs) {
		return nil, redacted("block %d: receipts do not match the %d transactions", number, len(b.Txs))
	}
	for i, x := range rs {
		enc, _, err := ethproof.EncodeReceiptJSON(x)
		if err != nil {
			return nil, redacted("block %d receipt %d: %v", number, i, err)
		}
		b.Receipts = append(b.Receipts, enc)
	}
	return b, nil
}

// Proof implements L1: eth_getProof from the proof endpoints, trying each in turn.
func (l *LiveL1) Proof(ctx context.Context, addr common.Address, slots []common.Hash, block uint64) (*StateProof, error) {
	ss := make([]string, len(slots))
	for i, s := range slots {
		ss[i] = s.Hex()
	}
	r, err := l.c().call(ctx, l.ProofEndpoints, "eth_getProof", addr.Hex(), ss, hexU(block))
	if err != nil {
		return nil, err
	}
	var p struct {
		AccountProof []string `json:"accountProof"`
		StorageProof []struct {
			Key   string   `json:"key"`
			Proof []string `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(r, &p); err != nil || len(p.StorageProof) != len(slots) {
		return nil, redacted("eth_getProof: the answer does not parse")
	}
	out := &StateProof{Storage: map[common.Hash][][]byte{}}
	conv := func(l []string) ([][]byte, error) {
		var o [][]byte
		for _, n := range l {
			b, err := unhex(n)
			if err != nil {
				return nil, err
			}
			o = append(o, b)
		}
		return o, nil
	}
	if out.Account, err = conv(p.AccountProof); err != nil {
		return nil, redacted("eth_getProof: a node does not parse")
	}
	for i, s := range slots {
		if out.Storage[s], err = conv(p.StorageProof[i].Proof); err != nil {
			return nil, redacted("eth_getProof: a node does not parse")
		}
	}
	return out, nil
}

// LiveL2 is the JSON-RPC Arbitrum source of headers.
type LiveL2 struct {
	Endpoints []string
	HTTP      *http.Client
}

var _ L2 = (*LiveL2)(nil)

func (l *LiveL2) c() *rpcClient { return &rpcClient{hc: l.HTTP} }

// Providers implements L2.
func (l *LiveL2) Providers() []string { return labels(l.Endpoints) }

// HeaderByHash implements L2.
func (l *LiveL2) HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	r, err := l.c().call(ctx, l.Endpoints, "eth_getBlockByHash", "0x"+hex.EncodeToString(hash[:]), false)
	if err != nil {
		return nil, err
	}
	raw, got, _, err := headerOfResult(r)
	if err != nil {
		return nil, err
	}
	if got != hash {
		return nil, redacted("the node answered another block for %x", hash[:4])
	}
	return raw, nil
}

// HeaderByNumber implements L2.
func (l *LiveL2) HeaderByNumber(ctx context.Context, number uint64) ([]byte, error) {
	hs, err := headersRange(ctx, l.c(), l.Endpoints, number, number, 1)
	if err != nil {
		return nil, err
	}
	return hs[0], nil
}

// Headers implements L2.
func (l *LiveL2) Headers(ctx context.Context, from, to uint64) ([][]byte, error) {
	return headersRange(ctx, l.c(), l.Endpoints, from, to, 40)
}

// BeaconLC assembles the L1-finality part from a Lodestar-compatible beacon API: the configured anchor (a Gloas bootstrap for a
// kind-2 anchor, or a SyncCommittee for kind 1), the best updates of the periods anchorPeriod..sigPeriod-1 as links, and the
// current finality update. The objects are untrusted; ethl1 verifies the chain from the pinned ledger.
type BeaconLC struct {
	Beacon       string
	HTTP         *http.Client
	AnchorKind   uint8
	AnchorPeriod uint64
	AnchorRoot   [32]byte
	AnchorBody   ethl1.LB
	// MaxLinks bounds the links requested (the pins' max_links, spec 8.2); 0 is no bound. More links than that is *TooManyLinksError, raised
	// before any link is requested.
	MaxLinks int
}

// TooManyLinksError is the refusal of a final update signed more than MaxLinks periods after the anchor: the evidence the pins can carry
// does not reach it. Period and Anchor are the signature period and the anchor period.
type TooManyLinksError struct {
	Signature, Anchor uint64
	Max               int
}

func (e *TooManyLinksError) Error() string {
	return fmt.Sprintf("the final update was signed in period %d, %d periods after the anchor %d; the pins allow %d links", e.Signature, e.Signature-e.Anchor, e.Anchor, e.Max)
}

var _ LCSource = (*BeaconLC)(nil)

const (
	gloasUpdateBytes         = 26424
	gloasFinalityUpdateBytes = 1448
)

func (b *BeaconLC) get(ctx context.Context, path string) ([]byte, error) {
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(b.Beacon, "/")+path, nil)
	if err != nil {
		return nil, redacted("beacon %s: %v", path, err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, redacted("beacon %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, redacted("beacon %s: status %d: %v: %.200s", path, resp.StatusCode, err, body)
	}
	return body, nil
}

func layoutOf(n, gloas int) ethl1.Layout {
	if n == gloas {
		return ethl1.LayoutGloas
	}
	return ethl1.LayoutElectra
}

// LC implements LCSource.
func (b *BeaconLC) LC(ctx context.Context) (ethl1.LC, error) {
	lc := ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: b.AnchorKind, AnchorPeriod: b.AnchorPeriod, AnchorRoot: b.AnchorRoot, AnchorBody: b.AnchorBody}
	fu, err := b.get(ctx, "/eth/v1/beacon/light_client/finality_update")
	if err != nil {
		return lc, err
	}
	if len(fu) != gloasFinalityUpdateBytes {
		return lc, redacted("the finality update has %d bytes, not the Gloas layout's %d", len(fu), gloasFinalityUpdateBytes)
	}
	sigSlot := binary.LittleEndian.Uint64(fu[len(fu)-8:])
	sigPeriod := sigSlot / 32 / 256
	if sigPeriod < b.AnchorPeriod {
		return lc, redacted("the finality update's signature period %d is below the anchor period %d", sigPeriod, b.AnchorPeriod)
	}
	if b.MaxLinks > 0 && sigPeriod-b.AnchorPeriod > uint64(b.MaxLinks) {
		return lc, &TooManyLinksError{Signature: sigPeriod, Anchor: b.AnchorPeriod, Max: b.MaxLinks}
	}
	if n := sigPeriod - b.AnchorPeriod; n > 0 {
		body, err := b.get(ctx, fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%d&count=%d", b.AnchorPeriod, n))
		if err != nil {
			return lc, err
		}
		parts, err := splitUpdates(body)
		if err != nil || uint64(len(parts)) != n {
			return lc, redacted("beacon updates %d..%d: %d parts: %v", b.AnchorPeriod, sigPeriod-1, len(parts), err)
		}
		for _, u := range parts {
			lc.Links = append(lc.Links, ethl1.LB{Layout: layoutOf(len(u), gloasUpdateBytes), SSZ: u})
		}
	}
	lc.FinalUpdate = ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: fu}
	return lc, nil
}

// splitUpdates parses the framed /updates response: u64le length, then 4 bytes of fork digest and the SSZ object.
func splitUpdates(body []byte) ([][]byte, error) {
	var out [][]byte
	pos := 0
	for pos < len(body) {
		if pos+12 > len(body) {
			return nil, fmt.Errorf("updates frame truncated at %d", pos)
		}
		n := int(binary.LittleEndian.Uint64(body[pos : pos+8]))
		if n < 4 || pos+8+n > len(body) {
			return nil, fmt.Errorf("updates frame length %d at %d overruns", n, pos)
		}
		out = append(out, body[pos+12:pos+8+n])
		pos += 8 + n
	}
	return out, nil
}
