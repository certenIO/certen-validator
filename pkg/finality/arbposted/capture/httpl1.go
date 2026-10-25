// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// HTTPL1 is the JSON-RPC L1Source over a list of providers tried in order. Provider error text goes through
// ethrpc.RedactText and a response body is never echoed: a non-200 answer is reported by status only, a JSON-RPC error by its
// code and redacted message.
type HTTPL1 struct {
	Providers []string
	Client    *http.Client
	MaxBody   int64
}

// NewHTTPL1 returns an HTTPL1 over the provider URLs.
func NewHTTPL1(providers ...string) *HTTPL1 {
	return &HTTPL1{Providers: providers, Client: &http.Client{Timeout: 40 * time.Second}, MaxBody: 64 << 20}
}

// label is the host of a provider URL: never the path or the query, where API keys live.
func label(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "provider"
	}
	return u.Hostname()
}

func (h *HTTPL1) rpc(ctx context.Context, provider, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("bad request")
	}
	req.Header.Set("content-type", "application/json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, errors.New("transport: " + ethrpc.RedactText(err.Error()))
	}
	defer resp.Body.Close()
	max := h.MaxBody
	if max <= 0 {
		max = 64 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, errors.New("read: " + ethrpc.RedactText(err.Error()))
	}
	if int64(len(b)) > max {
		return nil, errors.New("response exceeds the size bound")
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	jerr := json.Unmarshal(b, &out)
	switch {
	case jerr == nil && out.Error != nil:
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, ethrpc.RedactText(out.Error.Message))
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	case jerr != nil:
		return nil, errors.New("answer is not JSON-RPC")
	case len(out.Result) == 0 || string(out.Result) == "null":
		return nil, errors.New("null result")
	}
	return out.Result, nil
}

// each runs fn against the providers in order until one returns nil; the failures of all that failed are the error.
func (h *HTTPL1) each(ctx context.Context, op string, fn func(provider string) error) error {
	var fails []ProviderFailure
	for _, p := range h.Providers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := fn(p)
		if err == nil {
			return nil
		}
		fails = append(fails, ProviderFailure{Provider: label(p), Err: ethrpc.RedactText(err.Error())})
	}
	return &ProviderErrors{Op: op, Failures: fails}
}

func hexU64(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
}

func unhex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func to32(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) > 32 {
		return out, errors.New("value longer than 32 bytes")
	}
	copy(out[32-len(b):], b)
	return out, nil
}

func hexW(w [32]byte) string { return "0x" + hex.EncodeToString(w[:]) }

func (h *HTTPL1) HeadNumber(ctx context.Context) (uint64, error) {
	var head uint64
	err := h.each(ctx, "eth_blockNumber", func(p string) error {
		r, err := h.rpc(ctx, p, "eth_blockNumber")
		if err != nil {
			return err
		}
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			return errors.New("bad quantity")
		}
		head, err = hexU64(s)
		return err
	})
	return head, err
}

// headerRLP rebuilds the raw RLP header from eth_getBlockByNumber fields in consensus order; the caller checks the hash, which
// proves the field list was complete (the same construction as cmd/finalityethl1record).
func headerRLP(m map[string]any) ([]byte, error) {
	s := func(k string) string { v, _ := m[k].(string); return v }
	bytesOf := func(k string) ([]byte, error) { return unhex(s(k)) }
	bigOf := func(k string) (*big.Int, error) {
		v, ok := new(big.Int).SetString(strings.TrimPrefix(s(k), "0x"), 16)
		if !ok {
			return nil, fmt.Errorf("bad quantity %s", k)
		}
		return v, nil
	}
	var items []any
	for _, k := range []string{"parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom"} {
		b, err := bytesOf(k)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", k, err)
		}
		items = append(items, b)
	}
	for _, k := range []string{"difficulty", "number", "gasLimit", "gasUsed", "timestamp"} {
		v, err := bigOf(k)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	for _, k := range []string{"extraData", "mixHash", "nonce"} {
		b, err := bytesOf(k)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", k, err)
		}
		items = append(items, b)
	}
	if _, ok := m["baseFeePerGas"]; ok {
		v, err := bigOf("baseFeePerGas")
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	if _, ok := m["withdrawalsRoot"]; ok {
		b, err := bytesOf("withdrawalsRoot")
		if err != nil {
			return nil, err
		}
		items = append(items, b)
	}
	for _, k := range []string{"blobGasUsed", "excessBlobGas"} {
		if _, ok := m[k]; ok {
			v, err := bigOf(k)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
	}
	for _, k := range []string{"parentBeaconBlockRoot", "requestsHash", "blockAccessListHash"} {
		if _, ok := m[k]; ok {
			b, err := bytesOf(k)
			if err != nil {
				return nil, err
			}
			items = append(items, b)
		}
	}
	if _, ok := m["slotNumber"]; ok {
		v, err := bigOf("slotNumber")
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return rlp.EncodeToBytes(items)
}

func (h *HTTPL1) Header(ctx context.Context, number uint64) (Header, error) {
	var out Header
	err := h.each(ctx, "eth_getBlockByNumber", func(p string) error {
		r, err := h.rpc(ctx, p, "eth_getBlockByNumber", "0x"+strconv.FormatUint(number, 16), false)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil || m == nil {
			return errors.New("no such block")
		}
		raw, err := headerRLP(m)
		if err != nil {
			return err
		}
		stated, err := unhex(fmt.Sprint(m["hash"]))
		if err != nil || len(stated) != 32 {
			return errors.New("block hash missing")
		}
		got := crypto.Keccak256(raw)
		if !bytes.Equal(got, stated) {
			return errors.New("rebuilt header does not hash to the stated block hash (a header field is missing from the encoder)")
		}
		n, err := hexU64(fmt.Sprint(m["number"]))
		if err != nil || n != number {
			return errors.New("provider answered another block")
		}
		ts, err := hexU64(fmt.Sprint(m["timestamp"]))
		if err != nil {
			return errors.New("bad timestamp")
		}
		out = Header{Number: n, Timestamp: ts, RLP: raw}
		copy(out.Hash[:], got)
		ph, _ := unhex(fmt.Sprint(m["parentHash"]))
		copy(out.ParentHash[:], ph)
		return nil
	})
	return out, err
}

func (h *HTTPL1) Logs(ctx context.Context, address [20]byte, topic0 [32]byte, topic1 *[32]byte, from, to uint64) ([]Log, error) {
	var out []Log
	err := h.each(ctx, "eth_getLogs", func(p string) error {
		topics := []any{hexW(topic0)}
		if topic1 != nil {
			topics = append(topics, hexW(*topic1))
		}
		r, err := h.rpc(ctx, p, "eth_getLogs", map[string]any{
			"address": "0x" + hex.EncodeToString(address[:]), "fromBlock": "0x" + strconv.FormatUint(from, 16),
			"toBlock": "0x" + strconv.FormatUint(to, 16), "topics": topics,
		})
		if err != nil {
			return err
		}
		var raw []struct {
			Address     string   `json:"address"`
			Topics      []string `json:"topics"`
			Data        string   `json:"data"`
			BlockNumber string   `json:"blockNumber"`
			BlockHash   string   `json:"blockHash"`
			TxHash      string   `json:"transactionHash"`
			TxIndex     string   `json:"transactionIndex"`
			LogIndex    string   `json:"logIndex"`
			Removed     bool     `json:"removed"`
		}
		if err := json.Unmarshal(r, &raw); err != nil {
			return errors.New("bad logs")
		}
		var logs []Log
		for _, l := range raw {
			if l.Removed {
				continue
			}
			var lg Log
			a, err := unhex(l.Address)
			if err != nil || len(a) != 20 {
				return errors.New("bad log address")
			}
			copy(lg.Address[:], a)
			for _, t := range l.Topics {
				tb, err := unhex(t)
				if err != nil || len(tb) != 32 {
					return errors.New("bad log topic")
				}
				var w [32]byte
				copy(w[:], tb)
				lg.Topics = append(lg.Topics, w)
			}
			if lg.Data, err = unhex(l.Data); err != nil {
				return errors.New("bad log data")
			}
			if lg.BlockNumber, err = hexU64(l.BlockNumber); err != nil {
				return errors.New("bad log block")
			}
			bh, _ := unhex(l.BlockHash)
			th, _ := unhex(l.TxHash)
			if len(bh) != 32 || len(th) != 32 {
				return errors.New("bad log hashes")
			}
			copy(lg.BlockHash[:], bh)
			copy(lg.TxHash[:], th)
			lg.TxIndex, _ = hexU64(l.TxIndex)
			lg.LogIndex, _ = hexU64(l.LogIndex)
			logs = append(logs, lg)
		}
		out = logs
		return nil
	})
	return out, err
}

func (h *HTTPL1) TxByHash(ctx context.Context, hash [32]byte) (Tx, error) {
	var out Tx
	err := h.each(ctx, "eth_getTransactionByHash", func(p string) error {
		r, err := h.rpc(ctx, p, "eth_getTransactionByHash", hexW(hash))
		if err != nil {
			return err
		}
		enc, stated, err := ethproof.EncodeTxJSON(r)
		if err != nil {
			return errors.New("cannot encode the transaction: " + ethrpc.RedactText(err.Error()))
		}
		if h2 := crypto.Keccak256Hash(enc); h2 != stated || [32]byte(h2) != hash {
			return errors.New("transaction encoding does not hash to the requested hash")
		}
		var m struct {
			Type        string   `json:"type"`
			Input       string   `json:"input"`
			BlockHash   string   `json:"blockHash"`
			BlockNumber string   `json:"blockNumber"`
			Index       string   `json:"transactionIndex"`
			Blobs       []string `json:"blobVersionedHashes"`
		}
		if err := json.Unmarshal(r, &m); err != nil {
			return errors.New("bad transaction")
		}
		var t Tx
		t.Hash, t.Raw = hash, enc
		ty, _ := hexU64(m.Type)
		t.Type = uint8(ty)
		if t.Input, err = unhex(m.Input); err != nil {
			return errors.New("bad input")
		}
		bh, _ := unhex(m.BlockHash)
		if len(bh) != 32 {
			return errors.New("transaction is not in a block")
		}
		copy(t.BlockHash[:], bh)
		if t.BlockNumber, err = hexU64(m.BlockNumber); err != nil {
			return errors.New("bad block number")
		}
		t.Index, _ = hexU64(m.Index)
		for _, v := range m.Blobs {
			vb, err := unhex(v)
			if err != nil || len(vb) != 32 {
				return errors.New("bad blob versioned hash")
			}
			var w [32]byte
			copy(w[:], vb)
			t.BlobVersionedHashes = append(t.BlobVersionedHashes, w)
		}
		out = t
		return nil
	})
	return out, err
}

func (h *HTTPL1) GetProof(ctx context.Context, address [20]byte, slots [][32]byte, number uint64, accept func(*Proof) error) (*Proof, error) {
	var out *Proof
	err := h.each(ctx, "eth_getProof", func(p string) error {
		keys := make([]string, len(slots))
		for i, s := range slots {
			keys[i] = hexW(s)
		}
		r, err := h.rpc(ctx, p, "eth_getProof", "0x"+hex.EncodeToString(address[:]), keys, "0x"+strconv.FormatUint(number, 16))
		if err != nil {
			return err
		}
		var raw struct {
			AccountProof []string `json:"accountProof"`
			StorageHash  string   `json:"storageHash"`
			CodeHash     string   `json:"codeHash"`
			StorageProof []struct {
				Value string   `json:"value"`
				Proof []string `json:"proof"`
			} `json:"storageProof"`
		}
		if err := json.Unmarshal(r, &raw); err != nil {
			return errors.New("bad proof")
		}
		if len(raw.StorageProof) != len(slots) {
			return errors.New("proof answers a different slot list")
		}
		pr := &Proof{Address: address}
		for _, n := range raw.AccountProof {
			nb, err := unhex(n)
			if err != nil {
				return errors.New("bad proof node")
			}
			pr.AccountProof = append(pr.AccountProof, nb)
		}
		sh, _ := unhex(raw.StorageHash)
		ch, _ := unhex(raw.CodeHash)
		if pr.StorageHash, err = to32(sh); err != nil {
			return err
		}
		if pr.CodeHash, err = to32(ch); err != nil {
			return err
		}
		for i, sp := range raw.StorageProof {
			var s SlotProof
			s.Key = slots[i]
			vb, err := unhex(sp.Value)
			if err != nil {
				return errors.New("bad slot value")
			}
			if s.Value, err = to32(vb); err != nil {
				return err
			}
			for _, n := range sp.Proof {
				nb, err := unhex(n)
				if err != nil {
					return errors.New("bad proof node")
				}
				s.Proof = append(s.Proof, nb)
			}
			pr.Slots = append(pr.Slots, s)
		}
		if accept != nil {
			if err := accept(pr); err != nil {
				return errors.New("answer refused: " + err.Error())
			}
		}
		out = pr
		return nil
	})
	return out, err
}

// ---- beacon --------------------------------------------------------------------------------------------------------

// HTTPBeacon is the BeaconSource over beacon API bases tried in order. It reads GET /eth/v1/beacon/blobs/{slot} (JSON
// {"data":[hex blob...]}), the endpoint Fulu/Gloas beacon nodes serve (blob_sidecars is gone), computes each blob's KZG
// commitment and blob proof with go-ethereum crypto/kzg4844 (pure Go backend) and selects by versioned hash.
type HTTPBeacon struct {
	Bases   []string
	Client  *http.Client
	MaxBody int64
}

// NewHTTPBeacon returns an HTTPBeacon over the base URLs.
func NewHTTPBeacon(bases ...string) *HTTPBeacon {
	return &HTTPBeacon{Bases: bases, Client: &http.Client{Timeout: 90 * time.Second}, MaxBody: 96 << 20}
}

// VersionedHash is 0x01 || sha256(commitment)[1:].
func VersionedHash(c [48]byte) [32]byte {
	h := sha256.Sum256(c[:])
	h[0] = 0x01
	return h
}

func (b *HTTPBeacon) fetchBlobs(ctx context.Context, base string, slot uint64) ([][]byte, *BeaconError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/eth/v1/beacon/blobs/"+strconv.FormatUint(slot, 10), nil)
	if err != nil {
		return nil, &BeaconError{Slot: slot, Err: "bad request"}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, &BeaconError{Slot: slot, Err: "transport: " + ethrpc.RedactText(err.Error())}
	}
	defer resp.Body.Close()
	max := b.MaxBody
	if max <= 0 {
		max = 96 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, &BeaconError{Slot: slot, Status: resp.StatusCode, Err: "read: " + ethrpc.RedactText(err.Error())}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &BeaconError{Slot: slot, Status: resp.StatusCode, Err: "not served"}
	}
	if int64(len(body)) > max {
		return nil, &BeaconError{Slot: slot, Status: resp.StatusCode, Err: "response exceeds the size bound"}
	}
	var out struct {
		Data []string `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &BeaconError{Slot: slot, Status: resp.StatusCode, Err: "answer is not the blobs JSON"}
	}
	blobs := make([][]byte, 0, len(out.Data))
	for _, s := range out.Data {
		bb, err := unhex(s)
		if err != nil || len(bb) != BlobBytes {
			return nil, &BeaconError{Slot: slot, Status: resp.StatusCode, Err: "a blob is not 131072 bytes"}
		}
		blobs = append(blobs, bb)
	}
	return blobs, nil
}

func (b *HTTPBeacon) Sidecars(ctx context.Context, slot uint64, wanted [][32]byte) (map[[32]byte]Sidecar, error) {
	var fails []ProviderFailure
	var hosts []BeaconHost
	var last *BeaconError
	for _, base := range b.Bases {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		blobs, berr := b.fetchBlobs(ctx, base, slot)
		if berr != nil {
			fails = append(fails, ProviderFailure{Provider: label(base), Err: berr.Error()})
			hosts = append(hosts, BeaconHost{Host: label(base), Status: berr.Status, Gone: berr.Status == 404 || berr.Status == 410})
			last = berr
			continue
		}
		want := map[[32]byte]bool{}
		for _, w := range wanted {
			want[w] = true
		}
		out := map[[32]byte]Sidecar{}
		for _, raw := range blobs {
			var blob kzg4844.Blob
			copy(blob[:], raw)
			c, err := kzg4844.BlobToCommitment(&blob)
			if err != nil {
				return nil, errors.New("kzg commitment: " + ethrpc.RedactText(err.Error()))
			}
			vh := VersionedHash(c)
			if !want[vh] {
				continue
			}
			pr, err := kzg4844.ComputeBlobProof(&blob, c)
			if err != nil {
				return nil, errors.New("kzg proof: " + ethrpc.RedactText(err.Error()))
			}
			sc := Sidecar{Blob: raw}
			copy(sc.Commitment[:], c[:])
			copy(sc.Proof[:], pr[:])
			out[vh] = sc
		}
		if len(out) == len(want) {
			return out, nil
		}
		e := &BeaconError{Slot: slot, Status: 200, Err: fmt.Sprintf("the block's blobs hold %d of the %d wanted versioned hashes", len(out), len(want))}
		fails = append(fails, ProviderFailure{Provider: label(base), Err: e.Error()})
		hosts = append(hosts, BeaconHost{Host: label(base), Status: 200, Gone: true}) // the block was served without the wanted blobs
		last = e
	}
	if last == nil {
		return nil, &BeaconError{Slot: slot, Err: "no beacon endpoint configured"}
	}
	parts := make([]string, len(fails))
	for i, f := range fails {
		parts[i] = f.String()
	}
	return nil, &BeaconError{Slot: slot, Status: last.Status, Err: ethrpc.RedactText(strings.Join(parts, "; ")), Hosts: hosts}
}
