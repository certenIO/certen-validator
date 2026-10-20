// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

const (
	lodestar   = "https://lodestar-sepolia.chainsafe.io"
	publicnode = "https://ethereum-sepolia-rpc.publicnode.com"
	// firstGloasPeriod is the Gloas fork epoch 353024 / 256; the update of the period before it is Fulu (electra layout).
	fulu1378Period   = 1378
	firstLinkPeriod  = 1379
	spineHeaderCount = 20

	gloasUpdateSize       = 26424
	gloasBootstrapSize    = 25472
	gloasFinalityUpdSize  = 1448
	finalizedHeaderOffset = 496 // in a finality update: attested(496) then finalized_header
)

var httpc = &http.Client{Timeout: 60 * time.Second}

func get(url, accept string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return b, resp.StatusCode, err
}

func rpc(method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := httpc.Post(publicnode, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string }
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("rpc %s: %v: %.200s", method, err, b)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc %s: %s", method, out.Error.Message)
	}
	return out.Result, nil
}

func keccak(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}

func bigOf(s string) *big.Int {
	v, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		panic("bad quantity " + s)
	}
	return v
}

// headerFromBlock rebuilds the raw RLP header from eth_getBlockByHash fields. Every field the node serves is encoded in
// the consensus order; the caller checks keccak256(rlp) against the block hash, which proves the field list is complete.
func headerFromBlock(m map[string]any) ([]byte, error) {
	s := func(k string) string { v, _ := m[k].(string); return v }
	items := []any{
		unhex(s("parentHash")), unhex(s("sha3Uncles")), unhex(s("miner")), unhex(s("stateRoot")), unhex(s("transactionsRoot")),
		unhex(s("receiptsRoot")), unhex(s("logsBloom")), bigOf(s("difficulty")), bigOf(s("number")), bigOf(s("gasLimit")),
		bigOf(s("gasUsed")), bigOf(s("timestamp")), unhex(s("extraData")), unhex(s("mixHash")), unhex(s("nonce")),
	}
	for _, k := range []string{"baseFeePerGas"} {
		if _, ok := m[k]; ok {
			items = append(items, bigOf(s(k)))
		}
	}
	if _, ok := m["withdrawalsRoot"]; ok {
		items = append(items, unhex(s("withdrawalsRoot")))
	}
	for _, k := range []string{"blobGasUsed", "excessBlobGas"} {
		if _, ok := m[k]; ok {
			items = append(items, bigOf(s(k)))
		}
	}
	for _, k := range []string{"parentBeaconBlockRoot", "requestsHash", "blockAccessListHash"} {
		if _, ok := m[k]; ok {
			items = append(items, unhex(s(k)))
		}
	}
	if _, ok := m["slotNumber"]; ok {
		items = append(items, bigOf(s("slotNumber")))
	}
	return rlp.EncodeToBytes(items)
}

func blockByHash(h string) (map[string]any, error) {
	raw, err := rpc("eth_getBlockByHash", h, false)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("block %s not served: %v", h, err)
	}
	return m, nil
}

type capture struct {
	CapturedUTC      string   `json:"captured_utc"`
	Lodestar         string   `json:"lodestar"`
	ExecEndpoint     string   `json:"exec_endpoint"`
	SigPeriod        uint64   `json:"final_signature_period"`
	FinalAttested    uint64   `json:"final_attested_slot"`
	FinalSignature   uint64   `json:"final_signature_slot"`
	BootstrapRoot    string   `json:"bootstrap_block_root"`
	BootstrapSlot    uint64   `json:"bootstrap_header_slot"`
	LinkPeriods      []uint64 `json:"link_periods"`
	ExecFinalizedHex string   `json:"final_finalized_exec_hash"`
	NodeVersion      string   `json:"lodestar_node_version"`
	FinalizedTagHash string   `json:"eth_getBlockByNumber_finalized_hash"`
	FinalizedTagNum  string   `json:"eth_getBlockByNumber_finalized_number"`
}

// record captures the live data once into rawDir; every test afterwards is offline.
func record(rawDir string) error {
	if err := os.MkdirAll(filepath.Join(rawDir, "updates"), 0o755); err != nil {
		return err
	}
	cap := capture{CapturedUTC: time.Now().UTC().Format(time.RFC3339), Lodestar: lodestar, ExecEndpoint: publicnode}
	if b, _, err := get(lodestar+"/eth/v1/node/version", ""); err == nil {
		cap.NodeVersion = strings.TrimSpace(string(b))
	}
	fu, code, err := get(lodestar+"/eth/v1/beacon/light_client/finality_update", "application/octet-stream")
	if err != nil || code != 200 || len(fu) != gloasFinalityUpdSize {
		return fmt.Errorf("finality_update: code %d len %d err %v", code, len(fu), err)
	}
	attested := binary.LittleEndian.Uint64(fu[0:8])
	sigSlot := binary.LittleEndian.Uint64(fu[len(fu)-8:])
	sigPeriod := sigSlot / 32 / 256
	cap.FinalAttested, cap.FinalSignature, cap.SigPeriod = attested, sigSlot, sigPeriod
	cap.ExecFinalizedHex = "0x" + hex.EncodeToString(fu[finalizedHeaderOffset+112:finalizedHeaderOffset+144])
	if err := os.WriteFile(filepath.Join(rawDir, "finality_update.ssz"), fu, 0o644); err != nil {
		return err
	}

	// bootstrap: Lodestar serves it only for the checkpoint roots of the head epoch and the two before it.
	cp, code, err := get(lodestar+"/eth/v1/beacon/states/head/finality_checkpoints", "")
	if err != nil || code != 200 {
		return fmt.Errorf("finality_checkpoints: %d %v", code, err)
	}
	var cps struct {
		Data struct {
			PreviousJustified struct{ Root string } `json:"previous_justified"`
			CurrentJustified  struct{ Root string } `json:"current_justified"`
			Finalized         struct{ Root string } `json:"finalized"`
		} `json:"data"`
	}
	if err := json.Unmarshal(cp, &cps); err != nil {
		return err
	}
	var boot []byte
	for _, r := range []string{cps.Data.CurrentJustified.Root, cps.Data.PreviousJustified.Root, cps.Data.Finalized.Root} {
		b, code, _ := get(lodestar+"/eth/v1/beacon/light_client/bootstrap/"+r, "application/octet-stream")
		if code == 200 && len(b) == gloasBootstrapSize {
			boot = b
			cap.BootstrapRoot = r
			break
		}
	}
	if boot == nil {
		return fmt.Errorf("no bootstrap served for the head checkpoints")
	}
	cap.BootstrapSlot = binary.LittleEndian.Uint64(boot[0:8])
	if cap.BootstrapSlot/32/256 != sigPeriod {
		return fmt.Errorf("bootstrap period %d != final signature period %d: a period boundary fell inside the capture; run again", cap.BootstrapSlot/32/256, sigPeriod)
	}
	if err := os.WriteFile(filepath.Join(rawDir, "bootstrap.ssz"), boot, 0o644); err != nil {
		return err
	}

	// updates: one Fulu (period 1378) then the Gloas ones up to the period before the final update's.
	count := int(sigPeriod) - fulu1378Period
	body, code, err := get(fmt.Sprintf("%s/eth/v1/beacon/light_client/updates?start_period=%d&count=%d", lodestar, fulu1378Period, count), "application/octet-stream")
	if err != nil || code != 200 {
		return fmt.Errorf("updates: %d %v", code, err)
	}
	pos, i := 0, 0
	for pos < len(body) {
		if pos+12 > len(body) {
			return fmt.Errorf("updates frame truncated at %d", pos)
		}
		n := int(binary.LittleEndian.Uint64(body[pos : pos+8]))
		if pos+8+n > len(body) || n < 4 {
			return fmt.Errorf("updates frame length %d at %d overruns", n, pos)
		}
		ssz := body[pos+12 : pos+8+n]
		period := uint64(fulu1378Period + i)
		name := fmt.Sprintf("updates/%d.ssz", period)
		if period >= firstLinkPeriod && len(ssz) != gloasUpdateSize {
			return fmt.Errorf("update %d has %d bytes, want %d", period, len(ssz), gloasUpdateSize)
		}
		if err := os.WriteFile(filepath.Join(rawDir, name), ssz, 0o644); err != nil {
			return err
		}
		if period >= firstLinkPeriod {
			cap.LinkPeriods = append(cap.LinkPeriods, period)
		}
		pos += 8 + n
		i++
	}
	if i != count {
		return fmt.Errorf("got %d updates, want %d", i, count)
	}

	// execution spine from the finalized execution head
	head := cap.ExecFinalizedHex
	var hdrs []string
	var hashes []string
	cur := head
	for k := 0; k < spineHeaderCount; k++ {
		m, err := blockByHash(cur)
		if err != nil {
			return err
		}
		raw, err := headerFromBlock(m)
		if err != nil {
			return err
		}
		if got := "0x" + hex.EncodeToString(keccak(raw)); got != cur {
			return fmt.Errorf("header %d: rebuilt RLP hashes to %s, node says %s (a header field is missing from the encoder)", k, got, cur)
		}
		hdrs = append(hdrs, "0x"+hex.EncodeToString(raw))
		hashes = append(hashes, cur)
		cur, _ = m["parentHash"].(string)
	}
	hj, _ := json.MarshalIndent(map[string]any{"headers_rlp": hdrs, "hashes": hashes}, "", " ")
	if err := os.WriteFile(filepath.Join(rawDir, "spine.json"), hj, 0o644); err != nil {
		return err
	}
	if raw, err := rpc("eth_getBlockByNumber", "finalized", false); err == nil {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			cap.FinalizedTagHash, _ = m["hash"].(string)
			cap.FinalizedTagNum, _ = m["number"].(string)
		}
	}
	cj, _ := json.MarshalIndent(cap, "", " ")
	return os.WriteFile(filepath.Join(rawDir, "capture.json"), cj, 0o644)
}
