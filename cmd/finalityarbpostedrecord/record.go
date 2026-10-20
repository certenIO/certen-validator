// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

const (
	lodestar   = "https://lodestar-sepolia.chainsafe.io"
	l1RPC      = "https://ethereum-sepolia-rpc.publicnode.com"
	l2RPC      = "https://sepolia-rollup.arbitrum.io/rpc"
	chainArb   = uint64(421614)
	wspEpochs  = 279
	committee  = 24624
	offBootCom = 496
	offFinHdr  = 496 // finalized header inside a finality update (attested(496) first)
)

var httpc = &http.Client{Timeout: 90 * time.Second}

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

func rpcCall(url, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := httpc.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string }
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("rpc %s: undecodable answer (%d bytes)", method, len(b))
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc %s: %s", method, out.Error.Message)
	}
	return out.Result, nil
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

// headerFromBlock rebuilds the raw RLP header from eth_getBlockByHash fields in consensus order; the caller checks the hash.
func headerFromBlock(m map[string]any) []byte {
	s := func(k string) string { v, _ := m[k].(string); return v }
	items := []any{
		unhex(s("parentHash")), unhex(s("sha3Uncles")), unhex(s("miner")), unhex(s("stateRoot")), unhex(s("transactionsRoot")),
		unhex(s("receiptsRoot")), unhex(s("logsBloom")), bigOf(s("difficulty")), bigOf(s("number")), bigOf(s("gasLimit")),
		bigOf(s("gasUsed")), bigOf(s("timestamp")), unhex(s("extraData")), unhex(s("mixHash")), unhex(s("nonce")),
	}
	if _, ok := m["baseFeePerGas"]; ok {
		items = append(items, bigOf(s("baseFeePerGas")))
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
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return raw
}

func blockJSON(url, method string, arg any, full bool) (map[string]any, error) {
	raw, err := rpcCall(url, method, arg, full)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%s: no block served", method)
	}
	return m, nil
}

// l1Headers serves L1 execution headers (rebuilt RLP, hash checked) to the builder.
type l1Headers struct{ lc ethl1.LC }

func (l *l1Headers) LightClient(context.Context) (ethl1.LC, error) { return l.lc, nil }
func (l *l1Headers) HeaderRLP(_ context.Context, n uint64) ([]byte, error) {
	m, err := blockJSON(l1RPC, "eth_getBlockByNumber", fmt.Sprintf("0x%x", n), false)
	if err != nil {
		return nil, err
	}
	return checked(m)
}
func (l *l1Headers) HeaderRLPByHash(_ context.Context, h [32]byte) ([]byte, error) {
	m, err := blockJSON(l1RPC, "eth_getBlockByHash", "0x"+hex.EncodeToString(h[:]), false)
	if err != nil {
		return nil, err
	}
	return checked(m)
}

func checked(m map[string]any) ([]byte, error) {
	raw := headerFromBlock(m)
	if got := "0x" + hex.EncodeToString(crypto.Keccak256(raw)); got != m["hash"] {
		return nil, fmt.Errorf("rebuilt header hashes to %s, node says %v", got, m["hash"])
	}
	return raw, nil
}

type l2Block struct {
	txs map[[32]byte][][]byte
}

func (l *l2Block) BlockTxs(_ context.Context, h [32]byte) ([][]byte, error) {
	if t, ok := l.txs[h]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("block not loaded")
}

// lcFromLodestar builds a kind-1 LC: the committee of the finality update's signature period from a served bootstrap, and the
// live finality update. It returns the LC, the bootstrap block root and the finalized execution hash.
func lcFromLodestar() (ethl1.LC, string, [32]byte, error) {
	var lc ethl1.LC
	fu, code, err := get(lodestar+"/eth/v1/beacon/light_client/finality_update", "application/octet-stream")
	if err != nil || code != 200 || len(fu) != ethl1.LightClientFinalityUpdateSize {
		return lc, "", [32]byte{}, fmt.Errorf("finality_update: code %d len %d err %v", code, len(fu), err)
	}
	sigSlot := binary.LittleEndian.Uint64(fu[len(fu)-8:])
	period := sigSlot / 32 / 256
	var exec [32]byte
	copy(exec[:], fu[offFinHdr+112:offFinHdr+144])
	cp, code, err := get(lodestar+"/eth/v1/beacon/states/head/finality_checkpoints", "")
	if err != nil || code != 200 {
		return lc, "", exec, fmt.Errorf("finality_checkpoints: %d %v", code, err)
	}
	var cps struct {
		Data struct {
			PreviousJustified struct{ Root string } `json:"previous_justified"`
			CurrentJustified  struct{ Root string } `json:"current_justified"`
			Finalized         struct{ Root string } `json:"finalized"`
		} `json:"data"`
	}
	if err := json.Unmarshal(cp, &cps); err != nil {
		return lc, "", exec, err
	}
	for _, r := range []string{cps.Data.CurrentJustified.Root, cps.Data.PreviousJustified.Root, cps.Data.Finalized.Root} {
		b, code, _ := get(lodestar+"/eth/v1/beacon/light_client/bootstrap/"+r, "application/octet-stream")
		if code != 200 || len(b) != ethl1.LightClientBootstrapSize {
			continue
		}
		if binary.LittleEndian.Uint64(b[0:8])/32/256 != period {
			return lc, "", exec, fmt.Errorf("bootstrap period differs from the signature period %d: run again", period)
		}
		comm := b[offBootCom : offBootCom+committee]
		root, err := ethl1.HashTreeRootSyncCommittee(comm)
		if err != nil {
			return lc, "", exec, err
		}
		lc = ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: period, AnchorRoot: root,
			AnchorBody:  ethl1.LB{Layout: ethl1.LayoutNone, SSZ: append([]byte(nil), comm...)},
			FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: fu}}
		return lc, r, exec, nil
	}
	return lc, "", exec, fmt.Errorf("no bootstrap served for the head checkpoints")
}

// pinsWithAnchor is the embedded pins file with the ledger entry for the LC's period added: a configured pin derived from the
// served bootstrap (derived_by names Lodestar's bootstrap, not an independent client agreement).
func pinsWithAnchor(lc ethl1.LC, bootRoot string, bootstrapSHA [32]byte) ([]byte, error) {
	var d map[string]any
	dec := json.NewDecoder(bytes.NewReader(finality.EmbeddedPinsBytes()))
	dec.UseNumber()
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	e := d["eth_sepolia"].(map[string]any)
	e["anchors"] = []any{map[string]any{
		"period":         json.Number(fmt.Sprint(lc.AnchorPeriod)),
		"committee_root": "0x" + hex.EncodeToString(lc.AnchorRoot[:]),
		"block_root":     bootRoot,
		"wsp_epochs":     json.Number(fmt.Sprint(wspEpochs)),
		"link_sha256":    hex.EncodeToString(bootstrapSHA[:]),
		"derived_by":     []any{"lodestar-bootstrap (finalityethl1record method; vector pin, not an independent derivation)"},
	}}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type rawLeg struct {
	Chain     string   `json:"chain"`
	Number    string   `json:"number"`
	Hash      string   `json:"hash"`
	HeaderRLP string   `json:"header_rlp"`
	Txs       []string `json:"txs"`
}

// record assembles the live evidence for one captured batch and writes raw/{evidence.bin, leg.json, pins.json, capture.json}.
func record(storeDir, rawDir string, batchN uint64) error {
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return err
	}
	store, err := capture.NewDirStore(storeDir)
	if err != nil {
		return err
	}
	batches, err := capture.LoadBatches(store, chainArb)
	if err != nil {
		return err
	}
	var rec *capture.BatchRecord
	for i := range batches {
		if batches[i].N == batchN || (batchN == 0 && rec == nil) {
			ps, _ := capture.LoadProofs(store, chainArb, batches[i].N)
			if len(ps) > 0 && batches[i].DataLocation == capture.LocBlob {
				rec = &batches[i]
				if batchN != 0 {
					break
				}
			}
		}
	}
	if rec == nil {
		return fmt.Errorf("no captured blob batch with a proof (want %d)", batchN)
	}
	blobs, err := capture.LoadBlobs(store, chainArb, *rec)
	if err != nil || len(blobs) != len(rec.VersionedHashes) {
		return fmt.Errorf("blobs of batch %d: %v (%d of %d)", rec.N, err, len(blobs), len(rec.VersionedHashes))
	}
	raws := make([][]byte, len(blobs))
	for i := range blobs {
		raws[i] = blobs[i].Raw
	}
	payload, err := arbposted.PayloadFromBlobs(raws)
	if err != nil {
		return err
	}
	msgs, err := arbposted.MessageTxs(payload, 16777216, 102400)
	if err != nil {
		return err
	}
	// prefer a block with two standard transactions (an order-swap vector needs two); else one
	pick := -1
	for i, m := range msgs {
		if len(m) >= 2 && len(m) <= 3 {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i, m := range msgs {
			if len(m) == 1 {
				pick = i
				break
			}
		}
	}
	if pick < 0 {
		return fmt.Errorf("batch %d has no small message", rec.N)
	}
	txHash := crypto.Keccak256Hash(msgs[pick][0])
	tj, err := rpcCall(l2RPC, "eth_getTransactionByHash", txHash.Hex())
	if err != nil {
		return err
	}
	var tx struct {
		BlockHash string `json:"blockHash"`
	}
	if err := json.Unmarshal(tj, &tx); err != nil || tx.BlockHash == "" {
		return fmt.Errorf("L2 does not serve transaction %s", txHash.Hex())
	}
	bm, err := blockJSON(l2RPC, "eth_getBlockByHash", tx.BlockHash, true)
	if err != nil {
		return err
	}
	hdr, err := checked(bm)
	if err != nil {
		return err
	}
	var encs [][]byte
	for _, t := range bm["transactions"].([]any) {
		rawTx, _ := json.Marshal(t)
		enc, _, err := ethproof.EncodeTxJSON(rawTx)
		if err != nil {
			return fmt.Errorf("encode L2 transaction: %w", err)
		}
		encs = append(encs, enc)
	}
	fh, err := finality.ReadHeader(hdr)
	if err != nil {
		return err
	}
	if ethproof.TrieRoot(encs) != common.Hash(fh.TransactionRoot) {
		return fmt.Errorf("L2 transactions do not hash to the header's root")
	}

	lc, bootRoot, execHash, err := lcFromLodestar()
	if err != nil {
		return err
	}
	bootBytes, _, _ := get(lodestar+"/eth/v1/beacon/light_client/bootstrap/"+bootRoot, "application/octet-stream")
	pinsBytes, err := pinsWithAnchor(lc, bootRoot, sha256.Sum256(bootBytes))
	if err != nil {
		return err
	}
	pins, err := finality.ParsePinsOverride(pinsBytes)
	if err != nil {
		return err
	}
	b := &arbposted.Builder{Store: store, L2: &l2Block{txs: map[[32]byte][][]byte{fh.Hash: encs}}, L1: &l1Headers{lc: lc}, Pins: pins}
	ref := finality.BlockRef{Chain: chainArb, Number: fh.Number, Hash: fh.Hash, HeaderRLP: hdr}
	add, pend, err := b.BuildFor(context.Background(), ref)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if pend != nil {
		return fmt.Errorf("pending: %s", pend.State().Error())
	}
	leg := rawLeg{Chain: fmt.Sprint(chainArb), Number: fmt.Sprint(fh.Number), Hash: "0x" + hex.EncodeToString(fh.Hash[:]), HeaderRLP: "0x" + hex.EncodeToString(hdr)}
	for _, e := range encs {
		leg.Txs = append(leg.Txs, "0x"+hex.EncodeToString(e))
	}
	lj, _ := json.MarshalIndent(leg, "", " ")
	cj, _ := json.MarshalIndent(map[string]any{
		"captured_utc": time.Now().UTC().Format(time.RFC3339), "batch": rec.N, "message_index": pick, "l1_event_block": rec.L1Block,
		"lodestar": lodestar, "l1_rpc": l1RPC, "l2_rpc": l2RPC, "bootstrap_block_root": bootRoot,
		"finalized_exec_hash": "0x" + hex.EncodeToString(execHash[:]),
	}, "", " ")
	for name, data := range map[string][]byte{"evidence.bin": add.Evidence, "leg.json": lj, "pins.json": pinsBytes, "capture.json": cj} {
		if err := os.WriteFile(filepath.Join(rawDir, name), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("recorded batch %d block %d evidence %d bytes\n", rec.N, fh.Number, len(add.Evidence))
	return nil
}
