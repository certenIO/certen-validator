// Copyright 2026 Certen Protocol

// Command finalityarbfinalrecord performs ONE live run of the arb-sepolia/finalized/v1 builder and writes the raw capture of the
// REAL positive vector (V2_SPEC_S7 5.7, RB11-E1): a recent honest confirmation, the covering assertion, the Rollup proofs of S and K
// captured near the L1 head, the L1-finality part, the L2 header chain, the assembled and verified evidence, and the pins it was
// judged against. It also captures the 2025-10-13 owner force-confirm transaction and receipt (L1 block 9404699) with their
// trie proofs, the real classifier input. Every provider text that reaches stderr or a file goes through ethrpc.RedactText.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/build"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

const (
	defaultOut      = `C:\Users\jason\AppData\Local\Temp\claude\C--Accumulate-Stuff-certen\5bb82f09-6fd0-49ca-99b1-4e1bfad31384\scratchpad\arbfinal-live`
	forceTx         = "0x350518a98c5a0bee841046809ef90bab1ea849082de18c714d02c845033fcc16"
	forceBlock      = 9404699
	selectorConfirm = "10b98a35"
)

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", time.Now().UTC().Format("15:04:05"), ethrpc.RedactText(fmt.Sprintf(format, a...)))
}

func die(format string, a ...any) {
	logf("FATAL: "+format, a...)
	os.Exit(1)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func write(dir, name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		die("write %s: %v", name, err)
	}
}

func writeJSON(dir, name string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		die("json %s: %v", name, err)
	}
	write(dir, name, append(b, '\n'))
}

func main() {
	out := flag.String("out", defaultOut, "output directory")
	l1urls := flag.String("l1", "https://ethereum-sepolia-rpc.publicnode.com", "L1 JSON-RPC endpoints (logs, blocks, headers), comma separated")
	proofURLs := flag.String("proof", "https://0xrpc.io/sep,https://api.zan.top/eth-sepolia,https://1rpc.io/sepolia,https://sepolia.gateway.tenderly.co", "L1 eth_getProof endpoints, comma separated")
	l2url := flag.String("l2", "https://sepolia-rollup.arbitrum.io/rpc", "Arbitrum Sepolia JSON-RPC endpoints, comma separated")
	beacon := flag.String("beacon", "https://lodestar-sepolia.chainsafe.io", "beacon API (light client endpoints)")
	rawDir := flag.String("raw", `pkg/finality/ethl1/testdata/finality_ethl1_v2/raw`, "ethl1 v2 raw capture directory (the bootstrap of the ledger's last anchor)")
	ledger := flag.String("ledger", `pkg/finality/ethl1/testdata/finality_ethl1_v2/pins/main.json`, "ethl1 v2 ledger (anchors)")
	gap := flag.Uint64("gap", 800, "the leg is this many L2 blocks below the covering assertion's end block")
	freshness := flag.Uint64("fresh", 70, "a confirmation is captured only if it is at most this many L1 blocks below the head")
	stateAhead := flag.Uint64("state-ahead", 4, "S = K + this (capped at the head)")
	maxWait := flag.Duration("wait", 75*time.Minute, "give up after this long")
	skipForce := flag.Bool("skip-force", false, "skip the force-confirm capture")
	skipLive := flag.Bool("skip-live", false, "skip the live run")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *maxWait+10*time.Minute)
	defer cancel()
	l1 := &build.LiveL1{Endpoints: splitList(*l1urls), ProofEndpoints: splitList(*proofURLs)}
	l2 := &build.LiveL2{Endpoints: splitList(*l2url)}

	if !*skipForce {
		if err := recordForce(ctx, l1, *out); err != nil {
			die("force capture: %v", ethrpc.RedactText(err.Error()))
		}
	}
	if *skipLive {
		return
	}
	pinsRaw, anchorLB, anchorRoot, anchorPeriod, err := buildPins(*rawDir, *ledger)
	if err != nil {
		die("pins: %v", ethrpc.RedactText(err.Error()))
	}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		die("pins parse: %v", err)
	}
	write(*out, "pins.json", pinsRaw)
	lc := &build.BeaconLC{Beacon: *beacon, AnchorKind: 2, AnchorPeriod: anchorPeriod, AnchorRoot: anchorRoot, AnchorBody: anchorLB}
	arb, err := arbfinal.LoadPins(pins)
	if err != nil {
		die("arb pins: %v", err)
	}
	deadline := time.Now().Add(*maxWait)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		ok, err := liveAttempt(ctx, attempt, deadline, pins, arb, l1, l2, lc, *out, *gap, *freshness, *stateAhead)
		if err != nil {
			die("live attempt %d: %v", attempt, ethrpc.RedactText(err.Error()))
		}
		if ok {
			return
		}
	}
	die("no evidence within %s", *maxWait)
}

// buildPins is the embedded pins file with eth_sepolia.anchors replaced by the ledger of the ethl1 v2 vectors (the embedded
// ledger is empty on this branch) and the anchor of the walk: the Gloas bootstrap of the ledger's last kind-2 entry.
func buildPins(rawDir, ledgerPath string) ([]byte, ethl1.LB, [32]byte, uint64, error) {
	var zero [32]byte
	var lb ethl1.LB
	lraw, err := os.ReadFile(ledgerPath)
	if err != nil {
		return nil, lb, zero, 0, err
	}
	var led struct {
		Anchors []struct {
			Period        string  `json:"period"`
			CommitteeRoot string  `json:"committee_root"`
			BlockRoot     *string `json:"block_root"`
			WspEpochs     string  `json:"wsp_epochs"`
		} `json:"anchors"`
	}
	if err := json.Unmarshal(lraw, &led); err != nil || len(led.Anchors) == 0 {
		return nil, lb, zero, 0, fmt.Errorf("ledger %s: %v", ledgerPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &doc); err != nil {
		return nil, lb, zero, 0, err
	}
	es, _ := doc["eth_sepolia"].(map[string]any)
	if es == nil {
		return nil, lb, zero, 0, fmt.Errorf("embedded pins have no eth_sepolia")
	}
	var anchors []any
	var lastPeriod uint64
	var lastRoot string
	for _, a := range led.Anchors {
		var period, wsp uint64
		fmt.Sscan(a.Period, &period)
		fmt.Sscan(a.WspEpochs, &wsp)
		linkSrc := filepath.Join(rawDir, "updates", fmt.Sprintf("%d.ssz", period-1))
		if period == 1378 {
			linkSrc = filepath.Join(rawDir, "bootstrap_fulu.ssz")
		}
		lb, err := os.ReadFile(linkSrc)
		if err != nil {
			return nil, ethl1.LB{}, zero, 0, err
		}
		sum := sha256.Sum256(lb)
		m := map[string]any{"period": period, "committee_root": a.CommitteeRoot, "wsp_epochs": wsp, "link_sha256": hex.EncodeToString(sum[:]),
			"derived_by": []string{"ethl1-v2-vector-ledger (lodestar captured links, 2026-10-20)"}}
		if a.BlockRoot != nil {
			m["block_root"] = *a.BlockRoot
			lastPeriod, lastRoot = period, *a.BlockRoot
		}
		anchors = append(anchors, m)
	}
	es["anchors"] = anchors
	if lastRoot == "" {
		return nil, lb, zero, 0, fmt.Errorf("the ledger has no kind-2 anchor")
	}
	boot, err := os.ReadFile(filepath.Join(rawDir, "bootstrap.ssz"))
	if err != nil {
		return nil, lb, zero, 0, err
	}
	rb, _ := hex.DecodeString(strings.TrimPrefix(lastRoot, "0x"))
	var root [32]byte
	copy(root[:], rb)
	raw, err := marshalSorted(doc)
	return raw, ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: boot}, root, lastPeriod, err
}

func marshalSorted(v any) ([]byte, error) {
	var norm func(any) any
	norm = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			o := orderedMap{}
			for _, k := range keys {
				o = append(o, kv{k, norm(t[k])})
			}
			return o
		case []any:
			for i := range t {
				t[i] = norm(t[i])
			}
			return t
		}
		return x
	}
	b, err := json.MarshalIndent(norm(v), "", "  ")
	return append(b, '\n'), err
}

type kv struct {
	k string
	v any
}
type orderedMap []kv

func (o orderedMap) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(e.k)
		vb, err := json.Marshal(e.v)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// recordForce captures the 2025-10-13 owner force-confirm transaction and receipt with their trie proofs.
func recordForce(ctx context.Context, l1 *build.LiveL1, out string) error {
	logf("force capture: block %d", forceBlock)
	blk, err := l1.Block(ctx, forceBlock)
	if err != nil {
		return err
	}
	hf, err := finality.ReadHeader(blk.HeaderRLP)
	if err != nil {
		return err
	}
	if ethproof.TrieRoot(blk.Txs) != common.Hash(hf.TransactionRoot) || ethproof.TrieRoot(blk.Receipts) != common.Hash(hf.ReceiptsRoot) {
		return fmt.Errorf("the block's rebuilt tries do not match the header's roots")
	}
	want := common.HexToHash(forceTx)
	idx := -1
	for i, tx := range blk.Txs {
		if common.Hash(cryptoKeccak(tx)) == want {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("transaction %s not in block %d", forceTx[:12], forceBlock)
	}
	tp, err := ethproof.Prove(blk.Txs, uint64(idx), common.Hash(hf.TransactionRoot))
	if err != nil {
		return err
	}
	rp, err := ethproof.Prove(blk.Receipts, uint64(idx), common.Hash(hf.ReceiptsRoot))
	if err != nil {
		return err
	}
	nodes := finality.EncodeNodes(append(append([][]byte(nil), tp.ProofNodes...), rp.ProofNodes...))
	var w finality.Writer
	w.LPList(nodes)
	write(out, "force_header.bin", blk.HeaderRLP)
	write(out, "force_tx.bin", blk.Txs[idx])
	write(out, "force_receipt.bin", blk.Receipts[idx])
	write(out, "force_proof_nodes.bin", w.Bytes())
	writeJSON(out, "force.json", map[string]any{
		"tx_hash": forceTx, "block_number": forceBlock, "block_hash": "0x" + hex.EncodeToString(hf.Hash[:]), "tx_index": idx,
		"transactions_root": "0x" + hex.EncodeToString(hf.TransactionRoot[:]), "receipts_root": "0x" + hex.EncodeToString(hf.ReceiptsRoot[:]),
		"state_root": "0x" + hex.EncodeToString(hf.StateRoot[:]), "timestamp": hf.Timestamp, "header_items": hf.Items,
		"tx_bytes": len(blk.Txs[idx]), "receipt_bytes": len(blk.Receipts[idx]), "proof_node_count": len(nodes),
		"file_format": "force_proof_nodes.bin = u32be count, then u32be length + node, strictly ascending by keccak256 (the NODES set of spec 0)",
	})
	logf("force capture: tx index %d of %d, %d proof nodes", idx, len(blk.Txs), len(nodes))
	return nil
}
