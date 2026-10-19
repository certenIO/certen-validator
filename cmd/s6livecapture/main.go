// Copyright 2026 Certen Protocol

// s6livecapture - real S6 replay-guard evidence of fresh settlements, captured at inclusion from public providers
// (RB10-B3).
//
//	s6livecapture -chain base-sepolia -watch [-account 0x..] [-for 30m] [-out dir]
//	    watch the chain's head for a CertenAccount's LeafConsumed log and capture each settlement the moment it lands
//	s6livecapture -chain arbitrum-sepolia -tx 0x.. [-out dir]
//	    capture one settlement by transaction hash
//
// For each settlement it records every RAW provider answer - the transaction, the receipt, the block body and receipts,
// the headers N-1, N and up to the head H, and eth_getProof for the account and the slot keccak256(abi.encode(leaf, 4))
// at N-1, N and H from every provider tried, with each provider's error text - into <chain>-<tx>.world.json.gz. It then
// runs ethproof.CaptureReplayGuard and ethproof's Verify on that RECORDED world, served back to the same clients, and
// writes the evidence (<..>.evidence.json) and the verdict (<..>.verdict.json). Only public RPC URLs are used.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// chainDef is a live chain and its public providers.
type chainDef struct {
	Name    string
	ChainID int64
	URLs    []string
	Poll    time.Duration
}

var chains = map[string]chainDef{
	"sepolia": {Name: "sepolia", ChainID: 11155111, Poll: 3 * time.Second,
		URLs: []string{"https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.gateway.tenderly.co"}},
	"base-sepolia": {Name: "base-sepolia", ChainID: 84532, Poll: time.Second,
		URLs: []string{"https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"}},
	"arbitrum-sepolia": {Name: "arbitrum-sepolia", ChainID: 421614, Poll: 500 * time.Millisecond,
		URLs: []string{"https://sepolia-rollup.arbitrum.io/rpc", "https://arbitrum-sepolia-rpc.publicnode.com"}},
	"adiri": {Name: "adiri", ChainID: 2017, Poll: 500 * time.Millisecond,
		URLs: []string{"https://rpc.telcoin.network", "https://node1.telcoin.network", "https://node2.telcoin.network"}},
}

func providersOf(c chainDef) []Provider {
	var out []Provider
	for _, u := range c.URLs {
		out = append(out, Provider{Host: hostOf(u), URL: u})
	}
	return out
}

func main() {
	chainName := flag.String("chain", "base-sepolia", "sepolia | base-sepolia | arbitrum-sepolia | adiri")
	txHex := flag.String("tx", "", "capture this settlement transaction")
	watch := flag.Bool("watch", false, "watch the head for LeafConsumed and capture each settlement at inclusion")
	account := flag.String("account", "", "watch: only this account's LeafConsumed (default: any account)")
	forDur := flag.Duration("for", 30*time.Minute, "watch: how long")
	max := flag.Int("max", 1, "watch: stop after this many captures")
	out := flag.String("out", filepath.Join("pkg", "ethproof", "testdata", "s6live1"), "output directory")
	budget := flag.Duration("budget", 90*time.Second, "live capture budget per settlement")
	world := flag.String("world", "", "judge this recorded world again, offline, and rewrite its evidence and verdict")
	flag.Parse()

	if *world != "" {
		v, err := rejudge(*world)
		report(v, err)
		if err != nil {
			os.Exit(1)
		}
		return
	}

	c, ok := chains[*chainName]
	if !ok {
		fatal("unknown chain %q", *chainName)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal("%v", err)
	}
	switch {
	case *txHex != "":
		v, err := captureOne(context.Background(), c, common.HexToHash(*txHex), nil, *out, *budget)
		report(v, err)
	case *watch:
		var acct *common.Address
		if *account != "" {
			a := common.HexToAddress(*account)
			acct = &a
		}
		if err := watchChain(c, acct, *forDur, *max, *out, *budget); err != nil {
			fatal("%v", err)
		}
	default:
		fatal("give -tx or -watch")
	}
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "s6livecapture: "+f+"\n", a...)
	os.Exit(1)
}

func report(v *Verdict, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "s6livecapture: %v\n", err)
	}
	if v != nil {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	}
}

// hint is what the watcher already knows when it sees the log: the block, the account and the leaf, so the slot can be
// asked for at once while the block is still the head.
type hint struct {
	block   uint64
	account common.Address
	leaf    common.Hash
}

// watchChain polls one provider's logs (an unrecorded locator: it only says where to look) and captures each new
// settlement.
func watchChain(c chainDef, acct *common.Address, dur time.Duration, max int, out string, budget time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	var cl []*ethclient.Client
	for _, u := range c.URLs {
		e, err := ethclient.DialContext(ctx, u)
		if err != nil {
			return err
		}
		cl = append(cl, e)
	}
	var from uint64
	for i := 0; from == 0; i++ {
		if n, err := cl[i%len(cl)].BlockNumber(ctx); err == nil {
			from = n
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	fmt.Fprintf(os.Stderr, "%s watching %s from block %d for LeafConsumed\n", time.Now().UTC().Format(time.RFC3339), c.Name, from)
	seen := map[common.Hash]bool{}
	done := 0
	var wg sync.WaitGroup
	for i := 0; ctx.Err() == nil && done < max; i++ {
		e := cl[i%len(cl)]
		head, err := e.BlockNumber(ctx)
		if err == nil && head >= from {
			q := ethereum.FilterQuery{FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(head),
				Topics: [][]common.Hash{{ethproof.LeafConsumedTopic}}}
			if acct != nil {
				q.Addresses = []common.Address{*acct}
			}
			logs, lerr := e.FilterLogs(ctx, q)
			if lerr == nil {
				for _, lg := range logs {
					if seen[lg.TxHash] || len(lg.Topics) != 3 || done >= max {
						continue
					}
					seen[lg.TxHash] = true
					done++
					h := &hint{block: lg.BlockNumber, account: lg.Address, leaf: lg.Topics[2]}
					fmt.Fprintf(os.Stderr, "%s %s LeafConsumed tx %s block %d (head %d) account %s\n", time.Now().UTC().Format(time.RFC3339Nano),
						c.Name, lg.TxHash.Hex(), lg.BlockNumber, head, lg.Address.Hex())
					wg.Add(1)
					go func(tx common.Hash) {
						defer wg.Done()
						v, err := captureOne(context.Background(), c, tx, h, out, budget)
						report(v, err)
					}(lg.TxHash)
				}
				from = head + 1
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(c.Poll):
		}
	}
	wg.Wait()
	if done == 0 {
		return fmt.Errorf("%s: no LeafConsumed log within %s", c.Name, dur)
	}
	return nil
}

// captureOne records the settlement's world live, then judges the recorded world.
func captureOne(ctx context.Context, c chainDef, tx common.Hash, h *hint, out string, budget time.Duration) (*Verdict, error) {
	provs := providersOf(c)
	rec := NewRecorder(c.ChainID, c.Name, provs)
	src, err := newSource(ctx, c.ChainID, provs, rec.Transport)
	if err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	// What is urgent first: the slot at the settlement block and its parent, from every provider, while they are the head.
	extras := func(n uint64, account common.Address, leaf common.Hash) {
		slot := ethproof.ReplaySlotFor(leaf, 4)
		for _, p := range src.providers {
			for _, b := range []uint64{n, n - 1} {
				wg.Add(1)
				go func(p *provider, b uint64) {
					defer wg.Done()
					_, _ = p.GetProof(ctx, account, []string{slot.Hex()}, "0x"+new(big.Int).SetUint64(b).Text(16))
				}(p, b)
			}
		}
	}
	if h != nil {
		extras(h.block, h.account, h.leaf)
	}
	logf := func(f string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, time.Now().UTC().Format(time.RFC3339Nano)+" "+f+"\n", a...)
	}
	live := ethproof.CaptureReplayGuard(ctx, ethproof.ReplayCaptureConfig{ChainID: c.ChainID, Source: src, Budget: budget, Poll: time.Second, Logf: logf}, tx)

	// The rest of the world: every provider's transaction, receipt, block body and receipts, the parent header, and the
	// slot at N and N-1 from every provider (when the watcher did not already ask).
	rc, rerr := src.TransactionReceipt(ctx, tx)
	if rerr == nil && h == nil {
		for _, lg := range rc.Logs {
			if lg != nil && len(lg.Topics) == 3 && lg.Topics[0] == ethproof.LeafConsumedTopic {
				extras(rc.BlockNumber.Uint64(), lg.Address, lg.Topics[2])
				break
			}
		}
	}
	for _, p := range src.providers {
		_, _, _ = p.TransactionByHash(ctx, tx)
	}
	if rerr == nil {
		if hdr, herr := src.HeaderByHash(ctx, rc.BlockHash); herr == nil {
			_, _ = src.HeaderByHash(ctx, hdr.ParentHash)
		}
		_, _ = ethproof.ReadBlock(ctx, src, rc.BlockHash)
	}
	wg.Wait()

	w := rec.World()
	w.TxHash = tx.Hex()
	base := filepath.Join(out, fmt.Sprintf("%s-%s", c.Name, strings.ToLower(tx.Hex()[2:14])))
	if err := WriteWorldGz(base+".world.json.gz", w); err != nil {
		return nil, err
	}
	v, ev, err := Judge(context.Background(), w)
	if err != nil {
		return v, err
	}
	v.Live = summarize(live)
	if err := writeJSON(base+".evidence.json", ev); err != nil {
		return v, err
	}
	return v, writeJSON(base+".verdict.json", v)
}

// rejudge judges a recorded world offline and rewrites its evidence and verdict beside it, keeping the live summary.
func rejudge(path string) (*Verdict, error) {
	w, err := ReadWorldGz(path)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(path, ".world.json.gz")
	var old Verdict
	if b, rerr := os.ReadFile(base + ".verdict.json"); rerr == nil {
		_ = json.Unmarshal(b, &old)
	}
	v, ev, err := Judge(context.Background(), w)
	if err != nil {
		return v, err
	}
	v.Live = old.Live
	if err := writeJSON(base+".evidence.json", ev); err != nil {
		return v, err
	}
	return v, writeJSON(base+".verdict.json", v)
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Verdict is what the recorded world establishes for S6.
type Verdict struct {
	ChainID     int64  `json:"chainId"`
	Chain       string `json:"chain"`
	TxHash      string `json:"txHash"`
	BlockNumber uint64 `json:"blockNumber"`
	BlockHash   string `json:"blockHash"`
	// Settlement: the inclusion proof of tx and receipt built from the recorded block verified ("verified"), or why not.
	Settlement string `json:"settlement"`
	// State is "proven" or the named state; Reason its reason.
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Contract string `json:"contract,omitempty"`
	Slot     string `json:"slot,omitempty"`
	ProvenAt uint64 `json:"provenAt,omitempty"`
	// Before: "proven" (slot 0 at the parent) or "s6_before_unavailable".
	Before            string                            `json:"before,omitempty"`
	BeforeUnavailable *ethproof.ReplayBeforeUnavailable `json:"beforeUnavailable,omitempty"`
	Providers         []ethproof.ReplayProviderFailure  `json:"providerErrors,omitempty"`
	Detail            string                            `json:"detail,omitempty"`
	// ServedAfter / ServedBefore: the providers whose recorded proof at that block verifies against the agreed root.
	ServedAfter  []string `json:"servedAfter,omitempty"`
	ServedBefore []string `json:"servedBefore,omitempty"`
	// Live is the verdict of the capture as it ran against the live providers.
	Live string `json:"live,omitempty"`
}

func summarize(ev *ethproof.ReplayGuardEvidence) string {
	switch {
	case ev == nil:
		return "no S6 claim (not an account settlement)"
	case ev.Proof != nil:
		b := "before proven"
		if ev.Proof.Before == nil {
			b = "s6_before_unavailable"
		}
		return fmt.Sprintf("proven at block %d, %s", ev.Proof.ProvenAt.Number, b)
	default:
		return fmt.Sprintf("%s{%s}: %s", ev.State.State, ev.State.Reason, ev.State.Detail)
	}
}

// Judge runs the capture and the verifier over a recorded world, offline: the providers are the world's answers.
func Judge(ctx context.Context, w *World) (*Verdict, *ethproof.ReplayGuardEvidence, error) {
	tr := ReplayTransports(w)
	src, err := newSource(ctx, w.ChainID, w.Providers, func(host string) http.RoundTripper { return tr[host] })
	if err != nil {
		return nil, nil, err
	}
	tx := common.HexToHash(w.TxHash)
	v := &Verdict{ChainID: w.ChainID, Chain: w.Chain, TxHash: tx.Hex()}
	// RB10-F9: the recorded world answers instantly, so the capture runs with the production budget and the live poll
	// interval on a replay clock that moves only when the capture waits: it asks what the live capture asked, in order.
	start, terr := time.Parse(time.RFC3339Nano, w.StartedUTC)
	if terr != nil {
		start = time.Unix(0, 0).UTC()
	}
	ev := ethproof.CaptureReplayGuard(ctx, ethproof.ReplayCaptureConfig{ChainID: w.ChainID, Source: src, Budget: ethproof.ReplayCaptureBudget,
		Poll: time.Second, Clock: ethproof.NewVirtualClock(start)}, tx)
	if ev == nil {
		return v, nil, fmt.Errorf("%s is no account settlement: no S6 claim", tx.Hex())
	}
	rc, err := src.TransactionReceipt(ctx, tx)
	if err != nil {
		v.Settlement = "receipt not agreed in the recorded world: " + err.Error()
		v.State, v.Reason = ev.State.State, ev.State.Reason
		return v, ev, nil
	}
	v.BlockNumber, v.BlockHash = rc.BlockNumber.Uint64(), rc.BlockHash.Hex()
	s, err := ethproof.Build(ctx, src, rc.BlockHash, tx, uint64(rc.TransactionIndex))
	if err != nil {
		v.Settlement = err.Error()
	} else {
		v.Settlement = "verified"
	}
	var chk *ethproof.ReplayGuardCheck
	if s != nil {
		chk, err = ev.Verify(s)
	} else {
		err = fmt.Errorf("no settlement proof to hold the evidence to")
	}
	if err != nil {
		v.State, v.Detail = "verify_failed", err.Error()
		return v, ev, nil
	}
	v.State, v.Reason = chk.State, chk.Reason
	v.Contract = chk.Contract.Hex()
	if ev.Proof != nil {
		p := ev.Proof
		v.Slot, v.ProvenAt = p.Slot.Slot.Hex(), p.ProvenAt.Number
		if chk.BeforeVerified {
			v.Before = "proven"
		} else {
			v.Before, v.BeforeUnavailable = "s6_before_unavailable", chk.BeforeUnavailable
		}
		if hdrN, herr := src.HeaderByHash(ctx, p.SettlementBlock.Hash); herr == nil {
			at := hdrN
			if len(p.Headers) > 0 {
				var last types.Header
				if rlp.DecodeBytes(p.Headers[len(p.Headers)-1], &last) == nil {
					at = &last
				}
			}
			v.ServedAfter = servedAt(ctx, src, p.Contract, p.Slot.Slot, at)
			if parent, perr := src.HeaderByHash(ctx, hdrN.ParentHash); perr == nil {
				v.ServedBefore = servedAt(ctx, src, p.Contract, p.Slot.Slot, parent)
			}
		}
	} else {
		v.Providers, v.Detail = ev.State.Providers, ev.State.Detail
		v.Contract = ev.State.Contract.Hex()
	}
	return v, ev, nil
}

// servedAt names the providers whose recorded proof of the slot at block verifies against the agreed header's root.
func servedAt(ctx context.Context, src *source, account common.Address, slot common.Hash, hdr *types.Header) []string {
	var out []string
	for _, p := range src.providers {
		raw, err := p.GetProof(ctx, account, []string{slot.Hex()}, "0x"+hdr.Number.Text(16))
		if err != nil {
			continue
		}
		if verifyGetProof(raw, hdr.Root, account, slot) == nil {
			out = append(out, p.host)
		}
	}
	return out
}

// verifyGetProof verifies one eth_getProof answer for one slot against a state root.
func verifyGetProof(raw json.RawMessage, root common.Hash, account common.Address, slot common.Hash) error {
	var ans struct {
		AccountProof []hexutil.Bytes `json:"accountProof"`
		StorageProof []struct {
			Proof []hexutil.Bytes `json:"proof"`
		} `json:"storageProof"`
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		return err
	}
	if len(ans.StorageProof) != 1 {
		return fmt.Errorf("%d storage proofs", len(ans.StorageProof))
	}
	nodes := func(in []hexutil.Bytes) [][]byte {
		out := make([][]byte, len(in))
		for i, n := range in {
			out[i] = n
		}
		return out
	}
	_, err := ethproof.VerifyStorage(root, account, nodes(ans.AccountProof), slot, nodes(ans.StorageProof[0].Proof))
	return err
}
