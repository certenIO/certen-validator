// txrevert replays a mined-but-reverted transaction with eth_call at its own block and decodes
// the revert reason, including CertenAnchorV8_1's custom errors.
//
// A batch attestation that reverts costs the anchor gas AND drops every member to the
// per-intent path, so the reason matters more than the fact. Receipts carry no reason for a
// status-0 tx: it has to be replayed.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC URL")
	txh := flag.String("tx", "", "transaction hash")
	sol := flag.String("sol", "", "optional path to the contract source, to name custom errors")
	flag.Parse()
	if *txh == "" {
		fmt.Println("-tx required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}

	h := common.HexToHash(*txh)
	tx, _, err := c.TransactionByHash(ctx, h)
	if err != nil {
		fmt.Println("tx:", err)
		os.Exit(1)
	}
	rc, err := c.TransactionReceipt(ctx, h)
	if err != nil {
		fmt.Println("receipt:", err)
		os.Exit(1)
	}
	from, err := c.TransactionSender(ctx, tx, rc.BlockHash, rc.TransactionIndex)
	if err != nil {
		fmt.Println("sender:", err)
		os.Exit(1)
	}
	fmt.Printf("tx      %s\nstatus  %d\nblock   %s\ngasUsed %d\nlogs    %d\n\n",
		h.Hex(), rc.Status, rc.BlockNumber, rc.GasUsed, len(rc.Logs))

	msg := ethereum.CallMsg{
		From: from, To: tx.To(), Gas: tx.Gas(), GasPrice: tx.GasPrice(),
		Value: tx.Value(), Data: tx.Data(),
	}
	_, callErr := c.CallContract(ctx, msg, rc.BlockNumber)
	if callErr == nil {
		fmt.Println("replay succeeded — the revert was state-dependent and the state has since changed.")
		return
	}
	fmt.Printf("revert: %v\n", callErr)

	// Custom errors surface as a 4-byte selector. Recover the name by hashing every error
	// signature in the source, which is far more useful than a bare selector.
	es := callErr.Error()
	i := strings.Index(es, "0x")
	if i < 0 || *sol == "" {
		return
	}
	raw := strings.TrimSpace(es[i+2:])
	if len(raw) < 8 {
		return
	}
	want := strings.ToLower(raw[:8])

	b, rerr := os.ReadFile(*sol)
	if rerr != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "error ") {
			continue
		}
		sig := strings.TrimSuffix(strings.TrimPrefix(line, "error "), ";")
		sig = strings.ReplaceAll(sig, " ", "")
		sum := crypto.Keccak256([]byte(sig))
		if hex.EncodeToString(sum[:4]) == want {
			fmt.Printf("\n>>> custom error: %s  (selector 0x%s)\n", sig, want)
			return
		}
	}
	fmt.Printf("\nselector 0x%s not matched in %s\n", want, *sol)
}
