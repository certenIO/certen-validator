package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/execution"
)

const proofUnavailableUsage = "usage: certen-validator repair member-proof-unavailable --intent ID --chain CHAIN_ID --tx SETTLEMENT_TX " +
	"--operator NAME --evidence TEXT [--apply]"

// runProofUnavailableCommand runs `validator repair member-proof-unavailable` (RB6 state 3, owner decision 2026-10-04): it
// declares, with the operator's evidence, that an executed member's proof can never be produced - only after the member
// has been owed its proof for execution.ProofUnavailableMinPending and only when a fresh probe of every configured provider
// cannot prove its block now. Without --apply it reports what it would record.
//
// Exit status: 0 when declared (or, without --apply, declarable), 2 when refused, 1 on error.
func runProofUnavailableCommand(args []string) int {
	req := execution.ProofUnavailableRequest{}
	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return "", false
			}
			i++
			return strings.TrimSpace(args[i]), true
		}
		ok := true
		switch args[i] {
		case "--apply":
			req.Apply = true
		case "--intent":
			req.IntentID, ok = next()
		case "--tx":
			req.SettlementTx, ok = next()
		case "--operator":
			req.Operator, ok = next()
		case "--evidence":
			req.Evidence, ok = next()
		case "--chain":
			var v string
			if v, ok = next(); ok {
				n, err := strconv.ParseInt(v, 10, 64)
				ok = err == nil && n > 0
				req.ChainID = n
			}
		default:
			ok = false
		}
		if !ok {
			log.Print(proofUnavailableUsage)
			return 1
		}
	}
	cfg, err := config.Load()
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		log.Printf("database: %v", err)
		return 1
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := execution.DeclareProofUnavailable(ctx, client.DB(), database.NewIntentLifecycleRepository(client), probeProvability, req,
		time.Now())
	if err != nil {
		log.Printf("❌ %v", err)
		return 1
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Fprintln(os.Stdout, string(out))
	if res.Refused != "" {
		return 2
	}
	return 0
}

// probeProvability tries to prove the settlement through the chain's agreeing providers, and states what each provider
// alone serves for the transaction and its block.
func probeProvability(ctx context.Context, chainID int64, settlementTx string) (bool, []string, error) {
	urls := ethrpc.EndpointsForChainID(chainID, "")
	var findings []string
	for _, u := range urls {
		host := ethrpc.ProviderHosts([]string{u})
		name := strings.Join(host, "")
		c, err := rpc.DialContext(ctx, u)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: unreachable (%v)", name, err))
			continue
		}
		var receipt *struct {
			BlockHash common.Hash `json:"blockHash"`
		}
		rErr := c.CallContext(ctx, &receipt, "eth_getTransactionReceipt", common.HexToHash(settlementTx))
		finding := fmt.Sprintf("%s: receipt %s", name, served(rErr, receipt != nil))
		if receipt != nil {
			var block, receipts json.RawMessage
			bErr := c.CallContext(ctx, &block, "eth_getBlockByHash", receipt.BlockHash, true)
			brErr := c.CallContext(ctx, &receipts, "eth_getBlockReceipts", receipt.BlockHash)
			finding += fmt.Sprintf(", block %s %s, block receipts %s", receipt.BlockHash.Hex(), served(bErr, len(block) > 0 && string(block) != "null"),
				served(brErr, len(receipts) > 0 && string(receipts) != "null"))
		}
		c.Close()
		findings = append(findings, finding)
	}
	reader, err := ethrpc.NewAgreeingReader(ctx, chainID, urls, 30*time.Second)
	if err != nil {
		findings = append(findings, "agreeing providers: "+err.Error())
		return false, findings, nil
	}
	r, err := reader.TransactionReceipt(ctx, common.HexToHash(settlementTx))
	if err != nil {
		findings = append(findings, "agreed receipt: "+err.Error())
		return false, findings, nil
	}
	if _, err := ethproof.Build(ctx, reader, r.BlockHash, common.HexToHash(settlementTx), uint64(r.TransactionIndex)); err != nil {
		findings = append(findings, "agreed proof: "+err.Error())
		return false, findings, nil
	}
	findings = append(findings, "agreed proof: BUILT")
	return true, findings, nil
}

func served(err error, present bool) string {
	switch {
	case err != nil:
		return "error (" + err.Error() + ")"
	case present:
		return "served"
	default:
		return "not found"
	}
}
