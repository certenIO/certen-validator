// anchorstate decodes a createBatchAnchor transaction and compares what the caller SENT against what the anchor
// actually STORED, for either anchor generation.
//
// _verifyAllComponents re-derives a batch anchor's bundleId from stored state alone:
//
//	V8.1  keccak256("certen:batchbundle:v1", chainId, merkleRoot, batchLeafCount, operationID, height)
//	V8.2  keccak256("certen:batchbundle:v2", chainId, merkleRoot, batchLeafCount, operationID, height,
//	                accumulateValidatorSetRoot, accumulateIncarnation)
//
// If any stored field differs from what the caller passed, the re-derivation misses, merkleVerified is false, and
// executeComprehensiveProof reverts -- after the anchor has been paid for.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// v81ABI is CertenAnchorV8_1's fifteen-field anchors getter.
const v81ABI = `[
 {"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32"}],"outputs":[
  {"name":"bundleId","type":"bytes32"},{"name":"merkleRoot","type":"bytes32"},
  {"name":"adiURLHash","type":"bytes32"},{"name":"operationCommitment","type":"bytes32"},
  {"name":"crossChainCommitment","type":"bytes32"},{"name":"governanceRoot","type":"bytes32"},
  {"name":"executionCommitment","type":"bytes32"},{"name":"operationID","type":"bytes32"},
  {"name":"accumulateBlockHeight","type":"uint256"},{"name":"timestamp","type":"uint256"},
  {"name":"validator","type":"address"},{"name":"valid","type":"bool"},
  {"name":"proofExecuted","type":"bool"},{"name":"governanceExecuted","type":"bool"},
  {"name":"governanceLevel","type":"uint8"}],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	anchorHex := flag.String("anchor", "", "the anchor contract the transaction called (required)")
	txh := flag.String("tx", "", "createBatchAnchor tx hash (required)")
	flag.Parse()
	if !common.IsHexAddress(*anchorHex) || *txh == "" {
		fmt.Println("usage: anchorstate -anchor <address> -tx <createBatchAnchor tx hash> [-rpc <url>]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fail("dial", err)
	}
	chainID, err := c.ChainID(ctx)
	if err != nil {
		fail("chain id", err)
	}
	tx, _, err := c.TransactionByHash(ctx, common.HexToHash(*txh))
	if err != nil {
		fail("tx", err)
	}
	rc, err := c.TransactionReceipt(ctx, common.HexToHash(*txh))
	if err != nil {
		fail("receipt", err)
	}
	sent, err := contracts.DecodeCreateBatchAnchor(chainID.Int64(), tx.Data())
	if err != nil {
		fail("calldata", err)
	}
	fmt.Printf("createBatchAnchor (%s) tx %s (status %d)\n", sent.Version, *txh, rc.Status)
	fmt.Printf("  SENT bundleId=0x%x\n       root=0x%x\n       leafCount=%d\n       batchOpID=0x%x\n       height=%d\n",
		sent.BundleID, sent.Root, sent.LeafCount, sent.BatchOperationID, sent.Height)
	if sent.Version == contracts.BatchAnchorV8_2 {
		fmt.Printf("       accumulateValidatorSetRoot=0x%x\n       accumulateIncarnation=0x%x\n", sent.AccumulateSetRoot, sent.Incarnation)
	}
	fmt.Println()

	anchor := common.HexToAddress(*anchorHex)
	opts := &bind.CallOpts{Context: ctx}
	v82, err := contracts.NewCertenAnchorV8_2Batch(anchor, c)
	if err != nil {
		fail("bind", err)
	}
	count, err := v82.BatchLeafCount(opts, sent.BundleID)
	if err != nil {
		fail("batchLeafCount", err)
	}
	isBatch, err := v82.IsBatchAnchor(opts, sent.BundleID)
	if err != nil {
		fail("isBatchAnchor", err)
	}

	var root, opID, accRoot, inc [32]byte
	var height *big.Int
	var valid, executed bool
	if sent.Version == contracts.BatchAnchorV8_2 {
		st, err := v82.Anchors(opts, sent.BundleID)
		if err != nil {
			fail("anchors", err)
		}
		root, opID, height, valid, executed = st.MerkleRoot, st.OperationID, st.AccumulateBlockHeight, st.Valid, st.ProofExecuted
		accRoot, inc = st.AccumulateValidatorSetRoot, st.AccumulateIncarnation
	} else {
		pa, err := abi.JSON(strings.NewReader(v81ABI))
		if err != nil {
			fail("V8.1 ABI", err)
		}
		var out []interface{}
		if err := bind.NewBoundContract(anchor, pa, c, c, c).Call(opts, &out, "anchors", sent.BundleID); err != nil {
			fail("anchors (V8.1)", err)
		}
		if len(out) != 15 {
			fail("anchors (V8.1)", fmt.Errorf("%d values, want 15", len(out)))
		}
		root, opID = out[1].([32]byte), out[7].([32]byte)
		height, valid, executed = out[8].(*big.Int), out[11].(bool), out[12].(bool)
	}
	fmt.Printf("  STORED root=0x%x\n         leafCount=%s\n         operationID=0x%x\n         height=%s\n         valid=%v proofExecuted=%v isBatchAnchor=%v\n",
		root, count, opID, height, valid, executed, isBatch)
	if sent.Version == contracts.BatchAnchorV8_2 {
		fmt.Printf("         accumulateValidatorSetRoot=0x%x\n         accumulateIncarnation=0x%x\n", accRoot, inc)
	}
	fmt.Println()

	var re [32]byte
	if sent.Version == contracts.BatchAnchorV8_2 {
		re = contracts.DeriveV8_2BatchBundleID(chainID.Int64(), root, count.Uint64(), opID, height.Uint64(), accRoot, inc)
	} else {
		re = contracts.DeriveV8_1BatchBundleID(chainID.Int64(), root, count.Uint64(), opID, height.Uint64())
	}
	fmt.Printf("  rederived bundleId from STORED state = 0x%x\n", re)
	if re == sent.BundleID {
		fmt.Println("  ✅ merkleVerified would PASS")
		return
	}
	fmt.Printf("  ❌ merkleVerified FAILS — anchorId is 0x%x\n", sent.BundleID)
	if count.Uint64() != sent.LeafCount {
		fmt.Printf("     leafCount stored %s but %d was sent — this alone breaks the derivation\n", count, sent.LeafCount)
	}
	os.Exit(1)
}

func fail(what string, err error) {
	fmt.Printf("%s: %v\n", what, err)
	os.Exit(1)
}
