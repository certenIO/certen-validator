// anchorstate decodes a createBatchAnchor transaction and compares what the caller SENT against
// what the anchor actually STORED.
//
// _verifyAllComponents re-derives the bundleId for a batch from stored state alone:
//
//	keccak256("certen:batchbundle:v1", chainId, merkleRoot, batchLeafCount, operationID, height)
//
// If any stored field differs from what the caller passed, the re-derivation misses, merkleVerified
// is false, and executeComprehensiveProof reverts -- after the anchor has been paid for.
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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const aABI = `[
 {"type":"function","name":"anchors","inputs":[{"name":"","type":"bytes32"}],"outputs":[
  {"name":"bundleId","type":"bytes32"},{"name":"merkleRoot","type":"bytes32"},
  {"name":"adiURLHash","type":"bytes32"},{"name":"operationCommitment","type":"bytes32"},
  {"name":"crossChainCommitment","type":"bytes32"},{"name":"governanceRoot","type":"bytes32"},
  {"name":"executionCommitment","type":"bytes32"},{"name":"operationID","type":"bytes32"},
  {"name":"accumulateBlockHeight","type":"uint256"},{"name":"timestamp","type":"uint256"},
  {"name":"validator","type":"address"},{"name":"valid","type":"bool"},
  {"name":"proofExecuted","type":"bool"},{"name":"governanceExecuted","type":"bool"},
  {"name":"governanceLevel","type":"uint8"}],"stateMutability":"view"},
 {"type":"function","name":"batchLeafCount","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"isBatchAnchor","inputs":[{"name":"","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	anchorHex := flag.String("anchor", "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", "anchor")
	txh := flag.String("tx", "", "createBatchAnchor tx hash")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}

	tx, _, err := c.TransactionByHash(ctx, common.HexToHash(*txh))
	if err != nil {
		fmt.Println("tx:", err)
		os.Exit(1)
	}
	rc, _ := c.TransactionReceipt(ctx, common.HexToHash(*txh))
	d := tx.Data()
	if len(d) < 4+5*32 {
		fmt.Printf("input too short (%d bytes)\n", len(d))
		os.Exit(1)
	}
	arg := func(i int) []byte { return d[4+i*32 : 4+(i+1)*32] }
	var sentBundle, sentRoot, sentOpID [32]byte
	copy(sentBundle[:], arg(0))
	copy(sentRoot[:], arg(1))
	copy(sentOpID[:], arg(3))
	sentCount := new(big.Int).SetBytes(arg(2))
	sentHeight := new(big.Int).SetBytes(arg(4))

	fmt.Printf("createBatchAnchor tx %s (status %d)\n", *txh, rc.Status)
	fmt.Printf("  SENT bundleId=0x%x\n       root=0x%x\n       leafCount=%s\n       batchOpID=0x%x\n       height=%s\n\n",
		sentBundle, sentRoot, sentCount, sentOpID, sentHeight)

	pa, _ := abi.JSON(strings.NewReader(aABI))
	b := bind.NewBoundContract(common.HexToAddress(*anchorHex), pa, c, c, c)
	opts := &bind.CallOpts{Context: ctx}

	var out []interface{}
	if err := b.Call(opts, &out, "anchors", sentBundle); err != nil {
		fmt.Println("anchors:", err)
		os.Exit(1)
	}
	storedRoot := out[1].([32]byte)
	storedOpID := out[7].([32]byte)
	storedHeight := out[8].(*big.Int)
	valid := out[11].(bool)
	executed := out[12].(bool)

	var o2 []interface{}
	_ = b.Call(opts, &o2, "batchLeafCount", sentBundle)
	storedCount := big.NewInt(0)
	if len(o2) > 0 {
		if v, ok := o2[0].(*big.Int); ok {
			storedCount = v
		}
	}
	var o3 []interface{}
	_ = b.Call(opts, &o3, "isBatchAnchor", sentBundle)
	isBatch := false
	if len(o3) > 0 {
		isBatch, _ = o3[0].(bool)
	}

	fmt.Printf("  STORED root=0x%x\n         leafCount=%s\n         operationID=0x%x\n         height=%s\n         valid=%v proofExecuted=%v isBatchAnchor=%v\n\n",
		storedRoot, storedCount, storedOpID, storedHeight, valid, executed, isBatch)

	// Re-derive exactly as _verifyAllComponents does.
	chainID, _ := c.ChainID(ctx)
	packed := append([]byte("certen:batchbundle:v1"), common.LeftPadBytes(chainID.Bytes(), 32)...)
	packed = append(packed, storedRoot[:]...)
	packed = append(packed, common.LeftPadBytes(storedCount.Bytes(), 32)...)
	packed = append(packed, storedOpID[:]...)
	packed = append(packed, common.LeftPadBytes(storedHeight.Bytes(), 32)...)
	var re [32]byte
	copy(re[:], crypto.Keccak256(packed))

	fmt.Printf("  rederived bundleId from STORED state = 0x%x\n", re)
	if re == sentBundle {
		fmt.Println("  ✅ merkleVerified would PASS")
	} else {
		fmt.Printf("  ❌ merkleVerified FAILS — anchorId is 0x%x\n", sentBundle)
		if storedCount.Cmp(sentCount) != 0 {
			fmt.Printf("     leafCount stored %s but %s was sent — this alone breaks the derivation\n", storedCount, sentCount)
		}
	}
}
