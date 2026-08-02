// vkchain answers the question vkcheck cannot: is the verifier the ANCHOR ACTUALLY USES the one
// our proving key matches?
//
// vkcheck compares local keys against a .sol FILE. That proves nothing about deployment. The
// anchor holds a blsZKVerifier address, and if it points at a different deployment -- an older
// verifier, or one generated from a different trusted setup -- every proof we produce is
// structurally valid and rejected, which is exactly what a failing pairing looks like.
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
)

const anchorABI = `[
 {"type":"function","name":"blsZKVerifier","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"blsZKVerificationEnabled","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
 {"type":"function","name":"pubkeyBindingEnforced","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
 {"type":"function","name":"minimumGovernanceLevel","inputs":[],"outputs":[{"name":"","type":"uint8"}],"stateMutability":"view"},
 {"type":"function","name":"governanceVerifier","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"}]`

const verABI = `[
 {"type":"function","name":"vkInitialized","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"},
 {"type":"function","name":"ALPHA_X","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"alphaX","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"vk","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	anchorHex := flag.String("anchor", "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", "anchor")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	pa, _ := abi.JSON(strings.NewReader(anchorABI))
	b := bind.NewBoundContract(common.HexToAddress(*anchorHex), pa, c, c, c)
	opts := &bind.CallOpts{Context: ctx}

	get := func(m string) (interface{}, bool) {
		var out []interface{}
		if err := b.Call(opts, &out, m); err != nil || len(out) == 0 {
			fmt.Printf("  %-26s <call failed: %v>\n", m, err)
			return nil, false
		}
		fmt.Printf("  %-26s %v\n", m, out[0])
		return out[0], true
	}

	fmt.Printf("anchor %s\n\n", *anchorHex)
	v, ok := get("blsZKVerifier")
	get("blsZKVerificationEnabled")
	get("pubkeyBindingEnforced")
	get("minimumGovernanceLevel")
	get("governanceVerifier")
	if !ok {
		return
	}
	verAddr, _ := v.(common.Address)
	if verAddr == (common.Address{}) {
		fmt.Println("\n❌ no verifier configured")
		return
	}

	code, _ := c.CodeAt(ctx, verAddr, nil)
	fmt.Printf("\nverifier %s (%d bytes of code)\n", verAddr.Hex(), len(code))

	va, _ := abi.JSON(strings.NewReader(verABI))
	vb := bind.NewBoundContract(verAddr, va, c, c, c)
	var o []interface{}
	if err := vb.Call(opts, &o, "vkInitialized"); err == nil && len(o) > 0 {
		fmt.Printf("  vkInitialized              %v\n", o[0])
	} else {
		fmt.Printf("  vkInitialized              <not exposed: %v>\n", err)
	}
	for _, m := range []string{"ALPHA_X", "alphaX"} {
		var oo []interface{}
		if err := vb.Call(opts, &oo, m); err == nil && len(oo) > 0 {
			if bi, ok := oo[0].(*big.Int); ok {
				fmt.Printf("  %-26s %s\n", m, bi)
				fmt.Println("\nCompare against the local verification key's alpha.X (cmd/vkcheck prints it).")
			}
		}
	}
}
