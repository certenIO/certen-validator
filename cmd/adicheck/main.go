// adicheck enumerates every CertenAccountV7 deployed by CertenAccountFactoryV9 and reports the
// three things that decide whether an ADI can take part in a batch: the immutable adiURL that
// is hashed into its Merkle leaf, the anchor it is pinned to, and whether it can pay.
//
// An account pinned to a different anchor cannot join a V8_1 batch at all -- CertenAccountV7
// refuses any anchor other than its own -- and an account with no balance cannot settle a
// value-moving leg. Both are invisible until settlement reverts, after the batch anchor and its
// quorum attestation have been paid for.
//
// Usage: go run ./cmd/adicheck
package main

import (
	"context"
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

const factoryABI = `[
 {"type":"function","name":"getAccountForADI","inputs":[{"name":"adiURL","type":"string"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"getAccountCount","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"getAccountsPaginated","inputs":[{"name":"offset","type":"uint256"},{"name":"limit","type":"uint256"}],"outputs":[{"name":"accounts","type":"address[]"}],"stateMutability":"view"}]`

const acctABI = `[
 {"type":"function","name":"adiURL","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, "https://ethereum-sepolia-rpc.publicnode.com")
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	factory := common.HexToAddress("0xf96f936fbfc7c02e4e1d1c847b9817e60c4b6f4e")
	anchor := common.HexToAddress("0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0")

	fa, _ := abi.JSON(strings.NewReader(factoryABI))
	fb := bind.NewBoundContract(factory, fa, c, c, c)
	opts := &bind.CallOpts{Context: ctx}

	var out []interface{}
	if err := fb.Call(opts, &out, "getAccountCount"); err != nil {
		fmt.Println("count:", err)
		os.Exit(1)
	}
	n := out[0].(*big.Int)
	fmt.Printf("FactoryV9 %s has %s account(s)\n\n", factory.Hex(), n)

	out = nil
	if err := fb.Call(opts, &out, "getAccountsPaginated", big.NewInt(0), new(big.Int).Set(n)); err != nil {
		fmt.Println("paginate:", err)
		os.Exit(1)
	}
	accts := out[0].([]common.Address)
	aa, _ := abi.JSON(strings.NewReader(acctABI))
	for _, a := range accts {
		ab := bind.NewBoundContract(a, aa, c, c, c)
		var o []interface{}
		adi := "?"
		if err := ab.Call(opts, &o, "adiURL"); err == nil {
			adi = o[0].(string)
		}
		o = nil
		pinned := "?"
		if err := ab.Call(opts, &o, "anchorContract"); err == nil {
			if o[0].(common.Address) == anchor {
				pinned = "V8_1 ✅"
			} else {
				pinned = o[0].(common.Address).Hex()
			}
		}
		o = nil
		keyless := "?"
		if err := ab.Call(opts, &o, "isKeylessOwner"); err == nil {
			keyless = fmt.Sprintf("%v", o[0].(bool))
		}
		bal, _ := c.BalanceAt(ctx, a, nil)
		eth := new(big.Float).Quo(new(big.Float).SetInt(bal), big.NewFloat(1e18))
		fmt.Printf("%s\n   adiURL   %s\n   anchor   %s\n   keyless  %s\n   balance  %.6f ETH\n\n", a.Hex(), adi, pinned, keyless, eth)
	}
}
