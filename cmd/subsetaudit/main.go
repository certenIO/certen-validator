// subsetaudit enumerates every validator subset of size 5, 6 and 7, derives the aggregate
// pubkey commitment each would produce, and asks the DEPLOYED anchor whether it is authorized.
//
// CertenAnchorV8_1 gates a batch attestation on authorizedPubkeyCommitments[commitment]. If the
// subset that actually signed is not in that set, executeComprehensiveProof reverts AFTER the
// batch anchor has been paid for and every member is dropped to the per-intent path -- and the
// revert carries no data through public RPCs, so it is invisible from the receipt alone.
//
// This answers, offline and exhaustively, which quorums can settle.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

const anchorABI = `[
 {"type":"function","name":"validators","inputs":[{"name":"","type":"address"}],"outputs":[
   {"name":"registered","type":"bool"},{"name":"votingPower","type":"uint256"},
   {"name":"blsPublicKey","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"authorizedPubkeyCommitments","inputs":[{"name":"","type":"bytes32"}],
  "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC URL")
	anchorHex := flag.String("anchor", "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", "anchor")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	parsed, _ := abi.JSON(strings.NewReader(anchorABI))
	bound := bind.NewBoundContract(common.HexToAddress(*anchorHex), parsed, c, c, c)
	opts := &bind.CallOpts{Context: ctx}

	addrs, _, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		fmt.Println("roster:", err)
		os.Exit(1)
	}
	pubs := make([]*bls.PublicKey, len(addrs))
	for i, a := range addrs {
		var out []interface{}
		if err := bound.Call(opts, &out, "validators", a); err != nil {
			fmt.Printf("validators(%s): %v\n", a.Hex(), err)
			os.Exit(1)
		}
		pk, err := bls.PublicKeyFromBytes(out[2].([]byte))
		if err != nil {
			fmt.Printf("pubkey %s: %v\n", a.Hex(), err)
			os.Exit(1)
		}
		pubs[i] = pk
	}
	n := len(pubs)
	fmt.Printf("roster of %d, anchor %s\n\n", n, *anchorHex)

	authorized, unauthorized := 0, 0
	var missing []string
	for size := 5; size <= n; size++ {
		idx := make([]int, size)
		for i := range idx {
			idx[i] = i
		}
		for {
			sub := make([]*bls.PublicKey, size)
			names := make([]string, size)
			for i, j := range idx {
				sub[i] = pubs[j]
				names[i] = fmt.Sprintf("v%d", j+1)
			}
			agg, err := bls.AggregatePublicKeys(sub)
			if err != nil {
				fmt.Println("aggregate:", err)
				os.Exit(1)
			}
			var g2 bls12381.G2Affine
			if _, err := g2.SetBytes(agg.Bytes()); err != nil {
				fmt.Println("decode agg:", err)
				os.Exit(1)
			}
			cm, err := bls_zkp.ComputePubkeyCommitmentV2(g2)
			if err != nil {
				fmt.Println("commitment:", err)
				os.Exit(1)
			}
			var out []interface{}
			ok := false
			if err := bound.Call(opts, &out, "authorizedPubkeyCommitments", cm); err == nil {
				ok, _ = out[0].(bool)
			}
			if ok {
				authorized++
			} else {
				unauthorized++
				missing = append(missing, fmt.Sprintf("%d-of-%d %s -> 0x%x", size, n, strings.Join(names, "+"), cm[:8]))
			}
			// next combination
			i := size - 1
			for i >= 0 && idx[i] == i+n-size {
				i--
			}
			if i < 0 {
				break
			}
			idx[i]++
			for j := i + 1; j < size; j++ {
				idx[j] = idx[j-1] + 1
			}
		}
	}
	sort.Strings(missing)
	fmt.Printf("authorized:   %d\nUNAUTHORIZED: %d\n", authorized, unauthorized)
	if len(missing) > 0 {
		fmt.Println("\nsubsets whose quorum would REVERT executeComprehensiveProof:")
		for _, m := range missing {
			fmt.Println("  " + m)
		}
	}
}
