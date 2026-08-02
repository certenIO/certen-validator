// vkbytecode settles whether the DEPLOYED Groth16 verifier was generated from the same trusted
// setup as our proving key.
//
// cmd/vkcheck compares the local key against a .sol FILE, which proves nothing about what is
// deployed. A gnark-generated verifier hardcodes every verification-key element as a PUSH32
// constant, so the deployed bytecode can be searched for them directly. If an element is
// absent, that verifier cannot verify our proofs -- they will be structurally valid and
// rejected, which is precisely how a failing pairing presents.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

var bn254P, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

func negFp(v *big.Int) *big.Int {
	if v.Sign() == 0 {
		return new(big.Int)
	}
	return new(big.Int).Sub(bn254P, new(big.Int).Mod(v, bn254P))
}

func word(v *big.Int) string {
	b := v.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return hex.EncodeToString(out)
}

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	verifier := flag.String("verifier", "0x6f9049cdb948bd0B3eDcd8c10E9Ed796C0615100", "generated Groth16 verifier")
	keys := flag.String("keys", "./bls_zk_keys", "local key directory")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	code, err := c.CodeAt(ctx, common.HexToAddress(*verifier), nil)
	if err != nil {
		fmt.Println("code:", err)
		os.Exit(1)
	}
	hexCode := hex.EncodeToString(code)
	fmt.Printf("verifier %s\ncode     %d bytes\n\n", *verifier, len(code))

	prover := bls_zkp.NewBLSZKProver()
	if err := prover.InitializeFromKeys(
		filepath.Join(*keys, "proving_key.bin"),
		filepath.Join(*keys, "verification_key.bin"),
		filepath.Join(*keys, "constraint_system.bin"),
	); err != nil {
		fmt.Println("load keys:", err)
		os.Exit(1)
	}
	vk, err := prover.ExportVerificationKey()
	if err != nil {
		fmt.Println("export vk:", err)
		os.Exit(1)
	}

	type el struct {
		name string
		v    *big.Int
	}
	els := []el{
		{"alpha.X", vk.Alpha1[0]}, {"alpha.Y", vk.Alpha1[1]},
		{"beta.X0", vk.Beta2[0][0]}, {"beta.X1", vk.Beta2[0][1]},
		{"-beta.Y0", negFp(vk.Beta2[1][0])}, {"-beta.Y1", negFp(vk.Beta2[1][1])},
		{"gamma.X0", vk.Gamma2[0][0]}, {"gamma.X1", vk.Gamma2[0][1]},
		{"-gamma.Y0", negFp(vk.Gamma2[1][0])}, {"-gamma.Y1", negFp(vk.Gamma2[1][1])},
		{"delta.X0", vk.Delta2[0][0]}, {"delta.X1", vk.Delta2[0][1]},
		{"-delta.Y0", negFp(vk.Delta2[1][0])}, {"-delta.Y1", negFp(vk.Delta2[1][1])},
	}
	for i, p := range vk.IC {
		els = append(els,
			el{fmt.Sprintf("IC[%d].X", i), p[0]},
			el{fmt.Sprintf("IC[%d].Y", i), p[1]})
	}

	found, missing := 0, 0
	for _, e := range els {
		w := word(e.v)
		if strings.Contains(hexCode, w) {
			fmt.Printf("  ✅ %-12s present\n", e.name)
			found++
			continue
		}
		fmt.Printf("  ❌ %-12s ABSENT  (0x%s)\n", e.name, w[:24]+"…")
		missing++
	}

	fmt.Printf("\npresent %d / absent %d (IC points in our key: %d)\n", found, missing, len(vk.IC))
	if missing > 0 {
		fmt.Println("\n❌ THE DEPLOYED VERIFIER WAS NOT GENERATED FROM THESE KEYS.")
		fmt.Println("   Every proof this validator set produces will be rejected on chain, for the")
		fmt.Println("   batch path AND the per-intent path, because both submit through the same")
		fmt.Println("   verifier. Either deploy a verifier generated from these keys, or restore the")
		fmt.Println("   keys the deployed verifier was generated from. Never ship a mismatch.")
		os.Exit(1)
	}
	fmt.Println("\n✅ every verification-key element appears in the deployed bytecode")
}
