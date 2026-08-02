// g16probe calls the DEPLOYED gnark Groth16 verifier with the exact proof bytes from a failed
// transaction, so its own named error identifies the cause.
//
// Everything upstream has been eliminated: the verification key in the deployed bytecode matches
// our proving key element for element, the proof verifies locally in gnark and round-trips
// through ABI encoding, and the four public inputs the contract builds are the four the circuit
// declares. What remains can only be seen by asking the verifier itself -- gnark's generated
// Solidity reverts with ProofInvalid / PublicInputNotInField / CommitmentInvalid, and which one
// it is decides the fix.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var rMod, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

const g16ABI = `[{"type":"function","name":"verifyProof","inputs":[
 {"name":"proof","type":"uint256[8]"},
 {"name":"commitments","type":"uint256[2]"},
 {"name":"commitmentPok","type":"uint256[2]"},
 {"name":"input","type":"uint256[4]"}],"outputs":[],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	txh := flag.String("tx", "0x4eb341cd62f28e3e2a8281af6be2df4155bc04ce50180d0723e99ed41c25e7b4", "failed executeComprehensiveProof tx")
	g16 := flag.String("g16", "0x6f9049cdb948bd0B3eDcd8c10E9Ed796C0615100", "generated verifier")
	sol := flag.String("sol", "", "path to BLSZKVerifierV2Generated.sol to name the error")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
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
	data := tx.Data()
	// Skip the 4-byte selector: ABI words are aligned to 4+32k, not 32k.
	if len(data) > 4 {
		data = data[4:]
	}

	// Locate the 576-byte blob: a length word of 0x240 followed by 18 static words.
	const blobLen = 18 * 32
	var blob []byte
	for i := 0; i+32+blobLen <= len(data); i += 32 {
		w := new(big.Int).SetBytes(data[i : i+32])
		if w.Cmp(big.NewInt(blobLen)) == 0 {
			blob = data[i+32 : i+32+blobLen]
			fmt.Printf("found %d-byte blob at calldata offset %d\n", blobLen, i+32)
			break
		}
	}
	if blob == nil {
		fmt.Println("could not locate the proof blob in calldata")
		os.Exit(1)
	}

	wd := func(i int) *big.Int { return new(big.Int).SetBytes(blob[i*32 : (i+1)*32]) }
	var proof [8]*big.Int
	for i := 0; i < 8; i++ {
		proof[i] = wd(i)
	}
	commitments := [2]*big.Int{wd(8), wd(9)}
	pok := [2]*big.Int{wd(10), wd(11)}
	msgHash := wd(12)
	pkCommit := wd(13)
	signed := wd(14)
	total := wd(15)

	fmt.Printf("\n  messageHash      0x%064x\n  pubkeyCommitment 0x%064x\n  signed/total     %s / %s\n  thresholds       %s / %s\n\n",
		msgHash, pkCommit, signed, total, wd(16), wd(17))

	input := [4]*big.Int{new(big.Int).Mod(msgHash, rMod), pkCommit, signed, total}
	for i, v := range input {
		if v.Cmp(rMod) >= 0 {
			fmt.Printf("  ⚠️ input[%d] >= R — the verifier rejects with PublicInputNotInField\n", i)
		}
	}

	parsed, err := abi.JSON(strings.NewReader(g16ABI))
	if err != nil {
		fmt.Println("abi:", err)
		os.Exit(1)
	}
	packed, err := parsed.Pack("verifyProof", proof, commitments, pok, input)
	if err != nil {
		fmt.Println("pack:", err)
		os.Exit(1)
	}
	to := common.HexToAddress(*g16)
	_, callErr := c.CallContract(ctx, ethereum.CallMsg{To: &to, Data: packed}, nil)
	if callErr == nil {
		fmt.Println("✅ verifyProof SUCCEEDED against the deployed verifier — the proof is accepted here.")
		fmt.Println("   The rejection therefore came from a gate ABOVE it in BLSZKVerifierV2/CertenAnchorV8_1.")
		return
	}
	fmt.Printf("❌ verifyProof reverted: %v\n", callErr)

	// Name the custom error from its selector.
	es := callErr.Error()
	if i := strings.Index(es, "0x"); i >= 0 && *sol != "" {
		raw := strings.TrimSpace(es[i+2:])
		if len(raw) >= 8 {
			want := strings.ToLower(raw[:8])
			if b, rerr := os.ReadFile(*sol); rerr == nil {
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "error ") {
						continue
					}
					sig := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(line, "error "), ";"), " ", "")
					sum := crypto.Keccak256([]byte(sig))
					if hex.EncodeToString(sum[:4]) == want {
						fmt.Printf("\n>>> %s  (selector 0x%s)\n", sig, want)
						return
					}
				}
				fmt.Printf("\nselector 0x%s not matched in %s\n", want, *sol)
			}
		}
	}
}
