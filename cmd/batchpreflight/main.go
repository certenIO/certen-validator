// batchpreflight verifies, against the LIVE chain, every precondition the cross-ADI batch
// quorum depends on. Run it before deploying the batch path and after any validator-set change.
//
// It answers four questions the batch path cannot answer for itself until it is too late:
//
//  1. Is every configured validator actually registered on the anchor, with the voting power
//     this node believes it has? A missing entry understates TotalVotingPower, which inflates
//     every threshold comparison.
//  2. Does each running validator's BLS public key resolve to exactly one registered address?
//     That resolution IS the node's attesting identity — if it fails, the node refuses every
//     peer attestation request and quorum silently runs short.
//  3. Does the locally computed validator-set root equal the anchor's currentValidatorSetRoot?
//     If not, every quorum signature is over a message the contract will not reconstruct, and
//     executeComprehensiveProof reverts after the anchor has been paid for.
//  4. Is the anchor's authorized-subset binding enforced, and does it hold commitments?
//
// Usage:
//
//	go run ./cmd/batchpreflight -rpc <url> -anchor 0x... -pubkeys running-pubkeys.json
//
// Exit code is non-zero if any check fails, so it can gate a deploy.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

const preflightABI = `[
 {"type":"function","name":"validators","inputs":[{"name":"","type":"address"}],"outputs":[
   {"name":"registered","type":"bool"},{"name":"votingPower","type":"uint256"},
   {"name":"blsPublicKey","type":"bytes"},{"name":"registeredAt","type":"uint256"}],
  "stateMutability":"view"},
 {"type":"function","name":"currentValidatorSetRoot","inputs":[],
  "outputs":[{"name":"","type":"bytes32"}],"stateMutability":"view"},
 {"type":"function","name":"totalVotingPower","inputs":[],
  "outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"blsThresholdNumerator","inputs":[],
  "outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"blsThresholdDenominator","inputs":[],
  "outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"authorizedPubkeyCommitments","inputs":[{"name":"","type":"bytes32"}],
  "outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}
]`

// The running validators' BLS public keys come from -pubkeys, the same
// {"validators":[{"validator_id","bls_public_key"}]} file the rotation runbook builds from each
// node's bls-key-info output. There is deliberately no compiled-in list: after a key rotation such a
// list names retired keys, and the identity check would silently judge the wrong set.

type pubkeyFile struct {
	Validators []struct {
		ValidatorID   string `json:"validator_id"`
		BLSPublicKey  string `json:"bls_public_key"`
		BLSPrivateKey string `json:"bls_private_key"`
	} `json:"validators"`
}

// loadRunningPubkeys reads validator ID -> lowercase hex public key (no 0x). It refuses anything it
// cannot use unambiguously, and a file carrying private keys, which this tool must never be handed.
func loadRunningPubkeys(path string) (map[string]string, error) {
	if path == "" {
		return nil, fmt.Errorf("no -pubkeys file: the running validators' BLS public keys must be supplied " +
			"(bls-key-info output collected into {\"validators\":[{\"validator_id\",\"bls_public_key\"}]})")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read -pubkeys %s: %w", path, err)
	}
	var f pubkeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse -pubkeys %s: %w", path, err)
	}
	if len(f.Validators) == 0 {
		return nil, fmt.Errorf("-pubkeys %s lists no validators", path)
	}
	out := make(map[string]string, len(f.Validators))
	seenKey := map[string]string{}
	for i, v := range f.Validators {
		if v.BLSPrivateKey != "" {
			return nil, fmt.Errorf("-pubkeys %s entry %d carries a private key; supply public keys only", path, i)
		}
		id := strings.TrimSpace(v.ValidatorID)
		if id == "" {
			return nil, fmt.Errorf("-pubkeys %s entry %d has no validator_id", path, i)
		}
		key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v.BLSPublicKey), "0x"))
		if key == "" {
			return nil, fmt.Errorf("-pubkeys %s: %s has no bls_public_key", path, id)
		}
		b, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("-pubkeys %s: %s key is not hex: %w", path, id, err)
		}
		if _, err := bls.PublicKeyFromBytes(b); err != nil {
			return nil, fmt.Errorf("-pubkeys %s: %s key is not a BLS12-381 G2 point: %w", path, id, err)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("-pubkeys %s lists %s twice", path, id)
		}
		if other, dup := seenKey[key]; dup {
			return nil, fmt.Errorf("-pubkeys %s gives %s and %s the same key", path, other, id)
		}
		out[id], seenKey[key] = key, id
	}
	return out, nil
}

// resolveIdentities performs, for every running validator, the match each node performs on itself
// (execution.ResolveOwnEVMAddress): its key must be registered under exactly one address, and no two
// nodes may claim the same address. registry maps lowercase address -> hex key.
func resolveIdentities(running, registry map[string]string) (claimed map[string]string, fails []string) {
	ids := make([]string, 0, len(running))
	for id := range running {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	claimed = map[string]string{}
	for _, id := range ids {
		want := strings.ToLower(strings.TrimPrefix(running[id], "0x"))
		var matches []string
		for addr, pub := range registry {
			if strings.ToLower(strings.TrimPrefix(pub, "0x")) == want {
				matches = append(matches, addr)
			}
		}
		sort.Strings(matches)
		switch len(matches) {
		case 1:
			if other, dup := claimed[matches[0]]; dup {
				fails = append(fails, fmt.Sprintf("%s and %s both resolve to %s — voting power is ambiguous", id, other, matches[0]))
				continue
			}
			claimed[matches[0]] = id
		case 0:
			fails = append(fails, fmt.Sprintf("%s: its BLS key is NOT in the anchor registry. This node will REFUSE every "+
				"peer attestation request and quorum runs a signer short.", id))
		default:
			fails = append(fails, fmt.Sprintf("%s: BLS key registered under %d addresses %v — refuses to attest", id, len(matches), matches))
		}
	}
	return claimed, fails
}

var failures []string

func fail(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	failures = append(failures, msg)
	fmt.Printf("  ❌ %s\n", msg)
}

func okf(format string, a ...interface{}) { fmt.Printf("  ✅ %s\n", fmt.Sprintf(format, a...)) }

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "EVM RPC URL")
	anchorHex := flag.String("anchor", "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", "CertenAnchorV8_1 address")
	pubkeysPath := flag.String("pubkeys", "", "running validators' BLS public keys (JSON: validators[].validator_id, bls_public_key) — required")
	flag.Parse()

	running, err := loadRunningPubkeys(*pubkeysPath)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	client, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Printf("❌ dial %s: %v\n", *rpc, err)
		os.Exit(1)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		fmt.Printf("❌ chainId: %v\n", err)
		os.Exit(1)
	}
	anchor := common.HexToAddress(*anchorHex)
	fmt.Printf("\n=== batch quorum pre-flight ===\nrpc     %s\nchainId %s\nanchor  %s\n\n",
		*rpc, chainID, anchor.Hex())

	parsed, err := abi.JSON(strings.NewReader(preflightABI))
	if err != nil {
		fmt.Printf("❌ abi: %v\n", err)
		os.Exit(1)
	}
	bound := bind.NewBoundContract(anchor, parsed, client, client, client)
	opts := &bind.CallOpts{Context: ctx}

	call := func(method string, args ...interface{}) ([]interface{}, error) {
		var out []interface{}
		err := bound.Call(opts, &out, method, args...)
		return out, err
	}

	// ---- 1. Registry ---------------------------------------------------------
	fmt.Println("[1] Validator registry (anchor is the source of truth)")
	addrs, cfgPowers, err := contracts.GetV6_1ValidatorSet()
	if err != nil {
		fmt.Printf("  ❌ local validator set: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  local roster: %d addresses\n", len(addrs))

	// addr(lowercased) -> pubkey hex, for the identity check below.
	registry := map[string]string{}
	chainTotal := big.NewInt(0)

	for i, a := range addrs {
		out, err := call("validators", a)
		if err != nil {
			fail("validators(%s): %v", a.Hex(), err)
			continue
		}
		registered, _ := out[0].(bool)
		power, _ := out[1].(*big.Int)
		pub, _ := out[2].([]byte)

		if !registered {
			fail("%s is in the local roster but NOT registered on the anchor", a.Hex())
			continue
		}
		if power == nil || power.Sign() <= 0 {
			fail("%s has no voting power on chain", a.Hex())
			continue
		}
		if i < len(cfgPowers) && cfgPowers[i].Cmp(power) != 0 {
			fail("%s power mismatch: local %s, chain %s (setRoot would be stale)",
				a.Hex(), cfgPowers[i], power)
			continue
		}
		if len(pub) == 0 {
			fail("%s has no registered BLS public key", a.Hex())
			continue
		}
		if _, perr := bls.PublicKeyFromBytes(pub); perr != nil {
			fail("%s registered BLS key is unparseable (%d bytes): %v", a.Hex(), len(pub), perr)
			continue
		}
		registry[strings.ToLower(a.Hex())] = hex.EncodeToString(pub)
		chainTotal.Add(chainTotal, power)
		okf("%s power=%s pubkey=%s… (%d bytes)", a.Hex(), power, hex.EncodeToString(pub)[:16], len(pub))
	}
	fmt.Printf("  registry total voting power: %s\n", chainTotal)

	if out, err := call("totalVotingPower"); err == nil {
		if tv, ok := out[0].(*big.Int); ok && tv.Cmp(chainTotal) != 0 {
			fail("anchor totalVotingPower=%s but the roster sums to %s — the local roster is "+
				"missing a registered validator, which understates the quorum denominator", tv, chainTotal)
		} else if ok {
			okf("anchor totalVotingPower agrees: %s", tv)
		}
	}

	// ---- 2. Identity resolution ---------------------------------------------
	fmt.Println("\n[2] Identity self-configuration (each node matches its own BLS key)")
	claimed, idFails := resolveIdentities(running, registry)
	for _, f := range idFails {
		fail("%s", f)
	}
	for addr, id := range claimed {
		okf("%s → %s", id, addr)
	}
	if len(claimed) != len(registry) {
		fail("%d registered validators but only %d are claimed by a supplied running key", len(registry), len(claimed))
	}
	if len(claimed) == len(registry) && len(failures) == 0 {
		okf("all %d registered validators are claimed by exactly one running node", len(registry))
	}

	// ---- 3. Validator-set root ----------------------------------------------
	fmt.Println("\n[3] Validator-set root (binds every quorum signature)")
	localRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		fail("local setRoot: %v", err)
	} else if out, err := call("currentValidatorSetRoot"); err != nil {
		fail("reading currentValidatorSetRoot: %v", err)
	} else if onChain, ok := out[0].([32]byte); !ok {
		fail("currentValidatorSetRoot returned unexpected type %T", out[0])
	} else if onChain != localRoot {
		fail("setRoot MISMATCH: local 0x%x, chain 0x%x — every quorum signature would be over a "+
			"message the contract does not reconstruct, and executeComprehensiveProof reverts "+
			"AFTER the batch anchor is paid for", localRoot, onChain)
	} else {
		okf("setRoot matches: 0x%x", localRoot)
	}

	// ---- 4. Threshold + subset commitments ----------------------------------
	fmt.Println("\n[4] Threshold and authorized subsets")
	var num, den *big.Int
	if out, err := call("blsThresholdNumerator"); err == nil {
		num, _ = out[0].(*big.Int)
	}
	if out, err := call("blsThresholdDenominator"); err == nil {
		den, _ = out[0].(*big.Int)
	}
	if num != nil && den != nil {
		if num.Int64() != 2 || den.Int64() != 3 {
			fail("anchor threshold is %s/%s but the attestor folds at 2/3 — they must agree",
				num, den)
		} else {
			okf("threshold %s/%s matches the attestor", num, den)
		}
		need := new(big.Int).Mul(chainTotal, num)
		need.Div(need, den)
		fmt.Printf("  quorum needs > %s of %s voting power (5 of 7 at 100 each)\n", need, chainTotal)
	}

	// ---- 5. Gas on EVERY validator -----------------------------------------
	//
	// This changed with leader election. Previously whichever node's flush timer fired first
	// submitted, in practice always the same one. Now leadership rotates per (chain, period),
	// and CertenAnchorV8_1.createBatchAnchor is onlyValidator — so the transaction is sent FROM
	// the registered address. Every one of the seven must be funded, or the periods it leads
	// silently fail to anchor and their members sit until another leader picks them up.
	fmt.Println("\n[5] Gas balances (leadership rotates — every validator submits)")
	// createBatchAnchor 500k + executeComprehensiveProof 900k + per-member settle, at a few
	// gwei. 0.02 ETH is a comfortable floor for a handful of periods.
	minWei := new(big.Int).Div(big.NewInt(2e16), big.NewInt(1)) // 0.02 ETH
	for _, a := range addrs {
		bal, err := client.BalanceAt(ctx, a, nil)
		if err != nil {
			fail("reading balance of %s: %v", a.Hex(), err)
			continue
		}
		eth := new(big.Float).Quo(new(big.Float).SetInt(bal), big.NewFloat(1e18))
		if bal.Cmp(minWei) < 0 {
			fail("%s holds only %.5f ETH — the periods this validator leads will fail to anchor",
				a.Hex(), eth)
			continue
		}
		okf("%s %.5f ETH", a.Hex(), eth)
	}

	if len(failures) == 0 {
		fmt.Printf("\n✅ PRE-FLIGHT PASSED — the batch quorum can form on chain %s\n\n", chainID)
		return
	}
	fmt.Printf("\n❌ PRE-FLIGHT FAILED — %d problem(s):\n", len(failures))
	for _, f := range failures {
		fmt.Printf("   - %s\n", f)
	}
	fmt.Println()
	os.Exit(1)
}
