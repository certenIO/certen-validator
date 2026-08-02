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
//	go run ./cmd/batchpreflight -rpc <url> -anchor 0x... [-pubkeys file]
//
// Exit code is non-zero if any check fails, so it can gate a deploy.
package main

import (
	"context"
	"encoding/hex"
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

// liveValidatorPubkeys are the BLS public keys the seven running containers report at startup
// ("BLS PUBLIC KEY FOR CONTRACT REGISTRATION"). Passing them here lets the tool prove the
// identity resolution each node will perform, without needing any node's private key.
var liveValidatorPubkeys = map[string]string{
	"validator-1": "88eb4560b4147983e3d72bc6ddb04812d84be905d97f400f5c378b1fc0e252d53d9e2069891d56e2696fe43f2cd153df10bebf7f0fd4da4497f6d24f3cf9a82ff27ef2a8b731c609b732202334a4115b034dd18193d860c75837e46729c90a05",
	"validator-2": "b6034ecded6be69758a7bfe10dd6f38eba8068433821419762cdad9d1b9d423a02f6fe69f49d720315565700437302ca0edb2af84b1b2ae1114a9f131bcf6fa8ebe00bfa02834ac598ea9aa285a79c07d626e2b89f2784fce679d6e8b25e9ea5",
	"validator-3": "a060ce250119479f1cb22f0f55941f56204b4d291caff3a268f5f2e4c4a55dddcd5db8f8f7c9251eebbb613ddc8a0db20d59d4f9f90e49f0d91f7c4d87c7f1c5ef4d9106cb17295f807870dc400a6e8f54a0c250f40c66ef0ba0e1ae9e272827",
	"validator-4": "b3847f042172f34c28ad930ab6ea12057c23b80c018f8db7c073c7656c2b04049cee2accbf0f7162024af91f4c6def2216e55d59ab5203d9958d44ea6555dae20f9b98cd485f883c9cc3be2d3ca0c7fc454edf097f4c4b3dd8130922dda9bded",
	"validator-5": "a41cd7cfa2b90210776218db3e574cf31db620a0db69e0829682826fc0693a67759cd07c0f4c817f43d50f37e643aafe0047a6e84ebb4257dd7aa51208b7efe6814a04638ca2f12ae98e8709552b00fa954164819c283f0c5c52d7f8f7f5bcc0",
	"validator-6": "a02890dfab5831e608af5794245e5f3204358ff9d5ee6db86d77c08eb66406dfb7e4d19af8600a4f912987a8192b1cb008ec3829bbf78c5b6a62b284130477c6c5372d95b5c4e5f766e9c7d355dbf06495643b7fe62d3c50ceaff89336ed3ba1",
	"validator-7": "a533372f8b8b25660ae1908bf2de04a2fdafcef38d9fe4eb35022858b2e015bffd17423c23bd0ea2db7b5d5ce9dd51900be37c74bddd23d6cf246fef2b156c8878958350934a796b7fd60de9e795e7d19ec6bf5910db3f7770794d9cf4ddf26f",
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
	flag.Parse()

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
	ids := make([]string, 0, len(liveValidatorPubkeys))
	for id := range liveValidatorPubkeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	claimed := map[string]string{} // address -> validatorID, to catch two nodes claiming one entry
	for _, id := range ids {
		want := strings.ToLower(liveValidatorPubkeys[id])
		var matches []string
		for addr, pub := range registry {
			if strings.ToLower(pub) == want {
				matches = append(matches, addr)
			}
		}
		switch len(matches) {
		case 1:
			if other, dup := claimed[matches[0]]; dup {
				fail("%s and %s both resolve to %s — voting power is ambiguous", id, other, matches[0])
				continue
			}
			claimed[matches[0]] = id
			okf("%s → %s", id, matches[0])
		case 0:
			fail("%s: its BLS key is NOT in the anchor registry. This node will REFUSE every "+
				"peer attestation request and quorum runs a signer short.", id)
		default:
			fail("%s: BLS key registered under %d addresses %v — refuses to attest", id, len(matches), matches)
		}
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
