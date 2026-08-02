// deployaccount deploys the CertenAccountV7 for one ADI via CertenAccountFactoryV9 and, if
// asked, funds it.
//
// Two conditions decide whether an ADI can take part in a V8_1 batch, and both are invisible
// until settlement reverts -- by which point the batch anchor and its quorum attestation have
// already been paid for:
//
//   - the account must be pinned to the SAME anchor the batch is anchored on, because
//     CertenAccountV7 refuses any other;
//   - it must hold enough balance to pay the leg it is settling.
//
// So this verifies both after deploying, rather than reporting success on the transaction
// receipt alone.
//
// Run where ETH_PRIVATE_KEY lives. Never pass a key on the command line.
package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const factoryABI = `[
 {"type":"function","name":"createAccountForADI","inputs":[{"name":"adiURL","type":"string"},{"name":"salt","type":"uint256"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"payable"},
 {"type":"function","name":"getAccountForADI","inputs":[{"name":"adiURL","type":"string"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"deploymentFee","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"}]`

const acctABI = `[
 {"type":"function","name":"adiURL","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

func main() {
	rpc := flag.String("rpc", "https://ethereum-sepolia-rpc.publicnode.com", "RPC")
	factoryHex := flag.String("factory", "0xf96f936fbfc7c02e4e1d1c847b9817e60c4b6f4e", "CertenAccountFactoryV9")
	anchorHex := flag.String("anchor", "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", "expected anchor")
	adi := flag.String("adi", "", "adiURL, exactly as the intent will carry it")
	salt := flag.Int64("salt", 1, "CREATE2 salt")
	fundWei := flag.String("fund", "0", "wei to send to the account after deploy")
	flag.Parse()

	if *adi == "" {
		fmt.Println("-adi is required")
		os.Exit(2)
	}
	pkHex := strings.TrimPrefix(strings.TrimSpace(os.Getenv("ETH_PRIVATE_KEY")), "0x")
	if pkHex == "" {
		fmt.Println("ETH_PRIVATE_KEY not set")
		os.Exit(2)
	}
	pk, err := crypto.HexToECDSA(pkHex)
	if err != nil {
		fmt.Println("bad key:", err)
		os.Exit(1)
	}
	from := crypto.PubkeyToAddress(*pk.Public().(*ecdsa.PublicKey))

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, *rpc)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	chainID, _ := c.ChainID(ctx)
	fmt.Printf("deployer %s on chain %s\nadiURL   %q\n\n", from.Hex(), chainID, *adi)

	fa, _ := abi.JSON(strings.NewReader(factoryABI))
	factory := common.HexToAddress(*factoryHex)
	fb := bind.NewBoundContract(factory, fa, c, c, c)
	opts := &bind.CallOpts{Context: ctx}

	var out []interface{}
	if err := fb.Call(opts, &out, "getAccountForADI", *adi); err != nil {
		fmt.Println("getAccountForADI:", err)
		os.Exit(1)
	}
	acct := out[0].(common.Address)

	if acct == (common.Address{}) {
		fee := big.NewInt(0)
		var o []interface{}
		if err := fb.Call(opts, &o, "deploymentFee"); err == nil {
			if v, ok := o[0].(*big.Int); ok {
				fee = v
			}
		}
		fmt.Printf("no account yet; deploying (fee %s wei)\n", fee)

		auth, err := bind.NewKeyedTransactorWithChainID(pk, chainID)
		if err != nil {
			fmt.Println("transactor:", err)
			os.Exit(1)
		}
		auth.Context = ctx
		auth.Value = fee
		auth.GasLimit = 3000000
		tx, err := fb.Transact(auth, "createAccountForADI", *adi, big.NewInt(*salt))
		if err != nil {
			fmt.Println("createAccountForADI:", err)
			os.Exit(1)
		}
		fmt.Printf("  tx %s\n", tx.Hash().Hex())
		rc, err := bind.WaitMined(ctx, c, tx)
		if err != nil || rc.Status == 0 {
			fmt.Printf("  ❌ deploy failed (status %v, err %v)\n", rc.Status, err)
			os.Exit(1)
		}
		fmt.Printf("  mined, gas %d\n", rc.GasUsed)

		out = nil
		if err := fb.Call(opts, &out, "getAccountForADI", *adi); err != nil {
			fmt.Println("re-read:", err)
			os.Exit(1)
		}
		acct = out[0].(common.Address)
	}
	fmt.Printf("account  %s\n", acct.Hex())

	// Fund BEFORE asserting, so the final report reflects the end state.
	if w, ok := new(big.Int).SetString(*fundWei, 10); ok && w.Sign() > 0 {
		bal, _ := c.BalanceAt(ctx, acct, nil)
		if bal.Cmp(w) >= 0 {
			fmt.Printf("  already holds %s wei; not funding\n", bal)
		} else {
			nonce, _ := c.PendingNonceAt(ctx, from)
			tip, _ := c.SuggestGasTipCap(ctx)
			head, _ := c.HeaderByNumber(ctx, nil)
			feeCap := new(big.Int).Add(tip, new(big.Int).Mul(head.BaseFee, big.NewInt(2)))
			tx := types.NewTx(&types.DynamicFeeTx{
				ChainID: chainID, Nonce: nonce, To: &acct, Value: w,
				Gas: 21000, GasTipCap: tip, GasFeeCap: feeCap,
			})
			signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), pk)
			if err != nil {
				fmt.Println("sign fund:", err)
				os.Exit(1)
			}
			if err := c.SendTransaction(ctx, signed); err != nil {
				fmt.Println("send fund:", err)
				os.Exit(1)
			}
			fmt.Printf("  funding tx %s\n", signed.Hash().Hex())
			if rc, err := bind.WaitMined(ctx, c, signed); err != nil || rc.Status == 0 {
				fmt.Printf("  ❌ funding failed\n")
				os.Exit(1)
			}
		}
	}

	// Assert the two conditions that decide whether this account can settle at all.
	aa, _ := abi.JSON(strings.NewReader(acctABI))
	ab := bind.NewBoundContract(acct, aa, c, c, c)
	var o []interface{}
	gotADI := ""
	if err := ab.Call(opts, &o, "adiURL"); err == nil {
		gotADI = o[0].(string)
	}
	o = nil
	pinned := common.Address{}
	if err := ab.Call(opts, &o, "anchorContract"); err == nil {
		pinned = o[0].(common.Address)
	}
	o = nil
	keyless := false
	if err := ab.Call(opts, &o, "isKeylessOwner"); err == nil {
		keyless, _ = o[0].(bool)
	}
	bal, _ := c.BalanceAt(ctx, acct, nil)

	fmt.Printf("\n  adiURL   %q\n  anchor   %s\n  keyless  %v\n  balance  %s wei\n\n", gotADI, pinned.Hex(), keyless, bal)

	fail := false
	if gotADI != *adi {
		fmt.Printf("❌ adiURL mismatch: the leaf this account recomputes will never match one built from %q\n", *adi)
		fail = true
	}
	if pinned != common.HexToAddress(*anchorHex) {
		fmt.Printf("❌ pinned to %s, not the batch anchor %s — CertenAccountV7 refuses any other anchor\n", pinned.Hex(), *anchorHex)
		fail = true
	}
	if !keyless {
		fmt.Println("❌ not keyless")
		fail = true
	}
	if bal.Sign() == 0 {
		fmt.Println("⚠️  zero balance — it cannot settle a value-moving leg")
	}
	if fail {
		os.Exit(1)
	}
	fmt.Println("✅ ready to take part in a V8_1 batch")
}
