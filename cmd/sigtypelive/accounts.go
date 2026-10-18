package main

// accounts: the CertenAccount of each case's governing key book on the target chain (RB8-E).
//
// A CertenAccountV7_3 carries exactly one governing key book, fixed at creation and part of its CREATE2 address
// (CertenAccountFactoryV11: createAccountForADI(adiURL, governingBook, salt) with salt = uint256(keccak256(adiURL))).
// authorityLevelOfPage returns NONE for any page of another book, so an intent approved by acc://pv2-sig-1.acme/book-<tag>
// can only be executed by the account whose governing book is exactly that book. The live run has one key book per
// signature type, hence one account per case: a single account for all ten cases would settle one and revert nine.
//
//	sigtypelive accounts -rpc <url> [-factory 0x..]                      read-only: predicted address, code, binding and balance of each case's account
//	sigtypelive accounts -rpc <url> -create [-fund 20000000000000]       create the missing accounts, fund each to at least -fund wei
//
// -create and -fund send transactions and read the sender's key from ETH_PRIVATE_KEY in the process environment only
// (never a flag, never printed, never written). The result is written to captures/accounts.json (tag -> address), which
// `rerun` and `submit` read through -accounts.

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// factoryV11Address is CertenAccountFactoryV11 on Base Sepolia (memory rb5-base-finish-2026-10-04; the api-bridge's
// EVM_BASE_SEPOLIA_ACCOUNT_FACTORY).
const factoryV11Address = "0x8387D061830E10Eb42BC25C2A047631164803F25"

const factoryV11ABI = `[
 {"type":"function","name":"createAccountForADI","inputs":[{"name":"adiURL","type":"string"},{"name":"governingBook","type":"string"},{"name":"salt","type":"uint256"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"payable"},
 {"type":"function","name":"getAddressForADI","inputs":[{"name":"adiURL","type":"string"},{"name":"governingBook","type":"string"},{"name":"salt","type":"uint256"}],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"isGoverningBookOf","inputs":[{"name":"adiURL","type":"string"},{"name":"book","type":"string"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"pure"},
 {"type":"function","name":"canonicalSalt","inputs":[{"name":"adiURL","type":"string"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"pure"},
 {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"deploymentFee","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"isDeploymentPaused","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

const accountV73ABI = `[
 {"type":"function","name":"adiURL","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"governingBook","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"anchorContract","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"},
 {"type":"function","name":"isKeylessOwner","inputs":[],"outputs":[{"name":"","type":"bool"}],"stateMutability":"view"}]`

var addressRE = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// canonicalSalt is CertenAccountFactoryV11.canonicalSalt: uint256(keccak256(adiURL)).
func canonicalSalt(adi string) *big.Int { return new(big.Int).SetBytes(crypto.Keccak256([]byte(adi))) }

// isCanonicalBookOf mirrors CertenAccountFactoryV11.isGoverningBookOf: ADI and book lower case, the ADI without a trailing
// '/', and the book `<adi>/<name>` with a non-empty name that contains no '/'.
func isCanonicalBookOf(adi, book string) bool {
	if adi == "" || strings.HasSuffix(adi, "/") || len(book) < len(adi)+2 || strings.ToLower(adi) != adi || strings.ToLower(book) != book {
		return false
	}
	if !strings.HasPrefix(book, adi+"/") {
		return false
	}
	return !strings.Contains(book[len(adi)+1:], "/")
}

// authorityBook is the book whose pages carry the case's authority on the target chain: the key book the intent names
// (and the governance certificate certifies). For the delegated case that is the delegating book, the only authority of
// the case's data account.
func (c liveCase) authorityBook(adi string) string { return c.book(adi) }

// accountFor returns the CertenAccount that settles c: the account whose governing book is c's authority book.
func (l liveConfig) accountFor(adi string, c liveCase) (string, error) {
	if a, ok := l.Accounts[c.Tag]; ok {
		return a, nil
	}
	return "", fmt.Errorf("no CertenAccount for case %s: its governing book %s needs its own account on %s (run `sigtypelive accounts -create`, then pass -accounts)",
		c.Name, c.authorityBook(adi), l.Chain)
}

// parseAccounts builds the tag -> address map from an accounts file (written by `accounts`) and/or the -account flag:
// `tag=0x..,tag=0x..`, or one bare address when exactly one case is selected.
func parseAccounts(file, spec string, selected []liveCase) (map[string]string, error) {
	out := map[string]string{}
	if file != "" {
		b, err := os.ReadFile(file)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, &out); err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
		case !os.IsNotExist(err):
			return nil, err
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, addr, found := strings.Cut(part, "=")
		if !found {
			if len(selected) != 1 {
				return nil, fmt.Errorf("-account %q: a bare address names one account, but %d cases are selected and each governing key book has its own account; use tag=0x..", part, len(selected))
			}
			tag, addr = selected[0].Tag, part
		}
		out[strings.ToLower(strings.TrimSpace(tag))] = strings.TrimSpace(addr)
	}
	for tag, addr := range out {
		if !addressRE.MatchString(addr) {
			return nil, fmt.Errorf("account for %q: %q is not an address", tag, addr)
		}
	}
	return out, nil
}

type accountState struct {
	Tag, Book, Address string
	Deployed           bool
	Balance            *big.Int
	Binding            string // "" when bound correctly, else what is wrong
}

type accountsOpts struct {
	Factory string
	Create  bool
	FundWei *big.Int // fund each deployed account up to this balance (0: do not fund)
	File    string
}

func mustABI2(j string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(j))
	if err != nil {
		panic(err)
	}
	return a
}

var (
	factoryABIv11 = mustABI2(factoryV11ABI)
	accountABIv73 = mustABI2(accountV73ABI)
)

func callOut(ctx context.Context, c *ethclient.Client, to common.Address, a abi.ABI, method string, args ...any) ([]any, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	raw, err := c.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return a.Unpack(method, raw)
}

func (a *app) accounts(ctx context.Context, l liveConfig, o accountsOpts) error {
	cases, err := l.selected()
	if err != nil {
		return err
	}
	var targets []acctTarget
	for _, cs := range cases {
		targets = append(targets, acctTarget{Name: cs.Name, Tag: cs.Tag, ADI: a.adi, Book: cs.authorityBook(a.adi)})
	}
	return accountsOf(ctx, l, o, targets)
}

// acctTarget is one CertenAccount to deploy and check: the account of ADI whose governing book is Book (a canonical book of ADI).
type acctTarget struct{ Name, Tag, ADI, Book string }

// accountsOf deploys (with -create), funds (with -fund) and checks the accounts of targets on the target chain. The accounts of the
// signature-type run (one ADI, one book per case) and of the RB9-E scenarios (one ADI per scenario, its own `/book`) share it.
func accountsOf(ctx context.Context, l liveConfig, o accountsOpts, targets []acctTarget) error {
	if l.RPC == "" {
		return fmt.Errorf("accounts needs -rpc (the target chain's JSON-RPC URL)")
	}
	c, err := ethclient.DialContext(ctx, l.RPC)
	if err != nil {
		return err
	}
	defer c.Close()
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return err
	}
	if chainID.Int64() != baseSepoliaChainID {
		return fmt.Errorf("the RPC serves chain %s, the live intents target %d", chainID, baseSepoliaChainID)
	}
	factory := common.HexToAddress(o.Factory)
	r, err := callOut(ctx, c, factory, factoryABIv11, "anchorContract")
	if err != nil {
		return err
	}
	pinned := r[0].(common.Address)
	r, err = callOut(ctx, c, factory, factoryABIv11, "deploymentFee")
	if err != nil {
		return err
	}
	fee := r[0].(*big.Int)
	fmt.Printf("chain %s factory %s anchor %s deploymentFee %s wei\n", chainID, factory.Hex(), pinned.Hex(), fee)
	if !strings.EqualFold(pinned.Hex(), baseSepoliaAnchor) {
		return fmt.Errorf("the factory binds accounts to anchor %s, but the intents declare %s: CertenAccountV7_3 refuses any other anchor", pinned.Hex(), baseSepoliaAnchor)
	}

	var pk *ecdsa.PrivateKey
	var from common.Address
	var nonce uint64 // the sender's next nonce, tracked here: a load-balanced RPC answers PendingNonceAt from a lagging node right after a receipt
	if o.Create || (o.FundWei != nil && o.FundWei.Sign() > 0) {
		pk, err = crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(os.Getenv("ETH_PRIVATE_KEY")), "0x"))
		if err != nil {
			return fmt.Errorf("ETH_PRIVATE_KEY (environment) is not a usable key")
		}
		from = crypto.PubkeyToAddress(pk.PublicKey)
		bal, _ := c.BalanceAt(ctx, from, nil)
		fmt.Printf("sender %s balance %s wei\n", from.Hex(), bal)
		if nonce, err = c.PendingNonceAt(ctx, from); err != nil {
			return err
		}
	}

	states := make(map[string]string)
	var rows []accountState
	for _, cs := range targets {
		book, adi := cs.Book, cs.ADI
		salt := canonicalSalt(adi)
		if !isCanonicalBookOf(adi, book) {
			return fmt.Errorf("%s is not a canonical key book of %s", book, adi)
		}
		r, err := callOut(ctx, c, factory, factoryABIv11, "getAddressForADI", adi, book, salt)
		if err != nil {
			return err
		}
		addr := r[0].(common.Address)
		code, err := c.CodeAt(ctx, addr, nil)
		if err != nil {
			return err
		}
		if len(code) == 0 && o.Create {
			auth, err := bind.NewKeyedTransactorWithChainID(pk, chainID)
			if err != nil {
				return err
			}
			auth.Context, auth.Value, auth.Nonce = ctx, fee, new(big.Int).SetUint64(nonce)
			bc := bind.NewBoundContract(factory, factoryABIv11, c, c, c)
			tx, err := bc.Transact(auth, "createAccountForADI", adi, book, salt)
			if err != nil {
				return fmt.Errorf("createAccountForADI(%s): %w", book, err)
			}
			rc, err := bind.WaitMined(ctx, c, tx)
			if err != nil {
				return err
			}
			nonce++
			if rc.Status != types.ReceiptStatusSuccessful {
				return fmt.Errorf("createAccountForADI(%s) reverted: tx %s", book, tx.Hash().Hex())
			}
			fmt.Printf("%-24s created %s tx %s gas %d\n", cs.Name, addr.Hex(), tx.Hash().Hex(), rc.GasUsed)
			if err := waitState(ctx, "code at "+addr.Hex(), func() (bool, error) {
				code, err = c.CodeAt(ctx, addr, nil)
				return len(code) > 0, err
			}); err != nil {
				return err
			}
		}
		st := accountState{Tag: cs.Tag, Book: book, Address: addr.Hex(), Deployed: len(code) > 0}
		if st.Deployed {
			st.Binding = checkBinding(ctx, c, addr, adi, book, pinned)
			if o.FundWei != nil && o.FundWei.Sign() > 0 {
				bal, _ := c.BalanceAt(ctx, addr, nil)
				if bal.Cmp(o.FundWei) < 0 {
					if err := sendValue(ctx, c, pk, chainID, nonce, addr, new(big.Int).Sub(o.FundWei, bal)); err != nil {
						return fmt.Errorf("fund %s: %w", addr.Hex(), err)
					}
					nonce++
					if err := waitState(ctx, "balance of "+addr.Hex(), func() (bool, error) {
						b, err := c.BalanceAt(ctx, addr, nil)
						return err == nil && b.Cmp(o.FundWei) >= 0, err
					}); err != nil {
						return err
					}
				}
			}
		}
		st.Balance, _ = c.BalanceAt(ctx, addr, nil)
		rows = append(rows, st)
		states[cs.Tag] = addr.Hex()
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Tag < rows[j].Tag })
	bad := 0
	for _, s := range rows {
		status := "deployed"
		switch {
		case !s.Deployed:
			status, bad = "NOT DEPLOYED", bad+1
		case s.Binding != "":
			status, bad = "BAD BINDING: "+s.Binding, bad+1
		}
		fmt.Printf("%-14s %s balance %-18s %s\n", s.Tag, s.Address, s.Balance, status)
	}
	if o.File != "" {
		if err := os.MkdirAll(filepath.Dir(o.File), 0o755); err != nil {
			return err
		}
		merged := map[string]string{}
		if b, err := os.ReadFile(o.File); err == nil {
			_ = json.Unmarshal(b, &merged)
		}
		for _, s := range rows {
			if s.Deployed && s.Binding == "" {
				merged[s.Tag] = s.Address
			}
		}
		b, _ := json.MarshalIndent(merged, "", "  ")
		if err := os.WriteFile(o.File, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d accounts are not deployed and correctly bound", bad, len(rows))
	}
	return nil
}

// checkBinding reads the account back: its ADI, governing book, pinned anchor and keylessness must be the case's.
func checkBinding(ctx context.Context, c *ethclient.Client, acct common.Address, adi, book string, anchor common.Address) string {
	var bad []string
	if r, err := callOut(ctx, c, acct, accountABIv73, "adiURL"); err != nil || r[0].(string) != adi {
		bad = append(bad, fmt.Sprintf("adiURL %v (%v)", r, err))
	}
	if r, err := callOut(ctx, c, acct, accountABIv73, "governingBook"); err != nil || r[0].(string) != book {
		bad = append(bad, fmt.Sprintf("governingBook %v (%v)", r, err))
	}
	if r, err := callOut(ctx, c, acct, accountABIv73, "anchorContract"); err != nil || r[0].(common.Address) != anchor {
		bad = append(bad, fmt.Sprintf("anchorContract %v (%v)", r, err))
	}
	if r, err := callOut(ctx, c, acct, accountABIv73, "isKeylessOwner"); err != nil || r[0] != true {
		bad = append(bad, fmt.Sprintf("isKeylessOwner %v (%v)", r, err))
	}
	return strings.Join(bad, "; ")
}

// sendValue sends wei to a contract account (a call into a contract costs more than a bare transfer, so the gas is
// estimated, not 21000).
func sendValue(ctx context.Context, c *ethclient.Client, pk *ecdsa.PrivateKey, chainID *big.Int, nonce uint64, to common.Address, wei *big.Int) error {
	from := crypto.PubkeyToAddress(pk.PublicKey)
	tip, err := c.SuggestGasTipCap(ctx)
	if err != nil {
		return err
	}
	head, err := c.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	feeCap := new(big.Int).Add(tip, new(big.Int).Mul(head.BaseFee, big.NewInt(2)))
	gas, err := c.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Value: wei})
	if err != nil {
		return err
	}
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, To: &to, Value: wei, Gas: gas * 12 / 10, GasTipCap: tip, GasFeeCap: feeCap})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), pk)
	if err != nil {
		return err
	}
	if err := c.SendTransaction(ctx, signed); err != nil {
		return err
	}
	rc, err := bind.WaitMined(ctx, c, signed)
	if err != nil {
		return err
	}
	if rc.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("funding transfer reverted: tx %s", signed.Hash().Hex())
	}
	fmt.Printf("  funded %s with %s wei tx %s\n", to.Hex(), wei, signed.Hash().Hex())
	return nil
}

// waitState polls until ok reports true: the target chain's public RPC is load-balanced, and a node that has not yet seen
// the block of a receipt answers reads of the new state with the old one.
func waitState(ctx context.Context, what string, ok func() (bool, error)) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		good, err := ok()
		if err != nil {
			return err
		}
		if good {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: not visible on the RPC within 2 minutes", what)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
