// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/consensus"
)

// The relink of a chain's CertenAccountV7_2 accounts (factory V10) to CertenAccountV7_3 accounts (factory V11), before
// the chain's account leaf version moves to v4 (RB5-F57). After the switch no validator settles a V7_2 account on that
// chain, so value left in one is reachable only by a leaf no validator forms. A V7_2 account is keyless: only its own
// ADI's governance can move its value, so the relink is an intent the ADI signs, settled on the v3 path before the
// switch. This tool never signs, creates or sends anything:
//
//   inventory  every V10 account at a finalized block, with its native and ERC-20 balances, each read from every
//              provider at the same block hash (any disagreement is refused by name);
//   plan       each account's V11 address (CREATE2 from factory V11 and CertenAccountV7_3's creation code), and for every
//              funded account an UNSIGNED relink intent moving its balances to that address;
//   verify     at a finalized block: relinked (V10 empty, V11 holding at least what was planned) or not yet;
//   retire     every account not relinked at cut-over, by name, with its balance and the block it was read at.

const factoryV10ABI = `[
 {"type":"function","name":"getAccountCount","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"getAccountsPaginated","inputs":[{"name":"offset","type":"uint256"},{"name":"limit","type":"uint256"}],"outputs":[{"name":"accounts","type":"address[]"}],"stateMutability":"view"},
 {"type":"function","name":"entryPoint","inputs":[],"outputs":[{"name":"","type":"address"}],"stateMutability":"view"}]`

const accountABI = `[
 {"type":"function","name":"adiURL","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"governingBook","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"},
 {"type":"function","name":"LEAF_DOMAIN","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"view"}]`

const erc20ABI = `[
 {"type":"function","name":"balanceOf","inputs":[{"name":"a","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
 {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`

// transferTopic is keccak256("Transfer(address,address,uint256)").
var transferTopic = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

var (
	factoryABIParsed = mustABI(factoryV10ABI)
	accountABIParsed = mustABI(accountABI)
	erc20ABIParsed   = mustABI(erc20ABI)
)

func mustABI(j string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(j))
	if err != nil {
		panic(err)
	}
	return a
}

// chainReader is what the tool reads from a provider: ethclient.Client.
type chainReader interface {
	ethereum.ChainReader
	ethereum.ContractCaller
	ethereum.LogFilterer
	BalanceAt(ctx context.Context, account common.Address, block *big.Int) (*big.Int, error)
	CodeAt(ctx context.Context, account common.Address, block *big.Int) ([]byte, error)
	ChainID(ctx context.Context) (*big.Int, error)
}

// TokenBalance is an ERC-20 balance.
type TokenBalance struct {
	Token   common.Address `json:"token"`
	Balance string         `json:"balance"`
}

// Entry is one V10 account.
type Entry struct {
	Account       common.Address `json:"account"`
	ADIURL        string         `json:"adi_url"`
	GoverningBook string         `json:"governing_book"`
	LeafDomain    string         `json:"leaf_domain"`
	NativeWei     string         `json:"native_wei"`
	Tokens        []TokenBalance `json:"tokens,omitempty"`
	// AddressRederived: the account's address re-derived here from factory V10, CertenAccountV7_2's creation code and
	// its (ADI, governing book) equals the deployed one - so the same derivation's V11 address is the account's.
	AddressRederived bool `json:"address_rederived"`
}

// Funded reports whether the account holds anything.
func (e Entry) Funded() bool {
	if e.NativeWei != "0" {
		return true
	}
	for _, t := range e.Tokens {
		if t.Balance != "0" {
			return true
		}
	}
	return false
}

// Inventory is every V10 account of a chain at one finalized block.
type Inventory struct {
	ChainID    int64          `json:"chain_id"`
	FactoryV10 common.Address `json:"factory_v10"`
	EntryPoint common.Address `json:"entry_point"`
	Block      uint64         `json:"block"`
	BlockHash  common.Hash    `json:"block_hash"`
	BlockTime  time.Time      `json:"block_time"`
	Providers  int            `json:"providers"`
	// TokenScanFrom is the first block searched for ERC-20 transfers to the accounts: the factory's deployment.
	TokenScanFrom uint64  `json:"token_scan_from"`
	Entries       []Entry `json:"entries"`
}

// agreed reads the same value from every provider and refuses any disagreement by name.
func agreed[T any](ctx context.Context, providers []chainReader, what string, read func(chainReader) (T, error)) (T, error) {
	var first T
	var firstJSON []byte
	for i, p := range providers {
		v, err := read(p)
		if err != nil {
			return first, fmt.Errorf("%s from provider %d: %w", what, i, err)
		}
		j, _ := json.Marshal(v)
		if i == 0 {
			first, firstJSON = v, j
			continue
		}
		if !bytes.Equal(j, firstJSON) {
			return first, fmt.Errorf("%s: providers disagree (%s vs %s)", what, firstJSON, j)
		}
	}
	return first, nil
}

func call(ctx context.Context, p chainReader, a abi.ABI, to common.Address, block *big.Int, method string, args ...interface{}) ([]interface{}, error) {
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	var out []byte
	if err := rateLimited(ctx, func() error {
		var err error
		out, err = p.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, block)
		return err
	}); err != nil {
		return nil, err
	}
	return a.Unpack(method, out)
}

// balanceAt is the native balance of account at block.
func balanceAt(ctx context.Context, p chainReader, account common.Address, block *big.Int) (*big.Int, error) {
	var b *big.Int
	err := rateLimited(ctx, func() error {
		var err error
		b, err = p.BalanceAt(ctx, account, block)
		return err
	})
	return b, err
}

// finalizedHeader is the chain's finalized block, the same on every provider.
func finalizedHeader(ctx context.Context, providers []chainReader) (*types.Header, error) {
	h, err := providers[0].HeaderByNumber(ctx, big.NewInt(int64(-3))) // rpc.FinalizedBlockNumber
	if err != nil {
		return nil, fmt.Errorf("the finalized block: %w", err)
	}
	for i, p := range providers[1:] {
		o, err := p.HeaderByNumber(ctx, h.Number)
		if err != nil {
			return nil, fmt.Errorf("block %d from provider %d: %w", h.Number, i+1, err)
		}
		if o.Hash() != h.Hash() {
			return nil, fmt.Errorf("block %d is %s on provider 0 and %s on provider %d", h.Number, h.Hash(), o.Hash(), i+1)
		}
	}
	return h, nil
}

// deploymentBlock is the first block at which code exists at addr, by bisection up to head.
func deploymentBlock(ctx context.Context, p chainReader, addr common.Address, head uint64) (uint64, error) {
	lo, hi := uint64(0), head
	for lo < hi {
		mid := (lo + hi) / 2
		code, err := p.CodeAt(ctx, addr, new(big.Int).SetUint64(mid))
		if err != nil {
			return 0, fmt.Errorf("code of %s at block %d: %w", addr, mid, err)
		}
		if len(code) > 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo, nil
}

// isRateRefusal reports a provider's "request rate exceeded" answer (HTTP 429, JSON-RPC -32005/-32007/-32029).
func isRateRefusal(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "429") || strings.Contains(msg, "Too Many Requests") ||
		strings.Contains(msg, "-32005") || strings.Contains(msg, "-32007") || strings.Contains(msg, "-32029")
}

// rateLimited runs read, retrying it - the same read - while the provider answers that its request rate is exceeded
// (HTTP 429, JSON-RPC -32005/-32007/-32029), with a growing pause, at most eight times. Any other error, and the ninth
// rate refusal, is returned: a read is never replaced by another answer.
func rateLimited(ctx context.Context, read func() error) error {
	pause := 500 * time.Millisecond
	for attempt := 0; ; attempt++ {
		err := read()
		if err == nil || attempt == 8 {
			return err
		}
		if !isRateRefusal(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
		pause *= 2
	}
}

// tokensReceived is every token contract that emitted a Transfer to one of accounts in [from, to].
func tokensReceived(ctx context.Context, p chainReader, accounts []common.Address, from, to, chunk uint64) ([]common.Address, error) {
	if len(accounts) == 0 {
		return nil, nil
	}
	recipients := make([]common.Hash, len(accounts))
	for i, a := range accounts {
		recipients[i] = common.BytesToHash(a.Bytes())
	}
	seen := map[common.Address]bool{}
	for lo := from; lo <= to; lo += chunk {
		hi := lo + chunk - 1
		if hi > to {
			hi = to
		}
		logs, err := transferLogsSplitting(ctx, p, recipients, lo, hi)
		if err != nil {
			return nil, err
		}
		for _, l := range logs {
			if len(l.Topics) == 3 { // ERC-20 (ERC-721 Transfer has 4 topics)
				seen[l.Address] = true
			}
		}
	}
	out := make([]common.Address, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out, nil
}

// minLogSpan is the narrowest range transferLogsSplitting asks for before it accepts that the provider refuses the query
// itself, not its width.
const minLogSpan = 16

// transferLogsSplitting is every Transfer log to recipients in [lo, hi]. Providers cap eth_getLogs ranges differently and
// the cap is not discoverable up front (drpc's free plan refuses 10,000 blocks), so a refused range is split in two and
// each half asked for, as pkg/execution's filterLogsSplitting does. A rate refusal is retried as the same read
// (rateLimited), never split; a range at minLogSpan that is still refused is returned with the provider's error.
func transferLogsSplitting(ctx context.Context, p chainReader, recipients []common.Hash, lo, hi uint64) ([]types.Log, error) {
	var logs []types.Log
	err := rateLimited(ctx, func() error {
		var err error
		logs, err = p.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: new(big.Int).SetUint64(lo), ToBlock: new(big.Int).SetUint64(hi),
			Topics: [][]common.Hash{{transferTopic}, nil, recipients}})
		return err
	})
	if err == nil {
		return logs, nil
	}
	if ctx.Err() != nil || hi-lo+1 <= minLogSpan || isRateRefusal(err) {
		return nil, fmt.Errorf("Transfer logs in [%d, %d]: %w", lo, hi, err)
	}
	mid := lo + (hi-lo)/2
	left, err := transferLogsSplitting(ctx, p, recipients, lo, mid)
	if err != nil {
		return nil, err
	}
	right, err := transferLogsSplitting(ctx, p, recipients, mid+1, hi)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

// AccountAddress is the CREATE2 address factory deploys an (ADI, governing book) account at, exactly as factory V10
// and V11 compute it (getAddressForADI): salt = keccak256(adiURL), init code = creationCode ++ abi.encode(entryPoint,
// keyless owner, adiURL, governingBook).
func AccountAddress(factory, entryPoint common.Address, adiURL, book string, creationCode []byte) (common.Address, error) {
	owner := common.BytesToAddress(crypto.Keccak256([]byte(adiURL))[12:])
	addrT, _ := abi.NewType("address", "", nil)
	strT, _ := abi.NewType("string", "", nil)
	args, err := abi.Arguments{{Type: addrT}, {Type: addrT}, {Type: strT}, {Type: strT}}.Pack(entryPoint, owner, adiURL, book)
	if err != nil {
		return common.Address{}, err
	}
	init := append(append([]byte{}, creationCode...), args...)
	var salt [32]byte
	copy(salt[:], crypto.Keccak256([]byte(adiURL)))
	return crypto.CreateAddress2(factory, salt, crypto.Keccak256(init)), nil
}

// creationCodeOf reads a Foundry artifact's creation bytecode.
func creationCodeOf(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var art struct {
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
	}
	if err := json.Unmarshal(raw, &art); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	code, err := hex.DecodeString(strings.TrimPrefix(art.Bytecode.Object, "0x"))
	if err != nil || len(code) == 0 {
		return nil, fmt.Errorf("%s holds no creation bytecode", path)
	}
	return code, nil
}

// Inventory reads every V10 account of the chain at its finalized block.
func ReadInventory(ctx context.Context, providers []chainReader, factory common.Address, v72Creation []byte, logChunk uint64) (*Inventory, error) {
	if len(providers) == 0 {
		return nil, errors.New("no provider")
	}
	chainID, err := agreed(ctx, providers, "chain id", func(p chainReader) (string, error) {
		id, err := p.ChainID(ctx)
		if err != nil {
			return "", err
		}
		return id.String(), nil
	})
	if err != nil {
		return nil, err
	}
	head, err := finalizedHeader(ctx, providers)
	if err != nil {
		return nil, err
	}
	at := head.Number
	ep, err := agreed(ctx, providers, "factory entryPoint", func(p chainReader) (common.Address, error) {
		out, err := call(ctx, p, factoryABIParsed, factory, at, "entryPoint")
		if err != nil {
			return common.Address{}, err
		}
		return out[0].(common.Address), nil
	})
	if err != nil {
		return nil, err
	}
	accounts, err := agreed(ctx, providers, "the factory's accounts", func(p chainReader) ([]common.Address, error) {
		out, err := call(ctx, p, factoryABIParsed, factory, at, "getAccountCount")
		if err != nil {
			return nil, err
		}
		n := out[0].(*big.Int)
		var all []common.Address
		for off := int64(0); off < n.Int64(); off += 100 {
			page, err := call(ctx, p, factoryABIParsed, factory, at, "getAccountsPaginated", big.NewInt(off), big.NewInt(100))
			if err != nil {
				return nil, err
			}
			all = append(all, page[0].([]common.Address)...)
		}
		if int64(len(all)) != n.Int64() {
			return nil, fmt.Errorf("the factory counts %s accounts and lists %d", n, len(all))
		}
		return all, nil
	})
	if err != nil {
		return nil, err
	}
	from, err := deploymentBlock(ctx, providers[0], factory, at.Uint64())
	if err != nil {
		return nil, err
	}
	// The tokens to read balances of: every ERC-20 that sent the accounts anything, as every provider's logs state it.
	tokens, err := agreed(ctx, providers, "the tokens received", func(p chainReader) ([]common.Address, error) {
		return tokensReceived(ctx, p, accounts, from, at.Uint64(), logChunk)
	})
	if err != nil {
		return nil, err
	}
	id, _ := new(big.Int).SetString(chainID, 10)
	inv := &Inventory{ChainID: id.Int64(), FactoryV10: factory, EntryPoint: ep, Block: at.Uint64(), BlockHash: head.Hash(),
		BlockTime: time.Unix(int64(head.Time), 0).UTC(), Providers: len(providers), TokenScanFrom: from}
	for _, a := range accounts {
		e, err := agreed(ctx, providers, "account "+a.Hex(), func(p chainReader) (Entry, error) {
			e := Entry{Account: a}
			for _, f := range []struct {
				m   string
				dst *string
			}{{"adiURL", &e.ADIURL}, {"governingBook", &e.GoverningBook}, {"LEAF_DOMAIN", &e.LeafDomain}} {
				out, err := call(ctx, p, accountABIParsed, a, at, f.m)
				if err != nil {
					return e, fmt.Errorf("%s: %w", f.m, err)
				}
				*f.dst = out[0].(string)
			}
			bal, err := balanceAt(ctx, p, a, at)
			if err != nil {
				return e, err
			}
			e.NativeWei = bal.String()
			for _, tok := range tokens {
				out, err := call(ctx, p, erc20ABIParsed, tok, at, "balanceOf", a)
				if err != nil {
					return e, fmt.Errorf("balanceOf on %s: %w", tok, err)
				}
				if b := out[0].(*big.Int); b.Sign() > 0 {
					e.Tokens = append(e.Tokens, TokenBalance{Token: tok, Balance: b.String()})
				}
			}
			return e, nil
		})
		if err != nil {
			return nil, err
		}
		got, err := AccountAddress(factory, ep, e.ADIURL, e.GoverningBook, v72Creation)
		if err != nil {
			return nil, err
		}
		e.AddressRederived = got == a
		if !e.AddressRederived {
			return nil, fmt.Errorf("account %s of %s under %s re-derives as %s: the V7_2 creation code given is not the "+
				"deployed one, so no V11 address computed with the same derivation can be trusted", a, e.ADIURL, e.GoverningBook, got)
		}
		inv.Entries = append(inv.Entries, e)
	}
	return inv, nil
}

// Leg is one leg of a relink intent, in the shape the validator reads (consensus.MemberLegsForChain).
type Leg struct {
	LegID             string     `json:"legId"`
	Chain             string     `json:"chain"`
	ChainID           int64      `json:"chainId"`
	From              string     `json:"from"`
	DeadlineTimestamp int64      `json:"deadline_timestamp"`
	ExecutionPayload  LegPayload `json:"executionPayload"`
}

// LegPayload is a leg's call.
type LegPayload struct {
	Target   string `json:"target"`
	Value    string `json:"value"`
	CallData string `json:"callData"`
	// DataHash and ExecutionCommitment bind a contract-call leg to exactly its calldata (RB-1).
	DataHash            string `json:"dataHash,omitempty"`
	ExecutionCommitment string `json:"executionCommitment,omitempty"`
	// ExpectedEvents is what proves a token leg executed (RB-4): the token's Transfer. A token relink is a contract call,
	// which the validators settle only where CERTEN_ALLOW_CONTRACT_CALLS is enabled.
	ExpectedEvents []ExpectedEvent `json:"expectedEvents,omitempty"`
}

// ExpectedEvent is an event a contract-call leg must emit.
type ExpectedEvent struct {
	Contract string `json:"contract"`
	Topic0   string `json:"topic0"`
}

// PlanEntry is one account's relink.
type PlanEntry struct {
	Entry
	V11Account common.Address `json:"v11_account"`
	// UnsignedIntent is, for a funded account, the relink its ADI signs: the cross-chain legs moving every balance from
	// the V10 account to the V11 one, settled on the v3 path before the switch. Nil when nothing is to move.
	UnsignedIntent *RelinkIntent `json:"unsigned_intent,omitempty"`
}

// RelinkIntent is an unsigned relink: what the ADI's owner signs with the CERTEN SDK or CLI, as a CERTEN_INTENT.
type RelinkIntent struct {
	Purpose         string         `json:"purpose"`
	OrganizationADI string         `json:"organizationAdi"`
	CrossChainData  map[string]any `json:"crossChainData"`
}

// Plan is the relink of an inventory.
type Plan struct {
	Inventory  Inventory      `json:"inventory"`
	FactoryV11 common.Address `json:"factory_v11"`
	Entries    []PlanEntry    `json:"entries"`
}

// MakePlan computes every account's V11 address and the unsigned relink of every funded one. deadline is the relink
// legs' signed deadline: before the cut-over.
func MakePlan(inv *Inventory, factoryV11 common.Address, v73Creation []byte, deadline time.Time, chainName string) (*Plan, error) {
	if deadline.Before(inv.BlockTime) {
		return nil, fmt.Errorf("the relink deadline %s is before the inventory block's time %s", deadline, inv.BlockTime)
	}
	plan := &Plan{Inventory: *inv, FactoryV11: factoryV11}
	for _, e := range inv.Entries {
		v11, err := AccountAddress(factoryV11, inv.EntryPoint, e.ADIURL, e.GoverningBook, v73Creation)
		if err != nil {
			return nil, err
		}
		pe := PlanEntry{Entry: e, V11Account: v11}
		if e.Funded() {
			var legs []Leg
			if e.NativeWei != "0" {
				legs = append(legs, Leg{ExecutionPayload: LegPayload{Target: v11.Hex(), Value: e.NativeWei, CallData: "0x"}})
			}
			for _, t := range e.Tokens {
				amount, _ := new(big.Int).SetString(t.Balance, 10)
				data, err := erc20ABIParsed.Pack("transfer", v11, amount)
				if err != nil {
					return nil, err
				}
				ec := consensus.ComputeExecutionCommitment(inv.ChainID, t.Token, big.NewInt(0), data)
				legs = append(legs, Leg{ExecutionPayload: LegPayload{Target: t.Token.Hex(), Value: "0", CallData: "0x" + hex.EncodeToString(data),
					DataHash: crypto.Keccak256Hash(data).Hex(), ExecutionCommitment: common.Hash(ec).Hex(),
					ExpectedEvents: []ExpectedEvent{{Contract: t.Token.Hex(), Topic0: transferTopic.Hex()}}}})
			}
			for i := range legs {
				legs[i].LegID = fmt.Sprintf("relink-%d", i)
				legs[i].Chain = chainName
				legs[i].ChainID = inv.ChainID
				legs[i].From = e.Account.Hex()
				legs[i].DeadlineTimestamp = deadline.Unix()
			}
			pe.UnsignedIntent = &RelinkIntent{Purpose: "RB5-F57 account relink: CertenAccountV7_2 (factory V10) to CertenAccountV7_3 (factory V11)",
				OrganizationADI: e.ADIURL, CrossChainData: map[string]any{"legs": legs, "execution_mode": "atomic"}}
		}
		plan.Entries = append(plan.Entries, pe)
	}
	return plan, nil
}

// Status is one account's relink state at a block.
type Status struct {
	Account    common.Address `json:"account"`
	ADIURL     string         `json:"adi_url"`
	V11Account common.Address `json:"v11_account"`
	State      string         `json:"state"` // "relinked", "nothing to move", "not relinked"
	V10Native  string         `json:"v10_native_wei"`
	V11Native  string         `json:"v11_native_wei"`
	Detail     string         `json:"detail,omitempty"`
}

// Verification is a plan's state at a finalized block.
type Verification struct {
	Block     uint64      `json:"block"`
	BlockHash common.Hash `json:"block_hash"`
	Statuses  []Status    `json:"statuses"`
}

// Verify reads, at the finalized block, whether each planned relink happened: the V10 account holds none of what was
// planned and the V11 account holds at least it.
func Verify(ctx context.Context, providers []chainReader, plan *Plan) (*Verification, error) {
	head, err := finalizedHeader(ctx, providers)
	if err != nil {
		return nil, err
	}
	at := head.Number
	v := &Verification{Block: at.Uint64(), BlockHash: head.Hash()}
	for _, pe := range plan.Entries {
		st, err := agreed(ctx, providers, "relink of "+pe.Account.Hex(), func(p chainReader) (Status, error) {
			s := Status{Account: pe.Account, ADIURL: pe.ADIURL, V11Account: pe.V11Account}
			old, err := balanceAt(ctx, p, pe.Account, at)
			if err != nil {
				return s, err
			}
			nw, err := balanceAt(ctx, p, pe.V11Account, at)
			if err != nil {
				return s, err
			}
			s.V10Native, s.V11Native = old.String(), nw.String()
			if !pe.Funded() {
				s.State = "nothing to move"
				return s, nil
			}
			planned, _ := new(big.Int).SetString(pe.NativeWei, 10)
			var short []string
			if old.Sign() != 0 {
				short = append(short, "the V10 account still holds "+old.String()+" wei")
			}
			if nw.Cmp(planned) < 0 {
				short = append(short, "the V11 account holds "+nw.String()+" of the planned "+planned.String()+" wei")
			}
			for _, t := range pe.Tokens {
				want, _ := new(big.Int).SetString(t.Balance, 10)
				ob, err := call(ctx, p, erc20ABIParsed, t.Token, at, "balanceOf", pe.Account)
				if err != nil {
					return s, err
				}
				nb, err := call(ctx, p, erc20ABIParsed, t.Token, at, "balanceOf", pe.V11Account)
				if err != nil {
					return s, err
				}
				if ob[0].(*big.Int).Sign() != 0 || nb[0].(*big.Int).Cmp(want) < 0 {
					short = append(short, fmt.Sprintf("token %s: V10 %s, V11 %s of %s", t.Token, ob[0], nb[0], want))
				}
			}
			if len(short) == 0 {
				s.State = "relinked"
			} else {
				s.State, s.Detail = "not relinked", strings.Join(short, "; ")
			}
			return s, nil
		})
		if err != nil {
			return nil, err
		}
		v.Statuses = append(v.Statuses, st)
	}
	return v, nil
}

// Retirement is an account retired by name at cut-over: not relinked, so its value stays where no validator settles.
type Retirement struct {
	Account   common.Address `json:"account"`
	ADIURL    string         `json:"adi_url"`
	Book      string         `json:"governing_book"`
	NativeWei string         `json:"native_wei"`
	Block     uint64         `json:"block"`
	BlockHash common.Hash    `json:"block_hash"`
	Reason    string         `json:"reason"`
}

// Retire names every planned account the verification did not find relinked.
func Retire(plan *Plan, v *Verification, chainID int64) []Retirement {
	byAccount := map[common.Address]Status{}
	for _, s := range v.Statuses {
		byAccount[s.Account] = s
	}
	var out []Retirement
	for _, pe := range plan.Entries {
		s, ok := byAccount[pe.Account]
		if ok && s.State != "not relinked" {
			continue
		}
		reason := fmt.Sprintf("not relinked before chain %d switched to account leaf v4: a CertenAccountV7_2 holds it, which no "+
			"CERTEN validator settles on a v4 chain", chainID)
		if ok && s.Detail != "" {
			reason += " (" + s.Detail + ")"
		}
		out = append(out, Retirement{Account: pe.Account, ADIURL: pe.ADIURL, Book: pe.GoverningBook, NativeWei: s.V10Native,
			Block: v.Block, BlockHash: v.BlockHash, Reason: reason})
	}
	return out
}
