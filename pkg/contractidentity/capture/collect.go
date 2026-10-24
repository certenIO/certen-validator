// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

type blockAt struct {
	Number uint64
	Root   common.Hash
}

type acctKey struct {
	st string
	a  common.Address
}

type slotKey struct {
	acctKey
	s common.Hash
}

// collector is the Reader of a capture: it serves what it has verified, and for everything else it records the read as wanted and answers
// errPending. serve() then asks the providers for ALL wanted slots of a contract in one eth_getProof call; every answer is verified with the
// strict reads of the contractidentity package against the agreed state root before it is kept, so a lying provider adds nothing.
type collector struct {
	cfg   *Config
	roots map[string]blockAt
	rot   int

	accts map[acctKey]ci.AccountState
	slots map[slotKey]common.Hash
	codes map[common.Address][]byte
	pool  map[common.Hash][]byte
	bytes int

	wantAcct map[acctKey]bool
	wantSlot map[acctKey]map[common.Hash]bool
	wantCode map[acctKey]bool
	fails    *failures
}

func newCollector(cfg *Config, roots map[string]blockAt) *collector {
	return &collector{cfg: cfg, roots: roots, accts: map[acctKey]ci.AccountState{}, slots: map[slotKey]common.Hash{}, codes: map[common.Address][]byte{},
		pool: map[common.Hash][]byte{}, fails: newFailures()}
}

func (c *collector) resetWants() {
	c.wantAcct, c.wantSlot, c.wantCode = map[acctKey]bool{}, map[acctKey]map[common.Hash]bool{}, map[acctKey]bool{}
}

func (c *collector) Account(st string, a common.Address) (ci.AccountState, error) {
	k := acctKey{st, a}
	if acc, ok := c.accts[k]; ok {
		return acc, nil
	}
	c.wantAcct[k] = true
	return ci.AccountState{}, errPending
}

func (c *collector) Slot(st string, a common.Address, s common.Hash) (common.Hash, error) {
	k := acctKey{st, a}
	acc, ok := c.accts[k]
	if !ok {
		c.wantAcct[k] = true
		return common.Hash{}, errPending
	}
	if !acc.Exists {
		return common.Hash{}, nil // a verified exclusion proof: every slot of the absent account is zero
	}
	if v, ok := c.slots[slotKey{k, s}]; ok {
		return v, nil
	}
	if c.wantSlot[k] == nil {
		c.wantSlot[k] = map[common.Hash]bool{}
	}
	c.wantSlot[k][s] = true
	return common.Hash{}, errPending
}

func (c *collector) Code(st string, a common.Address) ([]byte, error) {
	k := acctKey{st, a}
	acc, ok := c.accts[k]
	if !ok {
		c.wantAcct[k] = true
		return nil, errPending
	}
	if !acc.HasCode() {
		return nil, nil
	}
	if code, ok := c.codes[a]; ok {
		return code, nil
	}
	c.wantCode[k] = true
	return nil, errPending
}

func (c *collector) Indexed(kind string, _ uint32) ([]byte, error) {
	return nil, fmt.Errorf("the settlement station reads no %s leaf", kind)
}

type proofAnswer struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []struct {
		Key   string          `json:"key"`
		Value string          `json:"value"`
		Proof []hexutil.Bytes `json:"proof"`
	} `json:"storageProof"`
}

// each tries the providers (distinct hosts, rotated start) in up to Passes passes with Backoff between them on the injected clock. It returns
// nil on the first provider whose attempt returns nil, an UnavailableError when none does within the budget, and a fatal error unchanged.
func (c *collector) each(ctx context.Context, what string, attempt func(Provider) error) error {
	ps := distinct(c.cfg.Source.Providers())
	if len(ps) == 0 {
		return &UnavailableError{What: what, Failures: []ci.ProviderFailure{{Host: "none", Error: "no provider configured"}}}
	}
	start := c.rot
	c.rot++
	for pass := 0; pass < c.cfg.passes(); pass++ {
		for i := range ps {
			if err := ctx.Err(); err != nil {
				return &UnavailableError{What: what, Failures: c.fails.list(), Cause: err}
			}
			p := ps[(start+i)%len(ps)]
			err := attempt(p)
			if err == nil {
				return nil
			}
			if errors.Is(err, ErrTooLarge) {
				return err
			}
			c.fails.note(p.Name(), err)
			c.cfg.logf("capture %s: provider %s: %v", what, p.Name(), err)
		}
		if pass+1 < c.cfg.passes() && !c.cfg.clock().Sleep(ctx, c.cfg.backoff()) {
			return &UnavailableError{What: what, Failures: c.fails.list(), Cause: ctx.Err()}
		}
	}
	return &UnavailableError{What: what, Failures: c.fails.list()}
}

func blockParam(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }

// accept verifies one eth_getProof answer with the strict reads and keeps ONLY the nodes those reads visited (a provider cannot pad the
// evidence). It commits nothing unless every account and slot of the answer verified.
func (c *collector) accept(st string, a common.Address, slots []common.Hash, raw json.RawMessage) error {
	if len(raw) > MaxResponseBytes {
		return fmt.Errorf("answer of %d bytes exceeds %d", len(raw), MaxResponseBytes)
	}
	var ans proofAnswer
	if err := json.Unmarshal(raw, &ans); err != nil {
		return fmt.Errorf("the answer cannot be read: %v", err)
	}
	if len(ans.StorageProof) != len(slots) {
		return fmt.Errorf("%d storage proofs for %d slots asked", len(ans.StorageProof), len(slots))
	}
	lim := ci.DefaultLimits()
	seen := map[common.Hash]bool{}
	var nodes [][]byte
	add := func(list []hexutil.Bytes) error {
		for _, n := range list {
			if len(n) == 0 || len(n) > lim.MaxNodeBytes {
				return fmt.Errorf("a proof node of %d bytes", len(n))
			}
			h := common.BytesToHash(crypto.Keccak256(n))
			if !seen[h] {
				seen[h] = true
				nodes = append(nodes, n)
			}
		}
		return nil
	}
	if err := add(ans.AccountProof); err != nil {
		return err
	}
	for _, sp := range ans.StorageProof {
		if err := add(sp.Proof); err != nil {
			return err
		}
	}
	ns, err := ci.NewNodeSet(nodes)
	if err != nil {
		return err
	}
	root := c.roots[st].Root
	acc, err := ci.ReadAccount(root, ns, a)
	if err != nil {
		return fmt.Errorf("account proof does not verify against the agreed state root of block %d: %v", c.roots[st].Number, err)
	}
	vals := make([]common.Hash, len(slots))
	for i, s := range slots {
		if got := common.HexToHash(ans.StorageProof[i].Key); got != s {
			return fmt.Errorf("storage proof %d is for slot %s, slot %s was asked", i, got.Hex(), s.Hex())
		}
		v, err := ci.ReadSlot(acc.StorageRoot, ns, s)
		if err != nil {
			return fmt.Errorf("slot %s does not verify: %v", s.Hex(), err)
		}
		if t := ans.StorageProof[i].Value; t != "" {
			n, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X"), 16)
			if !ok || common.BigToHash(n) != v {
				return fmt.Errorf("slot %s: the answer states %s, the proof proves %s", s.Hex(), t, v.Hex())
			}
		} else if v != (common.Hash{}) {
			return fmt.Errorf("slot %s: the answer states an empty value, the proof proves %s", s.Hex(), v.Hex())
		}
		vals[i] = v
	}
	kept := ns.VisitedNodes()
	add2 := 0
	for _, n := range kept {
		if h := common.BytesToHash(crypto.Keccak256(n)); c.pool[h] == nil {
			add2 += len(n)
		}
	}
	if c.bytes+add2 > c.cfg.poolCap() {
		return fmt.Errorf("%w: %d bytes held, %d more, budget %d", ErrTooLarge, c.bytes, add2, c.cfg.poolCap())
	}
	for _, n := range kept {
		c.pool[common.BytesToHash(crypto.Keccak256(n))] = n
	}
	c.bytes += add2
	k := acctKey{st, a}
	c.accts[k] = acc
	for i, s := range slots {
		c.slots[slotKey{k, s}] = vals[i]
	}
	return nil
}

// serve fetches everything the last plan pass wanted: one eth_getProof per contract and station with all its wanted slots, then the codes.
func (c *collector) serve(ctx context.Context) error {
	groups := map[acctKey]bool{}
	for k := range c.wantAcct {
		groups[k] = true
	}
	for k := range c.wantSlot {
		groups[k] = true
	}
	order := make([]acctKey, 0, len(groups))
	for k := range groups {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].st != order[j].st {
			return order[i].st < order[j].st
		}
		return bytes.Compare(order[i].a[:], order[j].a[:]) < 0
	})
	for _, k := range order {
		var slots []common.Hash
		for s := range c.wantSlot[k] {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return bytes.Compare(slots[i][:], slots[j][:]) < 0 })
		keys := make([]string, len(slots))
		for i, s := range slots {
			keys[i] = s.Hex()
		}
		blk := blockParam(c.roots[k.st].Number)
		what := fmt.Sprintf("eth_getProof %s at block %d", k.a.Hex(), c.roots[k.st].Number)
		if err := c.each(ctx, what, func(p Provider) error {
			raw, err := p.GetProof(ctx, k.a, keys, blk)
			if err != nil {
				return err
			}
			return c.accept(k.st, k.a, slots, raw)
		}); err != nil {
			return err
		}
	}
	codeKeys := make([]acctKey, 0, len(c.wantCode))
	for k := range c.wantCode {
		codeKeys = append(codeKeys, k)
	}
	sort.Slice(codeKeys, func(i, j int) bool {
		if codeKeys[i].st != codeKeys[j].st {
			return codeKeys[i].st < codeKeys[j].st
		}
		return bytes.Compare(codeKeys[i].a[:], codeKeys[j].a[:]) < 0
	})
	for _, k := range codeKeys {
		if _, have := c.codes[k.a]; have {
			continue
		}
		want := c.accts[k].CodeHash
		blk := blockParam(c.roots[k.st].Number)
		what := fmt.Sprintf("eth_getCode %s at block %d", k.a.Hex(), c.roots[k.st].Number)
		if err := c.each(ctx, what, func(p Provider) error {
			code, err := p.GetCode(ctx, k.a, blk)
			if err != nil {
				return err
			}
			if len(code) == 0 || len(code) > ci.DefaultLimits().MaxCodeBytes {
				return fmt.Errorf("code of %d bytes", len(code))
			}
			if got := common.BytesToHash(crypto.Keccak256(code)); got != want {
				return fmt.Errorf("code hashes to %s, the proven code hash is %s", got.Hex(), want.Hex())
			}
			if len(c.codes) >= ci.DefaultLimits().MaxCodes {
				return fmt.Errorf("%w: more than %d codes", ErrTooLarge, ci.DefaultLimits().MaxCodes)
			}
			c.codes[k.a] = append([]byte(nil), code...)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// run drives the plan to a fixed point: run, serve what was wanted, run again, until a run has nothing pending.
func (c *collector) run(ctx context.Context, plan func(Reader) (bool, error)) error {
	for iter := 0; iter < 64; iter++ {
		c.resetWants()
		pending, err := plan(c)
		if err != nil {
			return err
		}
		if !pending {
			return nil
		}
		if err := c.serve(ctx); err != nil {
			return err
		}
	}
	return &PlanError{Station: StationSettle, Reason: "plan_does_not_converge"}
}

// ---- the strict reader: the contractidentity reads over a container's nodes ----

type strictReader struct {
	ns     *ci.NodeSet
	roots  map[string]common.Hash
	txRoot common.Hash
	rcRoot common.Hash
	codes  map[common.Address][]byte
	accts  map[acctKey]ci.AccountState
	proven map[common.Address]bool // some station proved the code hash of the carried bytes
}

func newStrict(ns *ci.NodeSet, roots map[string]common.Hash, codes []ci.Code) *strictReader {
	r := &strictReader{ns: ns, roots: roots, codes: map[common.Address][]byte{}, accts: map[acctKey]ci.AccountState{}, proven: map[common.Address]bool{}}
	for _, c := range codes {
		r.codes[common.Address(c.Address)] = c.Runtime
	}
	return r
}

func (r *strictReader) Account(st string, a common.Address) (ci.AccountState, error) {
	root, ok := r.roots[st]
	if !ok {
		return ci.AccountState{}, fmt.Errorf("no state root for station %s", st)
	}
	acc, err := ci.ReadAccount(root, r.ns, a)
	if err == nil {
		r.accts[acctKey{st, a}] = acc
	}
	return acc, err
}

func (r *strictReader) Slot(st string, a common.Address, s common.Hash) (common.Hash, error) {
	acc, ok := r.accts[acctKey{st, a}]
	if !ok {
		return common.Hash{}, fmt.Errorf("slot read before the account read of %s at %s", a.Hex(), st)
	}
	return ci.ReadSlot(acc.StorageRoot, r.ns, s)
}

func (r *strictReader) Code(st string, a common.Address) ([]byte, error) {
	acc, ok := r.accts[acctKey{st, a}]
	if !ok {
		return nil, fmt.Errorf("code read before the account read of %s at %s", a.Hex(), st)
	}
	if !acc.HasCode() {
		return nil, nil
	}
	code, ok := r.codes[a]
	if !ok {
		return nil, fmt.Errorf("the code of %s (code hash %s at %s) is not carried", a.Hex(), acc.CodeHash.Hex(), st)
	}
	if common.BytesToHash(crypto.Keccak256(code)) == acc.CodeHash {
		r.proven[a] = true
	}
	return code, nil
}

func (r *strictReader) Indexed(kind string, idx uint32) ([]byte, error) {
	root := r.txRoot
	if kind == "receipt" {
		root = r.rcRoot
	}
	return ci.ReadIndexedLeaf(root, r.ns, uint64(idx), ci.DefaultLimits().MaxNodeBytes)
}
