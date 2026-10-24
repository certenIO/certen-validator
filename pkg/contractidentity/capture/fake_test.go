// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// fakeChain serves a derived H0 world as a chain: headers, the settlement transaction and receipt, and eth_getProof / eth_getCode answers
// built by walking the world's own nodes with the strict reads (the only nodes it holds are the ones the world's plan reads, so a request
// for anything else is answered like a pruned provider: missing trie node).
type fakeChain struct {
	w       *world.World
	nodes   [][]byte
	station map[uint64]string // block number -> station
	headers map[uint64]*types.Header
	tx      *types.Transaction
	rc      *types.Receipt
	codes   map[common.Address][]byte
}

func newFakeChain(t testing.TB, chain uint64, variant string) *fakeChain {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := world.Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	w, err := world.Derive(m, sp)
	if err != nil {
		t.Fatal(err)
	}
	if w.PlanErr != nil || w.CheckErr != nil {
		t.Fatalf("world %d/%s: plan %v check %v", chain, variant, w.PlanErr, w.CheckErr)
	}
	fc := &fakeChain{w: w, nodes: w.Container.Nodes, station: map[uint64]string{}, headers: map[uint64]*types.Header{}, codes: map[common.Address][]byte{}}
	add := func(name, st string, num uint64) {
		var h types.Header
		if err := rlp.DecodeBytes(w.HeaderRLP[name], &h); err != nil {
			t.Fatal(err)
		}
		if h.Hash() != w.BlockHashes[name] || h.Number.Uint64() != num {
			t.Fatalf("header %s does not round-trip", name)
		}
		fc.station[num], fc.headers[num] = st, &h
	}
	add(world.BlockSettle, world.StationSettle, sp.Blocks.Settle.Number)
	add(world.BlockAttest, world.StationPost, sp.Blocks.Attest.Number)
	add(world.BlockAttestParent, world.StationPre, sp.Blocks.AttestParent.Number)
	if sp.Link == "hops" {
		for i, b := range sp.Blocks.Between {
			add(fmt.Sprintf("between.%d", i), world.HopStation(i+1), b.Number)
		}
	}
	for _, c := range w.Container.Codes {
		fc.codes[common.Address(c.Address)] = c.Runtime
	}
	fc.tx = w.Ctx.Tx
	rl := w.Ctx.Receipt
	fc.rc = &types.Receipt{Status: uint64(rl.PostStateOrStatus[0]), Logs: rl.Logs, TxHash: fc.tx.Hash(), BlockHash: w.BlockHashes[world.BlockSettle],
		BlockNumber: new(big.Int).SetUint64(sp.Blocks.Settle.Number)}
	return fc
}

func (fc *fakeChain) request() capture.SettleRequest {
	sp := fc.w.Spec
	req := capture.SettleRequest{TxHash: fc.tx.Hash(), PKC: common.HexToHash(sp.Attestation.Blob[13]), Link: ci.LinkSpine}
	if sp.Link == "hops" {
		req.Link = ci.LinkHops
		req.HopNumbers = []uint64{sp.Blocks.Attest.Number}
		for _, b := range sp.Blocks.Between {
			req.HopNumbers = append(req.HopNumbers, b.Number)
		}
	}
	return req
}

// facts are the plan inputs of the whole leg, as the verifier derives them.
func (fc *fakeChain) facts(t testing.TB) *capture.Facts {
	t.Helper()
	m := fc.w.Manifest
	f, err := capture.DeriveFacts(m, fc.w.Spec.Chain, fc.tx, fc.rc, fc.request())
	if err != nil {
		t.Fatal(err)
	}
	f.OperationID = common.HexToHash(fc.w.Spec.Context.Batch.OperationID)
	f.TxIndex = fc.w.Container.Attest.Attest.TxIndex
	return f
}

func (fc *fakeChain) config(src capture.Source) capture.Config {
	return capture.Config{Chain: fc.w.Spec.Chain, Manifest: fc.w.Manifest, Source: src}
}

type hostile int

const (
	honest    hostile = iota
	down              // every call fails
	pruned            // "missing trie node"
	window            // "proof window" error text
	lieCode           // one byte of the code flipped
	lieSlot           // the proof of another slot under the asked key
	lieValue          // valid proofs, wrong value text
	lieBlock          // the state of another block than the one asked
	hugeReply         // an answer above MaxResponseBytes
	padNodes          // valid proofs plus nodes nobody reads
	leakyText         // errors that carry a URL with a key
)

type fakeProvider struct {
	name string
	fc   *fakeChain
	mode hostile
	mu   sync.Mutex
	// calls counts GetProof and GetCode requests.
	calls int
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *fakeProvider) fail() error {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	switch p.mode {
	case down:
		return errors.New("dial tcp: connection refused")
	case pruned:
		return errors.New("missing trie node abcdef (path ) state is not available")
	case window:
		return errors.New("proof window: requested block is older than the maximum proof window")
	case leakyText:
		return errors.New("Post https://eth.example/v2/SECRETKEY0123456789abcdef0123456789abcdef: 502 bad gateway")
	}
	return nil
}

func (fc *fakeChain) walk(root common.Hash, a common.Address, keys []common.Hash) (acct [][]byte, stor [][][]byte, vals []common.Hash, err error) {
	ns, err := ci.NewNodeSet(fc.nodes)
	if err != nil {
		return nil, nil, nil, err
	}
	acc, err := ci.ReadAccount(root, ns, a)
	if err != nil {
		return nil, nil, nil, err
	}
	acct = ns.VisitedNodes()
	for _, k := range keys {
		ns2, _ := ci.NewNodeSet(fc.nodes)
		v, err := ci.ReadSlot(acc.StorageRoot, ns2, k)
		if err != nil {
			return nil, nil, nil, err
		}
		stor, vals = append(stor, ns2.VisitedNodes()), append(vals, v)
	}
	return acct, stor, vals, nil
}

func hexList(n [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(n))
	for i := range n {
		out[i] = n[i]
	}
	return out
}

func (p *fakeProvider) GetProof(_ context.Context, a common.Address, keys []string, block string) (json.RawMessage, error) {
	if err := p.fail(); err != nil {
		return nil, err
	}
	num, err := strconv.ParseUint(strings.TrimPrefix(block, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}
	st, ok := p.fc.station[num]
	if !ok {
		return nil, fmt.Errorf("header not found: block %d", num)
	}
	if p.mode == lieBlock {
		st = world.StationPre
		if st == p.fc.station[num] {
			st = world.StationPost
		}
	}
	root := p.fc.w.StateRoots[st]
	hs := make([]common.Hash, len(keys))
	for i, k := range keys {
		hs[i] = common.HexToHash(k)
	}
	if p.mode == lieSlot && len(hs) > 0 {
		// serve the proof of the next key under the first key's name
		hs2 := append([]common.Hash(nil), hs...)
		hs2[0] = common.BigToHash(new(big.Int).Add(hs[0].Big(), big.NewInt(1)))
		hs = hs2
	}
	acct, stor, vals, err := p.fc.walk(root, a, hs)
	if err != nil {
		return nil, err
	}
	type sp struct {
		Key   string          `json:"key"`
		Value string          `json:"value"`
		Proof []hexutil.Bytes `json:"proof"`
	}
	out := struct {
		AccountProof []hexutil.Bytes `json:"accountProof"`
		StorageProof []sp            `json:"storageProof"`
	}{AccountProof: hexList(acct)}
	for i := range keys {
		v := "0x" + strings.TrimLeft(common.Bytes2Hex(vals[i][:]), "0")
		if v == "0x" {
			v = "0x0"
		}
		if p.mode == lieValue {
			v = "0x1234"
		}
		out.StorageProof = append(out.StorageProof, sp{Key: keys[i], Value: v, Proof: hexList(stor[i])})
	}
	if p.mode == padNodes {
		out.AccountProof = append(out.AccountProof, hexutil.Bytes(bytes.Repeat([]byte{0xc0}, 3)), hexutil.Bytes(append([]byte{0xf8, 0x40}, bytes.Repeat([]byte{7}, 64)...)))
	}
	raw, err := json.Marshal(out)
	if p.mode == hugeReply {
		raw = append(raw, bytes.Repeat([]byte(" "), capture.MaxResponseBytes)...)
	}
	return raw, err
}

func (p *fakeProvider) GetCode(_ context.Context, a common.Address, block string) ([]byte, error) {
	if err := p.fail(); err != nil {
		return nil, err
	}
	code, ok := p.fc.codes[a]
	if !ok {
		return nil, errors.New("no code")
	}
	out := append([]byte(nil), code...)
	if p.mode == lieCode {
		out[len(out)/2] ^= 0x01
	}
	return out, nil
}

type fakeSource struct {
	fc        *fakeChain
	providers []capture.Provider
	panicOn   string
}

func (s *fakeSource) TransactionByHash(_ context.Context, h common.Hash) (*types.Transaction, bool, error) {
	if h != s.fc.tx.Hash() {
		return nil, false, nil
	}
	return s.fc.tx, true, nil
}

func (s *fakeSource) TransactionReceipt(_ context.Context, h common.Hash) (*types.Receipt, error) {
	if h != s.fc.tx.Hash() {
		return nil, errors.New("not found")
	}
	return s.fc.rc, nil
}

func (s *fakeSource) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	if s.panicOn == "header" {
		panic("hostile header reader")
	}
	h, ok := s.fc.headers[n.Uint64()]
	if !ok {
		return nil, errors.New("not found")
	}
	return h, nil
}

func (s *fakeSource) Providers() []capture.Provider { return s.providers }

func (fc *fakeChain) source(modes ...hostile) (*fakeSource, []*fakeProvider) {
	src := &fakeSource{fc: fc}
	var ps []*fakeProvider
	for i, m := range modes {
		p := &fakeProvider{name: fmt.Sprintf("https://p%d.example", i), fc: fc, mode: m}
		ps = append(ps, p)
		src.providers = append(src.providers, p)
	}
	return src, ps
}

// attestStandIn is the attestation station's node set as the strict reads see it: the plan of the attestation block run over the world's
// nodes (E1 is WP-S8-3b; this stands in for it so that a whole container can be assembled).
type standInReader struct {
	ns     *ci.NodeSet
	roots  map[string]common.Hash
	tx, rc common.Hash
	codes  map[common.Address][]byte
	accts  map[string]ci.AccountState
}

func (r *standInReader) Account(st string, a common.Address) (ci.AccountState, error) {
	acc, err := ci.ReadAccount(r.roots[st], r.ns, a)
	if err == nil {
		r.accts[st+a.Hex()] = acc
	}
	return acc, err
}
func (r *standInReader) Slot(st string, a common.Address, s common.Hash) (common.Hash, error) {
	return ci.ReadSlot(r.accts[st+a.Hex()].StorageRoot, r.ns, s)
}
func (r *standInReader) Indexed(kind string, i uint32) ([]byte, error) {
	root := r.tx
	if kind == "receipt" {
		root = r.rc
	}
	return ci.ReadIndexedLeaf(root, r.ns, uint64(i), ci.DefaultLimits().MaxNodeBytes)
}
func (r *standInReader) Code(st string, a common.Address) ([]byte, error) {
	if !r.accts[st+a.Hex()].HasCode() {
		return nil, nil
	}
	return r.codes[a], nil
}

func (fc *fakeChain) attestPart(t testing.TB) *capture.AttestPart {
	t.Helper()
	ns, err := ci.NewNodeSet(fc.nodes)
	if err != nil {
		t.Fatal(err)
	}
	ap := fc.w.Container.Attest.Attest
	hv := fc.headers[fc.w.Spec.Blocks.Attest.Number]
	r := &standInReader{ns: ns, roots: map[string]common.Hash{world.StationPre: fc.w.StateRoots[world.StationPre], world.StationPost: fc.w.StateRoots[world.StationPost]},
		tx: hv.TxHash, rc: hv.ReceiptHash, codes: fc.codes, accts: map[string]ci.AccountState{}}
	for i := range fc.w.Spec.Blocks.Between {
		r.roots[world.HopStation(i+1)] = fc.w.StateRoots[world.HopStation(i+1)]
	}
	if pending, err := capture.RunAttest(r, fc.facts(t)); err != nil || pending {
		t.Fatalf("attest stand-in: pending %v err %v", pending, err)
	}
	return &capture.AttestPart{Proof: ap, Nodes: sortedHash(ns.VisitedNodes())}
}

func sortedHash(nodes [][]byte) [][]byte {
	out := append([][]byte(nil), nodes...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(crypto.Keccak256(out[j-1]), crypto.Keccak256(out[j])) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
