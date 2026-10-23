// Copyright 2026 Certen Protocol

package world

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The read plan: every proof read of steps 5-22 for the world, in the roots settle, attest_pre, attest_post and hop:<i>, with the reads that
// depend on a proven value (the validators, the key bytes, the hop slots) taken from that value. Step 22b says the container's NODES are
// exactly the nodes these reads visit. One plan serves two readers: the build reader proves each read against the tries and collects the path
// nodes (that union IS the container's node list), and the check reader re-runs the SAME plan with the strict reads of the contractidentity
// package over the container's nodes and requires that nothing is missing and nothing is left unvisited.
type reader interface {
	account(station string, a common.Address) (ci.AccountState, error)
	slot(station string, a common.Address, s common.Hash) (common.Hash, error)
	indexed(block, kind string, idx int) ([]byte, error) // kind tx | receipt
}

type planner struct {
	rd  reader
	err error
}

func (p *planner) account(st string, a common.Address) ci.AccountState {
	if p.err != nil {
		return ci.AccountState{}
	}
	acc, err := p.rd.account(st, a)
	if err != nil {
		p.err = fmt.Errorf("%s account %s: %w", st, a.Hex(), err)
	}
	return acc
}

func (p *planner) slot(st string, a common.Address, s common.Hash) common.Hash {
	if p.err != nil {
		return common.Hash{}
	}
	v, err := p.rd.slot(st, a, s)
	if err != nil {
		p.err = fmt.Errorf("%s slot %s of %s: %w", st, s.Hex(), a.Hex(), err)
	}
	return v
}

// dyn reads a bytes/string variable by the step 6 rule.
func (p *planner) dyn(st string, a common.Address, slot common.Hash, max uint64) []byte {
	head := p.slot(st, a, slot)
	if p.err != nil {
		return nil
	}
	h, err := ci.ParseDynHead(head, max)
	if err != nil {
		p.err = fmt.Errorf("%s slot %s of %s: %w", st, slot.Hex(), a.Hex(), err)
		return nil
	}
	var words []common.Hash
	for i := uint64(0); i < h.DynWordCount(); i++ {
		words = append(words, p.slot(st, a, ci.DynDataSlot(slot, i)))
	}
	if p.err != nil {
		return nil
	}
	out, err := h.Assemble(words)
	if err != nil {
		p.err = err
	}
	return out
}

func (p *planner) word(w common.Hash, kind string) uint64 {
	v, err := ci.WordUint64(w)
	if err != nil && p.err == nil {
		p.err = fmt.Errorf("%s: %w", kind, err)
	}
	return v
}

func (p *planner) addr(w common.Hash, kind string) common.Address {
	a, err := ci.WordAddress(w)
	if err != nil && p.err == nil {
		p.err = fmt.Errorf("%s: %w", kind, err)
	}
	return a
}

type planIDs struct {
	A, V, G, F, acct, O, hist       common.Address
	anchorID, opID, pkc, leaf, book common.Hash
	page                            uint64
	adiURL                          string
}

func (d *derived) ids() (planIDs, error) {
	sp := d.sp
	var ids planIDs
	var err error
	for _, r := range []struct {
		s string
		d *common.Address
	}{{sp.Roles.Anchor, &ids.A}, {sp.Roles.Verifier, &ids.V}, {sp.Roles.Groth16, &ids.G}, {sp.Roles.Factory, &ids.F}, {sp.Roles.Account, &ids.acct}, {sp.Roles.Owner, &ids.O}, {sp.Roles.History, &ids.hist}} {
		if *r.d, err = parseAddr(r.s); err != nil {
			return ids, err
		}
	}
	if ids.anchorID, err = parseHash(sp.Settlement.AnchorID); err != nil {
		return ids, err
	}
	if ids.opID, err = parseHash(sp.Context.Batch.OperationID); err != nil {
		return ids, err
	}
	if len(sp.Attestation.Blob) != 18 {
		return ids, fmt.Errorf("the attestation blob has %d words, not 18", len(sp.Attestation.Blob))
	}
	if ids.pkc, err = parseHash(sp.Attestation.Blob[13]); err != nil {
		return ids, err
	}
	if ids.leaf, err = parseHash(sp.Settlement.Leaf); err != nil {
		return ids, err
	}
	if ids.book, err = parseHash(sp.Settlement.AuthorityBook); err != nil {
		return ids, err
	}
	ids.page, ids.adiURL = sp.Settlement.AuthorityPage, sp.Context.ADIURL
	return ids, nil
}

// authSet reads the AUTH slot set (the frozen table: rows A01-A21, V01-V03, C01) at one station.
func (p *planner) authSet(st string, ids planIDs, flip bool) {
	for _, a := range []common.Address{ids.A, ids.V, ids.G, ids.O} {
		p.account(st, a)
	}
	rec := ci.MappingSlotAt(ci.KeyBytes32(ids.anchorID), 1)
	for k := uint64(0); k < 13; k++ { // A02: all 13 words of anchors[anchorId]
		p.slot(st, ids.A, ci.MemberSlot(rec, k))
	}
	for _, s := range []common.Hash{ci.SlotIndex(0), ci.MappingSlotAt(ci.KeyBytes32(ids.anchorID), 2), ci.MappingSlotAt(ci.KeyBytes32(ids.anchorID), 3),
		ci.MappingSlotAt(ci.KeyBytes32(ids.pkc), 4), ci.SlotIndex(5), ci.SlotIndex(6)} {
		p.slot(st, ids.A, s)
	}
	n := p.word(p.slot(st, ids.A, ci.SlotIndex(13)), "validatorList length")
	if p.err == nil && n > uint64(ci.DefaultLimits().MaxValidators) {
		p.err = fmt.Errorf("validatorList has %d entries, limit %d", n, ci.DefaultLimits().MaxValidators)
	}
	for i := uint64(0); i < n && p.err == nil; i++ {
		el, _, _ := ci.ArrayElementSlot(13, i, 20)
		v := p.addr(p.slot(st, ids.A, el), "validatorList element")
		base := ci.MappingSlotAt(ci.KeyAddress(v), 12)
		p.slot(st, ids.A, base)
		p.slot(st, ids.A, ci.MemberSlot(base, 1))
		p.dyn(st, ids.A, ci.MemberSlot(base, 2), 256)
		p.slot(st, ids.A, ci.MemberSlot(base, 3))
	}
	for _, s := range []uint64{14, 15, 16, 17, 27, 29, 30} {
		p.slot(st, ids.A, ci.SlotIndex(s))
	}
	if flip {
		p.slot(st, ids.A, ci.MappingSlotAt(ci.KeyBytes32(ids.opID), 18))
	}
	for _, s := range []uint64{0, 1, 2} {
		p.slot(st, ids.V, ci.SlotIndex(s))
	}
}

func (d *derived) runPlan(rd reader) error {
	ids, err := d.ids()
	if err != nil {
		return err
	}
	p := &planner{rd: rd}
	sp := d.sp
	// ---- settle (steps 5-14) ----
	p.account(StationSettle, ids.acct)
	adi := p.dyn(StationSettle, ids.acct, ci.SlotIndex(0), uint64(ci.DefaultLimits().MaxString))
	book := p.dyn(StationSettle, ids.acct, ci.SlotIndex(11), uint64(ci.DefaultLimits().MaxString))
	p.account(StationSettle, ids.F)
	p.slot(StationSettle, ids.F, ci.MappingSlotAt(ci.KeyAddress(ids.acct), 2))
	if p.err == nil {
		enc, e := abiPack([]string{"string", "string"}, string(adi), string(book))
		if e != nil {
			return e
		}
		p.slot(StationSettle, ids.F, ci.MappingSlotAt(ci.KeyBytes32(common.BytesToHash(crypto.Keccak256(enc))), 3))
	}
	p.slot(StationSettle, ids.acct, ci.SlotIndex(2))
	p.authSet(StationSettle, ids, false)
	for _, l := range sp.Settlement.Legs { // step 14
		p.slot(StationSettle, ids.acct, ci.PageSlot(10, ids.book, ids.page))
		p.slot(StationSettle, ids.acct, ci.PageSlot(9, ids.book, ids.page))
		data, e := parseHex(l.Data)
		if e != nil {
			return e
		}
		var sel [4]byte
		if len(data) >= 4 {
			copy(sel[:], data[:4])
		}
		p.slot(StationSettle, ids.acct, ci.MappingSlotAt(ci.KeyBytes4(sel), 8))
	}
	// ---- the attestation block: both stations, the transaction and the receipt ----
	p.authSet(StationPre, ids, true)
	p.authSet(StationPost, ids, true)
	ai := d.bAtt.txIndex["attestation"]
	for _, kind := range []string{"tx", "receipt"} {
		if p.err != nil {
			break
		}
		if _, e := rd.indexed(BlockAttest, kind, ai); e != nil {
			p.err = fmt.Errorf("attestation %s: %w", kind, e)
		}
	}
	// ---- link 1: the EIP-2935 ring at every hop ----
	if sp.Link == "hops" {
		nums := []uint64{d.bAtt.spec.Number}
		for _, b := range d.between {
			nums = append(nums, b.spec.Number)
		}
		e, _ := d.m.EIP2935(sp.Chain)
		for i := 0; i <= len(d.between); i++ {
			st := StationSettle
			if i < len(d.between) {
				st = HopStation(i + 1)
			}
			p.account(st, ids.hist)
			p.slot(st, ids.hist, wordU(nums[i]%e.Window))
		}
	}
	return p.err
}

// ---- the build reader: proves each read against the tries and collects the path nodes ----

type buildReader struct {
	d    *derived
	seen map[common.Hash][]byte
}

func (b *buildReader) add(nodes [][]byte) {
	for _, n := range nodes {
		b.seen[common.BytesToHash(crypto.Keccak256(n))] = n
	}
}

func (b *buildReader) account(st string, a common.Address) (ci.AccountState, error) {
	bs := b.d.states[st]
	if bs == nil {
		return ci.AccountState{}, fmt.Errorf("no state for station %s", st)
	}
	var col collector
	if err := bs.tr.Prove(crypto.Keccak256(a[:]), &col); err != nil {
		return ci.AccountState{}, err
	}
	b.add(col.nodes)
	ba := bs.accts[a]
	if ba == nil {
		return ci.AccountState{Balance: common.Big0, StorageRoot: types.EmptyRootHash}, nil
	}
	return ci.AccountState{Exists: true, Nonce: ba.nonce, Balance: ba.balance, StorageRoot: ba.root, CodeHash: ba.codeHash}, nil
}

func (b *buildReader) slot(st string, a common.Address, s common.Hash) (common.Hash, error) {
	bs := b.d.states[st]
	ba := bs.accts[a]
	if ba == nil || len(ba.storage) == 0 {
		return common.Hash{}, nil
	}
	var col collector
	if err := ba.sto.Prove(crypto.Keccak256(s[:]), &col); err != nil {
		return common.Hash{}, err
	}
	b.add(col.nodes)
	return ba.storage[s], nil
}

func (b *buildReader) indexed(block, kind string, idx int) ([]byte, error) {
	blk := b.d.bAtt
	if block != BlockAttest {
		return nil, fmt.Errorf("no indexed reads for block %s", block)
	}
	tr, vals := blk.txTrie, blk.wires
	if kind == "receipt" {
		tr, vals = blk.rcTrie, blk.receipts
	}
	key := mustIndexKey(idx)
	var col collector
	if err := tr.Prove(key, &col); err != nil {
		return nil, err
	}
	b.add(col.nodes)
	return vals[idx], nil
}

// ---- the check reader: the strict reads of the contractidentity package over the container's nodes ----

type checkReader struct {
	d     *derived
	ns    *ci.NodeSet
	accts map[string]ci.AccountState
}

func (c *checkReader) account(st string, a common.Address) (ci.AccountState, error) {
	root, err := c.d.headerStateRoot(st)
	if err != nil {
		return ci.AccountState{}, err
	}
	acc, err := ci.ReadAccount(root, c.ns, a)
	if err == nil {
		c.accts[st+"/"+a.Hex()] = acc
	}
	return acc, err
}

func (c *checkReader) slot(st string, a common.Address, s common.Hash) (common.Hash, error) {
	acc, ok := c.accts[st+"/"+a.Hex()]
	if !ok {
		return common.Hash{}, fmt.Errorf("slot read before the account read of %s", a.Hex())
	}
	return ci.ReadSlot(acc.StorageRoot, c.ns, s)
}

func (c *checkReader) indexed(block, kind string, idx int) ([]byte, error) {
	blk := c.d.bAtt
	root := blk.header.TxHash
	want := blk.wires
	if kind == "receipt" {
		root, want = blk.header.ReceiptHash, blk.receipts
	}
	// the strict walk is under the HEADER's root: a forged header root fails here, as it does in the verifier
	got, err := ci.ReadIndexedLeaf(root, c.ns, uint64(idx), ci.DefaultLimits().MaxNodeBytes)
	if err != nil {
		return nil, err
	}
	if string(got) != string(want[idx]) {
		return nil, fmt.Errorf("the %s leaf under the header root is not the carried leaf", kind)
	}
	return got, nil
}
