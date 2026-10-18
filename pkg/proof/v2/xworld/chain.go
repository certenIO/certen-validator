// Copyright 2026 Certen Protocol
//
// The certify chain of a world (RB9-F5): the minor-root items between the last major block and the certified anchor, each either
// continuous (a root proof from the previous root) or anchored (no root proof; a link, a Merkle receipt from the previous root to the
// item's own, travels in the evidence's links member). Options.Chain is nil for every earlier suite, which keeps its single continuous item
// and its bytes.

package xworld

import (
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Update kinds of a chain item.
const (
	// UpdateOracle is a write to acc://dn.acme/oracle: an update the walk neither applies nor accounts for (it does not touch the validator
	// set), which makes its item update-bearing.
	UpdateOracle = "oracle"
	// UpdateGlobals is a write to acc://dn.acme/globals of the genesis content: an update the walk applies and records.
	UpdateGlobals = "globals"
	// UpdateGenesisGlobals is a write to acc://dn.acme/globals of the genesis content whose transaction header carries the item's label as
	// its memo, so every item's write is a distinct transaction: an update the walk applies and records (the globals stay what they were),
	// which gives its item an effect.
	UpdateGenesisGlobals = "globals-genesis"
)

// ChainItem shapes one minor-root item.
type ChainItem struct {
	// Anchored: no root proof; the item's link is carried in the evidence's links member.
	Anchored bool
	// Update, when not empty, is the kind of the one transaction the item carries, written Repeat times (0 or 1: once); Repeat 2 is a
	// duplicated update.
	Update string
	Repeat int
	// Block overrides the item's Directory minor block (0: 110 + 10 x position).
	Block uint64
}

// Chain is the certify chain: Items, then the item the certified root closes (Final; its Block is the world's, 300, and is not overridden).
type Chain struct {
	Items []ChainItem
	Final ChainItem
	// Hops are the set check's items (check.hops): its own walk from the checkpoint, ending at a block at or after 300 whose state root holds
	// the proven network accounts. Empty: the set is checked at the certified block, as in every earlier suite.
	Hops []ChainItem
}

func updateTx(kind string, globals []byte, label string) (*protocol.Transaction, []byte) {
	var principal = protocol.DnUrl().JoinPath(protocol.Oracle)
	data := seed("oracle write")
	memo := ""
	if kind == UpdateGlobals || kind == UpdateGenesisGlobals {
		principal = protocol.DnUrl().JoinPath(protocol.Globals)
		data = globals
	}
	if kind == UpdateGenesisGlobals {
		memo = label
	}
	tx := &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: principal, Memo: memo},
		Body:   &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{data}}},
	}
	return tx, tx.GetHash()
}

// itemEntry returns the item's tree entry e (its root is h2(prev, e)) and the updates it carries, each with a receipt that ends at the
// item's root.
func itemEntry(it ChainItem, label string, prev, globals []byte) ([]byte, []*api.NetworkUpdateProof) {
	if it.Update == "" {
		return seed(label + " entry"), nil
	}
	tx, txh := updateTx(it.Update, globals, label)
	sib := seed(label + " update sibling")
	n := max(it.Repeat, 1)
	var ups []*api.NetworkUpdateProof
	for i := 0; i < n; i++ {
		ups = append(ups, &api.NetworkUpdateProof{Transaction: tx, Receipt: rcpt(txh, step{true, sib}, step{false, prev})})
	}
	return h2(txh, sib), ups
}

func (c *Chain) record(it ChainItem, prev, e []byte, ups []*api.NetworkUpdateProof, block uint64, root, state [32]byte, v []validator) (*api.MinorRootRecord, *merkle.Receipt) {
	anchor := directoryAnchor(block, root, state)
	rec := &api.MinorRootRecord{Anchor: anchor, Signatures: signAnchor(anchor, v[0], v[1], v[2]), Updates: ups}
	if it.Anchored {
		return rec, rcpt(prev, step{true, e})
	}
	rec.RootProof = &merkle.ReceiptList{MerkleState: &merkle.State{Count: 1, Pending: [][]byte{prev}}, Elements: [][]byte{e}, Receipt: rcpt(e, step{false, prev})}
	return rec, nil
}

// build returns the records and links of Items and the root they end at (the root the final item starts from).
func (c *Chain) build(start, globals []byte, v []validator) (recs []string, links []string, base []byte) {
	prev := start
	for j, it := range c.Items {
		label := "chain item " + string(rune('a'+j))
		e, ups := itemEntry(it, label, prev, globals)
		root := h2(prev, e)
		block := it.Block
		if block == 0 {
			block = uint64(110 + 10*j)
		}
		rec, link := c.record(it, prev, e, ups, block, a32(root), a32(seed(label+" state")), v)
		recs = append(recs, hexs(must(rec.MarshalBinary())))
		if link != nil {
			links = append(links, rcptHex(link))
		}
		prev = root
	}
	return recs, links, prev
}

// final returns the closing record, and its link when it is anchored. q is the tree root the certified root commits beside base. The
// closing item carries no update (an update's receipt would have to end at the certified root, which the world's fixed tree fixes).
func (c *Chain) final(base, q []byte, cert, state [32]byte, v []validator) (string, string) {
	if c.Final.Update != "" {
		panic("xworld: the closing item of a chain carries no update")
	}
	rec, link := c.record(c.Final, base, q, nil, dnBlockCert, cert, state, v)
	if link != nil {
		return hexs(must(rec.MarshalBinary())), rcptHex(link)
	}
	return hexs(must(rec.MarshalBinary())), ""
}

// UpdateTxHash is the hash (hex) of the transaction an update of the given kind carries in a world whose genesis globals record is
// globals (Built.Inputs.GlobalsRecord).
func UpdateTxHash(kind string, globals []byte) string {
	_, h := updateTx(kind, globals, "")
	return hexs(h)
}

// ForeignItem is a validly signed Directory anchor and anchored record of ANOTHER chain, with the link that is valid inside that chain: it
// starts at start (the world's own verified root when the caller wants a link that starts where the verifier stands, otherwise a root of the
// other chain) and ends at the record's root chain anchor. otherSet signs it with a validator set the world's genesis does not hold (a
// chain of another incarnation); otherwise it is signed by the world's own validators, so only its continuity is wrong.
func ForeignItem(start []byte, block uint64, otherSet bool) (record, link string) {
	if start == nil {
		start = seed("foreign chain root")
	}
	e := seed("foreign chain entry")
	root := h2(start, e)
	v := []validator{newValidator(1), newValidator(2), newValidator(3)}
	if otherSet {
		v = []validator{newValidator(11), newValidator(12), newValidator(13)}
	}
	anchor := directoryAnchor(block, a32(root), a32(seed("foreign chain state")))
	rec := &api.MinorRootRecord{Anchor: anchor, Signatures: signAnchor(anchor, v[0], v[1], v[2]),
		Updates: foreignUpdates()}
	return hexs(must(rec.MarshalBinary())), rcptHex(rcpt(start, step{true, e}))
}

// foreignUpdates is empty: the foreign item stands for a closing item, which needs no update.
func foreignUpdates() []*api.NetworkUpdateProof { return nil }

// GenesisRoot is the root the world's first major block closes at: the root every chain of the world starts from.
func GenesisRoot() []byte { return seed("root 1") }

// buildHops returns the records and links of Hops: the set check's own walk from the checkpoint (the root of the first major block) to a
// certified block at or after the certified one, whose state root is the one the network and globals accounts are proven into. The last
// hop is the last item of its sequence.
func (c *Chain) buildHops(start, globals []byte, state [32]byte, v []validator) (recs []string, links []string) {
	prev := start
	for j, it := range c.Hops {
		label := "hop item " + string(rune('a'+j))
		e, ups := itemEntry(it, label, prev, globals)
		root := h2(prev, e)
		block := it.Block
		if block == 0 {
			block = uint64(310 + 10*j)
		}
		rec, link := c.record(it, prev, e, ups, block, a32(root), state, v)
		recs = append(recs, hexs(must(rec.MarshalBinary())))
		if link != nil {
			links = append(links, rcptHex(link))
		}
		prev = root
	}
	return recs, links
}
