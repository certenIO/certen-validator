// Copyright 2026 Certen Protocol
//
// The timeline world of the evidence 2.1 conformance suite (docs/proof/G1_CROSS_PARTITION.md D3, RB9 Phase C1b-1): the three-partition
// world of world.go with a REAL transaction, a key page (BVN2's BankPage1) whose history is a scripted run of key-page transactions
// folded into its proven main chain, a signature chain whose index chain places the vote's key signature in the block it arrived in,
// and, when scripted, the production of the vote in BVN2's synthetic ledger. Every hash, index entry, receipt and signature is built
// from fixed seeds so the documents are reproducible; the page the verifier proves at B_Y is computed here by the script's own
// bookkeeping (add, remove, threshold, version), not by the verifier's replay, so the two are independent.
package xworld

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Timeline scripts BankPage1's history and the signatures recorded on it. The zero value is the valid world: genesis with key K0 at
// block 10, one signature by K0 at signer version 1 in block 65, nothing after.
type Timeline struct {
	// Genesis keys (labels "K0".."K3"); empty means K0.
	Genesis []string
	// Events are the page's transactions after genesis, in order, each in the given block (ascending, after 10 and before BlockBVN2).
	Events []PageEvent
	// Sigs are the key signatures recorded on the page for the transaction, in chain order (ascending blocks); the last is the one
	// that completed the page's vote and so the vote's cause (the hop), the rest are carried as counted. Empty means one signature by K0 at version 1 in block HopBlock.
	Sigs []SigEvent
	// ProduceBlock, when non-zero, places the vote's SequencedMessage in BVN2's synthetic ledger in that block, and the evidence
	// carries the production proof (Vote.Produced). Zero carries none.
	ProduceBlock uint64
	// OmitTransaction carries no transaction in the evidence.
	OmitTransaction bool
	// Delegated casts the vote through a delegation (timeline_delegated.go): BankPage2 delegates to the delegate book, the key signature
	// is recorded on DelePage1 (BVN3, block KeyBlock, default 64) and the delegate's authority signature on BankPage2 (BVN2, block
	// AuthBlock, default 66). Sigs, Genesis and Events then describe nothing (BankPage1 holds no signature); DelegatorEvents are
	// BankPage2's transactions after genesis.
	Delegated       bool
	DelegatorEvents []PageEvent
	AuthBlock       uint64
	KeyBlock        uint64
	// ProvenHeadKeys, when set, are the key labels the proven page holds although the history says otherwise.
	ProvenHeadKeys []string

	// HeaderAuthority, when set, is an authority URL the transaction's header names (Header.Authorities): the transaction then requires its
	// vote, and its book and pages are header-authority pages (RB9 Phase C1b-2). The valid use names a book that voted (BankBook).
	HeaderAuthority string
	// Initiate makes the last scripted signature the one that initiated the transaction: Header.Initiator is that signature's metadata
	// hash, as the signing builder sets it (RB9 Phase C1b-2). Not combined with Delegated.
	Initiate bool
	// LedgerVersion, when non-zero, proves the transaction partition's system ledger at its block with this executor version
	// (protocol.ExecutorVersion, e.g. 6 for Baikonur): the document then proves the version in force (RB9 Phase C1b-2).
	LedgerVersion uint64

	// Body, when set, is the governed transaction's body (default: a WriteData to the principal). It is a body of any type: the world
	// builds the same document around it (RB9 verifier round VA).
	Body protocol.TransactionBody
	// BindSequenced makes the vote's production a real SequencedMessage (RB9 verifier round VA, DEF-4): the vote is the
	// SignatureMessage of an authority signature, the SequencedMessage wrapping it (source the authority's partition, destination the
	// transaction's, Number voteNumber) is the synthetic ledger's entry, and the production carries the message. Needs ProduceBlock.
	BindSequenced bool
	// HoldUntil, when non-zero, makes the transaction a held one (Header.HoldUntil.MinorBlock).
	HoldUntil uint64
}

// PageEvent is one transaction on the page's main chain.
type PageEvent struct {
	Block     uint64
	Add       []string // key labels added
	Remove    []string // key labels removed
	Threshold uint64   // 0: unchanged
	Credits   bool     // a BurnCredits (no effect on the authority) instead of an UpdateKeyPage

	RemoveDelegate bool // (delegated world) remove the page's delegate entry
}

// SigEvent is one key signature recorded on the page's signature chain for the transaction.
type SigEvent struct {
	Key     string
	Version uint64
	Block   uint64
}

type keyMat struct {
	priv ed25519.PrivateKey
	pub  []byte
	hash []byte
}

func keyOf(label string) keyMat {
	priv := ed25519.NewKeyFromSeed(seed("timeline key " + label))
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return keyMat{priv: priv, pub: pub, hash: h[:]}
}

func sortedKeys(labels []string) [][]byte {
	var out [][]byte
	for _, l := range labels {
		out = append(out, keyOf(l).hash)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// namedChain is a chain of an account: its name and entries.
type namedChain struct {
	name    string
	entries [][]byte
}

// foldState folds entries into the merkle state the chain holds.
func foldState(entries [][]byte) *merkle.State {
	st := new(merkle.State)
	for _, e := range entries {
		st.AddEntry(e)
	}
	return st
}

func chainRootOf(c namedChain) proof.ChainRoot {
	st := foldState(c.entries)
	var pending []*string
	for _, p := range st.Pending {
		if p == nil {
			pending = append(pending, nil)
			continue
		}
		s := hexs(p)
		pending = append(pending, &s)
	}
	for len(pending) > 0 && pending[len(pending)-1] == nil {
		pending = pending[:len(pending)-1]
	}
	return proof.ChainRoot{Name: c.name, Count: uint64(len(c.entries)), Pending: pending, Anchor: hexs(st.Anchor())}
}

// subtree hashes the perfect subtree of 2^h entries starting at start.
func subtree(entries [][]byte, start, h uint64) []byte {
	if h == 0 {
		return entries[start]
	}
	return h2(subtree(entries, start, h-1), subtree(entries, start+1<<(h-1), h-1))
}

// entryReceipt builds the receipt of entries[i] in the chain of all entries, in Accumulate's shape: the path inside the perfect
// subtree holding the entry, then the smaller peaks combined (to the right), then each larger peak (to the left).
func entryReceipt(entries [][]byte, i int) *merkle.Receipt {
	n := uint64(len(entries))
	var heights []uint64
	for h := 63; h >= 0; h-- {
		if n>>uint(h)&1 == 1 {
			heights = append(heights, uint64(h))
		}
	}
	start := uint64(0)
	peakHash := make([][]byte, len(heights))
	peakStart := make([]uint64, len(heights))
	for j, h := range heights {
		peakStart[j] = start
		peakHash[j] = subtree(entries, start, h)
		start += 1 << h
	}
	for j, h := range heights {
		if uint64(i) >= peakStart[j]+1<<h {
			continue
		}
		off := uint64(i) - peakStart[j]
		var steps []step
		for l := uint64(0); l < h; l++ {
			sib := subtree(entries, peakStart[j]+((off>>l)^1)<<l, l)
			steps = append(steps, step{right: off>>l&1 == 0, hash: sib})
		}
		if j < len(heights)-1 {
			acc := peakHash[len(heights)-1]
			for k := len(heights) - 2; k > j; k-- {
				acc = h2(peakHash[k], acc)
			}
			steps = append(steps, step{right: true, hash: acc})
		}
		for k := j - 1; k >= 0; k-- {
			steps = append(steps, step{right: false, hash: peakHash[k]})
		}
		r := rcpt(entries[i], steps...)
		if want := foldState(entries).Anchor(); !bytes.Equal(r.Anchor, want) {
			panic("xworld: the receipt built for a chain entry does not end at the chain's anchor")
		}
		return r
	}
	panic("xworld: entry out of range")
}

// indexEntry is the 32-byte index chain entry the executor writes (addIndexChainEntry: the binary encoding padded with a fake field).
func indexEntry(source, anchor, block uint64) []byte {
	b := must((&protocol.IndexEntry{Source: source, Anchor: anchor, BlockIndex: block}).MarshalBinary())
	pad := make([]byte, 32-len(b))
	pad[0] = 32
	return append(b, pad...)
}

// indexFor builds the index chain of a chain whose entry i was written in blocks[i] (non-decreasing): one entry per block.
func indexFor(blocks []uint64) [][]byte {
	var out [][]byte
	for i := 0; i < len(blocks); i++ {
		if i+1 < len(blocks) && blocks[i+1] == blocks[i] {
			continue
		}
		out = append(out, indexEntry(uint64(i), uint64(len(out)+1), blocks[i]))
	}
	return out
}

// arrivalFor builds the arrival proof of entries[i] of a chain with index chain idx (built by indexFor over blocks).
func arrivalFor(idx [][]byte, blocks []uint64, i int) proofv2.Arrival {
	k := -1
	for j := range idx {
		e := new(protocol.IndexEntry)
		must(0, e.UnmarshalBinary(idx[j]))
		if e.Source >= uint64(i) {
			k = j
			break
		}
	}
	if k < 0 {
		panic("xworld: no index entry covers the chain entry")
	}
	proof1 := func(j int) proofv2.IndexProof {
		return proofv2.IndexProof{Position: uint64(j), Entry: hexs(idx[j]), Receipt: rcptHex(entryReceipt(idx, j))}
	}
	a := proofv2.Arrival{At: proof1(k)}
	if k > 0 {
		b := proof1(k - 1)
		a.Before = &b
	}
	return a
}

// timelineWorld is the scripted BankPage1 and everything the evidence carries about it.
type timelineWorld struct {
	t          Timeline
	txn        *protocol.Transaction
	txHash     []byte
	page       *protocol.KeyPage
	pageAcct   acct
	pageChains []namedChain
	history    *proofv2.PageHistory
	sigMsgs    [][]byte
	sigSigs    []protocol.Signature
	sigIdx     [][]byte
	sigBlkAll  []uint64
	sigEntries [][]byte
	sigPos     []int
	synth      *acct
	synthMsg   []byte
	synthPos   int
	synthIdx   [][]byte
	synthBlks  []uint64
	synthEnt   [][]byte
	dw         *delegatedWorld
	// BindSequenced: the vote message (the SignatureMessage's hash) and the SequencedMessage wrapping it, binary.
	voteMsg []byte
	seqRaw  []byte
}

func (t Timeline) withDefaults() Timeline {
	if len(t.Genesis) == 0 {
		t.Genesis = []string{"K0"}
	}
	if len(t.Sigs) == 0 {
		t.Sigs = []SigEvent{{Key: "K0", Version: 1, Block: HopBlock}}
	}
	return t
}

func newTimelineWorld(spec Timeline) *timelineWorld {
	t := spec.withDefaults()
	w := &timelineWorld{t: t}

	// The governed transaction: a WriteData to the principal.
	w.txn = &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: mustURL(Principal), Memo: "timeline world"},
		Body:   &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("timeline world")}}},
	}
	if t.Body != nil {
		w.txn.Body = t.Body
	}
	if t.HoldUntil != 0 {
		w.txn.Header.HoldUntil = &protocol.HoldUntilOptions{MinorBlock: t.HoldUntil}
	}
	if t.HeaderAuthority != "" {
		w.txn.Header.Authorities = append(w.txn.Header.Authorities, mustURL(t.HeaderAuthority))
	}
	if t.Initiate {
		if t.Delegated {
			panic("xworld: Initiate does not combine with Delegated")
		}
		last := t.Sigs[len(t.Sigs)-1]
		k := keyOf(last.Key)
		s := must(new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(mustURL(BankPage1)).SetVersion(last.Version).SetTimestamp(1700000000000).SetPrivateKey(k.priv).Sign(make([]byte, 32)))
		copy(w.txn.Header.Initiator[:], s.Metadata().Hash())
	}
	w.txHash = w.txn.GetHash()
	if t.Delegated {
		w.dw = newDelegatedWorld(t, w.txn, w.txHash)
		w.addSynth()
		return w
	}

	// The page's history and the page it leads to, by the script's own bookkeeping.
	genKeys := map[string]bool{}
	var specs []*protocol.KeySpecParams
	for _, l := range t.Genesis {
		genKeys[l] = true
		specs = append(specs, &protocol.KeySpecParams{KeyHash: keyOf(l).hash})
	}
	genesis := &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(BankBook), Memo: "genesis of the page"}, Body: &protocol.CreateKeyPage{Keys: specs}}
	txns := []*protocol.Transaction{genesis}
	blocks := []uint64{10}
	var held []string
	held = append(held, t.Genesis...)
	version, threshold := uint64(1), uint64(1)
	for n, e := range t.Events {
		if e.Credits {
			txns = append(txns, &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(BankPage1), Memo: fmt.Sprintf("event %d", n)}, Body: &protocol.BurnCredits{Amount: 1}})
			blocks = append(blocks, e.Block)
			continue
		}
		var ops []protocol.KeyPageOperation
		for _, l := range e.Add {
			ops = append(ops, &protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyOf(l).hash}})
			held = append(held, l)
		}
		for _, l := range e.Remove {
			ops = append(ops, &protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyOf(l).hash}})
			for i, x := range held {
				if x == l {
					held = append(held[:i:i], held[i+1:]...)
					break
				}
			}
		}
		if e.Threshold != 0 {
			ops = append(ops, &protocol.SetThresholdKeyPageOperation{Threshold: e.Threshold})
			threshold = e.Threshold
		}
		if threshold > uint64(len(held)) {
			threshold = uint64(len(held))
		}
		version++
		txns = append(txns, &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(BankPage1), Memo: fmt.Sprintf("event %d", n)}, Body: &protocol.UpdateKeyPage{Operation: ops}})
		blocks = append(blocks, e.Block)
	}
	headKeys := held
	if len(t.ProvenHeadKeys) > 0 {
		headKeys = t.ProvenHeadKeys
	}
	w.page = &protocol.KeyPage{Url: mustURL(BankPage1), Version: version, AcceptThreshold: threshold}
	for _, h := range sortedKeys(headKeys) {
		w.page.Keys = append(w.page.Keys, &protocol.KeySpec{PublicKeyHash: h})
	}

	var mainEntries [][]byte
	w.history = &proofv2.PageHistory{}
	for _, tx := range txns {
		mainEntries = append(mainEntries, tx.GetHash())
		w.history.Entries = append(w.history.Entries, proofv2.HistoryEntry{Transaction: hexs(must(tx.MarshalBinary()))})
	}
	mainIdx := indexFor(blocks)
	for _, e := range mainIdx {
		w.history.Index = append(w.history.Index, hexs(e))
	}

	// The signature chain: two earlier messages in block 30, the scripted signatures, one later message in block 69.
	w.sigEntries = [][]byte{seed("earlier hop a"), seed("earlier hop b")}
	w.sigBlkAll = []uint64{30, 30}
	for _, s := range t.Sigs {
		k := keyOf(s.Key)
		sig := must(new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(mustURL(BankPage1)).SetVersion(s.Version).SetTimestamp(1700000000000).SetPrivateKey(k.priv).Sign(w.txHash))
		msg := (&messaging.SignatureMessage{Signature: sig, TxID: w.txn.ID()}).Hash()
		w.sigPos = append(w.sigPos, len(w.sigEntries))
		w.sigEntries = append(w.sigEntries, msg[:])
		w.sigBlkAll = append(w.sigBlkAll, s.Block)
		w.sigSigs = append(w.sigSigs, sig)
	}
	w.sigEntries = append(w.sigEntries, seed("later signature"))
	w.sigBlkAll = append(w.sigBlkAll, 69)
	w.sigIdx = indexFor(w.sigBlkAll)

	w.pageChains = []namedChain{
		{"main", mainEntries}, {"main-index", mainIdx}, {"signature", w.sigEntries}, {"signature-index", w.sigIdx},
	}
	w.pageAcct = acct{a: w.page, chains: w.pageChains}

	w.addSynth()
	return w
}

// addSynth adds the synthetic ledger holding the vote's SequencedMessage when the script produces it in a block.
func (w *timelineWorld) addSynth() {
	t := w.t
	if t.ProduceBlock != 0 {
		w.synthMsg = seed("sequenced vote message")
		if t.BindSequenced {
			var cause [32]byte
			copy(cause[:], seed("cause of the vote"))
			auth := &protocol.AuthoritySignature{Origin: mustURL(BankPage1), Authority: mustURL(BankBook), Vote: protocol.VoteTypeAccept, TxID: w.txn.ID(),
				Cause: mustURL(BankPage1).WithTxID(cause)}
			inner := &messaging.SignatureMessage{Signature: auth, TxID: w.txn.ID()}
			seq := &messaging.SequencedMessage{Message: inner, Source: mustURL(PartBVN2), Destination: mustURL(PartBVN1), Number: voteNumber}
			ih, sh := inner.Hash(), seq.Hash()
			w.voteMsg, w.synthMsg = ih[:], sh[:]
			w.seqRaw = must(seq.MarshalBinary())
		}
		w.synthEnt = [][]byte{seed("earlier synthetic a"), w.synthMsg, seed("later synthetic")}
		w.synthBlks = []uint64{20, t.ProduceBlock, 69}
		w.synthIdx = indexFor(w.synthBlks)
		w.synthPos = 1
		sl := &protocol.SyntheticLedger{Url: protocol.PartitionUrl("BVN2").JoinPath(protocol.Synthetic)}
		a := acct{a: sl, chains: []namedChain{{"main", w.synthEnt}, {"main-index", w.synthIdx}}}
		w.synth = &a
	}
}

// hops returns the vote's cause hop and the other counted signatures.
func (w *timelineWorld) hops() (hop proofv2.VoteHop, counted []proofv2.VoteHop) {
	if w.dw != nil {
		return w.dw.hopAuth, nil
	}
	mk := func(i int) proofv2.VoteHop {
		pos := w.sigPos[i]
		return proofv2.VoteHop{
			Page: BankPage1, Message: hexs(w.sigEntries[pos]), Signature: hexs(must(w.sigSigs[i].MarshalBinary())),
			Block:   w.t.Sigs[i].Block,
			Receipt: rcptHex(entryReceipt(w.sigEntries, pos)),
			Arrival: func() *proofv2.Arrival { a := arrivalFor(w.sigIdx, w.sigBlkAll, pos); return &a }(),
		}
	}
	last := len(w.t.Sigs) - 1
	hop = mk(last)
	for i := last - 1; i >= 0; i-- {
		counted = append(counted, mk(i))
	}
	return hop, counted
}

func (w *timelineWorld) production() *proofv2.Production {
	if w.synth == nil {
		return nil
	}
	var seqHex string
	if w.seqRaw != nil {
		seqHex = hexs(w.seqRaw)
	}
	return &proofv2.Production{
		Account: w.synth.url(), Chain: "main", Message: hexs(w.synthMsg), Sequenced: seqHex,
		Receipt: rcptHex(entryReceipt(w.synthEnt, w.synthPos)),
		Arrival: arrivalFor(w.synthIdx, w.synthBlks, w.synthPos),
	}
}

// proveChains is acct.proveLeaf for an account with a scripted chain set: the chains in the given order, their anchors merkle-hashed
// with the (zero) pending component into the state hasher's second sibling.
func (a acct) proveChains() pageProof {
	state := must(a.a.MarshalBinary())
	var chains []proof.ChainRoot
	var anchors [][]byte
	for _, c := range a.chains {
		cr := chainRootOf(c)
		chains = append(chains, cr)
		anchors = append(anchors, must(hexDecode(cr.Anchor)))
	}
	component := foldState(anchors).Anchor()
	zero := make([]byte, 32)
	secondary := seed("secondary of " + a.url())
	cp := h2(component, zero)
	sum := sha256.Sum256(state)
	r := rcpt(sum[:], step{true, secondary}, step{true, cp})
	return pageProof{state: state, chains: chains, pending: hexs(zero), steps: []step{{true, secondary}, {true, cp}}, leaf: r.Anchor}
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
