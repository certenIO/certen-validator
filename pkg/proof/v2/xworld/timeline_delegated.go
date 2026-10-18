// Copyright 2026 Certen Protocol
//
// The delegated variant of the timeline world (docs/proof/G1_CROSS_PARTITION.md D3, delegated hops): the vote is cast through a
// delegation. BankPage2 (BVN2) holds an entry delegating to the delegate book; the key signature is recorded on the delegate book's
// page DelePage1 (BVN3), wrapped in a delegated signature naming BankPage2; DelePage1 votes (an authority signature), the vote is
// recorded on BankPage2's signature chain, and BankPage2 - the first ready page of the authority book - decides the book's vote.
// Both pages carry scripted histories folded into their proven main chains and signature chains whose index chains place each hop.
package xworld

import (
	"fmt"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// scriptedPage is a key page with a scripted history and one scripted message in its signature chain.
type scriptedPage struct {
	acct       acct
	history    *proofv2.PageHistory
	sigEntries [][]byte
	sigBlkAll  []uint64
	sigIdx     [][]byte
	sigPos     int
}

// entry is a key page entry in the script's bookkeeping: a key label or a delegate book.
type entry struct{ key, delegate string }

func (e entry) spec() *protocol.KeySpecParams {
	if e.delegate != "" {
		return &protocol.KeySpecParams{Delegate: mustURL(e.delegate)}
	}
	return &protocol.KeySpecParams{KeyHash: keyOf(e.key).hash}
}

func (e entry) keySpec() *protocol.KeySpec {
	if e.delegate != "" {
		return &protocol.KeySpec{Delegate: mustURL(e.delegate)}
	}
	return &protocol.KeySpec{PublicKeyHash: keyOf(e.key).hash}
}

// scriptPage builds a key page of book from its genesis entries and events, and a signature chain holding msg (the page's one
// message about the transaction) at sigBlock between two earlier messages and one later.
func scriptPage(pageURL, book string, genesis []entry, events []PageEvent, msg []byte, sigBlock uint64, tag string) scriptedPage {
	var specs []*protocol.KeySpecParams
	held := append([]entry{}, genesis...)
	for _, e := range genesis {
		specs = append(specs, e.spec())
	}
	txns := []*protocol.Transaction{{Header: protocol.TransactionHeader{Principal: mustURL(book), Memo: "genesis of " + pageURL}, Body: &protocol.CreateKeyPage{Keys: specs}}}
	blocks := []uint64{10}
	version, threshold := uint64(1), uint64(1)
	for n, ev := range events {
		var ops []protocol.KeyPageOperation
		for _, l := range ev.Add {
			ops = append(ops, &protocol.AddKeyOperation{Entry: *entry{key: l}.spec()})
			held = append(held, entry{key: l})
		}
		if ev.RemoveDelegate {
			for i, h := range held {
				if h.delegate != "" {
					ops = append(ops, &protocol.RemoveKeyOperation{Entry: *h.spec()})
					held = append(held[:i:i], held[i+1:]...)
					break
				}
			}
		}
		if len(ops) == 0 {
			panic("xworld: a page event that changes nothing")
		}
		if int(threshold) > len(held) {
			threshold = uint64(len(held))
		}
		version++
		txns = append(txns, &protocol.Transaction{Header: protocol.TransactionHeader{Principal: mustURL(pageURL), Memo: fmt.Sprintf("%s event %d", tag, n)}, Body: &protocol.UpdateKeyPage{Operation: ops}})
		blocks = append(blocks, ev.Block)
	}
	pg := &protocol.KeyPage{Url: mustURL(pageURL), Version: version, AcceptThreshold: threshold}
	var delegates []entry
	var keys []string
	for _, h := range held {
		if h.delegate != "" {
			delegates = append(delegates, h)
		} else {
			keys = append(keys, h.key)
		}
	}
	for _, h := range delegates { // entries without a key hash sort first
		pg.Keys = append(pg.Keys, h.keySpec())
	}
	for _, h := range sortedKeys(keys) {
		pg.Keys = append(pg.Keys, &protocol.KeySpec{PublicKeyHash: h})
	}

	var mainEntries [][]byte
	hist := &proofv2.PageHistory{}
	for _, tx := range txns {
		mainEntries = append(mainEntries, tx.GetHash())
		hist.Entries = append(hist.Entries, proofv2.HistoryEntry{Transaction: hexs(must(tx.MarshalBinary()))})
	}
	mainIdx := indexFor(blocks)
	for _, e := range mainIdx {
		hist.Index = append(hist.Index, hexs(e))
	}
	sp := scriptedPage{history: hist}
	sp.sigEntries = [][]byte{seed("earlier " + tag + " a"), seed("earlier " + tag + " b"), msg, seed("later " + tag)}
	sp.sigBlkAll = []uint64{30, 30, sigBlock, 69}
	sp.sigIdx = indexFor(sp.sigBlkAll)
	sp.sigPos = 2
	sp.acct = acct{a: pg, chains: []namedChain{{"main", mainEntries}, {"main-index", mainIdx}, {"signature", sp.sigEntries}, {"signature-index", sp.sigIdx}}}
	return sp
}

func (s scriptedPage) hop(page string, sig protocol.Signature, claimed uint64) proofv2.VoteHop {
	a := arrivalFor(s.sigIdx, s.sigBlkAll, s.sigPos)
	return proofv2.VoteHop{Page: page, Message: hexs(s.sigEntries[s.sigPos]), Signature: hexs(must(sig.MarshalBinary())), Block: claimed,
		Receipt: rcptHex(entryReceipt(s.sigEntries, s.sigPos)), Arrival: &a}
}

// delegatedWorld is the delegated variant.
type delegatedWorld struct {
	p2, p3    scriptedPage
	hopAuth   proofv2.VoteHop // the authority signature recorded on BankPage2
	hopKey    proofv2.VoteHop // the key signature recorded on DelePage1
	authBlock uint64
	keyBlock  uint64
	mids      []midPage // the intermediate delegations of a chain (timeline_chain.go), P1..P(N-1)
}

func newDelegatedWorld(t Timeline, txn *protocol.Transaction, txHash []byte) *delegatedWorld {
	d := &delegatedWorld{authBlock: 66, keyBlock: 64}
	if t.AuthBlock != 0 {
		d.authBlock = t.AuthBlock
	}
	if t.KeyBlock != 0 {
		d.keyBlock = t.KeyBlock
	}
	// The key signature: a key of the delegate book's page, delegated through BankPage2.
	k := keyOf("K2")
	keySig := must(new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(mustURL(DelePage1)).SetVersion(1).SetTimestamp(1700000000000).
		SetPrivateKey(k.priv).AddDelegator(mustURL(BankPage2)).Sign(txHash))
	keyMsg := (&messaging.SignatureMessage{Signature: keySig, TxID: txn.ID()}).Hash()
	// DelePage1 votes: an authority signature for the delegate book, recorded on BankPage2.
	auth := &protocol.AuthoritySignature{Origin: mustURL(DelePage1), Authority: mustURL(DeleBook), Vote: protocol.VoteTypeAccept, TxID: txn.ID(),
		Cause: mustURL(DelePage1).WithTxID(keyMsg), Delegator: []*url.URL{mustURL(BankPage2)}}
	authMsg := (&messaging.SignatureMessage{Signature: auth, TxID: txn.ID()}).Hash()

	deleEntries := []entry{{key: "K2"}}
	if t.DelegateCycle {
		deleEntries = append(deleEntries, entry{delegate: BankBook})
	}
	d.p3 = scriptPage(DelePage1, DeleBook, deleEntries, nil, keyMsg[:], d.keyBlock, "dele")
	d.p2 = scriptPage(BankPage2, BankBook, []entry{{delegate: DeleBook}}, t.DelegatorEvents, authMsg[:], d.authBlock, "bank2")
	d.hopAuth = d.p2.hop(BankPage2, auth, d.authBlock)
	d.hopKey = d.p3.hop(DelePage1, keySig, d.keyBlock)
	return d
}
