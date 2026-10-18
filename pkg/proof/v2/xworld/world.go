// Copyright 2026 Certen Protocol
//
// Package xworld builds the synthetic evidence 2.1 documents of the cross-partition conformance suite (docs/proof/
// G1_CROSS_PARTITION.md, RB9 Phase C1a): a whole portable proof, from fixed seeds, whose governing pages live on three
// partitions - the transaction's BVN1, the authority book's BVN2 and the delegate book's BVN3 - each proven at its own block
// through its own BlockValidatorAnchor into one certified Directory root, with the routing table proven beside the validator
// set. The Go tests and cmd/proofv2conformance use it, so the TypeScript verifier is judged on exactly the documents the Go
// verifier is.
//
// Nothing here is a real network. Every hash, receipt and signature is built from fixed seeds, so the documents are reproducible.
package xworld

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The accounts of the world. Their partitions are what the Kermit routing table sends their root identities to (R9 M9:
// pv2-cust-5 BVN1, pv2-bank-5 BVN2, pv2-dele-5 BVN3).
const (
	Principal   = "acc://pv2-cust-5.acme/data"
	BankBook    = "acc://pv2-bank-5.acme/book"
	BankPage1   = "acc://pv2-bank-5.acme/book/1"
	BankPage2   = "acc://pv2-bank-5.acme/book/2"
	DeleBook    = "acc://pv2-dele-5.acme/book"
	DelePage1   = "acc://pv2-dele-5.acme/book/1"
	PartBVN1    = "acc://bvn-BVN1.acme"
	PartBVN2    = "acc://bvn-BVN2.acme"
	PartBVN3    = "acc://bvn-BVN3.acme"
	BlockBVN1   = 50
	BlockBVN2   = 70
	BlockBVN3   = 90
	HopBlock    = 65 // the block of BVN2 the vote's key signature arrived in
	voteNumber  = 5
	dnBlockCert = 300
)

// Options changes the world before it is proven. The zero value is the valid world.
type Options struct {
	// Routing edits the routing table before it is proven (nil: the Kermit table).
	Routing func(*protocol.RoutingTable)
	// RoutingHeight is the main chain height of the proven routing account (0 or 1: written once, at genesis).
	RoutingHeight uint64
	// AltBlockPage is the URL of a page to prove at another block of its partition: its receipt is valid and ends at the state
	// root of a different block, not at the root the partition's anchor carries.
	AltBlockPage string
	// NoRouting omits the routing proof.
	NoRouting bool
	// Timeline, when set, builds the timeline world (timeline.go) instead of the plain one: a real transaction, BankPage1 with a
	// scripted history and signature chain, and the evidence members of RB9 Phase C1b-1. The plain world is unchanged by it.
	Timeline *Timeline
}

// Built is a built world.
type Built struct {
	Evidence *proofv2.Evidence
	Archive  *proofv2.Archive
	Inputs   proof.IncarnationInputs
	Pin      [32]byte
}

// Portable is the world as a portable document.
func (b *Built) Portable() (*proofv2.Portable, error) {
	return proofv2.Export(b.Evidence, b.Archive, b.Inputs, b.Pin)
}

type step struct {
	right bool
	hash  []byte
}

func seed(label string) []byte {
	s := sha256.Sum256([]byte("certen proof v2 synthetic cross-partition: " + label))
	return s[:]
}

func h2(a, b []byte) []byte {
	d := sha256.Sum256(append(append([]byte{}, a...), b...))
	return d[:]
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

// rcpt builds the receipt that starts at start and applies steps; its Anchor is where it ends.
func rcpt(start []byte, steps ...step) *merkle.Receipt {
	r := &merkle.Receipt{Start: start}
	cur := start
	for _, s := range steps {
		r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: s.right, Hash: s.hash})
		if s.right {
			cur = h2(cur, s.hash)
		} else {
			cur = h2(s.hash, cur)
		}
	}
	r.Anchor = cur
	return r
}

func rcptHex(r *merkle.Receipt) string { return hexs(must(r.MarshalBinary())) }

type validator struct {
	priv ed25519.PrivateKey
	pub  []byte
}

func newValidator(i int) validator {
	s := seed(fmt.Sprintf("validator %d", i))
	priv := ed25519.NewKeyFromSeed(s)
	return validator{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

func (v validator) info() *protocol.ValidatorInfo {
	h := sha256.Sum256(v.pub)
	return &protocol.ValidatorInfo{PublicKey: v.pub, PublicKeyHash: h, Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: true}, {ID: "BVN1", Active: true}}}
}

func directoryAnchor(minor uint64, root, state [32]byte) *messaging.SequencedMessage {
	return &messaging.SequencedMessage{
		Message: &messaging.TransactionMessage{Transaction: &protocol.Transaction{
			Header: protocol.TransactionHeader{Principal: protocol.DnUrl().JoinPath(protocol.AnchorPool)},
			Body: &protocol.DirectoryAnchor{
				PartitionAnchor: protocol.PartitionAnchor{Source: protocol.DnUrl(), MinorBlockIndex: minor, RootChainIndex: minor, RootChainAnchor: root, StateTreeAnchor: state},
			},
		}},
		Source: protocol.DnUrl(), Destination: protocol.DnUrl(), Number: minor,
	}
}

func signAnchor(msg *messaging.SequencedMessage, by ...validator) []protocol.KeySignature {
	h := msg.Hash()
	var out []protocol.KeySignature
	for _, v := range by {
		sig := must(new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(protocol.DnUrl().JoinPath(protocol.Network)).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(v.priv).Sign(h[:]))
		out = append(out, sig.(protocol.KeySignature))
	}
	return out
}

func a32(b []byte) [32]byte {
	var o [32]byte
	copy(o[:], b)
	return o
}

// acct is one account of a partition with the entries of its signature chain.
type acct struct {
	a    protocol.Account
	sigs [][]byte // zero or two entries: the signature chain's two leaves
	// chains, when set, are the account's whole chain set (name, entries) and replace the plain main/signature chains.
	chains []namedChain
}

func (a acct) url() string { return a.a.GetUrl().String() }

func chainRoot(name string, count uint64, pending []*string, anchor []byte) proof.ChainRoot {
	return proof.ChainRoot{Name: name, Count: count, Pending: pending, Anchor: hexs(anchor)}
}

// pageProof is an account's state, chains and the receipt up to the state hasher's root (the leaf of the partition's tree).
type pageProof struct {
	state   []byte
	chains  []proof.ChainRoot
	pending string
	steps   []step
	leaf    []byte
}

func (a acct) proveLeaf() pageProof {
	if len(a.chains) > 0 {
		return a.proveChains()
	}
	state := must(a.a.MarshalBinary())
	mainRoot := seed("main chain of " + a.url())
	mainHex := hexs(mainRoot)
	chains := []proof.ChainRoot{chainRoot("main", 1, []*string{&mainHex}, mainRoot)}
	component := mainRoot
	if len(a.sigs) == 2 {
		d := h2(a.sigs[0], a.sigs[1])
		dh := hexs(d)
		chains = append(chains, chainRoot("signature", 2, []*string{nil, &dh}, d))
		component = h2(mainRoot, d)
	}
	zero := make([]byte, 32)
	secondary := seed("secondary of " + a.url())
	cp := h2(component, zero)
	sum := sha256.Sum256(state)
	r := rcpt(sum[:], step{true, secondary}, step{true, cp})
	return pageProof{state: state, chains: chains, pending: hexs(zero), steps: []step{{true, secondary}, {true, cp}}, leaf: r.Anchor}
}

// tree is a partition's state tree over the leaves of its accounts, left-folded; paths[i] takes leaf i to the root.
func tree(leaves [][]byte) (root []byte, paths [][]step) {
	paths = make([][]step, len(leaves))
	acc := leaves[0]
	for i := 1; i < len(leaves); i++ {
		for j := 0; j < i; j++ {
			paths[j] = append(paths[j], step{true, leaves[i]})
		}
		paths[i] = append(paths[i], step{false, acc})
		acc = h2(acc, leaves[i])
	}
	return acc, paths
}

func ky(label string) []*protocol.KeySpec {
	return []*protocol.KeySpec{{PublicKeyHash: seed("key " + label)}}
}

func mustURL(s string) *url.URL { return url.MustParse(s) }

func page(u string, delegate string) *protocol.KeyPage {
	ks := ky(u)
	if delegate != "" {
		ks[0].Delegate = mustURL(delegate)
	}
	return &protocol.KeyPage{Url: mustURL(u), Version: 1, AcceptThreshold: 1, Keys: ks}
}

// RoutingTable is the Kermit routing table (pkg/proof/testdata/kermit_routing_2026-09-27.json).
func RoutingTable() *protocol.RoutingTable {
	ov := func(a, p string) protocol.RouteOverride {
		return protocol.RouteOverride{Account: mustURL(a), Partition: p}
	}
	return &protocol.RoutingTable{
		Overrides: []protocol.RouteOverride{ov("acc://ACME", "Directory"), ov("acc://bvn-BVN1.acme", "BVN1"), ov("acc://bvn-BVN2.acme", "BVN2"), ov("acc://bvn-BVN3.acme", "BVN3"), ov("acc://dn.acme", "Directory")},
		Routes:    []protocol.Route{{Length: 1, Value: 0, Partition: "BVN1"}, {Length: 2, Value: 2, Partition: "BVN2"}, {Length: 2, Value: 3, Partition: "BVN3"}},
	}
}

// Build builds the world.
func Build(o Options) (b *Built, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("xworld: %v", r)
		}
	}()
	return build(o), nil
}

func build(o Options) *Built {
	v := []validator{newValidator(1), newValidator(2), newValidator(3)}
	genNet := &protocol.NetworkDefinition{NetworkName: "Conformance", Version: 1,
		Partitions: []*protocol.PartitionInfo{{ID: "Directory", Type: protocol.PartitionTypeDirectory}, {ID: "BVN1", Type: protocol.PartitionTypeBlockValidator}}}
	for _, x := range v {
		genNet.Validators = append(genNet.Validators, x.info())
	}
	genGlob := &protocol.NetworkGlobals{
		OperatorAcceptThreshold:  protocol.Rational{Numerator: 2, Denominator: 3},
		ValidatorAcceptThreshold: protocol.Rational{Numerator: 2, Denominator: 3},
		MajorBlockSchedule:       "0 */12 * * *",
		FeeSchedule:              &protocol.FeeSchedule{CreateIdentitySliding: []protocol.Fee{500000}, CreateSubIdentity: 10000},
		Limits:                   &protocol.NetworkLimits{DataEntryParts: 100, AccountAuthorities: 20, BookPages: 20, PageEntries: 100, IdentityAccounts: 1000},
	}
	in := proof.IncarnationInputs{
		GenesisMinorBlockIndex: protocol.GenesisBlock,
		GenesisRootChainAnchor: a32(seed("genesis root")),
		GenesisStateTreeAnchor: a32(seed("genesis state")),
		GenesisTimeUnix:        1700000000,
		NetworkRecord:          must(genNet.MarshalBinary()),
		GlobalsRecord:          must(genGlob.MarshalBinary()),
	}
	pin := must(proof.ComputeIncarnation(in))

	// Major block 1, closed by the genesis set.
	r1 := seed("root 1")
	a1 := directoryAnchor(100, a32(r1), a32(seed("state 1")))
	m1 := &api.MajorHeaderRecord{Index: 1, Entry: &protocol.IndexEntry{BlockIndex: 1}, Anchor: a1, Signatures: signAnchor(a1, v[0], v[1], v[2])}

	var tw *timelineWorld
	if o.Timeline != nil {
		tw = newTimelineWorld(*o.Timeline)
	}

	// The accounts of each partition. The vote's key signature sits in BankPage1's signature chain, the vote itself in the
	// principal's.
	voteMsg := seed("vote message")
	hopMsg := seed("hop message")
	hopSig := &protocol.ED25519Signature{PublicKey: seed("hop key"), Signature: append(seed("hop sig a"), seed("hop sig b")...), Signer: mustURL(BankPage1), SignerVersion: 1, Timestamp: 1}
	principal := acct{a: &protocol.DataAccount{Url: mustURL(Principal),
		AccountAuth: protocol.AccountAuth{Authorities: []protocol.AuthorityEntry{{Url: mustURL(BankBook)}}}}, sigs: [][]byte{seed("earlier signature"), voteMsg}}
	bvn1 := []acct{principal}
	bvn2 := []acct{
		{a: &protocol.KeyBook{Url: mustURL(BankBook), BookType: protocol.BookTypeNormal, PageCount: 2}},
		{a: page(BankPage1, ""), sigs: [][]byte{seed("earlier hop"), hopMsg}},
		{a: page(BankPage2, DeleBook)},
	}
	bvn3 := []acct{
		{a: &protocol.KeyBook{Url: mustURL(DeleBook), BookType: protocol.BookTypeNormal, PageCount: 1}},
		{a: page(DelePage1, "")},
	}
	bvn2Roles := map[string][]proofv2.PageRole{
		BankBook:  {proofv2.RoleAuthorityBook},
		BankPage1: {proofv2.RoleAuthorityPage, proofv2.RoleVoter},
		BankPage2: {proofv2.RoleAuthorityPage},
	}
	bvn3Roles := map[string][]proofv2.PageRole{
		DeleBook:  {proofv2.RoleDelegateBook},
		DelePage1: {proofv2.RoleDelegatePage},
	}
	if tw != nil && tw.dw != nil {
		// the vote is cast through BankPage2 and DelePage1: they are the voters, BankPage1 only a page of the book
		bvn2[2], bvn3[1] = tw.dw.p2.acct, tw.dw.p3.acct
		bvn2Roles[BankPage1] = []proofv2.PageRole{proofv2.RoleAuthorityPage}
		bvn2Roles[BankPage2] = []proofv2.PageRole{proofv2.RoleAuthorityPage, proofv2.RoleVoter}
		bvn3Roles[DelePage1] = []proofv2.PageRole{proofv2.RoleDelegatePage, proofv2.RoleVoter}
	}
	if tw != nil {
		if tw.dw == nil {
			bvn2[1] = tw.pageAcct
		}
		if tw.synth != nil {
			bvn2 = append(bvn2, *tw.synth)
			bvn2Roles[tw.synth.url()] = []proofv2.PageRole{proofv2.RoleSyntheticChain}
		}
	}

	type partition struct {
		src, id string
		block   uint64
		accts   []acct
		roles   map[string][]proofv2.PageRole
	}
	parts := []*partition{
		{PartBVN1, "BVN1", BlockBVN1, bvn1, map[string][]proofv2.PageRole{Principal: {proofv2.RolePrincipalChain}}},
		{PartBVN2, "BVN2", BlockBVN2, bvn2, bvn2Roles},
		{PartBVN3, "BVN3", BlockBVN3, bvn3, bvn3Roles},
	}

	txHash := seed("transaction")
	if tw != nil {
		txHash = tw.txHash
	}
	txToPartition := rcpt(txHash, step{true, seed("tx sibling")})

	// Each partition's state root and each page's receipt to it.
	var pages []proofv2.PageState
	type anchored struct {
		msg       *messaging.SequencedMessage
		tx        []byte
		rootChain []byte
	}
	anchors := map[string]anchored{}
	for _, p := range parts {
		proofs := make([]pageProof, len(p.accts))
		leaves := make([][]byte, len(p.accts))
		for i, a := range p.accts {
			proofs[i] = a.proveLeaf()
			leaves[i] = proofs[i].leaf
		}
		root, paths := tree(leaves)
		for i, a := range p.accts {
			pp := proofs[i]
			steps := append(append([]step{}, pp.steps...), paths[i]...)
			if o.AltBlockPage != "" && a.url() == o.AltBlockPage {
				// The same page in another block of its partition: a sibling leaf differs there, so its valid receipt ends at a
				// different root.
				alt := append(append([][]byte{}, leaves...), seed("a page created in the other block"))
				_, altPaths := tree(alt)
				steps = append(append([]step{}, pp.steps...), altPaths[i]...)
			}
			sum := sha256.Sum256(pp.state)
			r := rcpt(sum[:], steps...)
			pages = append(pages, proofv2.PageState{
				URL: a.url(), State: hexs(pp.state), Receipt: rcptHex(r),
				Chains: pp.chains, PendingHash: pp.pending,
				Partition: p.src, Roles: must(proofv2.CanonicalRoles(p.roles[a.url()])),
			})
		}
		rc := seed("root chain of " + p.id)
		if p.id == "BVN1" {
			rc = txToPartition.Anchor // the transaction executed in this block: its receipt passes through the block's root chain anchor
		}
		msg := &messaging.SequencedMessage{
			Message: &messaging.TransactionMessage{Transaction: &protocol.Transaction{
				Header: protocol.TransactionHeader{Principal: protocol.DnUrl().JoinPath(protocol.AnchorPool)},
				Body: &protocol.BlockValidatorAnchor{PartitionAnchor: protocol.PartitionAnchor{
					Source: mustURL(p.src), MinorBlockIndex: p.block, RootChainIndex: p.block, RootChainAnchor: a32(rc), StateTreeAnchor: a32(root)}},
			}},
			Source: mustURL(p.src), Destination: protocol.DnUrl(), Number: 1,
		}
		anchors[p.id] = anchored{msg: msg, tx: msg.Message.(*messaging.TransactionMessage).Transaction.GetHash(), rootChain: rc}
	}

	// One tree holds the transaction and the three anchors: qP = H(rootChainP, anchorTxP); Q = H(H(q1, q2), q3); the root the
	// certifying record commits to is H(r1, Q).
	q1 := h2(anchors["BVN1"].rootChain, anchors["BVN1"].tx)
	q2 := h2(anchors["BVN2"].rootChain, anchors["BVN2"].tx)
	q3 := h2(anchors["BVN3"].rootChain, anchors["BVN3"].tx)
	q12 := h2(q1, q2)
	q := h2(q12, q3)
	certRoot := h2(r1, q)
	anchorReceipt := func(id string) *merkle.Receipt {
		a := anchors[id]
		switch id {
		case "BVN1":
			return rcpt(a.tx, step{false, a.rootChain}, step{true, q2}, step{true, q3}, step{false, r1})
		case "BVN2":
			return rcpt(a.tx, step{false, a.rootChain}, step{false, q1}, step{true, q3}, step{false, r1})
		default:
			return rcpt(a.tx, step{false, a.rootChain}, step{false, q12}, step{false, r1})
		}
	}
	txReceipt := rcpt(txHash, step{true, seed("tx sibling")}, step{true, anchors["BVN1"].tx}, step{true, q2}, step{true, q3}, step{false, r1})

	// The network, globals and routing accounts at the certified block, proven into one state tree.
	netRec := must(genNet.MarshalBinary())
	netAcct := &protocol.DataAccount{Url: protocol.DnUrl().JoinPath(protocol.Network), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{netRec}}}
	globAcct := &protocol.DataAccount{Url: protocol.DnUrl().JoinPath(protocol.Globals), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{must(genGlob.MarshalBinary())}}}
	table := RoutingTable()
	if o.Routing != nil {
		o.Routing(table)
	}
	routAcct := &protocol.DataAccount{Url: protocol.DnUrl().JoinPath(protocol.Routing), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{must(table.MarshalBinary())}}}

	dataProof := func(a *protocol.DataAccount, height uint64, tag string) (proof.AccountStateProof, []byte) {
		state := must(a.MarshalBinary())
		main := sha256.Sum256(state)
		secondary := make([]byte, 32) // a data account has no directory: its secondary state is 32 zero bytes
		pending := make([]byte, 32)
		entry := seed(tag + " entry")
		var chain proof.ChainRoot
		if height <= 1 {
			e := hexs(entry)
			chain = proof.ChainRoot{Name: "main", Count: 1, Pending: []*string{&e}, Anchor: e}
		} else {
			// height 2: the genesis entry and a later write
			d := h2(entry, seed(tag+" later write"))
			dh := hexs(d)
			chain = proof.ChainRoot{Name: "main", Count: 2, Pending: []*string{nil, &dh}, Anchor: dh}
		}
		chainAnchorBytes := must(hex.DecodeString(chain.Anchor))
		cp := h2(chainAnchorBytes, pending)
		sr := rcpt(main[:], step{true, secondary}, step{true, cp})
		return proof.AccountStateProof{
			AccountURL: a.Url.String(), AccountState: hexs(state), Chains: []proof.ChainRoot{chain},
			SecondaryHash: hexs(secondary), PendingHash: hexs(pending),
			StateReceipt: chained_proof.Receipt{Start: hexs(main[:]), Anchor: hexs(sr.Anchor), Entries: []chained_proof.ReceiptStep{{Hash: hexs(secondary), Right: true}, {Hash: hexs(cp), Right: true}}},
		}, sr.Anchor
	}
	netProof, netRoot := dataProof(netAcct, 1, "network")
	globProof, globRoot := dataProof(globAcct, 1, "globals")
	rh := o.RoutingHeight
	routProof, routRoot := dataProof(routAcct, rh, "routing")
	ng := h2(netRoot, globRoot)
	bpt := ng
	extend := func(p *proof.AccountStateProof, steps ...step) {
		for _, s := range steps {
			p.StateReceipt.Entries = append(p.StateReceipt.Entries, chained_proof.ReceiptStep{Hash: hexs(s.hash), Right: s.right})
		}
	}
	if o.NoRouting {
		extend(&netProof, step{true, globRoot})
		extend(&globProof, step{false, netRoot})
	} else {
		bpt = h2(ng, routRoot)
		extend(&netProof, step{true, globRoot}, step{true, routRoot})
		extend(&globProof, step{false, netRoot}, step{true, routRoot})
		extend(&routProof, step{false, ng})
	}
	netProof.StateReceipt.Anchor, globProof.StateReceipt.Anchor, routProof.StateReceipt.Anchor = hexs(bpt), hexs(bpt), hexs(bpt)

	ms := &merkle.State{Count: 1, Pending: [][]byte{r1}}
	cert := directoryAnchor(dnBlockCert, a32(certRoot), a32(bpt))
	certRecord := &api.MinorRootRecord{
		Anchor: cert, Signatures: signAnchor(cert, v[0], v[1], v[2]),
		RootProof: &merkle.ReceiptList{MerkleState: ms, Elements: [][]byte{q}, Receipt: rcpt(q, step{false, r1})},
	}

	// The vote: a member of the principal's signature chain at the transaction's block, produced on BVN2 and sequenced to BVN1;
	// its cause chain is the key signature in BankPage1's signature chain.
	vote := proofv2.Vote{
		Authority: BankBook, Origin: BankPage1, Vote: "accept",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportSequenced, Source: PartBVN2, Destination: PartBVN1, Number: voteNumber},
		Message:   hexs(voteMsg), Receipt: rcptHex(rcpt(voteMsg, step{false, seed("earlier signature")})),
		Hops: []proofv2.VoteHop{{
			Page: BankPage1, Message: hexs(hopMsg), Signature: hexs(must(hopSig.MarshalBinary())), Block: HopBlock,
			Receipt: rcptHex(rcpt(hopMsg, step{false, seed("earlier hop")})),
		}},
	}

	if tw != nil {
		hop, counted := tw.hops()
		vote.Hops = []proofv2.VoteHop{hop}
		if tw.dw != nil {
			vote.Origin = BankPage2
			vote.Hops = append(vote.Hops, tw.dw.hopKey)
		}
		vote.Counted = counted
		vote.Produced = tw.production()
	}

	ev := &proofv2.Evidence{
		Version: proofv2.Version21, Account: Principal, TxHash: hexs(txHash),
		Receipt: rcptHex(txReceipt),
		Majors:  1,
		Certify: []string{hexs(must(certRecord.MarshalBinary()))},
		Anchor:  proofv2.PartitionAnchor{Message: hexs(must(anchors["BVN1"].msg.MarshalBinary())), Receipt: rcptHex(anchorReceipt("BVN1"))},
		Anchors: map[string]proofv2.PartitionAnchor{
			PartBVN2: {Message: hexs(must(anchors["BVN2"].msg.MarshalBinary())), Receipt: rcptHex(anchorReceipt("BVN2"))},
			PartBVN3: {Message: hexs(must(anchors["BVN3"].msg.MarshalBinary())), Receipt: rcptHex(anchorReceipt("BVN3"))},
		},
		Pages: pages,
		Votes: []proofv2.Vote{vote},
		Check: proofv2.SetCheck{Majors: 1, Hops: []string{}, Set: proof.ValidatorSetProof{Incarnation: hexs(pin[:]), Network: netProof, Globals: globProof}},
	}
	if !o.NoRouting {
		ev.Check.Routing = &routProof
	}
	if tw != nil {
		if !tw.t.OmitTransaction {
			ev.Transaction = hexs(must(tw.txn.MarshalBinary()))
		}
		for i := range ev.Pages {
			switch {
			case tw.dw != nil && ev.Pages[i].URL == BankPage2:
				ev.Pages[i].History = tw.dw.p2.history
			case tw.dw != nil && ev.Pages[i].URL == DelePage1:
				ev.Pages[i].History = tw.dw.p3.history
			case tw.dw == nil && ev.Pages[i].URL == BankPage1:
				ev.Pages[i].History = tw.history
			}
		}
	}
	return &Built{Evidence: ev, Archive: &proofv2.Archive{Majors: []*api.MajorHeaderRecord{m1}}, Inputs: in, Pin: pin}
}
