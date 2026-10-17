package main

// The synthetic conformance document: a whole proof v2 portable document, built from fixed keys, whose spine contains a
// network update (the Directory's validator set gains a fourth validator in major block 2, and the anchor that certifies
// the transaction is signed by the post-update set). The live Kermit capture has no such update, so the apply rule, the
// quorum fallback and the main-chain accounting are otherwise shown to agree across languages only on records and
// signatures, never on a whole document.
//
// Nothing here is a real network. Every hash, receipt and signature is built from fixed seeds, so the document is
// reproducible, and every one of them is checked by the Go verifier before it is written.

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

func seed(label string) [32]byte {
	return sha256.Sum256([]byte("certen proof v2 synthetic conformance: " + label))
}

func sd(label string) []byte { s := seed(label); return s[:] }

func hashOf(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func mustV[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type validator struct {
	priv ed25519.PrivateKey
	pub  []byte
}

func newValidator(i int) validator {
	s := seed(fmt.Sprintf("validator %d", i))
	priv := ed25519.NewKeyFromSeed(s[:])
	return validator{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

func (v validator) info() *protocol.ValidatorInfo {
	h := sha256.Sum256(v.pub)
	return &protocol.ValidatorInfo{PublicKey: v.pub, PublicKeyHash: h, Partitions: []*protocol.ValidatorPartitionInfo{{ID: "Directory", Active: true}, {ID: "BVN1", Active: true}}}
}

func networkDefinition(version uint64, vs ...validator) *protocol.NetworkDefinition {
	d := &protocol.NetworkDefinition{
		NetworkName: "Conformance", Version: version,
		Partitions: []*protocol.PartitionInfo{{ID: "Directory", Type: protocol.PartitionTypeDirectory}, {ID: "BVN1", Type: protocol.PartitionTypeBlockValidator}},
	}
	for _, v := range vs {
		d.Validators = append(d.Validators, v.info())
	}
	return d
}

func globalsRecord() *protocol.NetworkGlobals {
	return &protocol.NetworkGlobals{
		OperatorAcceptThreshold:  protocol.Rational{Numerator: 2, Denominator: 3},
		ValidatorAcceptThreshold: protocol.Rational{Numerator: 2, Denominator: 3},
		MajorBlockSchedule:       "0 */12 * * *",
		FeeSchedule:              &protocol.FeeSchedule{CreateIdentitySliding: []protocol.Fee{500000}, CreateSubIdentity: 10000},
		Limits:                   &protocol.NetworkLimits{DataEntryParts: 100, AccountAuthorities: 20, BookPages: 20, PageEntries: 100, IdentityAccounts: 1000},
	}
}

// directoryAnchor is the Directory's self-anchor for a minor block.
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

// signAnchor is the quorum's signatures over an anchor, each by the key that is named.
func signAnchor(msg *messaging.SequencedMessage, by ...validator) []protocol.KeySignature {
	h := msg.Hash()
	var out []protocol.KeySignature
	for _, v := range by {
		sig := mustV(new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(protocol.DnUrl().JoinPath(protocol.Network)).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(v.priv).Sign(h[:]))
		out = append(out, sig.(protocol.KeySignature))
	}
	return out
}

func rcpt(start []byte, steps ...step) *merkle.Receipt {
	r := &merkle.Receipt{Start: start}
	cur := start
	for _, s := range steps {
		r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: s.right, Hash: s.hash})
		var d [32]byte
		if s.right {
			d = hashOf(cur, s.hash)
		} else {
			d = hashOf(s.hash, cur)
		}
		cur = d[:]
	}
	r.Anchor = cur
	return r
}

type step struct {
	right bool
	hash  []byte
}

func right(h []byte) step { return step{true, h} }
func left(h []byte) step  { return step{false, h} }

func hexs(b []byte) string { return hex.EncodeToString(b) }

// syntheticDocument builds the document, and returns it with the inputs its govRoot v3 is computed from.
func syntheticDocument() (*proofv2.Portable, error) {
	v := []validator{newValidator(1), newValidator(2), newValidator(3), newValidator(4)}

	// Genesis: three Directory validators.
	genNet := networkDefinition(1, v[0], v[1], v[2])
	genGlob := globalsRecord()
	in := proof.IncarnationInputs{
		GenesisMinorBlockIndex: protocol.GenesisBlock,
		GenesisRootChainAnchor: seed("genesis root"),
		GenesisStateTreeAnchor: seed("genesis state"),
		GenesisTimeUnix:        1700000000,
		NetworkRecord:          mustV(genNet.MarshalBinary()),
		GlobalsRecord:          mustV(genGlob.MarshalBinary()),
	}
	pin, err := proof.ComputeIncarnation(in)
	if err != nil {
		return nil, err
	}

	// Major block 1: closed by the genesis set.
	r1, s1 := seed("root 1"), seed("state 1")
	a1 := directoryAnchor(100, r1, s1)
	m1 := &api.MajorHeaderRecord{Index: 1, Entry: &protocol.IndexEntry{BlockIndex: 1}, Anchor: a1, Signatures: signAnchor(a1, v[0], v[1], v[2])}

	// Major block 2 carries a write to the network account that adds the fourth validator. The update's receipt ends at the
	// anchor's root chain anchor. The anchor is signed by validators 1, 2 and 4: only the post-update set accepts it.
	updated := networkDefinition(2, v[0], v[1], v[2], v[3])
	update := &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: protocol.DnUrl().JoinPath(protocol.Network)},
		Body:   &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{mustV(updated.MarshalBinary())}}},
	}
	updateHash := update.GetHash()
	updateReceipt := rcpt(updateHash, right(sd("update sibling")))
	var r2 [32]byte
	copy(r2[:], updateReceipt.Anchor)
	s2 := seed("state 2")
	a2 := directoryAnchor(200, r2, s2)
	m2 := &api.MajorHeaderRecord{Index: 2, Entry: &protocol.IndexEntry{BlockIndex: 2}, Anchor: a2, Signatures: signAnchor(a2, v[0], v[1], v[3]),
		Updates: []*api.NetworkUpdateProof{{Transaction: update, Receipt: updateReceipt}}}

	// The transaction, and the partition anchor that carries its block's roots into the Directory.
	txHash := seed("transaction")
	txToPartition := rcpt(txHash[:], right(sd("tx sibling")))
	var partitionRoot [32]byte
	copy(partitionRoot[:], txToPartition.Anchor)
	partitionState := seed("partition state")
	anchorMsg := &messaging.SequencedMessage{
		Message: &messaging.TransactionMessage{Transaction: &protocol.Transaction{
			Header: protocol.TransactionHeader{Principal: protocol.DnUrl().JoinPath(protocol.AnchorPool)},
			Body: &protocol.BlockValidatorAnchor{PartitionAnchor: protocol.PartitionAnchor{
				Source: url.MustParse("acc://bvn-BVN1.acme"), MinorBlockIndex: 50, RootChainIndex: 50, RootChainAnchor: partitionRoot, StateTreeAnchor: partitionState}},
		}},
		Source: url.MustParse("acc://bvn-BVN1.acme"), Destination: protocol.DnUrl(), Number: 1,
	}
	anchorTx := anchorMsg.Message.(*messaging.TransactionMessage).Transaction.GetHash()

	// One tree holds both: Q is the subtree of the partition root and the anchor transaction; the Directory's root chain
	// after major block 2 (r2) and Q make the root the certifying anchor commits to.
	q := hashOf(partitionRoot[:], anchorTx)
	txReceipt := rcpt(txHash[:], right(sd("tx sibling")), right(anchorTx), left(r2[:]))
	anchorReceipt := rcpt(anchorTx, left(partitionRoot[:]), left(r2[:]))
	var certRoot [32]byte
	copy(certRoot[:], txReceipt.Anchor)
	if hexs(anchorReceipt.Anchor) != hexs(certRoot[:]) {
		return nil, fmt.Errorf("the two receipts do not meet at one root")
	}

	// The network and globals accounts at the certified block, proven into its state root.
	ed := seed("genesis network entry")
	netChain := proof.ChainRoot{Name: "main"}
	h2 := hashOf(ed[:], updateHash)
	h2s := hexs(h2[:])
	netChain.Pending = []*string{nil, &h2s} // height 2: the genesis entry and the update
	netChain.Count, netChain.Anchor = 2, h2s
	gd := seed("genesis globals entry")
	gds := hexs(gd[:])
	globChain := proof.ChainRoot{Name: "main", Pending: []*string{&gds}, Count: 1, Anchor: gds}
	netAcct := &protocol.DataAccount{Url: protocol.DnUrl().JoinPath(protocol.Network), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{mustV(updated.MarshalBinary())}}}
	globAcct := &protocol.DataAccount{Url: protocol.DnUrl().JoinPath(protocol.Globals), Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{mustV(genGlob.MarshalBinary())}}}

	prove := func(acct *protocol.DataAccount, chain proof.ChainRoot, tag string) (proof.AccountStateProof, []byte) {
		state := mustV(acct.MarshalBinary())
		main := sha256.Sum256(state)
		secondary := seed(tag + " secondary")
		pending := seed(tag + " pending")
		chains := mustV(hex.DecodeString(chain.Anchor))
		// the state hasher is [main, secondary, chains, pending]; the chains component is the merkle hash of the chain anchors
		chainsComponent := chains // one chain: its merkle hash is its anchor
		cp := hashOf(chainsComponent, pending[:])
		sr := rcpt(main[:], right(secondary[:]), right(cp[:]))
		return proof.AccountStateProof{
			AccountURL: acct.Url.String(), AccountState: hexs(state), Chains: []proof.ChainRoot{chain},
			SecondaryHash: hexs(secondary[:]), PendingHash: hexs(pending[:]),
			StateReceipt: chained_proof.Receipt{Start: hexs(main[:]), Anchor: hexs(sr.Anchor), Entries: []chained_proof.ReceiptStep{{Hash: hexs(secondary[:]), Right: true}, {Hash: hexs(cp[:]), Right: true}}},
		}, sr.Anchor
	}
	netProof, netRoot := prove(netAcct, netChain, "network")
	globProof, globRoot := prove(globAcct, globChain, "globals")
	// the two accounts are leaves of one BPT whose root the certifying anchor commits to
	bpt := hashOf(netRoot, globRoot)
	netProof.StateReceipt.Entries = append(netProof.StateReceipt.Entries, chained_proof.ReceiptStep{Hash: hexs(globRoot), Right: true})
	netProof.StateReceipt.Anchor = hexs(bpt[:])
	globProof.StateReceipt.Entries = append(globProof.StateReceipt.Entries, chained_proof.ReceiptStep{Hash: hexs(netRoot), Right: false})
	globProof.StateReceipt.Anchor = hexs(bpt[:])

	// The certifying run: one minor-root record extending the verified root (r2) to certRoot, signed by the post-update set.
	ms := &merkle.State{Count: 1, Pending: [][]byte{r2[:]}}
	cert := directoryAnchor(300, certRoot, bpt)
	certRecord := &api.MinorRootRecord{
		Anchor: cert, Signatures: signAnchor(cert, v[0], v[1], v[3]),
		RootProof: &merkle.ReceiptList{MerkleState: ms, Elements: [][]byte{q[:]}, Receipt: rcpt(q[:], left(r2[:]))},
	}

	ev := &proofv2.Evidence{
		Version: proofv2.Version, Account: "acc://conformance.acme/data", TxHash: hexs(txHash[:]),
		Receipt: hexs(mustV(txReceipt.MarshalBinary())),
		Majors:  2,
		Certify: []string{hexs(mustV(certRecord.MarshalBinary()))},
		Anchor:  proofv2.PartitionAnchor{Message: hexs(mustV(anchorMsg.MarshalBinary())), Receipt: hexs(mustV(anchorReceipt.MarshalBinary()))},
		Check:   proofv2.SetCheck{Majors: 2, Hops: []string{}, Set: proof.ValidatorSetProof{Incarnation: hexs(pin[:]), Network: netProof, Globals: globProof}},
	}
	ar := &proofv2.Archive{Majors: []*api.MajorHeaderRecord{m1, m2}}
	return proofv2.Export(ev, ar, in, pin)
}
