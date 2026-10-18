// Copyright 2026 Certen Protocol

// sigtypevectors writes the shared conformance vectors for every key-signature type Accumulate's executor accepts
// (RB8-B). Go writes them; the TypeScript verifier consumes byte-identical copies of the files and must reach the same
// verdict on every vector.
//
//	go run ./cmd/sigtypevectors -out accumulate-lite-client-2/liteclient/proof/govsig/testdata/sigtypes
//
// It refuses to write into a directory that already holds vectors: vectors are evidence, never regenerated in place
// (a new set goes in a new directory under a new format version).
//
// Every vector is made with Accumulate's own signing code and judged by Accumulate's own Verify (govsig.Verify) before it
// is written: a vector whose verdict is not the one stated here stops the generator. Two vectors are real signatures
// delivered by Kermit (a btc signature, corpus case K; an ecdsaSha256 signature on tcl1 tx d2338dac...), carried as
// the JSON the network served; their transactions are not carried (non-typedData signatures cover a transaction HASH).
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const (
	pinnedModule = "gitlab.com/accumulatenetwork/accumulate v1.4.7-0.20260926030013-e1d1db9ebb7c"
	pinnedCommit = "e1d1db9ebb7c75318b6652293d5c7008da76ecf4"
)

// Kermit's network-status routing table as served on 2026-10-17 (R8 M2), enough to route a signer page.
const kermitNetworkStatus = `{"result":{"network":{"networkName":"DevNet"},"routing":{"overrides":[{"account":"acc://ACME","partition":"Directory"},{"account":"acc://bvn-BVN1.acme","partition":"BVN1"},{"account":"acc://bvn-BVN2.acme","partition":"BVN2"},{"account":"acc://bvn-BVN3.acme","partition":"BVN3"},{"account":"acc://dn.acme","partition":"Directory"}],"routes":[{"length":1,"partition":"BVN1"},{"length":2,"value":2,"partition":"BVN2"},{"length":2,"value":3,"partition":"BVN3"}]}}}`

type gen struct {
	vectors []sigfixture.Vector
	keys    map[protocol.SignatureType]sigfixture.Key
	extra   map[string]sigfixture.Key
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func (g *gen) key(t protocol.SignatureType) sigfixture.Key {
	if k, ok := g.keys[t]; ok {
		return k
	}
	k := must(sigfixture.NewKey(t, rand.Reader))
	g.keys[t] = k
	return k
}

func (g *gen) freshKey(t protocol.SignatureType) sigfixture.Key {
	return must(sigfixture.NewKey(t, rand.Reader))
}

var types = govsig.AcceptedKeyTypes()

func after(part string) *sigfixture.Where {
	return &sigfixture.Where{Partition: part, Block: govsig.KermitActivations()[part].Block + 1000}
}

func gated(t protocol.SignatureType) bool {
	return govsig.RequiredVersion(t, govsig.EthRuleV2RSV) != 0
}

// add judges the vector with Accumulate's own Verify and requires the verdict it was written to have.
func (g *gen) add(id, source, kind string, ty protocol.SignatureType, desc string, txn *protocol.Transaction, sig protocol.Signature,
	where *sigfixture.Where, page *sigfixture.Page, network string, wantVerdict string) {

	bin := must(sig.MarshalBinary())
	js := must(json.Marshal(sig))
	h := txn.Hash()
	v := sigfixture.Vector{
		ID: id, Source: source, Kind: kind, Type: ty.String(), Description: desc,
		TxHash: hex.EncodeToString(h[:]), Signature: hex.EncodeToString(bin), SignatureJSON: js,
		NetworkName: network, Where: where, Page: page,
	}
	if txn.Body != nil {
		v.Transaction = hex.EncodeToString(must(txn.MarshalBinary()))
	}
	g.finish(v, wantVerdict)
}

func (g *gen) finish(v sigfixture.Vector, wantVerdict string) {
	verdict, verified, err := sigfixture.Judge(v)
	if verdict != wantVerdict {
		panic(fmt.Sprintf("%s: Accumulate's Verify gives %q (%v); the vector was written to be %q", v.ID, verdict, err, wantVerdict))
	}
	v.Expect = sigfixture.Expect{Verdict: verdict}
	if verdict == "accepted" {
		v.Expect.KeyHash = hex.EncodeToString(verified.KeyHash)
		v.Expect.Form = verified.Form
		v.Expect.EthRule = verified.EthRule
		for _, d := range verified.Delegators {
			v.Expect.Delegators = append(v.Expect.Delegators, d.String())
		}
	}
	for _, e := range g.vectors {
		if e.ID == v.ID {
			panic("duplicate vector id " + v.ID)
		}
	}
	if err := sigfixture.Check(v); err != nil {
		panic(err)
	}
	g.vectors = append(g.vectors, v)
}

func newTxn(tag string) *protocol.Transaction {
	return sigfixture.Txn("acc://vectors.acme/data", "sigtypes vector "+tag)
}

func deleg(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("acc://delegator%d.acme/book/1", i+1)
	}
	return out
}

func sign(k sigfixture.Key, txn *protocol.Transaction, o sigfixture.Opts) protocol.Signature {
	return must(sigfixture.Sign(k, txn, o))
}

func pageOf(sig protocol.Signature) *sigfixture.Page {
	inner := sigfixture.Inner(sig).(protocol.KeySignature)
	return &sigfixture.Page{Entries: []string{hex.EncodeToString(inner.GetPublicKeyHash())}}
}

func main() {
	out := flag.String("out", "", "directory to write the vectors to (must not already hold any)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: sigtypevectors -out <dir>")
		os.Exit(2)
	}
	if entries, err := os.ReadDir(*out); err == nil && len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "%s already holds files: vectors are evidence and are never regenerated in place\n", *out)
		os.Exit(1)
	}
	g := &gen{keys: map[protocol.SignatureType]sigfixture.Key{}, extra: map[string]sigfixture.Key{}}
	g.valid()
	g.kermit()
	g.adversarial()
	if err := g.write(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// valid
// ---------------------------------------------------------------------------------------------------------------------

func (g *gen) valid() {
	local, kind := sigfixture.SourceLocal, "valid"
	for _, ty := range types {
		k := g.key(ty)
		var where *sigfixture.Where
		if gated(ty) {
			where = after("bvn1")
		}
		net := ""
		if ty == protocol.SignatureTypeTypedData {
			net = "DevNet"
		}
		for _, nd := range []int{0, 1, 2} {
			txn := newTxn(fmt.Sprintf("%v valid %d", ty, nd))
			sig := sign(k, txn, sigfixture.Opts{Delegators: deleg(nd)})
			name := "direct"
			if nd > 0 {
				name = fmt.Sprintf("delegated-%d", nd)
			}
			g.add(fmt.Sprintf("%v/valid/%s", ty, name), local, kind, ty,
				fmt.Sprintf("a %v signature over the metadata digest, %d delegator(s); the key hash is the type's own", ty, nd),
				txn, sig, where, pageOf(sig), net, "accepted")
		}
		if ty != protocol.SignatureTypeRsaSha256 && ty != protocol.SignatureTypeEcdsaSha256 && ty != protocol.SignatureTypeTypedData {
			txn := newTxn(fmt.Sprintf("%v merkle", ty))
			sig := sign(k, txn, sigfixture.Opts{Merkle: true})
			g.add(fmt.Sprintf("%v/valid/direct-initiator-merkle", ty), local, kind, ty,
				fmt.Sprintf("a %v signature over the initiator-merkle digest, the form the official builder initiates with", ty),
				txn, sig, where, pageOf(sig), net, "accepted")
		}
	}

	// the 20-deep chain Accumulate allows
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeED25519, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData} {
		txn := newTxn(fmt.Sprintf("%v depth 20", ty))
		sig := sign(g.key(ty), txn, sigfixture.Opts{Delegators: deleg(protocol.DelegationDepthLimit)})
		var where *sigfixture.Where
		if gated(ty) {
			where = after("bvn2")
		}
		net := ""
		if ty == protocol.SignatureTypeTypedData {
			net = "DevNet"
		}
		g.add(fmt.Sprintf("%v/valid/delegated-20", ty), local, kind, ty,
			"a delegation chain of exactly DelegationDepthLimit (20) layers", txn, sig, where, pageOf(sig), net, "accepted")
	}

	// vote, memo and data are inside the signed metadata
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeED25519, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeBTC} {
		for name, o := range map[string]sigfixture.Opts{
			"reject-vote":  {Vote: protocol.VoteTypeReject},
			"abstain-vote": {Vote: protocol.VoteTypeAbstain},
			"memo":         {Memo: "approved by the officer"},
			"data":         {Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		} {
			txn := newTxn(fmt.Sprintf("%v %s", ty, name))
			sig := sign(g.key(ty), txn, o)
			var where *sigfixture.Where
			if gated(ty) {
				where = after("bvn3")
			}
			g.add(fmt.Sprintf("%v/valid/%s", ty, name), local, kind, ty,
				"vote, memo and data are part of the signed metadata hash: a verifier that rebuilds the signature without them cannot verify it",
				txn, sig, where, pageOf(sig), "", "accepted")
		}
	}

	// Accumulate's own malleability: accepted
	{
		k := g.key(protocol.SignatureTypeEcdsaSha256)
		txn := newTxn("ecdsa high-s")
		sig := sign(k, txn, sigfixture.Opts{})
		ec := sig.(*protocol.EcdsaSha256Signature)
		r, s := sigfixture.ParseDER(ec.Signature)
		must0(sigfixture.SetSignature(sig, sigfixture.EncodeDER(r, new(big.Int).Sub(elliptic.P256().Params().N, s))))
		g.add("ecdsaSha256/valid/high-s", local, kind, protocol.SignatureTypeEcdsaSha256,
			"Accumulate's ecdsa.VerifyASN1 does not enforce low-S: the flipped-S twin of a valid signature verifies", txn, sig, after("bvn1"), pageOf(sig), "", "accepted")

		for name, c := range map[string]elliptic.Curve{"p224": elliptic.P224(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
			ck := must(sigfixture.NewECDSAKey(c, rand.Reader))
			ctxn := newTxn("ecdsa " + name)
			csig := sign(ck, ctxn, sigfixture.Opts{})
			g.add("ecdsaSha256/valid/curve-"+name, local, kind, protocol.SignatureTypeEcdsaSha256,
				"Accumulate verifies whatever crypto/x509 parses as an ECDSA key: P-224, P-256, P-384 and P-521", ctxn, csig, after("bvn1"), pageOf(csig), "", "accepted")
		}
	}
	{
		k := g.key(protocol.SignatureTypeBTC)
		txn := newTxn("btc lax der")
		sig := sign(k, txn, sigfixture.Opts{})
		bt := sig.(*protocol.BTCSignature)
		r, s := sigfixture.ParseDER(bt.Signature)
		for name, b := range map[string][]byte{
			"lax-der-trailing-bytes": append(append([]byte{}, bt.Signature...), 0xde, 0xad),
			"non-minimal-der":        sigfixture.NonMinimalDER(r, s),
			"high-s":                 sigfixture.EncodeDER(r, new(big.Int).Sub(sigfixture.SecpN(), s)),
		} {
			c := must(sigfixture.Clone(sig))
			must0(sigfixture.SetSignature(c, b))
			g.add("btc/valid/"+name, local, kind, protocol.SignatureTypeBTC,
				"btc uses a lax DER parser: trailing bytes, non-minimal integers and high-S are all accepted by Accumulate", txn, c, nil, pageOf(c), "", "accepted")
		}
	}
	{
		k := g.key(protocol.SignatureTypeETH)
		txn := newTxn("eth rsv")
		sig := sign(k, txn, sigfixture.Opts{})
		xe := sig.(*protocol.ETHSignature)
		for name, b := range map[string][]byte{
			"rsv-65-v0":    append(append([]byte{}, xe.Signature...), 0),
			"rsv-65-v0x99": append(append([]byte{}, xe.Signature...), 0x99),
		} {
			c := must(sigfixture.Clone(sig))
			must0(sigfixture.SetSignature(c, b))
			g.add("eth/valid/"+name, local, kind, protocol.SignatureTypeETH,
				"a 65-byte r||s||v signature: the V byte is dropped and any V is accepted", txn, c, after("bvn1"), pageOf(c), "", "accepted")
		}
		xr, xs := new(big.Int).SetBytes(xe.Signature[:32]), new(big.Int).SetBytes(xe.Signature[32:])
		c := must(sigfixture.Clone(sig))
		must0(sigfixture.SetSignature(c, append(xr.FillBytes(make([]byte, 32)), new(big.Int).Sub(sigfixture.SecpN(), xs).FillBytes(make([]byte, 32))...)))
		g.add("eth/valid/high-s", local, kind, protocol.SignatureTypeETH, "high-S is accepted", txn, c, after("bvn1"), pageOf(c), "", "accepted")
		// the pre-baikonur DER form, before any proven activation
		d := must(sigfixture.Clone(sig))
		must0(sigfixture.SetSignature(d, sigfixture.EncodeDER(xr, xs)))
		g.add("eth/valid/v1-der-before-activation", local, kind, protocol.SignatureTypeETH,
			"the DER form is the pre-v2-baikonur rule; at a block before the partition's proven activation it verifies under that rule",
			txn, d, &sigfixture.Where{Partition: "bvn1", Block: 1000}, pageOf(d), "", "accepted")
	}
	{
		k := must(sigfixture.NewRSAKey(1024, rand.Reader))
		txn := newTxn("rsa 1024")
		sig := sign(k, txn, sigfixture.Opts{})
		g.add("rsaSha256/valid/modulus-1024", local, kind, protocol.SignatureTypeRsaSha256,
			"Accumulate sets no minimum modulus: a 1024-bit RSA key verifies", txn, sig, after("bvn1"), pageOf(sig), "", "accepted")
	}
}

func must0(err error) {
	if err != nil {
		panic(err)
	}
}

// ---------------------------------------------------------------------------------------------------------------------
// Kermit-delivered
// ---------------------------------------------------------------------------------------------------------------------

func (g *gen) kermit() {
	// 1. corpus case K (validator docs/l4/phase7_corpus/traces.json): a btc signature Kermit delivered.
	{
		pub := must(hex.DecodeString("039d1c74200a8e95b73a699e22de2d7a2df50a07b2556825d8a903811b1e964b68"))
		sg := must(hex.DecodeString("304402200db4b7d316e7664f97a6a32f4e220092e9a46a2627a7ef1dbb3b4cda0a55488d0220241f5a530d61f57f7042db890a20606ecfa58e911ef01d3b2a250e5bb6147153"))
		th := must(hex.DecodeString("06195913c2ee872b15c39aa3e845ab29d03aa68b369f6ea6b6be0c2cfe4558f2"))
		s := &protocol.BTCSignature{PublicKey: pub, Signature: sg, Signer: sigfixture.MustURL("acc://certen-p7k.acme/book/1"), SignerVersion: 2, Timestamp: 1787690569949632}
		copy(s.TransactionHash[:], th)
		g.kermitVector("btc/kermit/case-k", protocol.SignatureTypeBTC,
			"corpus case K: a btc signature Kermit delivered (tx 06195913...58f2, signer certen-p7k.acme/book/1, BVN2). The validator refused it as unsupported until RB8-B.",
			s, nil, "accepted")
	}
	// 2. an ecdsaSha256 signature Kermit delivered (tcl1 tx d2338dac..., R8 M4), recorded at BVN block 13,561,925 on 2026-10-04.
	{
		js := `{"type":"ecdsaSha256","publicKey":"3059301306072a8648ce3d020106082a8648ce3d03010703420004e4f697355c67b1555676809053087a0e3ae2eaccc9e2d73113513c1b965d45a7c9cbdb22711b980787ef7031e77c1fa8c806e1a87885b954276f9dd711f44cb3","signature":"3045022100fa8872a4f89462e60f6f7b89a2b44f0a57d9204722715b126342debff421945202205d8fb34a4804717bf6ea5c1c109f108492a65a8797da27f6184621a323b5db4a","signer":"acc://northfield-inspection-tcl1.acme/book/1","signerVersion":6,"timestamp":1791119727023000,"transactionHash":"d2338dacb8849cc96fae1928a01294c246408c0acca95323ae57a4b2156ace2e"}`
		sig := must(protocol.UnmarshalSignatureJSON([]byte(js)))
		net := must(govsig.ParseNetworkStatus([]byte(kermitNetworkStatus)))
		part := must(net.Partition("acc://northfield-inspection-tcl1.acme/book/1"))
		where := &sigfixture.Where{Partition: part, Block: 13_561_925}
		// the signer page's entry, as Kermit served it at signerVersion 6 (R8 M4)
		page := &sigfixture.Page{Entries: []string{"2d35d3848f922e6095be4e78501cdff51dec7641194a77cc867bc7cc52b2a00e"}}
		g.kermitVector("ecdsaSha256/kermit/northfield-inspection", protocol.SignatureTypeEcdsaSha256,
			"an ecdsaSha256 signature Kermit delivered (tcl1 tx d2338dac...ce2e, signer northfield-inspection-tcl1.acme/book/1 v6, recorded at local block 13,561,925, 2026-10-04T13:15:28Z). The validator refused it as unsupported until RB8-B (G-42, scene SP-14).",
			sig, where, "accepted", page)
		g.kermitVector("ecdsaSha256/kermit/northfield-inspection-wrong-page", protocol.SignatureTypeEcdsaSha256,
			"the same Kermit-delivered signature judged against a page that does not hold its key",
			sig, where, "refused:key_not_on_page", &sigfixture.Page{Entries: []string{strings.Repeat("00", 32)}})
		g.kermitVector("ecdsaSha256/kermit/northfield-inspection-before-activation", protocol.SignatureTypeEcdsaSha256,
			"the same signature presented as recorded before its partition's proven executor activation: the version is unproven",
			sig, &sigfixture.Where{Partition: part, Block: govsig.KermitActivations()[part].Block - 1}, "named:g1_executor_version_unproven", page)
	}
}

func (g *gen) kermitVector(id string, ty protocol.SignatureType, desc string, sig protocol.Signature, where *sigfixture.Where, want string, page ...*sigfixture.Page) {
	th := sig.GetTransactionHash()
	bin := must(sig.MarshalBinary())
	js := must(json.Marshal(sig))
	v := sigfixture.Vector{ID: id, Source: sigfixture.SourceKermit, Kind: "valid", Type: ty.String(), Description: desc,
		TxHash: hex.EncodeToString(th[:]), Signature: hex.EncodeToString(bin), SignatureJSON: js, Where: where}
	if len(page) > 0 {
		v.Page = page[0]
	}
	if want != "accepted" {
		v.Kind = "adversarial"
	}
	g.finish(v, want)
}

// ---------------------------------------------------------------------------------------------------------------------
// adversarial
// ---------------------------------------------------------------------------------------------------------------------

func (g *gen) adversarial() {
	local, kind := sigfixture.SourceLocal, "adversarial"
	for _, ty := range types {
		k := g.key(ty)
		var where *sigfixture.Where
		if gated(ty) {
			where = after("bvn2")
		}
		net := ""
		if ty == protocol.SignatureTypeTypedData {
			net = "DevNet"
		}
		txn := newTxn(fmt.Sprintf("%v adversarial", ty))
		sig := sign(k, txn, sigfixture.Opts{})

		// correct key, the transaction it did not sign
		other := newTxn(fmt.Sprintf("%v is not what was signed", ty))
		o := sigfixture.Vector{}
		_ = o
		g.addAgainst(fmt.Sprintf("%v/adversarial/wrong-transaction", ty), ty, "the signature presented against a transaction it did not sign", other, sig, where, nil, net, "refused:signature_invalid")

		// a flipped bit in the signature
		flipped := must(sigfixture.Clone(sig))
		sb := append([]byte{}, sigfixture.Inner(flipped).(protocol.KeySignature).GetSignature()...)
		sb[len(sb)/2] ^= 0x01
		must0(sigfixture.SetSignature(flipped, sb))
		g.add(fmt.Sprintf("%v/adversarial/flipped-bit", ty), local, kind, ty, "one bit of the signature flipped", txn, flipped, where, pageOf(flipped), net, "refused:signature_invalid")

		// the right signature, a page that holds another key of the same type
		otherSig := sign(g.freshKey(ty), txn, sigfixture.Opts{})
		g.add(fmt.Sprintf("%v/adversarial/wrong-key-on-page", ty), local, kind, ty,
			"a valid signature whose key is not on the signer page (the page holds another key of the same type)",
			txn, sig, where, pageOf(otherSig), net, "refused:key_not_on_page")

		// the page holds sha256(key): right for ed25519/legacy/rsa/ecdsa, wrong for the other five
		pub := sigfixture.Inner(sig).(protocol.KeySignature).GetPublicKey()
		sum := sha256.Sum256(pub)
		if hex.EncodeToString(sum[:]) != hex.EncodeToString(sigfixture.Inner(sig).(protocol.KeySignature).GetPublicKeyHash()) {
			g.add(fmt.Sprintf("%v/adversarial/sha256-key-hash-on-page", ty), local, kind, ty,
				"the page holds sha256(public key), which is NOT this type's page-entry hash: the key is not a member",
				txn, sig, where, &sigfixture.Page{Entries: []string{hex.EncodeToString(sum[:])}}, net, "refused:key_not_on_page")
		}

		// one layer deeper than Accumulate allows
		deep := sign(k, txn, sigfixture.Opts{Delegators: deleg(protocol.DelegationDepthLimit + 1)})
		if ty == protocol.SignatureTypeED25519 || ty == protocol.SignatureTypeEcdsaSha256 || ty == protocol.SignatureTypeTypedData {
			g.add(fmt.Sprintf("%v/adversarial/delegated-21", ty), local, kind, ty, "21 delegators: one more than DelegationDepthLimit",
				txn, deep, where, pageOf(deep), net, "refused:delegation_depth_exceeded")
		}
	}

	// type labels swapped: the type tag is the first field of the signed metadata
	{
		txn := newTxn("label swap")
		ed := sign(g.key(protocol.SignatureTypeED25519), txn, sigfixture.Opts{}).(*protocol.ED25519Signature)
		ec := sign(g.key(protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{}).(*protocol.EcdsaSha256Signature)
		sv := func(s protocol.Signature) *sigfixture.Where { return after("bvn1") }
		for name, s := range map[string]protocol.Signature{
			"ed25519-bytes-as-ecdsaSha256": &protocol.EcdsaSha256Signature{PublicKey: ed.PublicKey, Signature: ed.Signature, Signer: ed.Signer, SignerVersion: ed.SignerVersion, Timestamp: ed.Timestamp},
			"ed25519-bytes-as-rsaSha256":   &protocol.RsaSha256Signature{PublicKey: ed.PublicKey, Signature: ed.Signature, Signer: ed.Signer, SignerVersion: ed.SignerVersion, Timestamp: ed.Timestamp},
			"ed25519-bytes-as-rcd1":        &protocol.RCD1Signature{PublicKey: ed.PublicKey, Signature: ed.Signature, Signer: ed.Signer, SignerVersion: ed.SignerVersion, Timestamp: ed.Timestamp},
			"ed25519-bytes-as-legacy":      &protocol.LegacyED25519Signature{PublicKey: ed.PublicKey, Signature: ed.Signature, Signer: ed.Signer, SignerVersion: ed.SignerVersion, Timestamp: ed.Timestamp},
			"ecdsa-bytes-as-ed25519":       &protocol.ED25519Signature{PublicKey: ec.PublicKey, Signature: ec.Signature, Signer: ec.Signer, SignerVersion: ec.SignerVersion, Timestamp: ec.Timestamp},
			"ecdsa-bytes-as-rsaSha256":     &protocol.RsaSha256Signature{PublicKey: ec.PublicKey, Signature: ec.Signature, Signer: ec.Signer, SignerVersion: ec.SignerVersion, Timestamp: ec.Timestamp},
		} {
			g.add("label-swap/"+name, local, kind, s.Type(), "the bytes of one type presented under another type's label", txn, s, sv(s), nil, "", "refused:signature_invalid")
		}
	}

	// malleability Accumulate refuses
	{
		txn := newTxn("refused forms")
		ed := sign(g.key(protocol.SignatureTypeED25519), txn, sigfixture.Opts{})
		must0(sigfixture.SetSignature(ed, sigfixture.EdAddL(sigfixture.Inner(ed).(*protocol.ED25519Signature).Signature)))
		g.add("ed25519/adversarial/s-plus-l", local, kind, protocol.SignatureTypeED25519, "the scalar S replaced by S+L: non-canonical, refused by Go's ed25519.Verify", txn, ed, nil, nil, "", "refused:signature_invalid")

		ec := sign(g.key(protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{})
		ecs := sigfixture.Inner(ec).(*protocol.EcdsaSha256Signature)
		r, s := sigfixture.ParseDER(ecs.Signature)
		for name, b := range map[string][]byte{
			"trailing-byte":   append(append([]byte{}, ecs.Signature...), 0),
			"raw-rs":          append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...),
			"non-minimal-der": sigfixture.NonMinimalDER(r, s),
		} {
			c := must(sigfixture.Clone(ec))
			must0(sigfixture.SetSignature(c, b))
			g.add("ecdsaSha256/adversarial/"+name, local, kind, protocol.SignatureTypeEcdsaSha256, "ecdsaSha256 uses strict ASN.1 (ecdsa.VerifyASN1): this form is refused", txn, c, after("bvn1"), nil, "", "refused:signature_invalid")
		}
		bp := &protocol.EcdsaSha256Signature{PublicKey: sigfixture.BrainpoolSPKI(), Signature: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
			Signer: sigfixture.MustURL("acc://probe.acme/book/1"), SignerVersion: 1, Timestamp: 1700000000000}
		g.add("ecdsaSha256/adversarial/brainpool-key", local, kind, protocol.SignatureTypeEcdsaSha256,
			"a brainpoolP256r1 key: the enum text names Brainpool, Go's x509.ParsePKIXPublicKey does not parse it, so Accumulate's Verify is false", txn, bp, after("bvn1"), nil, "", "refused:signature_invalid")

		bt := sign(g.key(protocol.SignatureTypeBTC), txn, sigfixture.Opts{})
		br, bs := sigfixture.ParseDER(sigfixture.Inner(bt).(*protocol.BTCSignature).Signature)
		c := must(sigfixture.Clone(bt))
		must0(sigfixture.SetSignature(c, append(br.FillBytes(make([]byte, 32)), bs.FillBytes(make([]byte, 32))...)))
		g.add("btc/adversarial/raw-rs", local, kind, protocol.SignatureTypeBTC, "btc needs DER: raw r||s is refused", txn, c, nil, nil, "", "refused:signature_invalid")

		xe := sign(g.key(protocol.SignatureTypeETH), txn, sigfixture.Opts{})
		xs := sigfixture.Inner(xe).(*protocol.ETHSignature).Signature
		c63 := must(sigfixture.Clone(xe))
		must0(sigfixture.SetSignature(c63, xs[:63]))
		g.add("eth/adversarial/length-63", local, kind, protocol.SignatureTypeETH, "63 bytes: neither 64 nor 65", txn, c63, after("bvn1"), nil, "", "refused:signature_invalid")
		c66 := must(sigfixture.Clone(xe))
		must0(sigfixture.SetSignature(c66, append(append([]byte{}, xs...), 0, 0)))
		g.add("eth/adversarial/length-66", local, kind, protocol.SignatureTypeETH, "66 bytes: neither 64 nor 65", txn, c66, after("bvn1"), nil, "", "refused:signature_invalid")
		xr, xv := new(big.Int).SetBytes(xs[:32]), new(big.Int).SetBytes(xs[32:])
		cd := must(sigfixture.Clone(xe))
		must0(sigfixture.SetSignature(cd, sigfixture.EncodeDER(xr, xv)))
		g.add("eth/adversarial/der-after-baikonur", local, kind, protocol.SignatureTypeETH,
			"the pre-v2-baikonur DER form at a block where the executor is proven to be at v2-kourou: it cannot have been accepted", txn, cd, after("bvn1"), nil, "", "refused:executor_gate_not_met")

		rs := sign(g.key(protocol.SignatureTypeRsaSha256), txn, sigfixture.Opts{})
		rr := sigfixture.Inner(rs).(*protocol.RsaSha256Signature)
		short := must(sigfixture.Clone(rs))
		must0(sigfixture.SetSignature(short, rr.Signature[:len(rr.Signature)-1]))
		g.add("rsaSha256/adversarial/one-byte-short", local, kind, protocol.SignatureTypeRsaSha256, "the signature must be exactly the modulus size", txn, short, after("bvn1"), nil, "", "refused:signature_invalid")
		lead := must(sigfixture.Clone(rs))
		must0(sigfixture.SetSignature(lead, append([]byte{0}, rr.Signature...)))
		g.add("rsaSha256/adversarial/leading-zero-byte", local, kind, protocol.SignatureTypeRsaSha256, "one byte too long", txn, lead, after("bvn1"), nil, "", "refused:signature_invalid")
		pk := must(sigfixture.Clone(rs))
		pk.(*protocol.RsaSha256Signature).PublicKey = sigfixture.PKCS1ToPKIX(rr.PublicKey)
		g.add("rsaSha256/adversarial/pkix-key", local, kind, protocol.SignatureTypeRsaSha256, "the key must be a PKCS#1 RSAPublicKey; a PKIX SPKI of the same key is refused", txn, pk, after("bvn1"), nil, "", "refused:signature_invalid")
	}

	// typedData
	{
		k := g.key(protocol.SignatureTypeTypedData)
		txn := newTxn("typed adversarial")
		sig := sign(k, txn, sigfixture.Opts{})
		w := after("bvn1")
		otherTxn := newTxn("typed: a different transaction")
		g.addAgainst("typedData/adversarial/different-transaction", protocol.SignatureTypeTypedData, "the EIP-712 encoding covers the whole transaction: another transaction's body does not verify", otherTxn, sig, w, nil, "DevNet", "refused:signature_invalid")
		g.add("typedData/adversarial/chain-id-1", local, kind, protocol.SignatureTypeTypedData,
			"signed under chain id 1: verifies cryptographically, refused by the executor's chain-id check",
			txn, sign(k, txn, sigfixture.Opts{ChainID: big.NewInt(1)}), w, nil, "DevNet", "refused:typed_data_chain_id_mismatch")
		g.add("typedData/adversarial/other-network", local, kind, protocol.SignatureTypeTypedData, "a DevNet signature judged on mainnet", txn, sig, w, nil, "mainnet", "refused:typed_data_chain_id_mismatch")
		g.add("typedData/adversarial/no-network-name", local, kind, protocol.SignatureTypeTypedData, "no network name: the chain id cannot be checked - a named state", txn, sig, w, nil, "", "named:network_name_unproven")
		memo := must(sigfixture.Clone(sig))
		memo.(*protocol.TypedDataSignature).Memo = "added after signing"
		g.add("typedData/adversarial/memo-added-after", local, kind, protocol.SignatureTypeTypedData, "memo is inside the signed message", txn, memo, w, nil, "DevNet", "refused:signature_invalid")

		// delegators swapped / an extra unsigned wrapper
		d2 := sign(k, txn, sigfixture.Opts{Delegators: deleg(2)})
		sw := must(sigfixture.Clone(d2)).(*protocol.DelegatedSignature)
		inn := sw.Signature.(*protocol.DelegatedSignature)
		sw.Delegator, inn.Delegator = inn.Delegator, sw.Delegator
		g.add("typedData/adversarial/delegators-swapped", local, kind, protocol.SignatureTypeTypedData, "the delegators are inside the signed message, outermost first: swapped order fails", txn, sw, w, nil, "DevNet", "refused:signature_invalid")
		extra := &protocol.DelegatedSignature{Delegator: sigfixture.MustURL("acc://unsigned.acme/book/1"), Signature: must(sigfixture.Clone(d2))}
		g.add("typedData/adversarial/extra-unsigned-wrapper", local, kind, protocol.SignatureTypeTypedData, "an extra delegation wrapper that the key did not sign", txn, extra, w, nil, "DevNet", "refused:signature_invalid")
	}

	// the gate
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData, protocol.SignatureTypeETH} {
		k := g.key(ty)
		txn := newTxn(fmt.Sprintf("%v gate", ty))
		sig := sign(k, txn, sigfixture.Opts{})
		net := ""
		if ty == protocol.SignatureTypeTypedData {
			net = "DevNet"
		}
		act := govsig.KermitActivations()["bvn3"].Block
		desc := "needs executor version v2-vandenberg (v2-baikonur for eth's raw r||s rule)"
		g.add(fmt.Sprintf("%v/gate/before-activation", ty), sigfixture.SourceLocal, "adversarial", ty, desc+": recorded one block before the partition's proven activation",
			txn, sig, &sigfixture.Where{Partition: "bvn3", Block: act - 1}, nil, net, "named:g1_executor_version_unproven")
		g.add(fmt.Sprintf("%v/gate/at-activation-block", ty), sigfixture.SourceLocal, "adversarial", ty, desc+": at the activation block itself - not yet proven (the table records the block the activation was received in)",
			txn, sig, &sigfixture.Where{Partition: "bvn3", Block: act}, nil, net, "named:g1_executor_version_unproven")
		g.add(fmt.Sprintf("%v/gate/no-location", ty), sigfixture.SourceLocal, "adversarial", ty, desc+": no partition or block named",
			txn, sig, nil, nil, net, "named:g1_executor_version_unproven")
		g.add(fmt.Sprintf("%v/gate/after-activation", ty), sigfixture.SourceLocal, "valid", ty, desc+": one block after the activation",
			txn, sig, &sigfixture.Where{Partition: "bvn3", Block: act + 1}, nil, net, "accepted")
	}
	{
		k := g.key(protocol.SignatureTypeEcdsaSha256)
		txn := newTxn("per partition")
		sig := sign(k, txn, sigfixture.Opts{})
		g.add("ecdsaSha256/gate/directory-block-10000000", sigfixture.SourceLocal, "valid", protocol.SignatureTypeEcdsaSha256,
			"block 10,000,000 is after the Directory's activation (9,538,105)", txn, sig, &sigfixture.Where{Partition: "directory", Block: 10_000_000}, nil, "", "accepted")
		g.add("ecdsaSha256/gate/bvn1-block-10000000", sigfixture.SourceLocal, "adversarial", protocol.SignatureTypeEcdsaSha256,
			"block 10,000,000 is long before BVN1's activation (12,491,272): block numbers are per partition", txn, sig, &sigfixture.Where{Partition: "bvn1", Block: 10_000_000}, nil, "", "named:g1_executor_version_unproven")
	}

	// non-key types presented as key signatures
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeAuthority, protocol.SignatureTypePartition, protocol.SignatureTypeReceipt,
		protocol.SignatureTypeRemote, protocol.SignatureTypeInternal, protocol.SignatureTypeSet} {
		txn := newTxn("non-key")
		s := must(protocol.NewSignature(ty))
		g.add(fmt.Sprintf("non-key/%v", ty), sigfixture.SourceLocal, "adversarial", ty, "not a KeySignature in Accumulate: never a key's vote", txn, s, nil, nil, "", "refused:not_a_key_signature")
		d := &protocol.DelegatedSignature{Delegator: sigfixture.MustURL("acc://d.acme/book/1"), Signature: must(protocol.NewSignature(ty))}
		g.add(fmt.Sprintf("non-key/delegated-%v", ty), sigfixture.SourceLocal, "adversarial", ty, "a delegation whose core is not a key signature", txn, d, nil, nil, "", "refused:not_a_key_signature")
	}
}

// addAgainst presents sig against txn (a different transaction from the one it signed).
func (g *gen) addAgainst(id string, ty protocol.SignatureType, desc string, txn *protocol.Transaction, sig protocol.Signature,
	where *sigfixture.Where, page *sigfixture.Page, network, want string) {
	g.add(id, sigfixture.SourceLocal, "adversarial", ty, desc, txn, sig, where, page, network, want)
}

// ---------------------------------------------------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------------------------------------------------

func (g *gen) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	pinned := sigfixture.Pinned{Accumulate: pinnedModule, Commit: pinnedCommit, Network: "DevNet", ChainID: protocol.EthChainID("DevNet").String()}
	groups := []struct {
		name, desc string
		pick       func(sigfixture.Vector) bool
	}{
		{"valid.json", "signatures Accumulate's executor accepts, every key type, direct and delegated", func(v sigfixture.Vector) bool {
			return v.Source == sigfixture.SourceLocal && v.Expect.Verdict == "accepted"
		}},
		{"adversarial.json", "signatures and evidence that must be refused, or must be a named state", func(v sigfixture.Vector) bool {
			return v.Source == sigfixture.SourceLocal && v.Expect.Verdict != "accepted"
		}},
		{"kermit.json", "signatures Kermit delivered, as the network served them", func(v sigfixture.Vector) bool { return v.Source == sigfixture.SourceKermit }},
	}
	var m sigfixture.Manifest
	m.Format = "certen:sigtypes-manifest:v1"
	m.Sources = map[string]int{}
	for _, gr := range groups {
		vf := sigfixture.VectorFile{Format: sigfixture.VectorFormat, Description: gr.desc, Pinned: pinned}
		for _, v := range g.vectors {
			if gr.pick(v) {
				vf.Vectors = append(vf.Vectors, v)
				m.Sources[v.Source]++
			}
		}
		b, err := json.MarshalIndent(vf, "", " ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(dir, gr.name), b, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, sigfixture.ManifestFile{Name: gr.name, SHA256: hex.EncodeToString(sum[:]), Vectors: len(vf.Vectors)})
		m.Count += len(vf.Vectors)
	}
	if m.Count != len(g.vectors) {
		return fmt.Errorf("%d vectors written of %d made", m.Count, len(g.vectors))
	}
	m.Hash = sigfixture.ManifestHash(m.Files)
	m.Note = "Written by cmd/sigtypevectors. Source 'kermit-delivered' = real signatures delivered by Kermit (btc: corpus case K; ecdsaSha256: tcl1 tx d2338dac...), " +
		"carried as the JSON the network served with the binary encoding derived by Accumulate's own marshaller. Source 'locally-generated' = made with " +
		"Accumulate's own signing code with keys generated for these vectors. Every verdict was produced by Accumulate's own Verify (protocol.VerifyUserSignature) " +
		"through govsig.Verify. The TypeScript verifier must reach the same verdict, key hash and digest form on every vector."
	mb, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d vectors (%v) to %s; manifest hash %s\n", m.Count, m.Sources, dir, m.Hash)
	return nil
}
