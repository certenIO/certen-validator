// Copyright 2026 Certen Protocol

package govsig_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// kourou is a place that is proven to be under v2-kourou on BVN1.
var kourou = govsig.Where{Partition: "bvn1", Block: govsig.KermitActivations()["bvn1"].Block + 1}

func mustKey(t *testing.T, ty protocol.SignatureType) sigfixture.Key {
	t.Helper()
	k, err := sigfixture.NewKey(ty, rand.Reader)
	if err != nil {
		t.Fatalf("key %v: %v", ty, err)
	}
	return k
}

func env(txn *protocol.Transaction) govsig.Env {
	return govsig.Env{TxHash: txn.Hash(), Transaction: txn, NetworkName: "DevNet", Where: kourou}
}

// The registry is a reviewed mirror of Accumulate's executor registry. When protocol gains a KeySignature type the
// list does not name, a counted vote could be one Accumulate accepts and CERTEN refuses (or the reverse): fail loudly.
func TestRegistryMirrorsProtocol(t *testing.T) {
	var inProtocol, listed []string
	for _, ty := range govsig.KeySignatureTypesInProtocol() {
		inProtocol = append(inProtocol, ty.String())
	}
	for _, ty := range govsig.AcceptedKeyTypes() {
		listed = append(listed, ty.String())
		if !govsig.IsAcceptedKeyType(ty) {
			t.Errorf("%v is listed but IsAcceptedKeyType refuses it", ty)
		}
	}
	sort.Strings(inProtocol)
	sort.Strings(listed)
	if strings.Join(inProtocol, ",") != strings.Join(listed, ",") {
		t.Fatalf("protocol's KeySignature types %v are not the accepted set %v", inProtocol, listed)
	}
	if len(listed) != 9 {
		t.Fatalf("R8 derives nine key-signature types, the registry lists %d: %v", len(listed), listed)
	}
}

func TestClassifyEveryNameAccumulateDefines(t *testing.T) {
	for name, want := range map[string]govsig.Class{
		"ed25519": govsig.ClassKey, "legacyED25519": govsig.ClassKey, "rcd1": govsig.ClassKey,
		"btc": govsig.ClassKey, "btcLegacy": govsig.ClassKey, "eth": govsig.ClassKey,
		"rsaSha256": govsig.ClassKey, "ecdsaSha256": govsig.ClassKey, "typedData": govsig.ClassKey,
		"ECDSASHA256": govsig.ClassKey,
		"delegated":   govsig.ClassDelegated,
		"authority":   govsig.ClassNotKey, "partition": govsig.ClassNotKey, "synthetic": govsig.ClassNotKey,
		"receipt": govsig.ClassNotKey, "remote": govsig.ClassNotKey, "internal": govsig.ClassNotKey,
		"set": govsig.ClassNotKey, "signatureRequest": govsig.ClassNotKey, "creditPayment": govsig.ClassNotKey,
		"unknown": govsig.ClassUnknown, "": govsig.ClassUnknown, "blsSignature": govsig.ClassUnknown,
	} {
		if _, got := govsig.Classify(name); got != want {
			t.Errorf("Classify(%q) = %v, want %v", name, got, want)
		}
	}
}

// Every accepted type verifies, directly and under delegation, over each digest the type has, with the key hash the
// type's own rule gives.
func TestVerifyEveryAcceptedType(t *testing.T) {
	deleg := []string{"acc://a.acme/book/1", "acc://b.acme/book/1"}
	for _, ty := range govsig.AcceptedKeyTypes() {
		k := mustKey(t, ty)
		for _, nd := range []int{0, 1, 2} {
			for _, merkle := range []bool{false, true} {
				if merkle && (ty == protocol.SignatureTypeRsaSha256 || ty == protocol.SignatureTypeEcdsaSha256 || ty == protocol.SignatureTypeTypedData) {
					continue // no merkle initiator for these
				}
				t.Run(fmt.Sprintf("%v/delegators=%d/merkle=%v", ty, nd, merkle), func(t *testing.T) {
					txn := sigfixture.Txn("acc://probe.acme/data", "vector")
					sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{Delegators: deleg[:nd], Merkle: merkle})
					if err != nil {
						t.Fatal(err)
					}
					v, err := govsig.Verify(sig, env(txn))
					if err != nil {
						t.Fatalf("a valid %v signature was refused: %v", ty, err)
					}
					if v.Inner.Type() != ty {
						t.Fatalf("inner type %v, want %v", v.Inner.Type(), ty)
					}
					want, _ := protocol.PublicKeyHash(v.Inner.GetPublicKey(), ty)
					if string(v.KeyHash) != string(want) || len(want) == 0 {
						t.Fatalf("key hash %x, protocol says %x", v.KeyHash, want)
					}
					if len(v.Delegators) != nd {
						t.Fatalf("%d delegators recovered, want %d", len(v.Delegators), nd)
					}
					wantForm := govsig.FormMetadata
					if merkle {
						wantForm = govsig.FormMerkle
					}
					if ty == protocol.SignatureTypeTypedData {
						wantForm = govsig.FormEIP712
					}
					if v.Form != wantForm {
						t.Fatalf("digest form %q, want %q", v.Form, wantForm)
					}
				})
			}
		}
	}
}

// A key hash is the type's own: sha256(key) is right for four types and wrong for the other five (R8 E9).
func TestKeyHashIsNotAlwaysSha256(t *testing.T) {
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC,
		protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH, protocol.SignatureTypeTypedData} {
		k := mustKey(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "x")
		sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		v, err := govsig.Verify(sig, env(txn))
		if err != nil {
			t.Fatal(err)
		}
		if len(v.KeyHash) == 32 && ty != protocol.SignatureTypeRCD1 {
			t.Errorf("%v: a 32-byte key hash %x is sha256-shaped; the type's rule gives 20 bytes", ty, v.KeyHash)
		}
	}
}

// The 20-deep chain is Accumulate's limit and verifies for every type; 21 is refused by name.
func TestDelegationDepthLimitForEveryType(t *testing.T) {
	chain := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("acc://d%d.acme/book/1", i)
		}
		return out
	}
	for _, ty := range govsig.AcceptedKeyTypes() {
		k := mustKey(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "deep")
		at, err := sigfixture.Sign(k, txn, sigfixture.Opts{Delegators: chain(protocol.DelegationDepthLimit)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := govsig.Verify(at, env(txn)); err != nil {
			t.Errorf("%v: a %d-deep chain is within Accumulate's limit and was refused: %v", ty, protocol.DelegationDepthLimit, err)
		}
		over, err := sigfixture.Sign(k, txn, sigfixture.Opts{Delegators: chain(protocol.DelegationDepthLimit + 1)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = govsig.Verify(over, env(txn))
		var d govsig.DepthExceeded
		if !errors.As(err, &d) || d.Depth != protocol.DelegationDepthLimit+1 || d.Limit != protocol.DelegationDepthLimit {
			t.Errorf("%v: a %d-deep chain must be refused for its depth, got %v", ty, protocol.DelegationDepthLimit+1, err)
		}
	}
}

// Correct key, the digest of a DIFFERENT transaction: a genuine rejection, never an unsupported-type or gate state.
func TestCorrectKeyWrongTransaction(t *testing.T) {
	for _, ty := range govsig.AcceptedKeyTypes() {
		k := mustKey(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "signed")
		other := sigfixture.Txn("acc://probe.acme/data", "something else")
		sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = govsig.Verify(sig, env(other))
		var inv govsig.SignatureInvalid
		if !errors.As(err, &inv) {
			t.Errorf("%v over a different transaction must be SignatureInvalid, got %v", ty, err)
		}
	}
}

// typedData over a different transaction is invalid; without the transaction it cannot be verified at all, and says so.
func TestTypedDataNeedsTheWholeTransaction(t *testing.T) {
	k := mustKey(t, protocol.SignatureTypeTypedData)
	txn := sigfixture.Txn("acc://probe.acme/data", "signed")
	sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	e := env(txn)
	e.Transaction = nil
	if _, err := govsig.Verify(sig, e); !errors.As(err, new(govsig.TransactionUnavailableForTypedData)) {
		t.Fatalf("a typedData signature with no transaction must be the named state, got %v", err)
	}
	other := sigfixture.Txn("acc://probe.acme/data", "different body")
	if _, err := govsig.Verify(sig, env(other)); !errors.As(err, new(govsig.SignatureInvalid)) {
		t.Fatalf("typedData over a different transaction must be invalid, got %v", err)
	}
}

// The chain id is part of the signature and the domain; the executor refuses a mismatch although the signature
// verifies cryptographically under any chain id (R8 E12).
func TestTypedDataChainID(t *testing.T) {
	k := mustKey(t, protocol.SignatureTypeTypedData)
	txn := sigfixture.Txn("acc://probe.acme/data", "signed")
	sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{ChainID: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.VerifyUserSignature(sig.(protocol.UserSignature), txn) {
		t.Fatal("precondition: the chain-id-1 signature verifies cryptographically")
	}
	_, err = govsig.Verify(sig, env(txn))
	var mm govsig.TypedDataChainIDMismatch
	if !errors.As(err, &mm) || mm.Got != "1" || mm.Want != protocol.EthChainID("DevNet").String() {
		t.Fatalf("a typedData signature under chain id 1 must be refused for its chain id, got %v", err)
	}
	good, _ := sigfixture.Sign(k, txn, sigfixture.Opts{})
	e := env(txn)
	e.NetworkName = ""
	if _, err := govsig.Verify(good, e); !errors.As(err, new(govsig.NetworkNameUnproven)) {
		t.Fatalf("no network name must be the named state, got %v", err)
	}
	e.NetworkName = "mainnet"
	if _, err := govsig.Verify(good, e); !errors.As(err, new(govsig.TypedDataChainIDMismatch)) {
		t.Fatalf("a DevNet signature must not verify as mainnet's, got %v", err)
	}
}

// A signature's bytes relabelled as another type never verify: the type tag is the first field of the signed metadata.
func TestTypeLabelSwapped(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "swap")
	ec, _ := sigfixture.Sign(mustKey(t, protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{})
	ed, _ := sigfixture.Sign(mustKey(t, protocol.SignatureTypeED25519), txn, sigfixture.Opts{})
	e := ec.(*protocol.EcdsaSha256Signature)
	d := ed.(*protocol.ED25519Signature)
	for name, s := range map[string]protocol.Signature{
		"ecdsa bytes as ed25519": &protocol.ED25519Signature{PublicKey: e.PublicKey, Signature: e.Signature, Signer: e.Signer, SignerVersion: e.SignerVersion, Timestamp: e.Timestamp},
		"ed25519 as ecdsa":       &protocol.EcdsaSha256Signature{PublicKey: d.PublicKey, Signature: d.Signature, Signer: d.Signer, SignerVersion: d.SignerVersion, Timestamp: d.Timestamp},
		"ed25519 as rsa":         &protocol.RsaSha256Signature{PublicKey: d.PublicKey, Signature: d.Signature, Signer: d.Signer, SignerVersion: d.SignerVersion, Timestamp: d.Timestamp},
		"ed25519 as rcd1":        &protocol.RCD1Signature{PublicKey: d.PublicKey, Signature: d.Signature, Signer: d.Signer, SignerVersion: d.SignerVersion, Timestamp: d.Timestamp},
		"ed25519 as legacy":      &protocol.LegacyED25519Signature{PublicKey: d.PublicKey, Signature: d.Signature, Signer: d.Signer, SignerVersion: d.SignerVersion, Timestamp: d.Timestamp},
	} {
		if _, err := govsig.Verify(s, env(txn)); !errors.As(err, new(govsig.SignatureInvalid)) {
			t.Errorf("%s: must be SignatureInvalid, got %v", name, err)
		}
	}
}

// Accumulate's own malleability matrix (R8 E5), recorded as tests: CERTEN accepts exactly what Accumulate's Verify
// accepts - high-S, lax DER for btc/btclegacy, 64- and 65-byte eth - and refuses what it refuses.
func TestMalleabilityMatrixIsAccumulates(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "malleability")
	check := func(name string, sig protocol.Signature, want bool) {
		t.Helper()
		_, err := govsig.Verify(sig, env(txn))
		if got := err == nil; got != want {
			t.Errorf("%s: accepted=%v, Accumulate's Verify says %v (err=%v)", name, got, want, err)
		}
	}

	// ecdsaSha256: strict ASN.1; high-S accepted.
	ek := mustKey(t, protocol.SignatureTypeEcdsaSha256)
	es, _ := sigfixture.Sign(ek, txn, sigfixture.Opts{})
	ec := es.(*protocol.EcdsaSha256Signature)
	r, s := sigfixture.ParseDER(ec.Signature)
	n := elliptic.P256().Params().N
	flipped := *ec
	flipped.Signature = sigfixture.EncodeDER(r, new(big.Int).Sub(n, s))
	check("ecdsa high-S", &flipped, true)
	trailing := *ec
	trailing.Signature = append(append([]byte{}, ec.Signature...), 0)
	check("ecdsa trailing byte after DER", &trailing, false)
	raw := *ec
	raw.Signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	check("ecdsa raw r||s", &raw, false)
	nonmin := *ec
	nonmin.Signature = sigfixture.NonMinimalDER(r, s)
	check("ecdsa non-minimal DER", &nonmin, false)

	// btc: lax DER; trailing bytes and non-minimal integers accepted; high-S accepted; raw r||s refused.
	bk := mustKey(t, protocol.SignatureTypeBTC)
	bs, _ := sigfixture.Sign(bk, txn, sigfixture.Opts{})
	bt := bs.(*protocol.BTCSignature)
	br, bsv := sigfixture.ParseDER(bt.Signature)
	b1 := *bt
	b1.Signature = append(append([]byte{}, bt.Signature...), 0xde, 0xad)
	check("btc DER + trailing garbage", &b1, true)
	b2 := *bt
	b2.Signature = sigfixture.NonMinimalDER(br, bsv)
	check("btc non-minimal DER", &b2, true)
	b3 := *bt
	b3.Signature = sigfixture.EncodeDER(br, new(big.Int).Sub(sigfixture.SecpN(), bsv))
	check("btc high-S", &b3, true)
	b4 := *bt
	b4.Signature = append(br.FillBytes(make([]byte, 32)), bsv.FillBytes(make([]byte, 32))...)
	check("btc raw r||s", &b4, false)

	// eth (executor >= baikonur): 64 and 65 bytes, any V; 63/66 refused; DER refused by the V2 rule but accepted as a
	// pre-baikonur (V1) signature.
	xk := mustKey(t, protocol.SignatureTypeETH)
	xs, _ := sigfixture.Sign(xk, txn, sigfixture.Opts{})
	xe := xs.(*protocol.ETHSignature)
	check("eth 64", xe, true)
	for _, v := range []byte{0, 1, 0x99} {
		c := *xe
		c.Signature = append(append([]byte{}, xe.Signature...), v)
		check(fmt.Sprintf("eth 65 with V=%#x", v), &c, true)
	}
	c63 := *xe
	c63.Signature = xe.Signature[:63]
	check("eth 63", &c63, false)
	c66 := *xe
	c66.Signature = append(append([]byte{}, xe.Signature...), 0, 0)
	check("eth 66", &c66, false)
	xr, xsv := new(big.Int).SetBytes(xe.Signature[:32]), new(big.Int).SetBytes(xe.Signature[32:])
	chigh := *xe
	chigh.Signature = append(xr.FillBytes(make([]byte, 32)), new(big.Int).Sub(sigfixture.SecpN(), xsv).FillBytes(make([]byte, 32))...)
	check("eth high-S", &chigh, true)
	der := *xe
	der.Signature = sigfixture.EncodeDER(xr, xsv)
	v, err := govsig.Verify(&der, env(txn))
	if err == nil {
		t.Errorf("eth DER form after v2-baikonur was accepted (rule %q); a proven v2-kourou executor refuses it", v.EthRule)
	}
	if !errors.As(err, new(govsig.SignatureInvalid)) && !errors.As(err, new(govsig.ExecutorGateNotMet)) {
		t.Errorf("eth DER after baikonur must be refused as invalid or gate-not-met, got %v", err)
	}
	// before any proven activation the V1 rule is the one that could have applied
	e := env(txn)
	e.Where = govsig.Where{Partition: "bvn1", Block: 1000}
	if v, err := govsig.Verify(&der, e); err != nil || v.EthRule != govsig.EthRuleV1DER {
		t.Errorf("eth DER at an unproven early block must verify under the V1 rule, got %+v %v", v, err)
	}

	// ed25519: canonical S only (S+L refused).
	dk := mustKey(t, protocol.SignatureTypeED25519)
	dsg, _ := sigfixture.Sign(dk, txn, sigfixture.Opts{})
	dd := *dsg.(*protocol.ED25519Signature)
	dd.Signature = sigfixture.EdAddL(dd.Signature)
	check("ed25519 S+L", &dd, false)

	// rsaSha256: signature exactly the modulus size; PKCS#1 key (PKIX refused); any modulus size.
	rk := mustKey(t, protocol.SignatureTypeRsaSha256)
	rs, _ := sigfixture.Sign(rk, txn, sigfixture.Opts{})
	rr := rs.(*protocol.RsaSha256Signature)
	short := *rr
	short.Signature = rr.Signature[:len(rr.Signature)-1]
	check("rsa one byte short", &short, false)
	lead := *rr
	lead.Signature = append([]byte{0}, rr.Signature...)
	check("rsa leading zero byte", &lead, false)
	pkix := *rr
	pkix.PublicKey = sigfixture.PKCS1ToPKIX(rr.PublicKey)
	check("rsa PKIX key instead of PKCS#1", &pkix, false)
	rk1024, err := sigfixture.NewRSAKey(1024, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r1024, _ := sigfixture.Sign(rk1024, txn, sigfixture.Opts{})
	check("rsa-1024 (no minimum modulus)", r1024, true)
}

// Curves: Accumulate's ecdsaSha256 verifies whatever crypto/x509 parses as an ecdsa key; Brainpool is not among them,
// and the refusal is named (R8 O4).
func TestEcdsaCurves(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "curves")
	for name, c := range map[string]elliptic.Curve{"P-224": elliptic.P224(), "P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		k, err := sigfixture.NewECDSAKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := govsig.Verify(sig, env(txn)); err != nil {
			t.Errorf("%s: Accumulate verifies it, CERTEN refused: %v", name, err)
		}
	}
	// Brainpool P256r1: Go's x509.ParsePKIXPublicKey does not know the curve, so Accumulate's Verify is false and the
	// refusal is SignatureInvalid. The SPKI below is a brainpoolP256r1 key (OID 1.3.36.3.3.2.8.1.1.7).
	bp := &protocol.EcdsaSha256Signature{
		PublicKey: sigfixture.BrainpoolSPKI(), Signature: []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		Signer: sigfixture.MustURL("acc://probe.acme/book/1"), SignerVersion: 1, Timestamp: 1700000000000,
	}
	_, err := govsig.Verify(bp, env(txn))
	if !errors.As(err, new(govsig.SignatureInvalid)) {
		t.Errorf("a Brainpool key must be refused by name (Go's x509 parser does not accept it), got %v", err)
	}
}

// A value that is not a key signature at its core is never a vote, however it is presented.
func TestNonKeyTypesAreNotKeySignatures(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "nonkey")
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeAuthority, protocol.SignatureTypePartition,
		protocol.SignatureTypeReceipt, protocol.SignatureTypeRemote, protocol.SignatureTypeInternal, protocol.SignatureTypeSet} {
		v, err := protocol.NewSignature(ty)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := govsig.Verify(v, env(txn)); !errors.As(err, new(govsig.NotKeySignature)) {
			t.Errorf("%v must be NotKeySignature, got %v", ty, err)
		}
		// and as the core of a delegation
		d := &protocol.DelegatedSignature{Delegator: sigfixture.MustURL("acc://d.acme/book/1"), Signature: v}
		if _, err := govsig.Verify(d, env(txn)); !errors.As(err, new(govsig.NotKeySignature)) {
			t.Errorf("delegated %v must be NotKeySignature, got %v", ty, err)
		}
	}
}
