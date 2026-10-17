// Copyright 2026 Certen Protocol

package main

// RB8-B: every key-signature type Accumulate's executor accepts is verified from its bytes.
//
// The extraction and verification entry points are the ones that existed before RB8-B (ExtractSignatureFromMessageResult,
// ValidateSignature, sigFactOf, AcceptedDigests); verification goes through rb8Verify, the location-aware verifier
// (VerifySignature) the executor-version gate needs. The refusal rule these tests replace was "ed25519 and delegated
// only". The signatures are real: made with Accumulate's own signing code (govsig/sigfixture), serialised with
// protocol's own JSON, which is the v3 shape Kermit returns.
//
// typedData cannot be verified from a hash (it signs the EIP-712 encoding of the whole transaction); it is in
// rb8_typeddata_test.go.

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// rb8Types are the eight accepted types a transaction hash alone can verify.
var rb8Types = []protocol.SignatureType{
	protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeED25519, protocol.SignatureTypeRCD1,
	protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH,
	protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256,
}

func rb8Key(t *testing.T, ty protocol.SignatureType) sigfixture.Key {
	t.Helper()
	k, err := sigfixture.NewKey(ty, rand.Reader)
	if err != nil {
		t.Fatalf("key %v: %v", ty, err)
	}
	return k
}

func rb8Sign(t *testing.T, k sigfixture.Key, txn *protocol.Transaction, o sigfixture.Opts) protocol.Signature {
	t.Helper()
	sig, err := sigfixture.Sign(k, txn, o)
	if err != nil {
		t.Fatalf("sign %v: %v", k.Type, err)
	}
	return sig
}

func rb8Hex(txn *protocol.Transaction) string { return hex.EncodeToString(txn.GetHash()) }

// rb8Message is the signature message as Kermit's v3 API returns it: the signature in protocol's own JSON, the
// transaction it covers in txID.
func rb8Message(t *testing.T, sig protocol.Signature, txHashHex string) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return rb8MessageFromObject(m, txHashHex)
}

func rb8MessageFromObject(sig map[string]interface{}, txHashHex string) map[string]interface{} {
	return map[string]interface{}{"message": map[string]interface{}{
		"type": "signature", "signature": sig, "txID": "acc://" + txHashHex + "@probe.acme/data",
	}}
}

// rb8Extract is the whole online path for one signature: extraction from the message, then verification.
func rb8Extract(t *testing.T, sig protocol.Signature, txn *protocol.Transaction) (SignatureData, error) {
	t.Helper()
	return NewSignatureVerifier("").ExtractSignatureFromMessageResult(rb8Message(t, sig, rb8Hex(txn)))
}

func rb8KeyHashHex(sig protocol.Signature) string {
	inner := sigfixture.Inner(sig).(protocol.KeySignature)
	return hex.EncodeToString(inner.GetPublicKeyHash())
}

// Every accepted type, directly and under one and two delegators, is extracted and verified from its bytes.
func TestRB8_EveryKeyTypeIsExtractedAndVerifiedFromItsBytes(t *testing.T) {
	deleg := []string{"acc://a.acme/book/1", "acc://b.acme/book/1"}
	sv := rb8Verifier(t)
	for _, ty := range rb8Types {
		k := rb8Key(t, ty)
		for nd := 0; nd <= 2; nd++ {
			t.Run(fmt.Sprintf("%v/delegators=%d", ty, nd), func(t *testing.T) {
				txn := sigfixture.Txn("acc://probe.acme/data", "rb8")
				sig := rb8Sign(t, k, txn, sigfixture.Opts{Delegators: deleg[:nd]})
				sd, err := rb8Extract(t, sig, txn)
				if err != nil {
					t.Fatalf("a valid %v signature was refused at extraction: %v", ty, err)
				}
				wantType := strings.ToLower(ty.String())
				if nd > 0 {
					wantType = "delegated"
				}
				if sd.Type != wantType {
					t.Fatalf("recorded type %q, want %q", sd.Type, wantType)
				}
				form, err := rb8Verify(t, sv, sd, rb8Hex(txn))
				if err != nil {
					t.Fatalf("a valid %v signature failed verification: %v", ty, err)
				}
				if form != DigestFormMetadata && form != DigestFormMerkle {
					t.Fatalf("digest form %q", form)
				}
			})
		}
	}
}

// Both digest forms for every type that has both: the merkle initiator form is how the official builder initiates.
func TestRB8_BothDigestFormsAreVerified(t *testing.T) {
	sv := rb8Verifier(t)
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeED25519,
		protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH} {
		k := rb8Key(t, ty)
		for _, merkle := range []bool{false, true} {
			txn := sigfixture.Txn("acc://probe.acme/data", "forms")
			sig := rb8Sign(t, k, txn, sigfixture.Opts{Merkle: merkle})
			sd, err := rb8Extract(t, sig, txn)
			if err != nil {
				t.Fatalf("%v merkle=%v: %v", ty, merkle, err)
			}
			form, err := rb8Verify(t, sv, sd, rb8Hex(txn))
			want := DigestFormMetadata
			if merkle {
				want = DigestFormMerkle
			}
			if err != nil || form != want {
				t.Fatalf("%v merkle=%v: form %q err %v, want %q", ty, merkle, form, err, want)
			}
		}
	}
}

// The fact the vote model reads carries the type's own key hash, not sha256(key): that is wrong for rcd1, btc,
// btclegacy, eth and typedData, whose page entries are other hashes (R8 E9).
func TestRB8_VoteFactKeyHashIsTheTypesOwn(t *testing.T) {
	for _, ty := range rb8Types {
		k := rb8Key(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "keyhash")
		sig := rb8Sign(t, k, txn, sigfixture.Opts{})
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("%v: %v", ty, err)
		}
		f, isVote, err := sigFactOf(ValidatedSignature{MessageID: "acc://" + strings.Repeat("ab", 32) + "@probe.acme/book/1",
			Signature: sd, Receipt: ReceiptData{LocalBlock: 7}})
		if err != nil || !isVote {
			t.Fatalf("%v: fact %v %v", ty, isVote, err)
		}
		if f.KeyHash != rb8KeyHashHex(sig) {
			t.Errorf("%v: the vote fact's key hash is %s, the key page entry (protocol.PublicKeyHash) is %s", ty, f.KeyHash, rb8KeyHashHex(sig))
		}
	}
}

// A key on the page is a member by the type's own hash; a different key of the same type is not.
func TestRB8_WrongKeyOnPage(t *testing.T) {
	sv := rb8Verifier(t)
	for _, ty := range rb8Types {
		k, other := rb8Key(t, ty), rb8Key(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "membership")
		sig := rb8Sign(t, k, txn, sigfixture.Opts{})
		otherSig := rb8Sign(t, other, txn, sigfixture.Opts{})
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("%v: %v", ty, err)
		}
		vs := ValidatedSignature{MessageHash: strings.Repeat("ab", 32), Signature: sd, Receipt: ReceiptData{LocalBlock: rb8KourouBlock(t, sd.Signer)}}
		onPage := KeyPageState{Version: 1, Keys: []string{rb8KeyHashHex(sig)}}
		if _, err := sv.ValidateSignature(t.Context(), vs, onPage, rb8Hex(txn), ""); err != nil {
			t.Errorf("%v: the signer's key is on the page and was refused: %v", ty, err)
		}
		offPage := KeyPageState{Version: 1, Keys: []string{rb8KeyHashHex(otherSig)}}
		_, err = sv.ValidateSignature(t.Context(), vs, offPage, rb8Hex(txn), "")
		if err == nil || !strings.Contains(err.Error(), "not in authority set") {
			t.Errorf("%v: a key that is not on the page must be refused as such, got %v", ty, err)
		}
	}
}

// The rsaSha256 case the runbook names: a valid RSA signature whose key is not on the page.
func TestRB8_RSAKeyNotOnPage(t *testing.T) {
	sv := rb8Verifier(t)
	k := rb8Key(t, protocol.SignatureTypeRsaSha256)
	pageKey := rb8Key(t, protocol.SignatureTypeRsaSha256)
	txn := sigfixture.Txn("acc://probe.acme/data", "rsa")
	sig := rb8Sign(t, k, txn, sigfixture.Opts{})
	sd, err := rb8Extract(t, sig, txn)
	if err != nil {
		t.Fatalf("a valid rsaSha256 signature was refused at extraction: %v", err)
	}
	page := KeyPageState{Version: 1, Keys: []string{rb8KeyHashHex(rb8Sign(t, pageKey, txn, sigfixture.Opts{}))}}
	_, err = sv.ValidateSignature(t.Context(), ValidatedSignature{MessageHash: strings.Repeat("ab", 32), Signature: sd, Receipt: ReceiptData{LocalBlock: rb8KourouBlock(t, sd.Signer)}}, page, rb8Hex(txn), "")
	if err == nil || !strings.Contains(err.Error(), "not in authority set") {
		t.Fatalf("an RSA key that is not on the page must be refused as not a member, got %v", err)
	}
}

// Correct key, a different transaction's hash: a genuine rejection - the signature does not sign this transaction -
// never an unsupported-type state.
func TestRB8_CorrectKeyWrongDigest(t *testing.T) {
	sv := rb8Verifier(t)
	for _, ty := range rb8Types {
		k := rb8Key(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "signed")
		other := sigfixture.Txn("acc://probe.acme/data", "not what was signed")
		sig := rb8Sign(t, k, txn, sigfixture.Opts{})
		// the message claims to cover `other`: the signature object is unchanged
		b, _ := json.Marshal(sig)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		m["transactionHash"] = rb8Hex(other)
		sd, err := sv.ExtractSignatureFromMessageResult(rb8MessageFromObject(m, rb8Hex(other)))
		if err != nil {
			t.Fatalf("%v: extraction must succeed (the message is well-formed): %v", ty, err)
		}
		_, err = rb8Verify(t, sv, sd, rb8Hex(other))
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("%v: a signature over another transaction must be a verification failure, got %v", ty, err)
		}
		if _, unsupported := IsUnsupportedSignatureType(err); unsupported {
			t.Errorf("%v: refused as unsupported", ty)
		}
	}
}

// Bytes of one type under another's label never verify.
func TestRB8_TypeLabelSwapped(t *testing.T) {
	sv := rb8Verifier(t)
	txn := sigfixture.Txn("acc://probe.acme/data", "swap")
	obj := func(sig protocol.Signature) map[string]interface{} {
		b, _ := json.Marshal(sig)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		return m
	}
	ed := obj(rb8Sign(t, rb8Key(t, protocol.SignatureTypeED25519), txn, sigfixture.Opts{}))
	ec := obj(rb8Sign(t, rb8Key(t, protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{}))

	// ed25519 bytes labelled as each other type: refused by VERIFICATION (the shape of an ed25519 key and signature is
	// legal input to every type's decoder), never counted.
	for _, label := range []string{"ecdsaSha256", "rsaSha256", "rcd1", "legacyED25519", "btc", "btcLegacy", "eth"} {
		m := map[string]interface{}{}
		for k, v := range ed {
			m[k] = v
		}
		m["type"] = label
		sd, err := sv.ExtractSignatureFromMessageResult(rb8MessageFromObject(m, rb8Hex(txn)))
		if err == nil {
			_, err = rb8Verify(t, sv, sd, rb8Hex(txn))
		}
		if err == nil {
			t.Errorf("ed25519 bytes labelled %s were accepted", label)
			continue
		}
		if _, unsupported := IsUnsupportedSignatureType(err); unsupported {
			t.Errorf("ed25519 bytes labelled %s: refused as an unsupported TYPE, but %s is a type Accumulate accepts: %v", label, label, err)
		}
	}
	// ECDSA bytes labelled ed25519 / rcd1 / legacy: refused, never counted.
	for _, label := range []string{"ed25519", "rcd1", "legacyED25519", "rsaSha256"} {
		m := map[string]interface{}{}
		for k, v := range ec {
			m[k] = v
		}
		m["type"] = label
		sd, err := sv.ExtractSignatureFromMessageResult(rb8MessageFromObject(m, rb8Hex(txn)))
		if err == nil {
			_, err = rb8Verify(t, sv, sd, rb8Hex(txn))
		}
		if err == nil {
			t.Errorf("ecdsa bytes labelled %s were accepted", label)
		}
	}
}

// Accumulate's own malleability matrix, through the online stack: what its Verify accepts is accepted (high-S, lax DER
// for btc, 64/65-byte eth with any V), and what it refuses is refused.
func TestRB8_MalleabilityAsTheExecutorTreatsIt(t *testing.T) {
	sv := rb8Verifier(t)
	txn := sigfixture.Txn("acc://probe.acme/data", "mall")
	run := func(name string, sig protocol.Signature, want bool) {
		t.Helper()
		sd, err := rb8Extract(t, sig, txn)
		if err == nil {
			_, err = rb8Verify(t, sv, sd, rb8Hex(txn))
		}
		if got := err == nil; got != want {
			t.Errorf("%s: accepted=%v, Accumulate's Verify says %v (%v)", name, got, want, err)
		}
	}

	es := rb8Sign(t, rb8Key(t, protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{}).(*protocol.EcdsaSha256Signature)
	r, s := sigfixture.ParseDER(es.Signature)
	hi := *es
	hi.Signature = sigfixture.EncodeDER(r, new(big.Int).Sub(elliptic.P256().Params().N, s))
	run("ecdsa high-S", &hi, true)
	tr := *es
	tr.Signature = append(append([]byte{}, es.Signature...), 0)
	run("ecdsa trailing byte", &tr, false)

	bs := rb8Sign(t, rb8Key(t, protocol.SignatureTypeBTC), txn, sigfixture.Opts{}).(*protocol.BTCSignature)
	br, bsv := sigfixture.ParseDER(bs.Signature)
	lax := *bs
	lax.Signature = append(append([]byte{}, bs.Signature...), 0xde, 0xad)
	run("btc lax DER trailing bytes", &lax, true)
	nm := *bs
	nm.Signature = sigfixture.NonMinimalDER(br, bsv)
	run("btc non-minimal DER", &nm, true)

	xs := rb8Sign(t, rb8Key(t, protocol.SignatureTypeETH), txn, sigfixture.Opts{}).(*protocol.ETHSignature)
	v99 := *xs
	v99.Signature = append(append([]byte{}, xs.Signature...), 0x99)
	run("eth 65 bytes, V=0x99", &v99, true)
	s63 := *xs
	s63.Signature = xs.Signature[:63]
	run("eth 63 bytes", &s63, false)

	ds := *rb8Sign(t, rb8Key(t, protocol.SignatureTypeED25519), txn, sigfixture.Opts{}).(*protocol.ED25519Signature)
	ds.Signature = sigfixture.EdAddL(ds.Signature)
	run("ed25519 S+L", &ds, false)
}

// Vote, memo and data are inside the signed metadata. buildProtocolSignature used to rebuild every signature without
// them, so an ed25519 reject/abstain vote - or a signature carrying memo or data - could never verify (RB8-A finding).
func TestRB8_VoteMemoDataAreInsideTheSignedBytes(t *testing.T) {
	sv := rb8Verifier(t)
	k := rb8Key(t, protocol.SignatureTypeED25519)
	for name, o := range map[string]sigfixture.Opts{
		"reject":  {Vote: protocol.VoteTypeReject},
		"abstain": {Vote: protocol.VoteTypeAbstain},
		"memo":    {Memo: "approved by the officer"},
		"data":    {Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		"all":     {Vote: protocol.VoteTypeReject, Memo: "m", Data: []byte{1}, Delegators: []string{"acc://a.acme/book/1"}},
	} {
		txn := sigfixture.Txn("acc://probe.acme/data", "vmd")
		sig := rb8Sign(t, k, txn, o)
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := rb8Verify(t, sv, sd, rb8Hex(txn)); err != nil {
			t.Errorf("%s: a valid ed25519 signature carrying it failed verification: %v", name, err)
		}
	}
	// the vote is also read, not assumed
	txn := sigfixture.Txn("acc://probe.acme/data", "vote")
	sd, err := rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{Vote: protocol.VoteTypeReject}), txn)
	if err != nil || sd.Vote != protocol.VoteTypeReject.String() {
		t.Fatalf("vote %q err %v", sd.Vote, err)
	}
}

// The inner key's type is recorded even under delegation: a delegated ECDSA must not read as a delegated ed25519.
func TestRB8_DelegatedInnerTypeIsNotLost(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "inner")
	var seen = map[string]string{}
	for _, ty := range rb8Types {
		sig := rb8Sign(t, rb8Key(t, ty), txn, sigfixture.Opts{Delegators: []string{"acc://a.acme/book/1"}})
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("%v: %v", ty, err)
		}
		b, _ := json.Marshal(sd)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		shape := fmt.Sprint(m["type"], "/", m["innerType"])
		if prev, dup := seen[shape]; dup && ty != protocol.SignatureTypeED25519 {
			t.Errorf("%v and %s are indistinguishable in the recorded shape (%s)", ty, prev, shape)
		}
		seen[shape] = ty.String()
	}
}

// Non-key types stay non-key, directly and as the core of a delegation; a name Accumulate does not define is an
// unsupported TYPE whose message states the real rule.
func TestRB8_NonKeyTypesAndUnknownNames(t *testing.T) {
	sv := rb8Verifier(t)
	for _, name := range []string{"authority", "partition", "receipt", "remote", "internal", "set", "signatureRequest", "creditPayment"} {
		for _, wrapped := range []bool{false, true} {
			var sig interface{} = map[string]interface{}{"type": name}
			if wrapped {
				sig = map[string]interface{}{"type": "delegated", "delegator": "acc://a.acme/book/1", "signature": sig}
			}
			_, err := sv.ExtractSignatureFromMessageResult(buildMsgResult(map[string]interface{}{"type": "signature", "signature": sig}))
			if _, ok := err.(NotAKeySignature); !ok || !isNotASignatureMessage(err) {
				t.Errorf("%s wrapped=%v: must be NotAKeySignature (routine), got %v", name, wrapped, err)
			}
		}
	}
	for _, name := range []string{"unknown", "blsSignature", "dsa"} {
		_, err := sv.ExtractSignatureFromMessageResult(buildMsgResult(map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{"type": name}}))
		u, ok := IsUnsupportedSignatureType(err)
		if !ok || u.Type != strings.ToLower(name) {
			t.Fatalf("%s: must be UnsupportedSignatureType, got %v", name, err)
		}
		msg := err.Error()
		for _, want := range []string{"ecdsaSha256", "rsaSha256", "typedData", "btc", "rcd1", "delegation"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: the refusal must state Accumulate's real rule; %q is missing from: %s", name, want, msg)
			}
		}
		if strings.Contains(msg, "ed25519 and delegated signatures only") {
			t.Errorf("%s: the refusal still states the superseded rule: %s", name, msg)
		}
	}
}

// Accumulate's depth limit is 20 delegators: 20 verifies, 21 is refused for its depth, for every type.
func TestRB8_DelegationDepthLimitForEveryType(t *testing.T) {
	sv := rb8Verifier(t)
	chain := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("acc://d%d.acme/book/1", i)
		}
		return out
	}
	for _, ty := range rb8Types {
		k := rb8Key(t, ty)
		txn := sigfixture.Txn("acc://probe.acme/data", "depth")
		sd, err := rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{Delegators: chain(protocol.DelegationDepthLimit)}), txn)
		if err != nil {
			t.Errorf("%v: a %d-deep chain is within Accumulate's limit: %v", ty, protocol.DelegationDepthLimit, err)
			continue
		}
		if _, err := rb8Verify(t, sv, sd, rb8Hex(txn)); err != nil {
			t.Errorf("%v: the %d-deep chain did not verify: %v", ty, protocol.DelegationDepthLimit, err)
		}
		_, err = rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{Delegators: chain(protocol.DelegationDepthLimit + 1)}), txn)
		if _, ok := err.(DelegationDepthExceeded); !ok {
			t.Errorf("%v: %d delegators must be refused for their depth, got %v", ty, protocol.DelegationDepthLimit+1, err)
		}
	}
}

// AcceptedDigests is the digest list Accumulate would try: ed25519-family and secp256k1 types have both, ecdsaSha256
// and rsaSha256 only the metadata form (their Initiator() refuses).
func TestRB8_AcceptedDigestsPerType(t *testing.T) {
	want := map[protocol.SignatureType]int{
		protocol.SignatureTypeLegacyED25519: 2, protocol.SignatureTypeED25519: 2, protocol.SignatureTypeRCD1: 2,
		protocol.SignatureTypeBTC: 2, protocol.SignatureTypeBTCLegacy: 2, protocol.SignatureTypeETH: 2,
		protocol.SignatureTypeRsaSha256: 1, protocol.SignatureTypeEcdsaSha256: 1,
	}
	for _, ty := range rb8Types {
		txn := sigfixture.Txn("acc://probe.acme/data", "digests")
		sd, err := rb8Extract(t, rb8Sign(t, rb8Key(t, ty), txn, sigfixture.Opts{}), txn)
		if err != nil {
			t.Fatalf("%v: %v", ty, err)
		}
		d, err := AcceptedDigests(sd, txn.Hash())
		if err != nil || len(d) != want[ty] {
			t.Errorf("%v: %d digests (%v), want %d", ty, len(d), err, want[ty])
		}
	}
}
