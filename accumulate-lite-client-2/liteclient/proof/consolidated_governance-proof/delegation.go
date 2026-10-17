// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Delegated signatures, and the two digests Accumulate accepts.
//
// Two facts from protocol/, both of which this file exists to respect rather
// than to reimplement:
//
//  1. DELEGATION IS INSIDE THE SIGNED BYTES.
//     DelegatedSignature.Metadata() recurses (protocol/signature.go:925) and
//     verifySigSplit hashes the OUTERMOST metadata, so the inner ed25519 key
//     signs a digest that commits to every Delegator URL in the chain.
//     Verifying the inner signature against a plain ed25519 digest and
//     resolving the path separately fails EVERY time - a well-formed digest
//     that never verifies.
//
//  2. THERE ARE TWO ACCEPTED DIGESTS, NOT ONE.
//     protocol/signature_utils.go:26-41 accepts the metadata digest OR the
//     Initiator() merkle digest. Implementing only the first counts a valid
//     signature as invalid, and because G1 fails closed that surfaces as a
//     governance REJECTION - indistinguishable from "the institution did not
//     authorize this". The Phase 7 corpus contains a signature in this form
//     that Kermit DELIVERED, so this is a live rejection of an authorized
//     signature, not a theoretical branch.
//
// The digests are built by constructing real protocol.DelegatedSignature and
// key-signature values (of whichever of the nine accepted types the record is) and calling their own methods. The
// canonical encoding is field-tagged, omit-if-zero and varint-length
// (protocol/types_gen.go:8996); hand-rolling it is how the field-strictness bugs
// happened before.
//
// RB8-B: the record is rebuilt from Accumulate's own binary encoding (SignatureData.Raw) whenever its fields cannot
// describe the signature completely, and the VERDICT on a signature is protocol.VerifyUserSignature on the rebuilt
// value (govsig.Verify), never a digest computed and checked here. AcceptedDigests below remains as the observable
// preimage list.

// SignerLink is one hop of a delegation chain: the key page that delegated its
// authority to the next hop inward.
//
// Delegator is a PAGE, not a book. A page delegates TO a book, but the
// Delegator field of a DelegatedSignature names the page that did the
// delegating - accumulate-core loads it with loadSigner and then asks it
// EntryByDelegate(authority) (internal/core/execute/v2/block/sig_authority.go).
// Getting this wrong produces a chain that looks plausible and never resolves.
type SignerLink struct {
	Delegator string `json:"delegator"`
}

// Digest form labels. Recorded on every counted signature so the distribution
// is observable: if the merkle form never appears in practice that is worth
// knowing, and if it does, defect D4 was rejecting real signatures.
const (
	DigestFormMetadata = "metadata"
	DigestFormMerkle   = "initiator-merkle"
)

// AcceptedDigest is one digest a signature may have been made over, with the
// name of the form that produced it.
type AcceptedDigest struct {
	Form   string `json:"form"`
	Digest []byte `json:"digest"`
}

// UnsupportedSignatureType is the refusal for a signature type that is not a signature type Accumulate defines (or
// is "unknown", type 0, which cannot exist on chain). Every key-signature type Accumulate's executor accepts is
// verified (govsig.AcceptedKeyTypes); a type Accumulate itself would refuse is the only thing refused by this name.
//
// It is its own type so that it can never be confused with a threshold
// shortfall. A silently skipped signature reduces the counted set, which reads
// as an unmet threshold, which reads as "the institution did not authorize
// this" - a false governance rejection, which is worse than an error, because
// an error is obviously a problem and a false rejection looks like a finding.
type UnsupportedSignatureType struct {
	Type string
}

func (e UnsupportedSignatureType) Error() string {
	return fmt.Sprintf("unsupported signature type %q: %s. Accumulate defines no such key signature, so it "+
		"cannot be a key's vote. This is a capability limit, NOT a governance rejection and NOT a "+
		"threshold shortfall", e.Type, govsig.TypeRule())
}

// Reason is the distinct reason code Gate 3 requires.
func (e UnsupportedSignatureType) Reason() string { return "unsupported-signature-type" }

// IsUnsupportedSignatureType reports whether err is the unsupported-type
// refusal, so a caller can keep it out of the threshold accounting.
func IsUnsupportedSignatureType(err error) (UnsupportedSignatureType, bool) {
	if err == nil {
		return UnsupportedSignatureType{}, false
	}
	var e UnsupportedSignatureType
	if errors.As(err, &e) {
		return e, true
	}
	return UnsupportedSignatureType{}, false
}

// DelegationDepthExceeded refuses a chain deeper than Accumulate allows.
//
// The limit is protocol.DelegationDepthLimit - Accumulate's number, not one we
// chose. accumulate-core refuses at len(delegators) > limit
// (internal/core/execute/v2/block/sig_user.go), and Kermit refuses corpus case
// G with exactly that message.
type DelegationDepthExceeded struct {
	Depth int
	Limit int
}

func (e DelegationDepthExceeded) Error() string {
	return fmt.Sprintf("delegation chain is %d deep, exceeding DelegationDepthLimit of %d",
		e.Depth, e.Limit)
}

func (e DelegationDepthExceeded) Reason() string { return "delegation-depth-exceeded" }

// SignatureBytesAbsent is the named state for a record whose type its fields cannot rebuild and that carries no
// Accumulate binary encoding: a non-ed25519 key signature without Raw. It is unavailable evidence, never a
// rejection and never silently treated as ed25519.
type SignatureBytesAbsent struct{ Type string }

func (e SignatureBytesAbsent) Error() string {
	return fmt.Sprintf("signature_bytes_absent{type=%s}: a %s signature cannot be rebuilt from its fields (its encoding "+
		"differs per type); the record carries no Accumulate binary encoding (raw). This is NOT a governance rejection",
		e.Type, e.Type)
}
func (e SignatureBytesAbsent) Reason() string { return "signature_bytes_absent" }

// SignatureUndecodable is the named state for bytes Accumulate's own decoder does not accept.
type SignatureUndecodable struct {
	Type string
	Err  error
}

func (e SignatureUndecodable) Error() string {
	return fmt.Sprintf("signature_undecodable{type=%s}: %v. This is NOT a governance rejection", e.Type, e.Err)
}
func (e SignatureUndecodable) Reason() string { return "signature_undecodable" }
func (e SignatureUndecodable) Unwrap() error  { return e.Err }

// SignatureFieldsDisagree is the named state for a record whose raw encoding decodes to something other than the
// fields beside it. Raw is never trusted over, or beside, the fields it must agree with.
type SignatureFieldsDisagree struct {
	Field       string
	Raw, Record string
}

func (e SignatureFieldsDisagree) Error() string {
	return fmt.Sprintf("signature_fields_disagree{field=%s}: the raw encoding says %q, the record says %q. This is NOT a "+
		"governance rejection", e.Field, e.Raw, e.Record)
}
func (e SignatureFieldsDisagree) Reason() string { return "signature_fields_disagree" }

// buildProtocolSignature reconstructs the protocol value a SignatureData describes.
//
// When the record carries Raw, the value is decoded from Accumulate's own binary encoding and every field of the
// record is checked against it. Otherwise the record's fields describe an ed25519 signature completely, and it is an
// ED25519Signature at the centre, wrapped once per delegation hop.
//
// The nesting order is load-bearing. Chain is stated outermost first, so it is
// walked BACKWARDS - the last link wraps first and ends up innermost, and
// Chain[0] ends up outermost, which is the one whose metadata is hashed.
func buildProtocolSignature(sig SignatureData) (protocol.Signature, error) {
	if err := requireSupportedType(sig); err != nil {
		return nil, err
	}
	if sig.Raw != "" {
		return signatureFromRaw(sig)
	}
	return buildFieldSignature(sig)
}

// buildFieldSignature rebuilds the ed25519 signature the record's fields describe. It is the path every record that
// existed before RB8-B takes, and it now sets the Vote the record carries (it used to drop it, so an ed25519
// reject/abstain/suggest vote could never verify: RB8-A finding).
func buildFieldSignature(sig SignatureData) (protocol.Signature, error) {
	// NO depth check here, deliberately. The depth limit is an execution rule,
	// not a property of the digest: accumulate-core's verifySigSplit hashes a
	// chain of any length, and unwrapDelegated in the EXECUTOR is what refuses
	// past the limit. Refusing here would mean we could not compute the digest of
	// an over-deep signature at all, and so could not show that we agree with
	// accumulate-core about what it signed - which is how we know our refusal is
	// about depth rather than about not understanding the signature.
	//
	// The walk is bounded where it is unbounded: unwrapDelegation, which is what
	// turns an untrusted response into a chain.
	t := strings.ToLower(sig.Type)
	if t == "delegated" && sig.InnerType != "" && !strings.EqualFold(sig.InnerType, "ed25519") {
		return nil, SignatureBytesAbsent{Type: strings.ToLower(sig.InnerType)}
	}
	if t != "ed25519" && t != "delegated" {
		return nil, SignatureBytesAbsent{Type: t}
	}

	pubKey, err := hex.DecodeString(strings.TrimPrefix(sig.PublicKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("public key is not hex: %w", err)
	}
	signerURL, err := url.Parse(sig.Signer)
	if err != nil {
		return nil, fmt.Errorf("signer URL %q: %w", sig.Signer, err)
	}

	inner := new(protocol.ED25519Signature)
	inner.PublicKey = pubKey
	inner.Signer = signerURL
	inner.SignerVersion = uint64(sig.SignerVersion)
	if sig.Timestamp != nil {
		inner.Timestamp = uint64(*sig.Timestamp)
	}
	if sig.Vote != "" {
		vote, ok := protocol.VoteTypeByName(sig.Vote)
		if !ok {
			return nil, ValidationError{Msg: fmt.Sprintf("signature.vote %q is not a vote Accumulate defines", sig.Vote)}
		}
		inner.Vote = vote
	}
	// The signature bytes are set so protocol's own Verify can check them. Neither they nor the transaction hash are
	// part of Metadata() or Initiator(): setting them does not move any digest.
	if sig.Signature != "" {
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(sig.Signature, "0x"))
		if err != nil {
			return nil, fmt.Errorf("signature is not hex: %w", err)
		}
		inner.Signature = sigBytes
	}

	var out protocol.Signature = inner
	for i := len(sig.Chain) - 1; i >= 0; i-- {
		delegator, err := url.Parse(sig.Chain[i].Delegator)
		if err != nil {
			return nil, fmt.Errorf("delegator URL %q: %w", sig.Chain[i].Delegator, err)
		}
		out = &protocol.DelegatedSignature{Delegator: delegator, Signature: out}
	}
	return out, nil
}

// signatureFromRaw decodes the record's Accumulate binary encoding with Accumulate's own unmarshaller and requires
// every field of the record to equal the decoded value.
func signatureFromRaw(sig SignatureData) (protocol.Signature, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(sig.Raw, "0x"))
	if err != nil || len(b) == 0 {
		return nil, SignatureUndecodable{Type: sig.Type, Err: fmt.Errorf("raw is not hex")}
	}
	decoded, err := protocol.UnmarshalSignature(b)
	if err != nil {
		return nil, SignatureUndecodable{Type: sig.Type, Err: err}
	}
	if err := fieldsAgreeWithRaw(sig, decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

// fieldsAgreeWithRaw checks a record's JSON-visible fields against the signature its raw encoding decodes to.
func fieldsAgreeWithRaw(sig SignatureData, decoded protocol.Signature) error {
	un, err := govsig.Unwrap(decoded)
	if err != nil {
		var nk govsig.NotKeySignature
		if errors.As(err, &nk) {
			return NotAKeySignature{Type: nk.Type}
		}
		var de govsig.DepthExceeded
		if errors.As(err, &de) {
			return DelegationDepthExceeded{Depth: de.Depth, Limit: de.Limit}
		}
		return err
	}
	inner := un.Inner
	disagree := func(field, raw, record string) error {
		return SignatureFieldsDisagree{Field: field, Raw: raw, Record: record}
	}

	innerName := strings.ToLower(inner.Type().String())
	wantType := innerName
	if len(un.Delegators) > 0 {
		wantType = "delegated"
		recInner := strings.ToLower(sig.InnerType)
		if recInner == "" {
			recInner = "ed25519"
		}
		if recInner != innerName {
			return disagree("innerType", innerName, recInner)
		}
	} else if sig.InnerType != "" {
		return disagree("innerType", "", sig.InnerType)
	}
	if strings.ToLower(sig.Type) != wantType {
		return disagree("type", wantType, strings.ToLower(sig.Type))
	}
	if !strings.EqualFold(hex.EncodeToString(inner.GetPublicKey()), strings.TrimPrefix(sig.PublicKey, "0x")) {
		return disagree("publicKey", hex.EncodeToString(inner.GetPublicKey()), sig.PublicKey)
	}
	if !strings.EqualFold(hex.EncodeToString(inner.GetSignature()), strings.TrimPrefix(sig.Signature, "0x")) {
		return disagree("signature", hex.EncodeToString(inner.GetSignature()), sig.Signature)
	}
	if normalizeAccURL(inner.GetSigner().String()) != normalizeAccURL(sig.Signer) {
		return disagree("signer", inner.GetSigner().String(), sig.Signer)
	}
	if inner.GetSignerVersion() != uint64(sig.SignerVersion) {
		return disagree("signerVersion", fmt.Sprint(inner.GetSignerVersion()), fmt.Sprint(sig.SignerVersion))
	}
	if sig.Timestamp != nil && inner.GetTimestamp() != uint64(*sig.Timestamp) {
		return disagree("timestamp", fmt.Sprint(inner.GetTimestamp()), fmt.Sprint(*sig.Timestamp))
	}
	recVote := protocol.VoteTypeAccept
	if sig.Vote != "" {
		v, ok := protocol.VoteTypeByName(sig.Vote)
		if !ok {
			return disagree("vote", decoded.GetVote().String(), sig.Vote)
		}
		recVote = v
	}
	if decoded.GetVote() != recVote {
		return disagree("vote", decoded.GetVote().String(), recVote.String())
	}
	if th := inner.GetTransactionHash(); th != [32]byte{} && sig.TransactionHash != "" &&
		!strings.EqualFold(hex.EncodeToString(th[:]), strings.TrimPrefix(sig.TransactionHash, "0x")) {
		return disagree("transactionHash", hex.EncodeToString(th[:]), sig.TransactionHash)
	}
	if len(un.Delegators) != len(sig.Chain) {
		return disagree("chain", fmt.Sprint(len(un.Delegators)), fmt.Sprint(len(sig.Chain)))
	}
	for i, d := range un.Delegators {
		if normalizeAccURL(d.String()) != normalizeAccURL(sig.Chain[i].Delegator) {
			return disagree(fmt.Sprintf("chain[%d]", i), d.String(), sig.Chain[i].Delegator)
		}
	}
	return nil
}

// nonKeySignatureTypes are the things that live on a key page's P#signature
// chain WITHOUT being a user's key signature over a transaction.
//
// This distinction is load-bearing and easy to lose. A key page's signature
// chain legitimately carries authority signatures, partition signatures,
// receipts and so on - verified live on Kermit, where enumerating a page yields
// entries of type "authority". Those are not a capability limit: there is
// nothing to verify and nothing missing. They are a routine rejection.
//
// An unsupported KEY type - btc, eth, rcd1, rsa - is the opposite: a real user
// signature that really did authorize the transaction, which we cannot check.
// That must fail closed with its own reason (runbook rule 7).
//
// Collapsing the two turns every routine chain entry into a capability failure,
// which is how the enumeration route stopped working the first time this was
// written.
var nonKeySignatureTypes = map[string]bool{
	"authority":        true,
	"partition":        true,
	"receipt":          true,
	"remote":           true,
	"internal":         true,
	"set":              true,
	"signatureRequest": true,
	"creditPayment":    true,
	"signaturerequest": true,
	"creditpayment":    true,
}

// NotAKeySignature reports an entry that is not a user key signature at all.
// It is a routine outcome, not a refusal to verify something we should.
type NotAKeySignature struct {
	Type string
}

func (e NotAKeySignature) Error() string {
	return fmt.Sprintf("not a key signature (type: %s) - a key page's signature chain carries "+
		"several message kinds and only user key signatures are votes on a transaction", e.Type)
}

func (e NotAKeySignature) Reason() string { return "not-a-key-signature" }

// requireSupportedType fails closed, with its own reason, on any signature type
// that is not a key signature Accumulate's executor accepts - and distinguishes "this is not a key
// signature" (a routine chain entry) from "Accumulate defines no such signature type".
//
// The accepted set is govsig.AcceptedKeyTypes - nine key-signature types, derived from Accumulate's own executor
// (research R8), expressed as protocol constants - plus the DelegatedSignature wrapper.
func requireSupportedType(sig SignatureData) error {
	t := strings.ToLower(sig.Type)
	if t == "" {
		return ValidationError{Msg: "signature has no type"}
	}
	_, class := govsig.Classify(t)
	switch class {
	case govsig.ClassKey, govsig.ClassDelegated:
		return nil
	case govsig.ClassNotKey:
		return NotAKeySignature{Type: t}
	default:
		return UnsupportedSignatureType{Type: t}
	}
}

// AcceptedDigests returns every digest accumulate-core will check this signature
// against, in the order verifySigSplit checks them.
//
// This mirrors protocol/signature_utils.go:21-41 exactly:
//
//	digest[0] = SHA256( outer.Metadata().Hash() || txHash )
//	digest[1] = SHA256( outer.Initiator().MerkleHash() || txHash )   (if available)
//
// For legacyED25519 each digest also commits to the signature's timestamp:
// SHA256( H || uvarint(timestamp) || txHash ) (protocol/signature.go LegacyED25519Signature.Verify).
//
// The merkle digest is absent, not zero, when the signature cannot produce an
// initiator - ED25519Signature.Initiator() refuses when the public key, signer,
// version or timestamp is unset, and rsaSha256 and ecdsaSha256 never can. An absent digest must never be treated as a
// digest that failed to match.
//
// typedData has neither digest: it signs an EIP-712 encoding of the whole transaction, which a hash cannot give.
//
// This is the observable preimage list. The VERDICT on a signature is govsig.Verify (protocol's own Verify), not a
// comparison against these.
func AcceptedDigests(sig SignatureData, txHash [32]byte) ([]AcceptedDigest, error) {
	outer, err := buildProtocolSignature(sig)
	if err != nil {
		return nil, err
	}
	// NO depth limit here either (see buildFieldSignature): the digest of an over-deep chain is still computable, and
	// being able to compute it is how we show that a refusal is about depth.
	key := innermostKeySignature(outer)
	if key == nil {
		return nil, NotAKeySignature{Type: outer.Type().String()}
	}
	if key.Type() == protocol.SignatureTypeTypedData {
		return nil, govsig.TransactionUnavailableForTypedData{TxHash: hex.EncodeToString(txHash[:])}
	}

	// the term between the metadata (or merkle) hash and the transaction hash
	var middle []byte
	if key.Type() == protocol.SignatureTypeLegacyED25519 {
		middle = binary.AppendUvarint(nil, key.GetTimestamp())
	}

	digests := []AcceptedDigest{{
		Form:   DigestFormMetadata,
		Digest: sha256Concat(outer.Metadata().Hash(), middle, txHash[:]),
	}}

	us, ok := outer.(protocol.UserSignature)
	if !ok {
		return digests, nil
	}
	init, err := us.Initiator()
	if err != nil {
		// Not an error for us: accumulate-core also just stops here and reports
		// the signature invalid under the merkle form. The metadata form stands.
		return digests, nil
	}
	return append(digests, AcceptedDigest{
		Form:   DigestFormMerkle,
		Digest: sha256Concat(init.MerkleHash(), middle, txHash[:]),
	}), nil
}

// innermostKeySignature descends through delegation of any depth to the key signature, or nil if there is none.
func innermostKeySignature(sig protocol.Signature) protocol.KeySignature {
	for {
		switch s := sig.(type) {
		case *protocol.DelegatedSignature:
			sig = s.Signature
		case protocol.KeySignature:
			return s
		default:
			return nil
		}
	}
}

func sha256Concat(parts ...[]byte) []byte {
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	sum := sha256.Sum256(all)
	return sum[:]
}

// DelegatorChain renders the chain as URLs, outermost first, for evidence and
// for comparison against a resolution path.
func (s SignatureData) DelegatorChain() []string {
	out := make([]string, 0, len(s.Chain))
	for _, l := range s.Chain {
		out = append(out, l.Delegator)
	}
	return out
}

// IsDelegated reports whether the signature carries any delegation.
func (s SignatureData) IsDelegated() bool { return len(s.Chain) > 0 }

// unwrapDelegation walks a v3 signature object inward through any delegation
// nesting, returning the innermost key-signature object and the chain of
// delegator URLs, OUTERMOST FIRST.
//
// The shape is the one Kermit returns and the one protocol marshals:
//
//	{"type":"delegated","delegator":"acc://...","signature":{ ... }}
//
// nested to whatever depth, with the key signature at the centre. Confirmed
// against a real depth-3 delegated signature on Kermit rather than assumed.
//
// The depth bound is checked HERE, before anything is built, because the guard
// is also what stops a malformed or hostile response from walking forever.
func unwrapDelegation(pu ProofUtilities, sigMap map[string]interface{}) (
	map[string]interface{}, []SignerLink, error) {

	var chain []SignerLink
	for {
		typeVal, _ := pu.CaseInsensitiveGet(sigMap, "type").(string)
		if !strings.EqualFold(typeVal, "delegated") {
			return sigMap, chain, nil
		}

		delegator, _ := pu.CaseInsensitiveGet(sigMap, "delegator").(string)
		if delegator == "" {
			return nil, nil, ValidationError{
				Msg: "delegated signature has no delegator - the delegator is inside the " +
					"signed bytes, so a signature without one cannot be verified against any path",
			}
		}
		uu := URLUtils{}
		chain = append(chain, SignerLink{Delegator: uu.NormalizeURL(delegator)})

		if len(chain) > protocol.DelegationDepthLimit {
			return nil, nil, DelegationDepthExceeded{
				Depth: len(chain), Limit: protocol.DelegationDepthLimit,
			}
		}

		inner, ok := pu.CaseInsensitiveGet(sigMap, "signature").(map[string]interface{})
		if !ok {
			return nil, nil, ValidationError{
				Msg: "delegated signature does not wrap a signature object",
			}
		}
		sigMap = inner
	}
}

// DelegationNotResolved refuses a delegated signature that has reached a check
// which cannot decide it.
//
// The key of a delegated signature is not on the page whose authority is being
// tested - it is on the innermost page, reached through the delegation chain.
// Failing the plain membership check would report "public key not in authority
// set", which is TRUE, MISLEADING, and reads as a governance rejection. This
// says what is actually the case instead.
type DelegationNotResolved struct {
	Chain  []string
	Signer string
}

func (e DelegationNotResolved) Error() string {
	return fmt.Sprintf("delegated signature by %s via %d delegator(s) [%s] cannot be decided by a "+
		"direct key-page membership check: its key is on the innermost page, not on the page "+
		"being tested. This is NOT a governance rejection",
		e.Signer, len(e.Chain), strings.Join(e.Chain, " -> "))
}

func (e DelegationNotResolved) Reason() string { return "delegation-not-resolved" }
