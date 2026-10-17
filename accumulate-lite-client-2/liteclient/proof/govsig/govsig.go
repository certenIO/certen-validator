// Copyright 2026 Certen Protocol

// Package govsig is the one place CERTEN decides which Accumulate signatures count as a key's vote, and how one is
// verified. It exists so the online governance proof (consolidated_governance-proof, package main), the offline vote
// evidence (govvote) and the validator's own partition/leg discovery (pkg/proof, pkg/consensus) apply ONE rule, and
// that rule is Accumulate's, not a list written by hand next to the code that needs it.
//
// THE RULE (research/R8-signature-types.md Q2-Q4, derived from accumulate commit e1d1db9ebb7c = what Kermit runs):
//
//	A signature is a countable key signature iff, after unwrapping at most protocol.DelegationDepthLimit (20)
//	DelegatedSignature layers, the innermost value is one of the nine KeySignature types below, protocol's own
//	VerifyUserSignature accepts the OUTERMOST signature over the transaction, (for typedData) its ChainID is the
//	network's, and its GetPublicKeyHash() is an entry of the signer page as of the block it was recorded in.
//
// Nothing here implements cryptography. Verification is Accumulate's own Verify methods on values rebuilt with
// Accumulate's own unmarshallers; key hashes are protocol.PublicKeyHash.
package govsig

import (
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// acceptedKeyTypes is the reviewed mirror of Accumulate's executor registry (internal/core/execute/v2/block/
// sig_user.go:20-43) intersected with "implements protocol.KeySignature" (sig_user.go:158-184). Accumulate keeps the
// registry in the executor, not in protocol, so the list is held here and TestRegistryMirrorsProtocol fails the day
// protocol gains a KeySignature type that is not in it.
var acceptedKeyTypes = []protocol.SignatureType{
	protocol.SignatureTypeLegacyED25519,
	protocol.SignatureTypeED25519,
	protocol.SignatureTypeRCD1,
	protocol.SignatureTypeBTC,
	protocol.SignatureTypeBTCLegacy,
	protocol.SignatureTypeETH,
	protocol.SignatureTypeRsaSha256,
	protocol.SignatureTypeEcdsaSha256,
	protocol.SignatureTypeTypedData,
}

// AcceptedKeyTypes is the set of key-signature types whose votes CERTEN counts, as protocol constants.
func AcceptedKeyTypes() []protocol.SignatureType {
	return append([]protocol.SignatureType(nil), acceptedKeyTypes...)
}

// AcceptedKeyTypeNames is AcceptedKeyTypes as Accumulate spells them in JSON.
func AcceptedKeyTypeNames() []string {
	out := make([]string, len(acceptedKeyTypes))
	for i, t := range acceptedKeyTypes {
		out[i] = t.String()
	}
	return out
}

// IsAcceptedKeyType reports whether t is a type CERTEN verifies: in the reviewed list AND a protocol.KeySignature, so
// the guard is never looser than Accumulate's own "innermost value implements KeySignature" rule.
func IsAcceptedKeyType(t protocol.SignatureType) bool {
	listed := false
	for _, a := range acceptedKeyTypes {
		if a == t {
			listed = true
			break
		}
	}
	if !listed {
		return false
	}
	v, err := protocol.NewSignature(t)
	if err != nil {
		return false
	}
	_, isKey := v.(protocol.KeySignature)
	return isKey
}

// KeySignatureTypesInProtocol enumerates every SignatureType the pinned protocol package can instantiate whose value
// is a protocol.KeySignature. Used by the drift test; exported so the root module can pin the same fact.
func KeySignatureTypesInProtocol() []protocol.SignatureType {
	var out []protocol.SignatureType
	for i := 0; i < 64; i++ {
		t := protocol.SignatureType(i)
		v, err := protocol.NewSignature(t)
		if err != nil {
			continue
		}
		if _, ok := v.(protocol.KeySignature); ok {
			out = append(out, t)
		}
	}
	return out
}

// Class is what a signature type name is.
type Class int

const (
	// ClassKey is one of the nine accepted key-signature types.
	ClassKey Class = iota + 1
	// ClassDelegated is the DelegatedSignature wrapper (a UserSignature, never a key).
	ClassDelegated
	// ClassNotKey is something that lives on a key page's signature chain without being a user's key signature over a
	// transaction: authority, partition (synthetic), receipt, remote, internal, set, and the message kinds
	// signatureRequest / creditPayment. Accumulate itself never counts these as a key's vote.
	ClassNotKey
	// ClassUnknown is a name Accumulate does not define as a signature type (or "unknown", type 0, which
	// protocol.NewSignature refuses to instantiate).
	ClassUnknown
)

// notKeyMessageKinds are message kinds that share a signature chain with signatures but are not signatures.
var notKeyMessageKinds = map[string]bool{
	"signaturerequest": true,
	"creditpayment":    true,
}

// Classify names what a signature type name is. The name is matched case-insensitively, exactly as
// protocol.SignatureTypeByName does.
func Classify(name string) (protocol.SignatureType, Class) {
	n := strings.ToLower(strings.TrimSpace(name))
	if notKeyMessageKinds[n] {
		return protocol.SignatureTypeUnknown, ClassNotKey
	}
	t, ok := protocol.SignatureTypeByName(n)
	if !ok || t == protocol.SignatureTypeUnknown {
		return protocol.SignatureTypeUnknown, ClassUnknown
	}
	if t == protocol.SignatureTypeDelegated {
		return t, ClassDelegated
	}
	if IsAcceptedKeyType(t) {
		return t, ClassKey
	}
	// Every other defined type is not a KeySignature (R8 E10): receipt, partition, set, remote, internal, authority.
	return t, ClassNotKey
}

// TypeRule is the sentence that states the real rule, for every refusal message that names a type.
func TypeRule() string {
	return "CERTEN verifies exactly the key-signature types Accumulate's executor accepts on a key page " +
		"(" + strings.Join(AcceptedKeyTypeNames(), ", ") + "), directly or as the innermost signature of a " +
		fmt.Sprintf("delegation chain of at most %d layers", protocol.DelegationDepthLimit)
}

// Unwrapped is a signature taken apart the way the executor does (sig_user.go unwrapDelegated).
type Unwrapped struct {
	// Inner is the innermost value, a KeySignature.
	Inner protocol.KeySignature
	// Delegators are the delegators' pages, OUTERMOST FIRST (the order a SignatureData chain states them).
	Delegators []*url.URL
}

// NotKeySignature is the refusal for a value that is not a key signature at its core.
type NotKeySignature struct{ Type string }

func (e NotKeySignature) Error() string {
	return fmt.Sprintf("not a key signature (type: %s): only a user's key signature over a transaction is a vote; %s",
		e.Type, TypeRule())
}
func (e NotKeySignature) Reason() string { return "not-a-key-signature" }

// DepthExceeded is the refusal for a delegation chain deeper than Accumulate allows.
type DepthExceeded struct{ Depth, Limit int }

func (e DepthExceeded) Error() string {
	return fmt.Sprintf("delegation chain is %d deep, exceeding DelegationDepthLimit of %d", e.Depth, e.Limit)
}
func (e DepthExceeded) Reason() string { return "delegation-depth-exceeded" }

// Unwrap descends through DelegatedSignature layers (collecting delegators) to the innermost value, which must be a
// protocol.KeySignature of an accepted type. This is the executor's rule, line for line: loop DelegatedSignature ->
// descend; protocol.KeySignature -> done; anything else -> refused; more than DelegationDepthLimit delegators ->
// refused.
func Unwrap(sig protocol.Signature) (*Unwrapped, error) {
	var delegators []*url.URL
	cur := sig
	for {
		switch s := cur.(type) {
		case *protocol.DelegatedSignature:
			delegators = append(delegators, s.Delegator)
			if len(delegators) > protocol.DelegationDepthLimit {
				return nil, DepthExceeded{Depth: len(delegators), Limit: protocol.DelegationDepthLimit}
			}
			cur = s.Signature
			continue
		case protocol.KeySignature:
			if !IsAcceptedKeyType(s.Type()) {
				return nil, NotKeySignature{Type: s.Type().String()}
			}
			return &Unwrapped{Inner: s, Delegators: delegators}, nil
		case nil:
			return nil, NotKeySignature{Type: "nil"}
		default:
			return nil, NotKeySignature{Type: cur.Type().String()}
		}
	}
}

// KeyHash is the page-entry hash of the innermost key: protocol.PublicKeyHash by the key's own type (sha256 for
// ed25519, legacyED25519, rsaSha256, ecdsaSha256; sha256(sha256(0x01||key)) for rcd1; ripemd160(sha256) for btc and
// btclegacy; the keccak address for eth and typedData). It refuses an empty hash: a delegate-only page entry has an
// empty hash and KeyPage.EntryByKeyHash(nil) matches it (R8 E11).
func KeyHash(key protocol.KeySignature) ([]byte, error) {
	h, err := protocol.PublicKeyHash(key.GetPublicKey(), key.Type())
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, fmt.Errorf("the %v key %x has no key hash (it does not parse as a %v key)", key.Type(),
			key.GetPublicKey(), key.Type())
	}
	return h, nil
}
