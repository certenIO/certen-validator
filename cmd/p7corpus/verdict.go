package main

// The verdict, and only accumulate-core may give it.
//
// PHASE7_RUNBOOK.md section 1.2: every corpus expectation is computed with the
// protocol package itself. Our verifier's job is to AGREE with it. So this file
// does two separate things and insists they match:
//
//   1. asks protocol.VerifyUserSignature for the verdict - the reference;
//   2. re-derives BOTH accepted digests the way protocol/signature_utils.go
//      does, to record WHICH form carried the signature.
//
// (2) exists because PHASE7_DELEGATION_PLAN section 1.4 says a signature is
// valid under the metadata digest OR the Initiator() merkle digest and CERTEN
// implements only the first, so a signature valid under the second is currently
// counted invalid - which, because G1 fails closed, surfaces as a governance
// REJECTION. Knowing which form a signature used is the difference between
// "unauthorized" and "we cannot read this".
//
// (1) and (2) disagreeing means the re-derivation is wrong, and that is an
// error, never a warning: every later gate is measured against this file.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

const (
	formMetadata = "metadata"
	formMerkle   = "initiator-merkle"
	formNone     = "none"
)

// acceptedDigests returns the digests accumulate-core will check a signature
// against, in the order verifySigSplit checks them. The first is always
// available; the second only for a signature that can produce an initiator.
func acceptedDigests(outer protocol.Signature, txHash [32]byte) (metadata, merkle []byte) {
	md := outer.Metadata().Hash()
	metadata = sha256sum(md, txHash[:])

	us, ok := outer.(protocol.UserSignature)
	if !ok {
		return metadata, nil
	}
	h, err := us.Initiator()
	if err != nil {
		return metadata, nil
	}
	return metadata, sha256sum(h.MerkleHash(), txHash[:])
}

func sha256sum(parts ...[]byte) []byte {
	var all []byte
	for _, p := range parts {
		all = append(all, p...)
	}
	sum := sha256.Sum256(all)
	return sum[:]
}

// innerKeySig walks to the key signature at the centre of any delegation
// nesting. It is the key signature that actually carries public key and
// signature bytes; the wrappers carry only the path.
func innerKeySig(sig protocol.Signature) (protocol.KeySignature, []*url.URL, error) {
	var path []*url.URL
	for {
		switch s := sig.(type) {
		case *protocol.DelegatedSignature:
			path = append(path, s.Delegator)
			sig = s.Signature
		case protocol.KeySignature:
			return s, path, nil
		default:
			return nil, nil, fmt.Errorf("not a key or delegated signature: %v", sig.Type())
		}
	}
}

// classify returns accumulate-core's verdict and the digest form that carried
// it, refusing to return anything if the two disagree.
func classify(sig protocol.Signature, txHash [32]byte) (verdict bool, form string, digest []byte, err error) {
	us, ok := sig.(protocol.UserSignature)
	if !ok {
		return false, formNone, nil, fmt.Errorf("%v is not a user signature", sig.Type())
	}
	verdict = protocol.VerifyUserSignature(us, protocol.SignableHash(txHash))

	form, digest = formNone, nil
	if ks, _, kerr := innerKeySig(sig); kerr == nil {
		// Only ed25519 is re-derived here. Every other key type is refused by
		// CERTEN with an unsupported-type reason (runbook rule 7), so recording
		// "which digest form it used" for one would be recording a detail about
		// a signature we will never count.
		if ed, isEd := ks.(*protocol.ED25519Signature); isEd &&
			len(ed.PublicKey) == ed25519.PublicKeySize && len(ed.Signature) == ed25519.SignatureSize {
			md, mk := acceptedDigests(sig, txHash)
			switch {
			case ed25519.Verify(ed.PublicKey, md, ed.Signature):
				form, digest = formMetadata, md
			case mk != nil && ed25519.Verify(ed.PublicKey, mk, ed.Signature):
				form, digest = formMerkle, mk
			}
		}
	}

	// The cross-check. A mismatch means this file's mirror of
	// protocol/signature_utils.go has drifted from the original, and every gate
	// downstream is measured against it.
	if isEd25519Rooted(sig) && verdict != (form != formNone) {
		return false, "", nil, fmt.Errorf(
			"digest re-derivation disagrees with protocol.VerifyUserSignature "+
				"(core says %t, re-derivation found form %q) - the mirror of "+
				"verifySigSplit is wrong and nothing downstream of it can be trusted",
			verdict, form)
	}
	return verdict, form, digest, nil
}

func isEd25519Rooted(sig protocol.Signature) bool {
	ks, _, err := innerKeySig(sig)
	if err != nil {
		return false
	}
	_, ok := ks.(*protocol.ED25519Signature)
	return ok
}
