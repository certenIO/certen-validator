// Copyright 2026 Certen Protocol
//
// Decoding the two network accounts a ValidatorSetProof carries.
//
// These are deliberately narrow: they take the canonical binary encoding of an
// account, as it appears in the BPT leaf preimage, and pull out exactly the two
// facts the proof is about — the validator set and the accept threshold.
//
// Nothing here trusts a JSON field. The bytes decoded are the same bytes that
// were hashed to produce the leaf the merkle path proves, which is what makes
// the result derived rather than asserted.
package proof

import (
	"fmt"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// dataEntryOf unwraps an account's binary encoding to its first data blob.
func dataEntryOf(raw []byte, label string) ([]byte, error) {
	acct, err := protocol.UnmarshalAccount(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: does not decode as an account: %w", label, err)
	}
	da, ok := acct.(*protocol.DataAccount)
	if !ok {
		return nil, fmt.Errorf("%s: expected a dataAccount, got %v", label, acct.Type())
	}
	if da.Entry == nil {
		return nil, fmt.Errorf("%s: data account has no entry", label)
	}
	blobs := da.Entry.GetData()
	if len(blobs) == 0 {
		return nil, fmt.Errorf("%s: data account entry is empty", label)
	}
	return blobs[0], nil
}

// decodeValidators reads acc://dn.acme/network and returns its validator set in
// the shape L4 carries, so the two can be compared directly.
//
// PublicKeyHash is deliberately left empty: it is a derived value
// (sha256(publicKey)) and re-deriving it here would invite a comparison that
// passes on a field neither side got from the chain. sameValidatorSet compares
// public keys and partition membership only.
func decodeValidators(raw []byte) ([]chained_proof.ValidatorKey, error) {
	blob, err := dataEntryOf(raw, "network account")
	if err != nil {
		return nil, err
	}
	var nd protocol.NetworkDefinition
	if err := nd.UnmarshalBinary(blob); err != nil {
		return nil, fmt.Errorf("network account: entry is not a NetworkDefinition: %w", err)
	}
	if len(nd.Validators) == 0 {
		return nil, fmt.Errorf("network account: NetworkDefinition carries no validators")
	}

	out := make([]chained_proof.ValidatorKey, 0, len(nd.Validators))
	for i, v := range nd.Validators {
		if len(v.PublicKey) != 32 {
			return nil, fmt.Errorf("network account: validator %d has a %d-byte public key, expected 32",
				i, len(v.PublicKey))
		}
		activeOn := make([]string, 0, len(v.Partitions))
		for _, part := range v.Partitions {
			if part.Active {
				activeOn = append(activeOn, part.ID)
			}
		}
		out = append(out, chained_proof.ValidatorKey{
			PublicKey: fmt.Sprintf("%x", v.PublicKey),
			ActiveOn:  activeOn,
		})
	}
	return out, nil
}

// decodeAcceptThreshold reads acc://dn.acme/globals and returns
// validatorAcceptThreshold — the DENOMINATOR that a set commitment without a
// threshold commitment is missing.
func decodeAcceptThreshold(raw []byte) (num, den uint64, err error) {
	blob, err := dataEntryOf(raw, "globals account")
	if err != nil {
		return 0, 0, err
	}
	var ng protocol.NetworkGlobals
	if err := ng.UnmarshalBinary(blob); err != nil {
		return 0, 0, fmt.Errorf("globals account: entry is not NetworkGlobals: %w", err)
	}
	t := ng.ValidatorAcceptThreshold
	if t.Denominator == 0 {
		return 0, 0, fmt.Errorf("globals account: zero validatorAcceptThreshold denominator")
	}
	if t.Numerator == 0 {
		return 0, 0, fmt.Errorf("globals account: zero validatorAcceptThreshold numerator would " +
			"admit an unsigned anchor")
	}
	if t.Numerator > t.Denominator {
		return 0, 0, fmt.Errorf("globals account: validatorAcceptThreshold numerator %d exceeds "+
			"denominator %d", t.Numerator, t.Denominator)
	}
	return t.Numerator, t.Denominator, nil
}
