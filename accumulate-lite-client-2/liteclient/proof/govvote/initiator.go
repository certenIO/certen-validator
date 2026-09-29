// Copyright 2026 Certen Protocol

package govvote

import (
	"bytes"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// InitiatorOf is what initiated txn, established from the initiating signature alone:
//
//   - the signature's metadata must hash to the initiator the transaction header commits to - so the signature is the
//     initiator, and the header is part of the transaction hash the page's chain entry proves;
//   - the payer is the signature's signer, as core's getSigner resolves it (a lite token address pays as its lite
//     identity) - the account core's initiating credit payment names (sig_user.go sendCreditPayment);
//   - the key hash is the signature's, when it is a key signature (a delegated signature carries none: its payer is
//     the delegate page, which the page's delegate entry names).
//
// The payer used to be taken from the credit payment message as that message asserted it; it is now derived from the
// committed signature, and the online reader requires the payment to agree (RB4-F66).
func InitiatorOf(txn *protocol.Transaction, sig protocol.Signature) (*Initiator, error) {
	if txn == nil || sig == nil {
		return nil, fmt.Errorf("no transaction or no initiating signature")
	}
	if !bytes.Equal(sig.Metadata().Hash(), txn.Header.Initiator[:]) {
		return nil, fmt.Errorf("the signature is not the one the transaction header commits to as its initiator")
	}
	signer := sig.GetSigner()
	if signer == nil {
		return nil, fmt.Errorf("the initiating signature names no signer")
	}
	payer := signer
	if key, _ := protocol.ParseLiteIdentity(signer); key == nil {
		if key, _, _ := protocol.ParseLiteTokenAddress(signer); key != nil {
			payer = signer.RootIdentity()
		}
	}
	out := &Initiator{Payer: payer}
	if ks, ok := sig.(protocol.KeySignature); ok {
		out.KeyHash = ks.GetPublicKeyHash()
	}
	return out, nil
}
