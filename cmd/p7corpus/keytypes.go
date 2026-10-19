package main

// Keys for every key-signature type the corpus can capture.
//
// RB8-B (research R8, gap G-42): Accumulate's executor accepts nine key-signature types on a key page and CERTEN's G1
// verifies all nine, so the capture program can make a signature of any of them. The ed25519 family (ed25519,
// legacyED25519, rcd1) is derived from the corpus seed like every other corpus key. The other six - btc, btclegacy,
// eth, typedData, rsaSha256, ecdsaSha256 - have no seed in keys.json and Accumulate's key encodings differ per type, so
// a key is generated once per (seed name, type) for the life of the process: the key that is registered on the page
// (ensureKeyRegistered) and the key that signs (buildSignature) are the same value, and it is never written to disk by
// this program. A captured trace records only public values.

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

var (
	typeKeysMu sync.Mutex
	typeKeys   = map[string]sigfixture.Key{}
)

// keyOfType returns the key a signaturePlan of type t signs with.
func keyOfType(seeds map[string]string, seed string, t protocol.SignatureType) (sigfixture.Key, error) {
	if t != protocol.SignatureTypeUnknown && !govsig.IsAcceptedKeyType(t) {
		return sigfixture.Key{}, fmt.Errorf("%v is not a key-signature type Accumulate's executor accepts; %s", t, govsig.TypeRule())
	}
	switch t {
	case protocol.SignatureTypeUnknown, protocol.SignatureTypeED25519, protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeRCD1:
		priv, err := keyFor(seeds, seed)
		if err != nil {
			return sigfixture.Key{}, err
		}
		if t == protocol.SignatureTypeUnknown {
			t = protocol.SignatureTypeED25519
		}
		return sigfixture.Key{Type: t, Priv: priv}, nil
	}
	typeKeysMu.Lock()
	defer typeKeysMu.Unlock()
	id := fmt.Sprintf("%s/%v", seed, t)
	if k, ok := typeKeys[id]; ok {
		return k, nil
	}
	k, err := sigfixture.NewKey(t, rand.Reader)
	if err != nil {
		return sigfixture.Key{}, err
	}
	typeKeys[id] = k
	return k, nil
}

// buildKeyTypeSignature builds a signature of a type the official Builder cannot make with an ed25519 seed (it has no
// typedData branch at all): through Accumulate's own signing functions, over the metadata digest, or as the initiator
// when initiator is set.
func buildKeyTypeSignature(seeds map[string]string, p signaturePlan, version, ts uint64,
	txn *protocol.Transaction, initiator bool) (protocol.Signature, error) {

	k, err := keyOfType(seeds, p.Seed, p.Type)
	if err != nil {
		return nil, err
	}
	return sigfixture.Sign(k, txn, sigfixture.Opts{
		Signer: p.SignerPage, Version: version, Timestamp: ts, Delegators: p.Delegators,
		Initiate: initiator, Merkle: p.Merkle && !initiator,
	})
}
