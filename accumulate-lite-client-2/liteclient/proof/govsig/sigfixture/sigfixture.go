// Copyright 2026 Certen Protocol

// Package sigfixture makes real Accumulate signatures of every key type with Accumulate's own signing code, for tests
// and for the shared sigtypes conformance vectors. It is not used by any verifier: a verifier built on the same helper
// it is tested with would agree with itself and prove nothing.
//
// Keys are generated with crypto/rand per call. A vector writer that needs reproducible bytes seeds a Source.
package sigfixture

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"

	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	altcrypto "gitlab.com/accumulatenetwork/accumulate/pkg/crypto"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Key is a private key of one signature type, in the byte form pkg/client/signing wants.
type Key struct {
	Type protocol.SignatureType
	Priv []byte
}

// NewKey generates a key of type t from rnd. The secp256k1 types reject a private scalar with a zero top byte: the
// pinned library exports such a key short (upstream MR !1237, not in the pinned commit), and the library cannot then
// sign with it. That is a key-generation limit, never a verification rule.
func NewKey(t protocol.SignatureType, rnd io.Reader) (Key, error) {
	switch t {
	case protocol.SignatureTypeED25519, protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeRCD1:
		_, sk, err := ed25519.GenerateKey(rnd)
		return Key{t, sk}, err
	case protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH, protocol.SignatureTypeTypedData:
		for {
			b := make([]byte, 32)
			if _, err := io.ReadFull(rnd, b); err != nil {
				return Key{}, err
			}
			if b[0] == 0 {
				continue
			}
			if _, err := altcrypto.ToECDSA(b); err == nil {
				return Key{t, b}, nil
			}
		}
	case protocol.SignatureTypeEcdsaSha256:
		return NewECDSAKey(elliptic.P256(), rnd)
	case protocol.SignatureTypeRsaSha256:
		return NewRSAKey(2048, rnd)
	}
	return Key{}, fmt.Errorf("%v is not a key type", t)
}

// NewECDSAKey generates an ecdsaSha256 key on the given curve.
func NewECDSAKey(c elliptic.Curve, rnd io.Reader) (Key, error) {
	k, err := ecdsa.GenerateKey(c, rnd)
	if err != nil {
		return Key{}, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	return Key{protocol.SignatureTypeEcdsaSha256, der}, err
}

// NewRSAKey generates an rsaSha256 key of the given modulus size.
func NewRSAKey(bits int, rnd io.Reader) (Key, error) {
	k, err := rsa.GenerateKey(rnd, bits)
	if err != nil {
		return Key{}, err
	}
	return Key{protocol.SignatureTypeRsaSha256, x509.MarshalPKCS1PrivateKey(k)}, nil
}

// Txn is a small WriteData transaction on principal.
func Txn(principal, payload string) *protocol.Transaction {
	t := new(protocol.Transaction)
	t.Header.Principal = url.MustParse(principal)
	t.Body = &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte(payload)}}}
	return t
}

// Opts shapes a signature. The zero value is a version-1 accept vote with timestamp 1700000000000 on
// acc://probe.acme/book/1, over the metadata digest.
type Opts struct {
	Signer     string
	Version    uint64
	Timestamp  uint64
	Vote       protocol.VoteType
	Memo       string
	Data       []byte
	Delegators []string // OUTERMOST FIRST
	// Merkle signs the initiator-merkle digest instead of the metadata digest. It is refused for rsaSha256 and
	// ecdsaSha256, which cannot form a merkle initiator (ErrCannotInitiate), and ignored by typedData.
	Merkle  bool
	ChainID *big.Int // typedData only; default protocol.EthChainID("DevNet")
}

func (o *Opts) defaults() {
	if o.Signer == "" {
		o.Signer = "acc://probe.acme/book/1"
	}
	if o.Version == 0 {
		o.Version = 1
	}
	if o.Timestamp == 0 {
		o.Timestamp = 1700000000000
	}
}

// Sign makes a signature of k's type over txn, wrapped once per delegator, signed the way the executor verifies it.
func Sign(k Key, txn *protocol.Transaction, o Opts) (protocol.Signature, error) {
	o.defaults()
	signer := url.MustParse(o.Signer)
	txHash := txn.GetHash()

	var inner protocol.KeySignature
	switch k.Type {
	case protocol.SignatureTypeLegacyED25519:
		inner = &protocol.LegacyED25519Signature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote}
	case protocol.SignatureTypeED25519:
		inner = &protocol.ED25519Signature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeRCD1:
		inner = &protocol.RCD1Signature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeBTC:
		inner = &protocol.BTCSignature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeBTCLegacy:
		inner = &protocol.BTCLegacySignature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeETH:
		inner = &protocol.ETHSignature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeRsaSha256:
		inner = &protocol.RsaSha256Signature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeEcdsaSha256:
		inner = &protocol.EcdsaSha256Signature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data}
	case protocol.SignatureTypeTypedData:
		chain := o.ChainID
		if chain == nil {
			chain = protocol.EthChainID("DevNet")
		}
		td := &protocol.TypedDataSignature{Signer: signer, SignerVersion: o.Version, Timestamp: o.Timestamp, Vote: o.Vote, Memo: o.Memo, Data: o.Data, ChainID: chain}
		priv, err := altcrypto.ToECDSA(k.Priv)
		if err != nil {
			return nil, err
		}
		td.PublicKey = altcrypto.FromECDSAPub(&priv.PublicKey)
		inner = td
	default:
		return nil, fmt.Errorf("%v is not a key type", k.Type)
	}
	if k.Type != protocol.SignatureTypeTypedData {
		if err := signing.PrivateKey(k.Priv).SetPublicKey(inner); err != nil {
			return nil, err
		}
	}

	var outer protocol.Signature = inner
	for i := len(o.Delegators) - 1; i >= 0; i-- {
		outer = &protocol.DelegatedSignature{Delegator: url.MustParse(o.Delegators[i]), Signature: outer}
	}

	if k.Type == protocol.SignatureTypeTypedData {
		return outer, protocol.SignEip712TypedData(inner.(*protocol.TypedDataSignature), k.Priv, outer, txn)
	}

	sigMd := outer.Metadata().Hash()
	if o.Merkle {
		us, ok := outer.(protocol.UserSignature)
		if !ok {
			return nil, fmt.Errorf("not a user signature")
		}
		init, err := us.Initiator()
		if err != nil {
			return nil, err
		}
		sigMd = init.MerkleHash()
	}
	setTxHash(inner, txHash)
	return outer, signing.PrivateKey(k.Priv).Sign(inner, sigMd, txHash)
}

func setTxHash(s protocol.Signature, h []byte) {
	var a [32]byte
	copy(a[:], h)
	switch s := s.(type) {
	case *protocol.LegacyED25519Signature:
		s.TransactionHash = a
	case *protocol.ED25519Signature:
		s.TransactionHash = a
	case *protocol.RCD1Signature:
		s.TransactionHash = a
	case *protocol.BTCSignature:
		s.TransactionHash = a
	case *protocol.BTCLegacySignature:
		s.TransactionHash = a
	case *protocol.ETHSignature:
		s.TransactionHash = a
	case *protocol.RsaSha256Signature:
		s.TransactionHash = a
	case *protocol.EcdsaSha256Signature:
		s.TransactionHash = a
	case *protocol.TypedDataSignature:
		s.TransactionHash = a
	}
}

// Inner returns the innermost value of a (possibly delegated) signature.
func Inner(sig protocol.Signature) protocol.Signature {
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			return sig
		}
		sig = d.Signature
	}
}
