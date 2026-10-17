// Copyright 2026 Certen Protocol

package sigfixture

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	altcrypto "gitlab.com/accumulatenetwork/accumulate/pkg/crypto"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// Helpers that build the malleated and malformed encodings the adversarial vectors need. They produce bytes; whether
// Accumulate accepts them is for Accumulate's own Verify to say.

type rsPair struct{ R, S *big.Int }

// ParseDER reads r and s out of a DER ECDSA signature. It panics on bytes that are not the shape the fixtures write.
func ParseDER(der []byte) (r, s *big.Int) {
	var p rsPair
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		panic(err)
	}
	return p.R, p.S
}

// EncodeDER is the minimal DER encoding of (r, s).
func EncodeDER(r, s *big.Int) []byte {
	b, err := asn1.Marshal(rsPair{r, s})
	if err != nil {
		panic(err)
	}
	return b
}

// NonMinimalDER encodes r with one extra leading 0x00 byte: the same integers, not minimal DER.
func NonMinimalDER(r, s *big.Int) []byte {
	rb := r.Bytes()
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0}, rb...)
	}
	rb = append([]byte{0}, rb...)
	sb := s.Bytes()
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0}, sb...)
	}
	body := []byte{0x02, byte(len(rb))}
	body = append(body, rb...)
	body = append(body, 0x02, byte(len(sb)))
	body = append(body, sb...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// SecpN is the order of secp256k1.
func SecpN() *big.Int { return new(big.Int).Set(altcrypto.S256().Params().N) }

// EdAddL returns an ed25519 signature with its scalar S replaced by S+L (L the group order): the non-canonical twin
// that Go's ed25519.Verify refuses.
func EdAddL(sig []byte) []byte {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	s := make([]byte, 32)
	for i := 0; i < 32; i++ { // S is little-endian
		s[31-i] = sig[32+i]
	}
	n := new(big.Int).Add(new(big.Int).SetBytes(s), l)
	out := append([]byte{}, sig...)
	be := n.FillBytes(make([]byte, 32))
	for i := 0; i < 32; i++ {
		out[32+i] = be[31-i]
	}
	return out
}

// PKCS1ToPKIX re-wraps an RSA PKCS#1 RSAPublicKey as a SubjectPublicKeyInfo.
func PKCS1ToPKIX(pkcs1 []byte) []byte {
	k, err := x509.ParsePKCS1PublicKey(pkcs1)
	if err != nil {
		panic(err)
	}
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	return b
}

// BrainpoolSPKI is the SubjectPublicKeyInfo of the brainpoolP256r1 generator point (private key 1): a valid key on a
// curve Accumulate's enum text names and Go's x509 parser does not know.
func BrainpoolSPKI() []byte {
	type algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	type spki struct {
		Algo algID
		Key  asn1.BitString
	}
	gx, _ := new(big.Int).SetString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16)
	gy, _ := new(big.Int).SetString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16)
	pt := append([]byte{0x04}, append(gx.FillBytes(make([]byte, 32)), gy.FillBytes(make([]byte, 32))...)...)
	b, err := asn1.Marshal(spki{
		Algo: algID{asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}},
		Key:  asn1.BitString{Bytes: pt, BitLength: len(pt) * 8},
	})
	if err != nil {
		panic(err)
	}
	return b
}

// MustURL parses an Accumulate URL.
func MustURL(s string) *url.URL { return url.MustParse(s) }
