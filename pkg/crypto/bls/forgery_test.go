package bls

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// RB5-F54: a message's hash point must have no discrete log anyone knows. If H(m) = s(m)·G1 with s public, one
// signature sk·s(m)·G1 reveals sk·G1 = s(m)⁻¹·σ, and from it a signature on ANY message: s(m')·(sk·G1).
// This test plays the attacker against the validator's real signing and verification code.
func TestOneSignatureMustNotLetAnyoneSignAnotherMessage(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seen := []byte("a Phase 8 result attestation the validator really signed")
	sigma := sk.SignWithDomain(seen, DomainResult)

	// The attacker's only inputs: the public message, the domain, the signature.
	scalarOf := func(message []byte) *big.Int {
		h := sha256.New()
		h.Write([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"))
		h.Write(computeDomainMessage(DomainResult, message))
		h2 := sha256.New()
		h2.Write(h.Sum(nil))
		_ = binary.Write(h2, binary.BigEndian, uint64(0))
		var s fr.Element
		s.SetBytes(h2.Sum(nil))
		var b big.Int
		s.BigInt(&b)
		return &b
	}
	s := scalarOf(seen)
	sInv := new(big.Int).ModInverse(s, fr.Modulus())
	var skG1 bls12381.G1Affine
	skG1.ScalarMultiplication(&sigma.point, sInv)

	forgedMsg := []byte("an outcome the validator never attested")
	var forged bls12381.G1Affine
	forged.ScalarMultiplication(&skG1, scalarOf(forgedMsg))

	if pk.VerifyWithDomain(&Signature{point: forged}, forgedMsg, DomainResult) {
		t.Fatal("FORGED: one signature let an outsider sign another message under the validator's key - the hash point has a public discrete log")
	}
}
