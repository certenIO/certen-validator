// Copyright 2025 Certen Protocol
//
// BLS Library Tests - Comprehensive testing of BLS12-381 implementation

package bls

import (
	"bytes"
	"testing"
)

func TestInitialize(t *testing.T) {
	err := Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	// Safe to call multiple times
	err = Initialize()
	if err != nil {
		t.Fatalf("Second initialize failed: %v", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if sk == nil {
		t.Fatal("Private key is nil")
	}
	if pk == nil {
		t.Fatal("Public key is nil")
	}

	// Check key sizes
	if !IsValidPrivateKeySize(sk.Bytes()) {
		t.Errorf("Invalid private key size: got %d, want %d", len(sk.Bytes()), PrivateKeySize)
	}
	if !IsValidPublicKeySize(pk.Bytes()) {
		t.Errorf("Invalid public key size: got %d, want %d", len(pk.Bytes()), PublicKeySize)
	}
}

func TestGenerateKeyPairFromSeed(t *testing.T) {
	seed := []byte("this is a test seed for BLS key generation - 32+ bytes required")

	sk1, pk1, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to generate key pair from seed: %v", err)
	}

	// Same seed should produce same keys
	sk2, pk2, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to generate second key pair from seed: %v", err)
	}

	if !bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
		t.Error("Same seed produced different private keys")
	}
	if !bytes.Equal(pk1.Bytes(), pk2.Bytes()) {
		t.Error("Same seed produced different public keys")
	}
}

func TestSignAndVerify(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Hello, CERTEN Protocol!")
	sig := sk.Sign(message)

	if sig == nil {
		t.Fatal("Signature is nil")
	}

	if !IsValidSignatureSize(sig.Bytes()) {
		t.Errorf("Invalid signature size: got %d, want %d", len(sig.Bytes()), SignatureSize)
	}

	// Verify should succeed
	if !pk.Verify(sig, message) {
		t.Error("Valid signature verification failed")
	}

	// Wrong message should fail
	wrongMessage := []byte("Wrong message!")
	if pk.Verify(sig, wrongMessage) {
		t.Error("Verification succeeded with wrong message")
	}
}

func TestSignWithDomain(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Test message")
	domain := DomainAttestation

	sig := sk.SignWithDomain(message, domain)

	// Verify with same domain should succeed
	if !pk.VerifyWithDomain(sig, message, domain) {
		t.Error("Domain verification failed")
	}

	// Wrong domain should fail
	if pk.VerifyWithDomain(sig, message, "WRONG_DOMAIN") {
		t.Error("Verification succeeded with wrong domain")
	}
}

func TestSerializationRoundtrip(t *testing.T) {
	// Test private key serialization
	sk1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	skBytes := sk1.Bytes()
	sk2, err := PrivateKeyFromBytes(skBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize private key: %v", err)
	}

	if !bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
		t.Error("Private key serialization roundtrip failed")
	}

	// Test public key serialization
	pk1 := sk1.PublicKey()
	pkBytes := pk1.Bytes()
	pk2, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}

	if !pk1.Equal(pk2) {
		t.Error("Public key serialization roundtrip failed")
	}

	// Test signature serialization
	message := []byte("Test message for signature serialization")
	sig1 := sk1.Sign(message)
	sigBytes := sig1.Bytes()
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize signature: %v", err)
	}

	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("Signature serialization roundtrip failed")
	}

	// Deserialized signature should still verify
	if !pk1.Verify(sig2, message) {
		t.Error("Deserialized signature verification failed")
	}
}

func TestHexSerialization(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test private key hex
	skHex := sk.Hex()
	sk2, err := PrivateKeyFromHex(skHex)
	if err != nil {
		t.Fatalf("Failed to deserialize private key from hex: %v", err)
	}
	if !bytes.Equal(sk.Bytes(), sk2.Bytes()) {
		t.Error("Private key hex roundtrip failed")
	}

	// Test public key hex
	pkHex := pk.Hex()
	pk2, err := PublicKeyFromHex(pkHex)
	if err != nil {
		t.Fatalf("Failed to deserialize public key from hex: %v", err)
	}
	if !pk.Equal(pk2) {
		t.Error("Public key hex roundtrip failed")
	}

	// Test signature hex
	message := []byte("Test message")
	sig := sk.Sign(message)
	sigHex := sig.Hex()
	sig2, err := SignatureFromHex(sigHex)
	if err != nil {
		t.Fatalf("Failed to deserialize signature from hex: %v", err)
	}
	if !bytes.Equal(sig.Bytes(), sig2.Bytes()) {
		t.Error("Signature hex roundtrip failed")
	}
}

func TestAggregateSignatures(t *testing.T) {
	// Generate multiple key pairs
	numSigners := 5
	privateKeys := make([]*PrivateKey, numSigners)
	publicKeys := make([]*PublicKey, numSigners)

	for i := 0; i < numSigners; i++ {
		sk, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		privateKeys[i] = sk
		publicKeys[i] = pk
	}

	// All signers sign the same message
	message := []byte("This is a message for aggregate signature testing")
	signatures := make([]*Signature, numSigners)

	for i := 0; i < numSigners; i++ {
		signatures[i] = privateKeys[i].Sign(message)
	}

	// Aggregate signatures
	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}

	if !IsValidSignatureSize(aggSig.Bytes()) {
		t.Errorf("Invalid aggregate signature size: got %d, want %d", len(aggSig.Bytes()), SignatureSize)
	}

	// Verify aggregate signature
	if !VerifyAggregateSignature(aggSig, publicKeys, message) {
		t.Error("Aggregate signature verification failed")
	}

	// Wrong message should fail
	if VerifyAggregateSignature(aggSig, publicKeys, []byte("wrong message")) {
		t.Error("Aggregate verification succeeded with wrong message")
	}
}

func TestAggregatePublicKeys(t *testing.T) {
	numKeys := 3
	publicKeys := make([]*PublicKey, numKeys)

	for i := 0; i < numKeys; i++ {
		_, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		publicKeys[i] = pk
	}

	aggPk, err := AggregatePublicKeys(publicKeys)
	if err != nil {
		t.Fatalf("Failed to aggregate public keys: %v", err)
	}

	if !IsValidPublicKeySize(aggPk.Bytes()) {
		t.Errorf("Invalid aggregate public key size: got %d, want %d", len(aggPk.Bytes()), PublicKeySize)
	}
}

func TestEmptyAggregation(t *testing.T) {
	// Empty signatures should fail
	_, err := AggregateSignatures([]*Signature{})
	if err == nil {
		t.Error("Expected error for empty signatures")
	}

	// Empty public keys should fail
	_, err = AggregatePublicKeys([]*PublicKey{})
	if err == nil {
		t.Error("Expected error for empty public keys")
	}
}

func TestSingleSignerAggregation(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Single signer message")
	sig := sk.Sign(message)

	// Aggregate single signature
	aggSig, err := AggregateSignatures([]*Signature{sig})
	if err != nil {
		t.Fatalf("Failed to aggregate single signature: %v", err)
	}

	// Should verify with single public key
	if !VerifyAggregateSignature(aggSig, []*PublicKey{pk}, message) {
		t.Error("Single signature aggregation verification failed")
	}
}

func TestComputeMessageHash(t *testing.T) {
	domain := "TEST_DOMAIN"
	data1 := []byte("data1")
	data2 := []byte("data2")

	hash1 := ComputeMessageHash(domain, data1, data2)
	hash2 := ComputeMessageHash(domain, data1, data2)

	// Same inputs should produce same hash
	if hash1 != hash2 {
		t.Error("Same inputs produced different hashes")
	}

	// Different domain should produce different hash
	hash3 := ComputeMessageHash("OTHER_DOMAIN", data1, data2)
	if hash1 == hash3 {
		t.Error("Different domains produced same hash")
	}

	// Different data should produce different hash
	hash4 := ComputeMessageHash(domain, data1, []byte("different"))
	if hash1 == hash4 {
		t.Error("Different data produced same hash")
	}
}

func TestDerivedPublicKeyConsistency(t *testing.T) {
	sk, pk1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Derive public key from private key
	pk2 := sk.PublicKey()

	if !pk1.Equal(pk2) {
		t.Error("Derived public keys not equal")
	}
}

func BenchmarkSign(b *testing.B) {
	sk, _, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Benchmark message for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(message)
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Benchmark message for verification")
	sig := sk.Sign(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, message)
	}
}

func BenchmarkAggregateSignatures(b *testing.B) {
	numSigners := 100
	signatures := make([]*Signature, numSigners)
	message := []byte("Benchmark message for aggregation")

	for i := 0; i < numSigners; i++ {
		sk, _, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("Failed to generate key pair: %v", err)
		}
		signatures[i] = sk.Sign(message)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(signatures)
	}
}

func BenchmarkVerifyAggregateSignature(b *testing.B) {
	numSigners := 100
	privateKeys := make([]*PrivateKey, numSigners)
	publicKeys := make([]*PublicKey, numSigners)
	signatures := make([]*Signature, numSigners)
	message := []byte("Benchmark message for aggregate verification")

	for i := 0; i < numSigners; i++ {
		sk, pk, err := GenerateKeyPair()
		if err != nil {
			b.Fatalf("Failed to generate key pair: %v", err)
		}
		privateKeys[i] = sk
		publicKeys[i] = pk
		signatures[i] = sk.Sign(message)
	}

	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		b.Fatalf("Failed to aggregate signatures: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyAggregateSignature(aggSig, publicKeys, message)
	}
}
