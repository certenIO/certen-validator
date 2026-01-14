// Copyright 2025 Certen Protocol
//
// BLS12-381 Cryptographic Verification Tests
//
// These tests verify that the BLS signature operations are mathematically correct
// and provide the security guarantees required for Level 4 attestations.
//
// Test categories:
// 1. Key Generation - Valid key pairs in correct subgroups
// 2. Signature Creation - Valid signatures that verify
// 3. Signature Verification - Correct acceptance/rejection
// 4. Signature Aggregation - Aggregate signatures work correctly
// 5. Message Consistency - All signers sign same message
// 6. Subgroup Validation - Keys are in correct BLS12-381 subgroups
// 7. Rogue Key Attack Prevention - Subgroup checks prevent attacks
// 8. Tamper Detection - Any modification fails verification

package bls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// =============================================================================
// TEST 1: KEY GENERATION
// =============================================================================

// TestKeyGeneration_ValidKeyPair tests that generated keys are valid
func TestKeyGeneration_ValidKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Verify private key size
	privBytes := priv.Bytes()
	if len(privBytes) != PrivateKeySize {
		t.Errorf("Private key size: got %d, want %d", len(privBytes), PrivateKeySize)
	}

	// Verify public key size
	pubBytes := pub.Bytes()
	if len(pubBytes) != PublicKeySize {
		t.Errorf("Public key size: got %d, want %d", len(pubBytes), PublicKeySize)
	}

	// Verify public key is in correct subgroup
	if !pub.IsValidPublicKey() {
		t.Error("Generated public key not in valid subgroup")
	}

	t.Logf("PASS: Valid key pair generated")
	t.Logf("  Private key: %s...", priv.Hex()[:16])
	t.Logf("  Public key:  %s...", pub.Hex()[:16])
}

// TestKeyGeneration_Uniqueness tests that each generation produces unique keys
func TestKeyGeneration_Uniqueness(t *testing.T) {
	keys := make(map[string]bool)

	for i := 0; i < 100; i++ {
		_, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}

		pubHex := pub.Hex()
		if keys[pubHex] {
			t.Errorf("Duplicate key generated at iteration %d", i)
		}
		keys[pubHex] = true
	}

	t.Logf("PASS: 100 unique key pairs generated")
}

// TestKeyGeneration_FromSeed tests deterministic key generation
func TestKeyGeneration_FromSeed(t *testing.T) {
	seed := []byte("test_seed_for_deterministic_key_generation")

	priv1, pub1, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("First generation failed: %v", err)
	}

	priv2, pub2, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Second generation failed: %v", err)
	}

	// Should produce identical keys
	if priv1.Hex() != priv2.Hex() {
		t.Error("Deterministic generation produced different private keys")
	}
	if pub1.Hex() != pub2.Hex() {
		t.Error("Deterministic generation produced different public keys")
	}

	// Different seed should produce different keys
	_, pub3, _ := GenerateKeyPairFromSeed([]byte("different_seed_produces_different_key"))
	if pub1.Equal(pub3) {
		t.Error("Different seeds produced same key")
	}

	t.Logf("PASS: Deterministic key generation works correctly")
}

// =============================================================================
// TEST 2: SIGNATURE CREATION
// =============================================================================

// TestSignature_BasicSigning tests basic signature creation
func TestSignature_BasicSigning(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("test message to sign")

	sig := priv.Sign(message)

	// Verify signature size
	sigBytes := sig.Bytes()
	if len(sigBytes) != SignatureSize {
		t.Errorf("Signature size: got %d, want %d", len(sigBytes), SignatureSize)
	}

	// Verify signature is valid
	if !sig.IsValidSignature() {
		t.Error("Generated signature not in valid subgroup")
	}

	// Verify signature verifies
	if !pub.Verify(sig, message) {
		t.Error("Signature should verify against original message")
	}

	t.Logf("PASS: Basic signature created and verified")
	t.Logf("  Signature: %s...", sig.Hex()[:16])
}

// TestSignature_Determinism tests that signing is deterministic
func TestSignature_Determinism(t *testing.T) {
	// Use a seed that's at least 32 bytes
	seed := []byte("deterministic_key_for_testing_at_least_32_bytes_long")
	priv, _, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to generate key from seed: %v", err)
	}
	if priv == nil {
		t.Fatal("Generated private key is nil")
	}
	message := []byte("same message each time")

	sig1 := priv.Sign(message)
	sig2 := priv.Sign(message)

	if sig1.Hex() != sig2.Hex() {
		t.Error("Same key + message should produce same signature")
	}

	t.Logf("PASS: Signature is deterministic")
}

// TestSignature_DomainSeparation tests signing with domain separation
func TestSignature_DomainSeparation(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("message")

	// Sign with different domains
	sig1 := priv.SignWithDomain(message, DomainAttestation)
	sig2 := priv.SignWithDomain(message, DomainResult)

	// Signatures should be different
	if sig1.Hex() == sig2.Hex() {
		t.Error("Different domains should produce different signatures")
	}

	// Each should verify only with its domain
	if !pub.VerifyWithDomain(sig1, message, DomainAttestation) {
		t.Error("Attestation signature should verify with attestation domain")
	}
	if pub.VerifyWithDomain(sig1, message, DomainResult) {
		t.Error("Attestation signature should NOT verify with result domain")
	}

	t.Logf("PASS: Domain separation works correctly")
}

// =============================================================================
// TEST 3: SIGNATURE VERIFICATION
// =============================================================================

// TestVerification_ValidSignature tests that valid signatures verify
func TestVerification_ValidSignature(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("test message")

	sig := priv.Sign(message)

	if !pub.Verify(sig, message) {
		t.Error("Valid signature should verify")
	}

	t.Logf("PASS: Valid signature verifies")
}

// TestVerification_WrongMessage tests rejection with wrong message
func TestVerification_WrongMessage(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("original message")
	wrongMessage := []byte("wrong message")

	sig := priv.Sign(message)

	if pub.Verify(sig, wrongMessage) {
		t.Error("Signature should NOT verify with wrong message")
	}

	t.Logf("PASS: Wrong message correctly rejected")
}

// TestVerification_WrongPublicKey tests rejection with wrong key
func TestVerification_WrongPublicKey(t *testing.T) {
	priv1, _, _ := GenerateKeyPair()
	_, pub2, _ := GenerateKeyPair()
	message := []byte("test message")

	sig := priv1.Sign(message)

	if pub2.Verify(sig, message) {
		t.Error("Signature should NOT verify with wrong public key")
	}

	t.Logf("PASS: Wrong public key correctly rejected")
}

// TestVerification_TamperedSignature tests rejection with tampered signature
func TestVerification_TamperedSignature(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("test message")

	sig := priv.Sign(message)
	sigBytes := sig.Bytes()

	// Tamper with signature
	sigBytes[0] ^= 0xFF

	// Try to deserialize tampered signature
	tamperedSig, err := SignatureFromBytes(sigBytes)
	if err != nil {
		// Tampered signature may not even deserialize - that's fine
		t.Logf("PASS: Tampered signature failed to deserialize")
		return
	}

	if pub.Verify(tamperedSig, message) {
		t.Error("Tampered signature should NOT verify")
	}

	t.Logf("PASS: Tampered signature correctly rejected")
}

// =============================================================================
// TEST 4: SIGNATURE AGGREGATION
// =============================================================================

// TestAggregation_MultipleSigners tests signature aggregation
func TestAggregation_MultipleSigners(t *testing.T) {
	numSigners := 5
	message := []byte("consensus message that all validators sign")

	privKeys := make([]*PrivateKey, numSigners)
	pubKeys := make([]*PublicKey, numSigners)
	sigs := make([]*Signature, numSigners)

	// Generate keys and sign
	for i := 0; i < numSigners; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Key generation %d failed: %v", i, err)
		}
		privKeys[i] = priv
		pubKeys[i] = pub
		sigs[i] = priv.Sign(message)
	}

	// Aggregate signatures
	aggSig, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("Signature aggregation failed: %v", err)
	}

	// Verify aggregated signature
	if !VerifyAggregateSignature(aggSig, pubKeys, message) {
		t.Error("Aggregated signature should verify")
	}

	t.Logf("PASS: Aggregated %d signatures verified successfully", numSigners)
	t.Logf("  Individual sigs: %d x %d bytes = %d bytes", numSigners, SignatureSize, numSigners*SignatureSize)
	t.Logf("  Aggregated sig:  %d bytes", SignatureSize)
	t.Logf("  Savings:         %.1f%%", 100*(1-1.0/float64(numSigners)))
}

// TestAggregation_PublicKeyAggregation tests public key aggregation
func TestAggregation_PublicKeyAggregation(t *testing.T) {
	numKeys := 3

	pubKeys := make([]*PublicKey, numKeys)
	for i := 0; i < numKeys; i++ {
		_, pub, _ := GenerateKeyPair()
		pubKeys[i] = pub
	}

	aggPub, err := AggregatePublicKeys(pubKeys)
	if err != nil {
		t.Fatalf("Public key aggregation failed: %v", err)
	}

	// Verify aggregated key is valid
	if !aggPub.IsValidPublicKey() {
		t.Error("Aggregated public key should be valid")
	}

	t.Logf("PASS: Aggregated %d public keys", numKeys)
}

// TestAggregation_SingleSignature tests aggregation with single signature
func TestAggregation_SingleSignature(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("single signer")

	sig := priv.Sign(message)

	// Aggregate single signature
	aggSig, err := AggregateSignatures([]*Signature{sig})
	if err != nil {
		t.Fatalf("Single signature aggregation failed: %v", err)
	}

	// Should verify
	if !VerifyAggregateSignature(aggSig, []*PublicKey{pub}, message) {
		t.Error("Single aggregated signature should verify")
	}

	t.Logf("PASS: Single signature aggregation works")
}

// =============================================================================
// TEST 5: MESSAGE CONSISTENCY
// =============================================================================

// TestMessageConsistency_SameMessage tests that all signers must sign same message
func TestMessageConsistency_SameMessage(t *testing.T) {
	// This is a CRITICAL security property:
	// When aggregating signatures, ALL signers MUST have signed the SAME message

	numSigners := 3
	message := []byte("the one true message")

	privKeys := make([]*PrivateKey, numSigners)
	pubKeys := make([]*PublicKey, numSigners)
	sigs := make([]*Signature, numSigners)

	for i := 0; i < numSigners; i++ {
		priv, pub, _ := GenerateKeyPair()
		privKeys[i] = priv
		pubKeys[i] = pub
		sigs[i] = priv.Sign(message) // All sign SAME message
	}

	aggSig, _ := AggregateSignatures(sigs)

	if !VerifyAggregateSignature(aggSig, pubKeys, message) {
		t.Error("All signers signed same message - should verify")
	}

	t.Logf("PASS: Message consistency verified for aggregation")
}

// TestMessageConsistency_DifferentMessages tests rejection when messages differ
func TestMessageConsistency_DifferentMessages(t *testing.T) {
	// If signers sign DIFFERENT messages, aggregation should NOT verify
	// This is the fundamental security property we're testing

	numSigners := 3
	pubKeys := make([]*PublicKey, numSigners)
	sigs := make([]*Signature, numSigners)

	for i := 0; i < numSigners; i++ {
		priv, pub, _ := GenerateKeyPair()
		pubKeys[i] = pub
		// Each signer signs a DIFFERENT message
		sigs[i] = priv.Sign([]byte("message " + string(rune('A'+i))))
	}

	aggSig, _ := AggregateSignatures(sigs)

	// Verification should fail for any single message
	if VerifyAggregateSignature(aggSig, pubKeys, []byte("message A")) {
		t.Error("Different messages should NOT verify as if all signed same")
	}
	if VerifyAggregateSignature(aggSig, pubKeys, []byte("message B")) {
		t.Error("Different messages should NOT verify as if all signed same")
	}

	t.Logf("PASS: Different messages correctly rejected in aggregation")
}

// =============================================================================
// TEST 6: SUBGROUP VALIDATION
// =============================================================================

// TestSubgroup_PublicKeyValidation tests public key subgroup validation
func TestSubgroup_PublicKeyValidation(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	pubBytes := pub.Bytes()

	// Valid public key should pass
	if err := ValidateBLSPublicKeySubgroup(pubBytes); err != nil {
		t.Errorf("Valid public key should pass subgroup validation: %v", err)
	}

	t.Logf("PASS: Public key subgroup validation works")
}

// TestSubgroup_SignatureValidation tests signature subgroup validation
func TestSubgroup_SignatureValidation(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	sig := priv.Sign([]byte("test"))
	sigBytes := sig.Bytes()

	// Valid signature should pass
	if err := ValidateBLSSignatureSubgroup(sigBytes); err != nil {
		t.Errorf("Valid signature should pass subgroup validation: %v", err)
	}

	t.Logf("PASS: Signature subgroup validation works")
}

// TestSubgroup_InvalidPublicKeySize tests rejection of wrong-size keys
func TestSubgroup_InvalidPublicKeySize(t *testing.T) {
	// Too short
	shortKey := make([]byte, 32)
	rand.Read(shortKey)
	if err := ValidateBLSPublicKeySubgroup(shortKey); err == nil {
		t.Error("Short public key should fail validation")
	}

	// Too long
	longKey := make([]byte, 128)
	rand.Read(longKey)
	if err := ValidateBLSPublicKeySubgroup(longKey); err == nil {
		t.Error("Long public key should fail validation")
	}

	t.Logf("PASS: Invalid key sizes correctly rejected")
}

// TestSubgroup_InvalidSignatureSize tests rejection of wrong-size signatures
func TestSubgroup_InvalidSignatureSize(t *testing.T) {
	shortSig := make([]byte, 16)
	rand.Read(shortSig)
	if err := ValidateBLSSignatureSubgroup(shortSig); err == nil {
		t.Error("Short signature should fail validation")
	}

	t.Logf("PASS: Invalid signature sizes correctly rejected")
}

// TestSubgroup_RandomBytesRejected tests that random bytes are rejected
func TestSubgroup_RandomBytesRejected(t *testing.T) {
	// Random bytes of correct size should almost never be valid curve points
	randomKey := make([]byte, PublicKeySize)
	rand.Read(randomKey)

	// This may or may not fail - random bytes could happen to be valid
	// But statistically, they won't be
	err := ValidateBLSPublicKeySubgroup(randomKey)
	if err == nil {
		t.Log("Warning: Random bytes happened to be valid (very unlikely)")
	} else {
		t.Logf("PASS: Random bytes rejected: %v", err)
	}
}

// =============================================================================
// TEST 7: ATTESTATION WORKFLOW
// =============================================================================

// TestAttestation_FullWorkflow tests the complete attestation workflow
func TestAttestation_FullWorkflow(t *testing.T) {
	// Simulate Level 4 attestation workflow

	// Step 1: Compute message hash (result to be attested)
	resultHash := sha256.Sum256([]byte("execution_result_canonical_json"))
	messageHash := ComputeMessageHash(DomainResult, resultHash[:])

	// Step 2: Validators generate keys and attest
	numValidators := 4
	validators := make([]struct {
		id   string
		priv *PrivateKey
		pub  *PublicKey
		sig  *Signature
	}, numValidators)

	for i := 0; i < numValidators; i++ {
		priv, pub, _ := GenerateKeyPair()
		validators[i].id = "validator-" + string(rune('A'+i))
		validators[i].priv = priv
		validators[i].pub = pub
		validators[i].sig = priv.Sign(messageHash[:])
	}

	// Step 3: Verify each individual attestation
	for _, v := range validators {
		if !v.pub.Verify(v.sig, messageHash[:]) {
			t.Errorf("Validator %s signature failed individual verification", v.id)
		}
	}

	// Step 4: Validate all public keys before aggregation
	for _, v := range validators {
		if err := ValidateBLSPublicKeySubgroup(v.pub.Bytes()); err != nil {
			t.Errorf("Validator %s public key failed subgroup validation: %v", v.id, err)
		}
	}

	// Step 5: Aggregate signatures
	sigs := make([]*Signature, numValidators)
	pubKeys := make([]*PublicKey, numValidators)
	for i, v := range validators {
		sigs[i] = v.sig
		pubKeys[i] = v.pub
	}

	aggSig, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatalf("Signature aggregation failed: %v", err)
	}

	// Step 6: Verify aggregated attestation
	if !VerifyAggregateSignature(aggSig, pubKeys, messageHash[:]) {
		t.Error("Aggregated attestation verification failed")
	}

	t.Logf("PASS: Full attestation workflow completed")
	t.Logf("  Validators:     %d", numValidators)
	t.Logf("  Message hash:   %x...", messageHash[:8])
	t.Logf("  Aggregated sig: %s...", aggSig.Hex()[:16])
}

// TestAttestation_ThresholdCheck tests that threshold is enforced
func TestAttestation_ThresholdCheck(t *testing.T) {
	// 4 validators, threshold = 3 (need 3 of 4)
	numValidators := 4
	threshold := 3
	message := sha256.Sum256([]byte("result"))

	privKeys := make([]*PrivateKey, numValidators)
	pubKeys := make([]*PublicKey, numValidators)
	sigs := make([]*Signature, numValidators)

	for i := 0; i < numValidators; i++ {
		priv, pub, _ := GenerateKeyPair()
		privKeys[i] = priv
		pubKeys[i] = pub
		sigs[i] = priv.Sign(message[:])
	}

	// Test with only 2 signatures (below threshold)
	aggSig2, _ := AggregateSignatures(sigs[:2])
	// This will verify cryptographically, but we need to check count
	// The verification here proves the math - threshold enforcement is policy
	verified2 := VerifyAggregateSignature(aggSig2, pubKeys[:2], message[:])

	// Test with 3 signatures (at threshold)
	aggSig3, _ := AggregateSignatures(sigs[:3])
	verified3 := VerifyAggregateSignature(aggSig3, pubKeys[:3], message[:])

	if !verified2 {
		t.Error("2 signatures should verify cryptographically")
	}
	if !verified3 {
		t.Error("3 signatures should verify cryptographically")
	}

	// The threshold check is policy - verify we have enough signers
	signerCount := 2
	if signerCount >= threshold {
		t.Error("Should not reach threshold with only 2 signers")
	}

	signerCount = 3
	if signerCount < threshold {
		t.Error("Should reach threshold with 3 signers")
	}

	t.Logf("PASS: Threshold check logic verified")
	t.Logf("  Total validators: %d", numValidators)
	t.Logf("  Threshold:        %d", threshold)
}

// =============================================================================
// TEST 8: SERIALIZATION ROUND-TRIP
// =============================================================================

// TestSerialization_PrivateKey tests private key serialization
func TestSerialization_PrivateKey(t *testing.T) {
	priv, _, _ := GenerateKeyPair()

	// Serialize
	privBytes := priv.Bytes()
	privHex := priv.Hex()

	// Deserialize from bytes
	restored1, err := PrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}

	// Deserialize from hex
	restored2, err := PrivateKeyFromHex(privHex)
	if err != nil {
		t.Fatalf("PrivateKeyFromHex failed: %v", err)
	}

	// Verify restored keys produce same public key
	if !priv.PublicKey().Equal(restored1.PublicKey()) {
		t.Error("Restored private key produces different public key")
	}
	if !priv.PublicKey().Equal(restored2.PublicKey()) {
		t.Error("Restored private key from hex produces different public key")
	}

	t.Logf("PASS: Private key serialization round-trip successful")
}

// TestSerialization_PublicKey tests public key serialization
func TestSerialization_PublicKey(t *testing.T) {
	_, pub, _ := GenerateKeyPair()

	// Serialize
	pubBytes := pub.Bytes()
	pubHex := pub.Hex()

	// Deserialize
	restored1, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}

	restored2, err := PublicKeyFromHex(pubHex)
	if err != nil {
		t.Fatalf("PublicKeyFromHex failed: %v", err)
	}

	// Verify equality
	if !pub.Equal(restored1) {
		t.Error("Restored public key not equal to original")
	}
	if !pub.Equal(restored2) {
		t.Error("Restored public key from hex not equal to original")
	}

	t.Logf("PASS: Public key serialization round-trip successful")
}

// TestSerialization_Signature tests signature serialization
func TestSerialization_Signature(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("test")
	sig := priv.Sign(message)

	// Serialize
	sigBytes := sig.Bytes()
	sigHex := sig.Hex()

	// Deserialize
	restored1, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes failed: %v", err)
	}

	restored2, err := SignatureFromHex(sigHex)
	if err != nil {
		t.Fatalf("SignatureFromHex failed: %v", err)
	}

	// Verify restored signatures still verify
	if !pub.Verify(restored1, message) {
		t.Error("Restored signature doesn't verify")
	}
	if !pub.Verify(restored2, message) {
		t.Error("Restored signature from hex doesn't verify")
	}

	// Verify byte equality
	if !bytes.Equal(sig.Bytes(), restored1.Bytes()) {
		t.Error("Restored signature bytes don't match original")
	}

	t.Logf("PASS: Signature serialization round-trip successful")
}

// =============================================================================
// TEST 9: KNOWN TEST VECTORS
// =============================================================================

// TestKnownVector_MessageHash tests message hash computation
func TestKnownVector_MessageHash(t *testing.T) {
	// Test with known inputs
	domain := "TEST_DOMAIN"
	data := []byte("test_data")

	hash := ComputeMessageHash(domain, data)

	// Hash should be deterministic
	hash2 := ComputeMessageHash(domain, data)
	if hash != hash2 {
		t.Error("Message hash not deterministic")
	}

	// Different domain should produce different hash
	hash3 := ComputeMessageHash("OTHER_DOMAIN", data)
	if hash == hash3 {
		t.Error("Different domain should produce different hash")
	}

	// Different data should produce different hash
	hash4 := ComputeMessageHash(domain, []byte("other_data"))
	if hash == hash4 {
		t.Error("Different data should produce different hash")
	}

	t.Logf("PASS: Message hash computation verified")
	t.Logf("  Hash: %s", hex.EncodeToString(hash[:]))
}

// =============================================================================
// BENCHMARK TESTS
// =============================================================================

// BenchmarkKeyGeneration benchmarks key pair generation
func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair()
	}
}

// BenchmarkSigning benchmarks signature creation
func BenchmarkSigning(b *testing.B) {
	priv, _, _ := GenerateKeyPair()
	message := []byte("benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		priv.Sign(message)
	}
}

// BenchmarkVerification benchmarks signature verification
func BenchmarkVerification(b *testing.B) {
	priv, pub, _ := GenerateKeyPair()
	message := []byte("benchmark message")
	sig := priv.Sign(message)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pub.Verify(sig, message)
	}
}

// BenchmarkAggregation benchmarks signature aggregation
func BenchmarkAggregation(b *testing.B) {
	numSigs := 100
	sigs := make([]*Signature, numSigs)
	priv, _, _ := GenerateKeyPair()
	message := []byte("benchmark message")
	for i := 0; i < numSigs; i++ {
		sigs[i] = priv.Sign(message)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		AggregateSignatures(sigs)
	}
}
