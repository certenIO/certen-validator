// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// CERTEN Governance Proof - Signature Verification
// This file provides Ed25519 signature verification with Accumulate protocol integration
// Direct translation of Python signature verification methods from gov_proof_level_G1.py

// =============================================================================
// Signature Verifier
// =============================================================================

// SignatureVerifier handles Ed25519 signature verification and Accumulate digest computation
type SignatureVerifier struct {
	sigbytesPath string // Path to sigbytes tool for Accumulate-specific digest computation
}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier(sigbytesPath string) *SignatureVerifier {
	return &SignatureVerifier{
		sigbytesPath: sigbytesPath,
	}
}

// ComputeAccumulateDigest computes Accumulate-specific signing digest using sigbytes helper
// Direct translation of Python _compute_accumulate_ed25519_digest
func (sv *SignatureVerifier) ComputeAccumulateDigest(ctx context.Context, sig SignatureData, txHash string) ([]byte, error) {
	fmt.Printf("[DIGEST] [ENTRY] sigbytesPath='%s', txHash=%s\n", sv.sigbytesPath, txHash[:16])
	if sv.sigbytesPath == "" {
		// In-process Accumulate protocol digest computation using the official protocol package
		// This matches what the sigbytes tool does:
		//   mdHash := sig.Metadata().Hash()
		//   digest := sha256.Sum256(append(mdHash, txnHash[:]...))

		// Use the transaction hash from the signature, not the outer txHash parameter
		actualTxHash := sig.TransactionHash
		if actualTxHash == "" {
			actualTxHash = txHash
		}

		txHashBytes, err := hex.DecodeString(strings.TrimPrefix(actualTxHash, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to decode transaction hash: %v", err)
		}
		if len(txHashBytes) != 32 {
			return nil, fmt.Errorf("transaction hash must be 32 bytes, got %d", len(txHashBytes))
		}
		var txHashArray [32]byte
		copy(txHashArray[:], txHashBytes)

		// Decode public key
		pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(sig.PublicKey, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key: %v", err)
		}

		// Parse signer URL
		signerUrl, err := url.Parse(sig.Signer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse signer URL '%s': %v", sig.Signer, err)
		}

		// Build the ED25519Signature using Accumulate protocol
		accSig := new(protocol.ED25519Signature)
		accSig.PublicKey = pubKeyBytes
		accSig.Signer = signerUrl
		accSig.SignerVersion = uint64(sig.SignerVersion)
		if sig.Timestamp != nil {
			accSig.Timestamp = uint64(*sig.Timestamp)
		}
		// Vote defaults to 0 (no vote)

		// Debug: show the values being used
		fmt.Printf("[DIGEST] [DEBUG] txHash=%s, pubKey=%x, signer=%s, version=%d, timestamp=%d\n",
			actualTxHash[:16], pubKeyBytes[:8], sig.Signer, sig.SignerVersion, accSig.Timestamp)

		// Compute the metadata hash using Accumulate's official method
		mdHash := accSig.Metadata().Hash()
		fmt.Printf("[DIGEST] [DEBUG] mdHash=%x\n", mdHash[:8])

		// Final digest = SHA256(mdHash + txnHash)
		digestInput := append(mdHash, txHashArray[:]...)
		digest := sha256.Sum256(digestInput)
		fmt.Printf("[DIGEST] [DEBUG] final digest=%x\n", digest[:8])

		return digest[:], nil
	}

	// Build command arguments
	var cmd *exec.Cmd

	// Check if sigbytes_path is a Go source file or executable
	if strings.HasSuffix(sv.sigbytesPath, ".go") {
		cmd = exec.CommandContext(ctx,
			"go", "run", sv.sigbytesPath,
			"--pubkey", sig.PublicKey,
			"--signer", sig.Signer,
			"--signer-version", strconv.FormatInt(sig.SignerVersion, 10),
			"--timestamp", func() string { if sig.Timestamp != nil { return strconv.FormatInt(*sig.Timestamp, 10) }; return "0" }(),
			"--txhash", txHash,
		)
	} else {
		cmd = exec.CommandContext(ctx,
			sv.sigbytesPath,
			"--pubkey", sig.PublicKey,
			"--signer", sig.Signer,
			"--signer-version", strconv.FormatInt(sig.SignerVersion, 10),
			"--timestamp", func() string { if sig.Timestamp != nil { return strconv.FormatInt(*sig.Timestamp, 10) }; return "0" }(),
			"--txhash", txHash,
		)
	}

	// Execute sigbytes tool
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("sigbytes failed (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("sigbytes execution failed: %v", err)
	}

	// Parse output to extract digest
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "digest=") {
			digestHex := strings.TrimPrefix(line, "digest=")
			digest, err := hex.DecodeString(digestHex)
			if err != nil {
				return nil, fmt.Errorf("invalid digest hex from sigbytes: %v", err)
			}
			return digest, nil
		}
	}

	return nil, fmt.Errorf("digest not found in sigbytes output")
}

// VerifyEd25519 verifies Ed25519 signature
// Direct translation of Python _verify_ed25519 with proper cryptographic implementation
func (sv *SignatureVerifier) VerifyEd25519(pubkeyHex, sigHex string, signedBytes []byte) error {
	// Decode public key
	pubkeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubkeyHex, "0x"))
	if err != nil {
		return fmt.Errorf("invalid public key hex: %v", err)
	}
	if len(pubkeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d (expected %d)", len(pubkeyBytes), ed25519.PublicKeySize)
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return fmt.Errorf("invalid signature hex: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d (expected %d)", len(sigBytes), ed25519.SignatureSize)
	}

	// Verify signature
	pubkey := ed25519.PublicKey(pubkeyBytes)
	if !ed25519.Verify(pubkey, signedBytes, sigBytes) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// ComputeKeyHash converts public key to SHA256 hash for membership checking
// Direct translation of Python _pubkey_hash_sha256
func (sv *SignatureVerifier) ComputeKeyHash(pubkeyHex string) (string, error) {
	pubkeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubkeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid public key hex: %v", err)
	}

	hash := sha256.Sum256(pubkeyBytes)
	return hex.EncodeToString(hash[:]), nil
}

// =============================================================================
// Signature Set Validation
// =============================================================================

// ValidateSignature validates a single signature against authority state
func (sv *SignatureVerifier) ValidateSignature(ctx context.Context, sig ValidatedSignature, state KeyPageState, txHash string) error {
	fmt.Printf("[SIGNATURE] [DEBUG] Starting validation for signature %s\n", SafeTruncate(sig.MessageHash, 16))
	fmt.Printf("[SIGNATURE] [DEBUG] Signature version: %d, State version: %d\n", sig.Signature.SignerVersion, state.Version)

	// Validate signer version matches current state
	if uint64(sig.Signature.SignerVersion) != state.Version {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Version mismatch %d != %d\n", sig.Signature.SignerVersion, state.Version)
		return fmt.Errorf("signature signer version mismatch: %d != %d", sig.Signature.SignerVersion, state.Version)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Public key: %s\n", SafeTruncate(sig.Signature.PublicKey, 16))

	// Compute key hash for membership check
	keyHash, err := sv.ComputeKeyHash(sig.Signature.PublicKey)
	if err != nil {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Key hash computation failed: %v\n", err)
		return fmt.Errorf("failed to compute key hash: %v", err)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Computed key hash: %s\n", SafeTruncate(keyHash, 16))
	fmt.Printf("[SIGNATURE] [DEBUG] Authority has %d authorized keys\n", len(state.Keys))
	for i, authorizedKey := range state.Keys {
		fmt.Printf("[SIGNATURE] [DEBUG] Authority key[%d]: %s\n", i, SafeTruncate(authorizedKey, 16))
	}

	// Check key membership in authority set
	found := false
	for _, authorizedKey := range state.Keys {
		if authorizedKey == keyHash {
			found = true
			break
		}
	}
	if !found {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Key not in authority set. Computed: %s\n", SafeTruncate(keyHash, 16))
		return fmt.Errorf("public key not in authority set: %s", SafeTruncate(keyHash, 16))
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Key membership verified\n")

	// Compute Accumulate-specific digest
	digest, err := sv.ComputeAccumulateDigest(ctx, sig.Signature, txHash)
	if err != nil {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Digest computation failed: %v\n", err)
		return fmt.Errorf("failed to compute signature digest: %v", err)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Digest computed successfully (len=%d, hex=%s)\n", len(digest), hex.EncodeToString(digest[:8]))
	fmt.Printf("[SIGNATURE] [DEBUG] Using txHash for digest: %s\n", txHash)
	fmt.Printf("[SIGNATURE] [DEBUG] Signature's embedded transactionHash: %s\n", sig.Signature.TransactionHash)
	fmt.Printf("[SIGNATURE] [DEBUG] Signature bytes: %s...\n", sig.Signature.Signature[:32])
	fmt.Printf("[SIGNATURE] [DEBUG] SignerVersion=%d, Timestamp=%v\n", sig.Signature.SignerVersion, sig.Signature.Timestamp)

	// Verify Ed25519 signature
	if err := sv.VerifyEd25519(sig.Signature.PublicKey, sig.Signature.Signature, digest); err != nil {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Ed25519 verification failed: %v\n", err)
		return fmt.Errorf("signature verification failed: %v", err)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] SUCCESS: Signature validated\n")

	return nil
}

// ValidateSignatureSet validates a complete set of signatures for authorization
// Direct translation of Python evaluate_authorization logic
func (sv *SignatureVerifier) ValidateSignatureSet(ctx context.Context, signatures []ValidatedSignature, snapshot AuthoritySnapshot, txHash string) (*AuthorizationResult, error) {
	fmt.Printf("[SIGNATURE] [DEBUG] ValidateSignatureSet: Received %d signatures to validate\n", len(signatures))
	fmt.Printf("[SIGNATURE] [DEBUG] Authority state: version=%d, threshold=%d, keys=%d\n", snapshot.StateExec.Version, snapshot.StateExec.Threshold, len(snapshot.StateExec.Keys))

	state := snapshot.StateExec
	validSignatures := make([]ValidatedSignature, 0)
	uniqueKeyHashes := make(map[string]bool)

	// Validate each signature
	for i, sig := range signatures {
		fmt.Printf("[SIGNATURE] [DEBUG] Processing signature %d/%d: %s\n", i+1, len(signatures), SafeTruncate(sig.MessageHash, 16))
		if err := sv.ValidateSignature(ctx, sig, state, txHash); err != nil {
			// Log validation failure but continue (non-fatal for individual signatures)
			fmt.Printf("[SIGNATURE] [FAIL] Signature %s validation failed: %v\n", sig.MessageHash[:16], err)
			continue
		}

		// Compute key hash for uniqueness tracking
		keyHash, err := sv.ComputeKeyHash(sig.Signature.PublicKey)
		if err != nil {
			fmt.Printf("[SIGNATURE] [FAIL] Failed to compute key hash for %s: %v\n", sig.MessageHash[:16], err)
			continue
		}

		// All validations passed
		validSignatures = append(validSignatures, sig)
		uniqueKeyHashes[keyHash] = true
		fmt.Printf("[SIGNATURE] [OK] Signature verified: %s (key: %s)\n", sig.MessageHash[:16], keyHash[:16])
	}

	// Check threshold satisfaction
	uniqueValidKeys := len(uniqueKeyHashes)
	thresholdSatisfied := uint64(uniqueValidKeys) >= state.Threshold
	executionSuccess := true // Transaction exists on principal#main
	timingValid := true

	// Check timing for all valid signatures
	for _, sig := range validSignatures {
		if !sig.TimingVerified {
			timingValid = false
			break
		}
	}

	fmt.Printf("[SIGNATURE] [STATS] Authorization evaluation complete:\n")
	fmt.Printf("[SIGNATURE]   Valid signatures: %d\n", len(validSignatures))
	fmt.Printf("[SIGNATURE]   Unique valid keys: %d\n", uniqueValidKeys)
	fmt.Printf("[SIGNATURE]   Required threshold: %d\n", state.Threshold)
	fmt.Printf("[SIGNATURE]   Threshold satisfied: %t\n", thresholdSatisfied)
	fmt.Printf("[SIGNATURE]   Timing valid: %t\n", timingValid)

	if !thresholdSatisfied {
		return nil, ValidationError{Msg: fmt.Sprintf("Threshold not satisfied: %d/%d", uniqueValidKeys, state.Threshold)}
	}

	// Create authorization result
	result := &AuthorizationResult{
		TxScope:             fmt.Sprintf("acc://%s@%s", txHash, snapshot.Page),
		TxHash:              txHash,
		KeyPage:             snapshot.Page,
		AuthoritySnapshot:   snapshot,
		ValidatedSignatures: validSignatures,
		UniqueValidKeys:     uniqueValidKeys,
		ThresholdSatisfied:  thresholdSatisfied,
		ExecutionSuccess:    executionSuccess,
		TimingValid:         timingValid,
		G1ProofComplete:     true,
	}

	return result, nil
}

// =============================================================================
// Signature Parsing and Extraction
// =============================================================================

// ExtractSignatureFromMessageResult extracts signature fields from v3 message result
// Direct translation of Python _extract_signature_from_message_result
func (sv *SignatureVerifier) ExtractSignatureFromMessageResult(msgResult map[string]interface{}) (SignatureData, error) {
	pu := ProofUtilities{}

	// Extract message object
	msg := pu.CaseInsensitiveGet(msgResult, "message")
	if msg == nil {
		return SignatureData{}, ValidationError{Msg: "Message result missing message{}"}
	}

	msgMap, ok := msg.(map[string]interface{})
	if !ok {
		return SignatureData{}, ValidationError{Msg: "Message is not an object"}
	}

	// Check message type
	msgType := pu.CaseInsensitiveGet(msgMap, "type")
	msgTypeStr, ok := msgType.(string)
	if !ok || msgTypeStr == "" {
		return SignatureData{}, ValidationError{Msg: "Message missing message.type"}
	}

	if strings.ToLower(msgTypeStr) != "signature" {
		return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Not a signature message (type: %s)", msgTypeStr)}
	}

	// Extract signature object
	sigObj := pu.CaseInsensitiveGet(msgMap, "signature")
	if sigObj == nil {
		return SignatureData{}, ValidationError{Msg: "Signature message missing message.signature{}"}
	}

	sigMap, ok := sigObj.(map[string]interface{})
	if !ok {
		return SignatureData{}, ValidationError{Msg: "Signature is not an object"}
	}

	// Extract signature type
	sigType := pu.CaseInsensitiveGet(sigMap, "type")
	sigTypeStr, ok := sigType.(string)
	if !ok || sigTypeStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.type missing"}
	}

	if strings.ToLower(sigTypeStr) != "ed25519" {
		return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Not an ed25519 signature (type: %s)", sigTypeStr)}
	}

	// Extract required fields
	sig := SignatureData{
		Type: strings.ToLower(sigTypeStr),
	}

	// Public key
	pubkey := pu.CaseInsensitiveGet(sigMap, "publicKey")
	pubkeyStr, ok := pubkey.(string)
	if !ok || pubkeyStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.publicKey missing/invalid"}
	}
	hv := HexValidator{}
	normalizedPubkey, err := hv.RequireHex32(pubkeyStr, "signature.publicKey")
	if err != nil {
		return SignatureData{}, err
	}
	sig.PublicKey = normalizedPubkey

	// Signature bytes
	signature := pu.CaseInsensitiveGet(sigMap, "signature")
	signatureStr, ok := signature.(string)
	if !ok || signatureStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.signature missing/invalid"}
	}
	normalizedSig, err := hv.RequireHex64(signatureStr, "signature.signature")
	if err != nil {
		return SignatureData{}, err
	}
	sig.Signature = normalizedSig

	// Transaction hash
	txHash := pu.CaseInsensitiveGet(sigMap, "transactionHash")
	txHashStr, ok := txHash.(string)
	if !ok || txHashStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.transactionHash missing/invalid"}
	}
	normalizedTxHash, err := hv.RequireHex32(txHashStr, "signature.transactionHash")
	if err != nil {
		return SignatureData{}, err
	}
	sig.TransactionHash = normalizedTxHash

	// Signer
	signer := pu.CaseInsensitiveGet(sigMap, "signer")
	if signer != nil {
		if signerMap, ok := signer.(map[string]interface{}); ok {
			// Nested signer object
			signerValue := pu.CaseInsensitiveGet(signerMap, "value")
			if signerValue == nil {
				signerValue = pu.CaseInsensitiveGet(signerMap, "url")
			}
			if signerStr, ok := signerValue.(string); ok && signerStr != "" {
				uu := URLUtils{}
				sig.Signer = uu.NormalizeURL(signerStr)
			}
		} else if signerStr, ok := signer.(string); ok && signerStr != "" {
			uu := URLUtils{}
			sig.Signer = uu.NormalizeURL(signerStr)
		}
	}

	// Signer version
	signerVersion := pu.CaseInsensitiveGet(sigMap, "signerVersion")
	if signerVersion == nil {
		return SignatureData{}, ValidationError{Msg: "Signature missing signerVersion"}
	}

	switch sv := signerVersion.(type) {
	case float64:
		sig.SignerVersion = int64(sv)
	case int:
		sig.SignerVersion = int64(sv)
	case int64:
		sig.SignerVersion = sv
	case uint64:
		sig.SignerVersion = int64(sv)
	case string:
		parsed, err := strconv.ParseInt(sv, 10, 64)
		if err != nil {
			return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Signature signerVersion not integer: %v", signerVersion)}
		}
		sig.SignerVersion = parsed
	default:
		return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Signature signerVersion not integer: %v", signerVersion)}
	}

	// Timestamp (optional)
	timestamp := pu.CaseInsensitiveGet(sigMap, "timestamp")
	if timestamp != nil {
		switch ts := timestamp.(type) {
		case float64:
			val := int64(ts)
			sig.Timestamp = &val
		case int:
			val := int64(ts)
			sig.Timestamp = &val
		case int64:
			sig.Timestamp = &ts
		case uint64:
			val := int64(ts)
			sig.Timestamp = &val
		case string:
			parsed, err := strconv.ParseInt(ts, 10, 64)
			if err == nil {
				sig.Timestamp = &parsed
			}
		}
	}

	// TXID (optional)
	txid := pu.CaseInsensitiveGet(sigMap, "txID")
	if txid != nil {
		if txidStr, ok := txid.(string); ok && txidStr != "" {
			sig.TXID = txidStr
		}
	}

	return sig, nil
}

// ValidateSignatureTiming validates signature timing against execution MBI
func (sv *SignatureVerifier) ValidateSignatureTiming(receipt ReceiptData, execMBI int64) bool {
	return receipt.LocalBlock <= execMBI
}

// ValidateTransactionHash validates signature transactionHash against expected TX_HASH
func (sv *SignatureVerifier) ValidateTransactionHash(sig SignatureData, expectedTxHash string) bool {
	hv := HexValidator{}

	// Normalize both hashes for comparison
	normalizedSig, err1 := hv.RequireHex32(sig.TransactionHash, "signature.transactionHash")
	normalizedExpected, err2 := hv.RequireHex32(expectedTxHash, "expected TX_HASH")

	if err1 != nil || err2 != nil {
		return false
	}

	return normalizedSig == normalizedExpected
}