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

	// resolver decides whether a key page's authority is satisfied, by walking
	// the delegation path each signature commits to. Optional: with none set,
	// threshold evaluation falls back to counting distinct keys, which is
	// correct for a page whose entries are all keys and cannot decide a
	// delegated signature at all - so one arriving without a resolver is
	// reported as unavailable rather than counted as absent.
	resolver *AuthorityResolver
}

// WithResolver returns the verifier with authority resolution enabled.
func (sv *SignatureVerifier) WithResolver(r *AuthorityResolver) *SignatureVerifier {
	sv.resolver = r
	return sv
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
		// The METADATA digest, which is the first of the two accumulate-core
		// accepts. It is computed by AcceptedDigests rather than rebuilt here, so
		// there is one implementation of the preimage and not two that can drift.
		//
		// This function is retained because callers and pinned fixtures use it,
		// and because "the metadata digest" is a meaningful thing to ask for. It
		// is NOT sufficient on its own to decide whether a signature is valid -
		// use VerifyAgainstAcceptedDigests for that, or a signature made over the
		// Initiator() merkle digest is counted invalid.
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

		digests, err := AcceptedDigests(sig, txHashArray)
		if err != nil {
			return nil, err
		}
		for _, d := range digests {
			if d.Form == DigestFormMetadata {
				fmt.Printf("[DIGEST] [DEBUG] metadata digest=%x (%d delegation hop(s))\n",
					d.Digest[:8], len(sig.Chain))
				return d.Digest, nil
			}
		}
		return nil, fmt.Errorf("no metadata digest was produced for this signature")
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
			"--timestamp", func() string {
				if sig.Timestamp != nil {
					return strconv.FormatInt(*sig.Timestamp, 10)
				}
				return "0"
			}(),
			"--txhash", txHash,
		)
	} else {
		cmd = exec.CommandContext(ctx,
			sv.sigbytesPath,
			"--pubkey", sig.PublicKey,
			"--signer", sig.Signer,
			"--signer-version", strconv.FormatInt(sig.SignerVersion, 10),
			"--timestamp", func() string {
				if sig.Timestamp != nil {
					return strconv.FormatInt(*sig.Timestamp, 10)
				}
				return "0"
			}(),
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
func (sv *SignatureVerifier) ValidateSignature(ctx context.Context, sig ValidatedSignature, state KeyPageState, txHash string) (string, error) {
	fmt.Printf("[SIGNATURE] [DEBUG] Starting validation for signature %s\n", SafeTruncate(sig.MessageHash, 16))
	fmt.Printf("[SIGNATURE] [DEBUG] Signature version: %d, State version: %d\n", sig.Signature.SignerVersion, state.Version)

	// A delegated signature's key does not sit on the page being checked, and
	// its version is the INNER page's version, so neither of the two checks
	// below means anything for it. Its AUTHORITY is decided by resolution
	// (authority_resolution.go), which walks the path the digest commits to and
	// asks the page that can actually answer.
	//
	// What this function still does for it - the important half - is verify the
	// CRYPTOGRAPHY: the digest, built over the whole delegation chain, against
	// the key. Membership is skipped here because it is the wrong question at
	// this point, not because it goes unasked.
	if sig.Signature.IsDelegated() {
		return sv.VerifyAgainstAcceptedDigests(sig.Signature, txHash)
	}

	// Validate signer version matches current state
	if uint64(sig.Signature.SignerVersion) != state.Version {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Version mismatch %d != %d\n", sig.Signature.SignerVersion, state.Version)
		return "", fmt.Errorf("signature signer version mismatch: %d != %d", sig.Signature.SignerVersion, state.Version)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Public key: %s\n", SafeTruncate(sig.Signature.PublicKey, 16))

	// Compute key hash for membership check
	keyHash, err := sv.ComputeKeyHash(sig.Signature.PublicKey)
	if err != nil {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Key hash computation failed: %v\n", err)
		return "", fmt.Errorf("failed to compute key hash: %v", err)
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
		return "", fmt.Errorf("public key not in authority set: %s", SafeTruncate(keyHash, 16))
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Key membership verified\n")

	// Verify against every digest Accumulate accepts, not just the first.
	//
	// A signature counts if EITHER the metadata digest or the Initiator() merkle
	// digest verifies (protocol/signature_utils.go:26-41). Checking only the
	// metadata form counted a valid signature as invalid, and because G1 fails
	// closed that surfaced as a governance rejection.
	form, err := sv.VerifyAgainstAcceptedDigests(sig.Signature, txHash)
	if err != nil {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: %v\n", err)
		return "", err
	}

	fmt.Printf("[SIGNATURE] [DEBUG] SUCCESS: Signature validated (%s digest, %d delegation hop(s))\n",
		form, len(sig.Signature.Chain))

	// The form is RETURNED rather than written to sig, which is a value copy.
	// Assigning it here would look like it was recorded and record nothing.
	return form, nil
}

// VerifyAgainstAcceptedDigests verifies a signature against each digest
// accumulate-core would accept, and reports which one carried it.
//
// The digest set is computed from the signature's own transaction hash when it
// has one, falling back to the caller's, which is the behaviour
// ComputeAccumulateDigest already had.
func (sv *SignatureVerifier) VerifyAgainstAcceptedDigests(sig SignatureData, txHash string) (string, error) {
	actualTxHash := sig.TransactionHash
	if actualTxHash == "" {
		actualTxHash = txHash
	}
	txHashBytes, err := hex.DecodeString(strings.TrimPrefix(actualTxHash, "0x"))
	if err != nil {
		return "", fmt.Errorf("failed to decode transaction hash: %v", err)
	}
	if len(txHashBytes) != 32 {
		return "", fmt.Errorf("transaction hash must be 32 bytes, got %d", len(txHashBytes))
	}
	var txHashArray [32]byte
	copy(txHashArray[:], txHashBytes)

	digests, err := AcceptedDigests(sig, txHashArray)
	if err != nil {
		// An unsupported type or an over-deep chain reaches the caller as
		// itself, so a capability limit is never reported as a bad signature.
		return "", err
	}

	var lastErr error
	for _, d := range digests {
		if err := sv.VerifyEd25519(sig.PublicKey, sig.Signature, d.Digest); err == nil {
			return d.Form, nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("signature verification failed against all %d accepted digest form(s): %v",
		len(digests), lastErr)
}

// ValidateSignatureSet validates a complete set of signatures for authorization
// Direct translation of Python evaluate_authorization logic
func (sv *SignatureVerifier) ValidateSignatureSet(ctx context.Context, signatures []ValidatedSignature, snapshot AuthoritySnapshot, txHash string, executionVerified bool) (*AuthorizationResult, error) {
	fmt.Printf("[SIGNATURE] [DEBUG] ValidateSignatureSet: Received %d signatures to validate\n", len(signatures))
	fmt.Printf("[SIGNATURE] [DEBUG] Authority state: version=%d, threshold=%d, keys=%d\n", snapshot.StateExec.Version, snapshot.StateExec.Threshold, len(snapshot.StateExec.Keys))

	state := snapshot.StateExec
	validSignatures := make([]ValidatedSignature, 0)
	uniqueKeyHashes := make(map[string]bool)

	// Validate each signature.
	//
	// These two failure paths used to be `continue`, and the threshold was
	// then computed over whatever survived. That is the same defect that
	// recorded nine healthy proofs as governance failures: an infrastructure
	// error and a genuinely invalid signature were dropped identically.
	//
	// Every signature reaching this function has already been fully validated
	// and counted by a signature route, so a failure here is not a routine
	// rejection - it is either an inconsistency between the two validations or
	// an outage. Both fail closed, and they fail closed DIFFERENTLY so an
	// outage is never recorded as an unmet threshold.
	var unavailable []UnavailableSignature
	for i, sig := range signatures {
		fmt.Printf("[SIGNATURE] [DEBUG] Processing signature %d/%d: %s\n", i+1, len(signatures), SafeTruncate(sig.MessageHash, 16))

		form, err := sv.ValidateSignature(ctx, sig, state, txHash)
		if err != nil {
			if isInfrastructureDigestFailure(err) {
				unavailable = append(unavailable, UnavailableSignature{
					MessageID: sig.MessageID, Stage: "revalidate-signature", Err: err.Error(),
				})
				continue
			}
			return nil, ValidationError{Msg: fmt.Sprintf(
				"signature %s passed route validation but failed re-validation: %v -- "+
					"refusing to compute a threshold over an inconsistent set",
				SafeTruncate(sig.MessageHash, 16), err)}
		}

		// Record which digest form carried this signature. It is evidence, and
		// it is the only way to observe whether the merkle form appears in
		// practice - which decides whether defect D4 was a live bug or a dormant
		// one.
		sig.Signature.DigestForm = form

		keyHash, err := sv.ComputeKeyHash(sig.Signature.PublicKey)
		if err != nil {
			// Cannot compute the key hash, so cannot establish uniqueness.
			// Dropping this signature would understate the signer count.
			unavailable = append(unavailable, UnavailableSignature{
				MessageID: sig.MessageID, Stage: "compute-key-hash", Err: err.Error(),
			})
			continue
		}

		validSignatures = append(validSignatures, sig)
		uniqueKeyHashes[keyHash] = true
		fmt.Printf("[SIGNATURE] [OK] Signature verified: %s (key: %s)\n", sig.MessageHash[:16], keyHash[:16])
	}

	if len(unavailable) > 0 {
		return nil, &SignatureEvidenceIncomplete{
			Route:       "authorization",
			Requested:   len(signatures),
			Evaluated:   len(signatures) - len(unavailable),
			Unavailable: unavailable,
		}
	}

	// Check threshold satisfaction, by RESOLVING the authority rather than by
	// counting distinct keys.
	//
	// Counting keys is right only when every entry is a key and every signature
	// is direct - which is every one of the 400 production proofs, and is why
	// the difference never showed. It is wrong the moment an entry is a
	// delegate: the delegated signer's key is not on this page, so it counts
	// zero, and the threshold comes up short. That reads as "the institution did
	// not authorize this" about a transaction the institution did authorize.
	//
	// Resolution counts satisfied ENTRIES, which is what a key page's
	// AcceptThreshold actually means, and it is also where the distinct-entry
	// rule lives - so one key signing twice is one acceptance here rather than
	// by the happy accident of a map key.
	//
	// With no resolver configured this falls back to the key count, which keeps
	// the 1-of-1 path working in callers that never set one up. The fallback is
	// recorded, not silent: a delegated signature cannot be resolved by it and
	// is reported as unavailable rather than counted as absent.
	uniqueValidKeys := len(uniqueKeyHashes)
	var thresholdSatisfied bool
	var resolution *ResolutionResult

	if sv.resolver != nil {
		sigs := make([]SignatureData, 0, len(validSignatures))
		for _, s := range validSignatures {
			sigs = append(sigs, s.Signature)
		}
		res, err := sv.resolver.Resolve(ctx, snapshot.Page, state, sigs)
		if err != nil {
			// Resolution could not be completed. That is an outage, not a
			// verdict, and it must never become one.
			return nil, &SignatureEvidenceIncomplete{
				Route:     "authority-resolution",
				Requested: len(validSignatures),
				Unavailable: []UnavailableSignature{{
					Stage: "resolve-authority", Err: err.Error(),
				}},
			}
		}
		resolution = res
		thresholdSatisfied = res.ThresholdMet()
		uniqueValidKeys = res.Satisfied

		for _, r := range res.Refused {
			if r.Reason == ReasonPageUnavailable {
				return nil, &SignatureEvidenceIncomplete{
					Route:     "authority-resolution",
					Requested: len(validSignatures),
					Unavailable: []UnavailableSignature{{
						MessageID: r.SignerPage, Stage: r.Reason, Err: r.Detail,
					}},
				}
			}
		}
	} else {
		for _, s := range validSignatures {
			if s.Signature.IsDelegated() {
				return nil, &SignatureEvidenceIncomplete{
					Route:     "authority-resolution",
					Requested: len(validSignatures),
					Unavailable: []UnavailableSignature{{
						MessageID: s.MessageID, Stage: "resolve-authority",
						Err: "a delegated signature reached threshold evaluation with no " +
							"resolver configured; counting keys cannot decide it, and " +
							"dropping it would understate the authority",
					}},
				}
			}
		}
		thresholdSatisfied = uint64(uniqueValidKeys) >= state.Threshold
	}

	// Timing starts FALSE and is earned. It previously started true and could
	// only be falsified by a signature in validSignatures, so an empty set
	// left it true - "never checked" reading as "checked and passed".
	timingValid := len(validSignatures) > 0
	for _, sig := range validSignatures {
		if !sig.TimingVerified {
			timingValid = false
			break
		}
	}

	// Execution success is G0's claim, not something this function can assert.
	// It was hardcoded `true` with the comment "Transaction exists on
	// principal#main" - a boolean defaulting to true, asserting a fact this
	// function never checked. It is now supplied by the caller from the G0
	// result that actually proved execution inclusion.
	executionSuccess := executionVerified

	fmt.Printf("[SIGNATURE] [STATS] Authorization evaluation complete:\n")
	fmt.Printf("[SIGNATURE]   Valid signatures: %d\n", len(validSignatures))
	fmt.Printf("[SIGNATURE]   Unique valid keys: %d\n", uniqueValidKeys)
	fmt.Printf("[SIGNATURE]   Required threshold: %d\n", state.Threshold)
	fmt.Printf("[SIGNATURE]   Threshold satisfied: %t\n", thresholdSatisfied)
	fmt.Printf("[SIGNATURE]   Timing valid: %t\n", timingValid)

	if !thresholdSatisfied {
		// The reason carries WHY each signature failed to count, not just the
		// arithmetic. "1/2" is indistinguishable between an institution that did
		// not authorize this and a signature we could not resolve.
		detail := ""
		if resolution != nil {
			detail = "; " + describeResolutionRefusals(resolution)
		}
		return nil, ValidationError{Msg: fmt.Sprintf("Threshold not satisfied: %d/%d%s",
			uniqueValidKeys, state.Threshold, detail)}
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
		// G1 completion is the conjunction of what was actually established,
		// not a literal. It was hardcoded `true`, so a result could report
		// G1ProofComplete while carrying TimingValid=false.
		G1ProofComplete: thresholdSatisfied && timingValid && executionSuccess,
	}
	if !result.G1ProofComplete {
		return nil, ValidationError{Msg: fmt.Sprintf(
			"G1 incomplete: thresholdSatisfied=%t timingValid=%t executionSuccess=%t",
			thresholdSatisfied, timingValid, executionSuccess)}
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

	// Unwrap any delegation before looking at the key signature.
	//
	// This used to be a flat type check that refused anything whose type was not
	// "ed25519", and a delegated signature's type is "delegated" - so every
	// delegated signature was refused here, before a digest was computed or a
	// key was checked. The delegation is not decoration on the signature: it is
	// inside the bytes the inner key signed, so the chain is collected here and
	// carried on the SignatureData rather than discarded. See delegation.go.
	sigMap, chain, err := unwrapDelegation(pu, sigMap)
	if err != nil {
		return SignatureData{}, err
	}

	// Extract signature type
	sigType := pu.CaseInsensitiveGet(sigMap, "type")
	sigTypeStr, ok := sigType.(string)
	if !ok || sigTypeStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.type missing"}
	}

	// Two different refusals, deliberately kept apart.
	//
	// An entry that is not a key signature at all - an authority signature, a
	// signature request - is routine: a key page's chain carries those, and
	// skipping them is correct. A key type we cannot verify is not routine: it
	// is a real vote we cannot count, and it must say so in its own words, or
	// the shrunken counted set reads as an unmet threshold, which reads as "the
	// institution did not authorize this".
	if err := requireSupportedType(SignatureData{Type: sigTypeStr}); err != nil {
		return SignatureData{}, err
	}

	// Extract required fields
	sig := SignatureData{
		Type:  strings.ToLower(sigTypeStr),
		Chain: chain,
	}
	if len(chain) > 0 {
		// The outermost type is what Accumulate calls this signature, and it is
		// the one whose metadata is hashed.
		sig.Type = "delegated"
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

	// Transaction hash: check signature.transactionHash first (devnet),
	// then fall back to message.txID which is acc://<txHash>@<scope> (Kermit/production)
	txHash := pu.CaseInsensitiveGet(sigMap, "transactionHash")
	txHashStr, ok := txHash.(string)
	if !ok || txHashStr == "" {
		// Fall back to message.txID: acc://<transactionHash>@<scope>
		txID := pu.CaseInsensitiveGet(msgMap, "txID")
		if txIDStr, ok2 := txID.(string); ok2 && txIDStr != "" {
			uu := URLUtils{}
			txHashStr, _ = uu.ParseAccURLHash(txIDStr)
		}
		if txHashStr == "" {
			return SignatureData{}, ValidationError{Msg: "Signature.transactionHash missing and no message.txID fallback"}
		}
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
