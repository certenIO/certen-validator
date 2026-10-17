// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// CERTEN Governance Proof - Signature Verification
// This file verifies every key-signature type Accumulate's executor accepts (govsig.AcceptedKeyTypes), with
// Accumulate's own protocol code (govsig.Verify), and provides the original Ed25519 helpers the pinned fixtures use.
// Direct translation of Python signature verification methods from gov_proof_level_G1.py

// =============================================================================
// Signature Verifier
// =============================================================================

// SignatureVerifier verifies key signatures and computes the Accumulate digests they are made over.
//
// The zero value is usable. The two optional functions give it the environment some types need: typedData signs the
// EIP-712 encoding of the whole transaction under the network's chain id, and the executor-version gate needs the
// partition a signature was recorded on. NewG1Layer sets both; without them a typedData signature and a gated
// signature are NAMED STATES (transaction_unavailable_for_typed_data, network_name_unproven,
// g1_executor_version_unproven), never accepted and never silently refused.
type SignatureVerifier struct {
	sigbytesPath string // Path to sigbytes tool for Accumulate-specific digest computation

	// governed returns the governed transaction, decoded and bound to txHash.
	governed func(txHash string) (*protocol.Transaction, error)
	// network returns the network's name and routing table.
	network func() (*govsig.Network, error)
}

// SignedAt says where a signature was recorded: the signer page whose signature chain holds it and the block of that
// page's partition that chain's receipt names. Zero means unknown.
type SignedAt struct {
	Signer string
	Block  int64
}

// RoutingUnavailable is the infrastructure failure of not being able to learn the network's routing, which the
// executor-version gate needs. It is unavailable evidence, never a rejection.
type RoutingUnavailable struct{ Err error }

func (e RoutingUnavailable) Error() string {
	return fmt.Sprintf("failed to compute signature digest: the network's routing could not be read: %v", e.Err)
}
func (e RoutingUnavailable) Reason() string { return "routing_unavailable" }
func (e RoutingUnavailable) Unwrap() error  { return e.Err }

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
//
// sha256(key) is the page-entry hash of FOUR of the nine accepted types (ed25519, legacyED25519, rsaSha256,
// ecdsaSha256). For rcd1, btc, btclegacy, eth and typedData it is the wrong hash. It is retained for the callers that
// hold only a bare key with no type (a page entry that carries only a publicKey) and for pinned fixtures; everything
// that holds a signature uses KeyHashOf, which applies the type's own rule.
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
//
// statePage is the URL `state` describes. A signature made on a DIFFERENT page
// cannot be checked against it - see the sibling-authority note below - and
// passing "" keeps the old behaviour of assuming they are the same page.
func (sv *SignatureVerifier) ValidateSignature(ctx context.Context, sig ValidatedSignature, state KeyPageState, txHash string, statePage string) (string, error) {
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
		return sv.VerifySignature(sig, txHash)
	}

	// A SIBLING AUTHORITY'S SIGNATURE IS THE SAME SITUATION, for the same reason.
	//
	// `state` is the KPSW-EXEC snapshot of ONE page - the principal's. A
	// signature cast by another authority of the account sits on that
	// authority's own page, carries that page's version, and its key is on that
	// page. Checking it against the principal's page asks whether one book's key
	// is on a different book's page, and the answer is always no.
	//
	// Measured on Kermit, corpus case L: l2 signing from
	// acc://certen-p8l.acme/book2/1 was rejected as "public key not in authority
	// set" against acc://certen-p8l.acme/book/1 - a false governance rejection of
	// a signature the network accepted, on a transaction it DELIVERED.
	//
	// Membership and version are therefore left to resolution, which evaluates
	// each authority against ITS OWN page state (authority_set.go
	// resolveAuthority -> Resolve). What still happens here is the important
	// half: the CRYPTOGRAPHY is verified. Skipped because it is the wrong
	// question at this point, not because it goes unasked - exactly as for a
	// delegated signature above.
	if statePage != "" {
		signerPage := normalizeAccURL(sig.Signature.Signer)
		if signerPage != "" && signerPage != normalizeAccURL(statePage) {
			fmt.Printf("[SIGNATURE] [DEBUG] %s signs from %s, not the snapshot page %s - "+
				"membership and version are resolution's question, verifying cryptography only\n",
				SafeTruncate(sig.MessageHash, 16), signerPage, normalizeAccURL(statePage))
			return sv.VerifySignature(sig, txHash)
		}
	}

	// Validate signer version matches current state
	if uint64(sig.Signature.SignerVersion) != state.Version {
		fmt.Printf("[SIGNATURE] [DEBUG] FAIL: Version mismatch %d != %d\n", sig.Signature.SignerVersion, state.Version)
		return "", fmt.Errorf("signature signer version mismatch: %d != %d", sig.Signature.SignerVersion, state.Version)
	}

	fmt.Printf("[SIGNATURE] [DEBUG] Public key: %s\n", SafeTruncate(sig.Signature.PublicKey, 16))

	// Compute key hash for membership check
	keyHash, err := sv.KeyHashOf(sig.Signature)
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
	form, err := sv.VerifySignature(sig, txHash)
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

// VerifyAgainstAcceptedDigests verifies a signature as Accumulate's executor does and reports which digest form
// carried it.
//
// The verdict is protocol.VerifyUserSignature on the signature rebuilt from the record (govsig.Verify): the digests
// Accumulate accepts - the metadata hash, the initiator merkle hash, and for typedData the EIP-712 encoding - are
// tried by Accumulate's own Verify, not recomputed here. The transaction hash it covers is the signature's own when
// it has one, falling back to the caller's, which is the behaviour ComputeAccumulateDigest already had.
//
// This form knows nothing of where the signature was recorded, so a type whose acceptance depends on the executor
// version in force there (rsaSha256, ecdsaSha256, typedData; eth by the raw r||s rule) is the named state
// g1_executor_version_unproven. Use VerifySignature when the receipt's block is known.
func (sv *SignatureVerifier) VerifyAgainstAcceptedDigests(sig SignatureData, txHash string) (string, error) {
	return sv.verifyAt(sig, txHash, SignedAt{})
}

// VerifySignature verifies a validated signature where it was recorded: the executor-version gate is judged at the
// partition of its signer page and the block its receipt names.
func (sv *SignatureVerifier) VerifySignature(sig ValidatedSignature, txHash string) (string, error) {
	return sv.verifyAt(sig.Signature, txHash, SignedAt{Signer: sig.Signature.Signer, Block: sig.Receipt.LocalBlock})
}

func (sv *SignatureVerifier) verifyAt(sig SignatureData, txHash string, at SignedAt) (string, error) {
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

	outer, err := buildProtocolSignature(sig)
	if err != nil {
		// An unsupported type, a record that cannot be rebuilt or an over-deep chain reaches the caller as itself, so
		// a capability limit is never reported as a bad signature.
		return "", err
	}
	un, err := govsig.Unwrap(outer)
	if err != nil {
		return "", govsigRefusal(err)
	}

	env := govsig.Env{TxHash: txHashArray}
	var net *govsig.Network
	needsNetwork := func() (*govsig.Network, error) {
		if net != nil {
			return net, nil
		}
		if sv.network == nil {
			return nil, nil
		}
		n, err := sv.network()
		if err != nil {
			return nil, RoutingUnavailable{Err: err}
		}
		net = n
		return n, nil
	}

	ty := un.Inner.Type()
	if ty == protocol.SignatureTypeTypedData {
		if sv.governed != nil {
			if txn, err := sv.governed(hex.EncodeToString(txHashArray[:])); err == nil {
				env.Transaction = txn
			}
		}
		n, err := needsNetwork()
		if err != nil {
			return "", err
		}
		if n != nil {
			env.NetworkName = n.Name
		}
	}
	if govsig.RequiredVersion(ty, govsig.EthRuleV2RSV) != 0 || govsig.RequiredVersion(ty, govsig.EthRuleNone) != 0 {
		// gated: learn the signer page's partition
		if at.Signer != "" && at.Block > 0 {
			n, err := needsNetwork()
			if err != nil {
				return "", err
			}
			if n != nil {
				part, err := n.Partition(at.Signer)
				if err != nil {
					return "", RoutingUnavailable{Err: err}
				}
				env.Where = govsig.Where{Partition: part, Block: at.Block}
			}
		}
	}

	v, err := govsig.Verify(outer, env)
	if err != nil {
		return "", govsigRefusal(err)
	}
	return v.Form, nil
}

// govsigRefusal maps govsig's typed refusals onto this package's, so that a caller classifying an error sees the same
// types it always has for the cases that existed before.
func govsigRefusal(err error) error {
	var nk govsig.NotKeySignature
	if errors.As(err, &nk) {
		return NotAKeySignature{Type: nk.Type}
	}
	var de govsig.DepthExceeded
	if errors.As(err, &de) {
		return DelegationDepthExceeded{Depth: de.Depth, Limit: de.Limit}
	}
	return err
}

// namedState reports whether err is one of the named states that mean "this signature could not be judged", with the
// reason code to record and whether retrying could change the answer.
func namedState(err error) (reason string, permanent bool, ok bool) {
	var (
		unproven govsig.ExecutorVersionUnproven
		notMet   govsig.ExecutorGateNotMet
		noTxn    govsig.TransactionUnavailableForTypedData
		noName   govsig.NetworkNameUnproven
		routing  RoutingUnavailable
		bytesAbs SignatureBytesAbsent
		undec    SignatureUndecodable
		disagree SignatureFieldsDisagree
	)
	switch {
	case errors.As(err, &unproven):
		return unproven.Reason(), true, true
	case errors.As(err, &notMet):
		return notMet.Reason(), true, true
	case errors.As(err, &noTxn):
		return noTxn.Reason(), false, true
	case errors.As(err, &noName):
		return noName.Reason(), false, true
	case errors.As(err, &routing):
		return routing.Reason(), false, true
	case errors.As(err, &bytesAbs):
		return bytesAbs.Reason(), true, true
	case errors.As(err, &undec):
		return undec.Reason(), true, true
	case errors.As(err, &disagree):
		return disagree.Reason(), true, true
	}
	return "", false, false
}

// KeyHashOf is the page-entry hash of the signature's innermost key by the TYPE'S OWN rule (protocol.PublicKeyHash):
// sha256(key) for ed25519, legacyED25519, rsaSha256 and ecdsaSha256, and a different hash for rcd1, btc, btclegacy,
// eth and typedData. ComputeKeyHash is sha256 only and is wrong for those five.
func (sv *SignatureVerifier) KeyHashOf(sig SignatureData) (string, error) {
	outer, err := buildProtocolSignature(sig)
	if err != nil {
		return "", err
	}
	un, err := govsig.Unwrap(outer)
	if err != nil {
		return "", govsigRefusal(err)
	}
	h, err := govsig.KeyHash(un.Inner)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h), nil
}

// ValidateSignatureSet validates a complete set of signatures for authorization
// Direct translation of Python evaluate_authorization logic
//
// principal is the ACCOUNT THE TRANSACTION WAS EXECUTED AGAINST — the data
// account, not the signer's key page and not the ADI. It is what carries the
// authority set Accumulate evaluates, and passing anything else asks a narrower
// question. Empty falls back to the key page, which is the pre-Phase-8
// behaviour, and the fallback says so.
// extra carries the authorities the TRANSACTION requires beyond the
// principal's, plus the ignoreDisabled flag, both derived from the body. See
// g1_extra_authorities.go. A zero value means an ordinary transaction that adds
// no authority - which is every writeData intent.
func (sv *SignatureVerifier) ValidateSignatureSet(ctx context.Context, signatures []ValidatedSignature, snapshot AuthoritySnapshot, txHash string, executionVerified bool, principal string, authz authorizationEvaluator, extra ExtraAuthorities) (*AuthorizationResult, error) {
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

		// The cryptography, which is true at any time: the key signed this
		// transaction. Whether its page, version and vote made it count is
		// decided per page at the block it was recorded, by the vote model
		// below - not here against the page at execution.
		form, err := sv.VerifySignature(sig, txHash)
		if err != nil {
			if isInfrastructureDigestFailure(err) {
				unavailable = append(unavailable, UnavailableSignature{
					MessageID: sig.MessageID, Stage: "revalidate-signature", Err: err.Error(),
				})
				continue
			}
			// A signature that could not be judged (a named state) is unavailable evidence, never a rejection.
			if reason, _, named := namedState(err); named {
				unavailable = append(unavailable, UnavailableSignature{
					MessageID: sig.MessageID, Stage: reason, Err: err.Error(),
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

		keyHash, err := sv.KeyHashOf(sig.Signature)
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

	// THE AUTHORITY VOTE, AS ACCUMULATE-CORE COUNTS IT (g1_votes.go).
	//
	// Each page is judged at the block it received each message, votes are
	// tallied per delegation path at one signer version, every delegate page's
	// own threshold applies, a signature's vote is read rather than assumed,
	// and every authority of the principal as of execution must vote accept.
	//
	// There is no fallback. Counting distinct keys against one page's
	// threshold - what this did with no resolver configured - answers a
	// narrower question than G1 claims and cannot see delegation at all.
	if authz == nil {
		return nil, &SignatureEvidenceIncomplete{
			Route:     "authority-vote",
			Requested: len(validSignatures),
			Unavailable: []UnavailableSignature{{
				Stage: "evaluate-authority-vote",
				Err:   "no authorization evaluator was supplied for this transaction; nothing was evaluated",
			}},
		}
	}
	vote, err := authz.Evaluate(ctx, validSignatures, extra)
	if err != nil {
		// A vote the chain records but that could not be re-established, an
		// authority set that cannot be read as of execution, a page whose
		// history cannot be replayed: none of these is the institution
		// withholding approval, and none may produce a governance verdict.
		return nil, &SignatureEvidenceIncomplete{
			Route:     "authority-vote",
			Requested: len(validSignatures),
			Unavailable: []UnavailableSignature{{
				MessageID: principal,
				Stage:     "evaluate-authority-vote",
				Err: "the authority vote could not be established, so no governance verdict was " +
					"computed: " + err.Error() + ". This is NOT a governance rejection",
			}},
		}
	}
	thresholdSatisfied := vote.Satisfied
	uniqueValidKeys := vote.AcceptingKeys()

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

	// WHICH authorities voted, and how. This is the evidence for the claim G1
	// actually makes - "the account's authority set approved".
	fmt.Printf("[SIGNATURE]   Authority set (%d authority/ies): %s\n", len(vote.Authorities), vote.Describe())

	if !thresholdSatisfied {
		// Name WHICH authority did not vote to accept, and what each of its
		// pages recorded. "1/2" cannot distinguish an institution that did not
		// authorize this from one that voted against it.
		return nil, &AuthorizationNotSatisfied{Msg: fmt.Sprintf("Threshold not satisfied: %d/%d; %s",
			uniqueValidKeys, state.Threshold, vote.Describe())}
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
		Authorization:       vote,
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
	outermost := sigMap // the signature as the network delivered it, delegation wrappers included

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
	keyType := strings.ToLower(sigTypeStr)
	sig := SignatureData{
		Type:  keyType,
		Chain: chain,
	}
	if len(chain) > 0 {
		// The outermost type is what Accumulate calls this signature, and it is
		// the one whose metadata is hashed.
		sig.Type = "delegated"
		// The key's own type is recorded beside it - a delegated ECDSA signature must not read as a delegated ed25519
		// one. Omitted for ed25519 so every record that existed before keeps its bytes.
		if keyType != "ed25519" {
			sig.InnerType = keyType
		}
	}

	// Public key and signature bytes. ed25519, legacyED25519 and rcd1 keys are 32 bytes and their signatures 64; every
	// other type has its own encoding (secp256k1 keys 33 or 65 bytes, an ECDSA P-256 SPKI 91, an RSA PKCS#1 270 for a
	// 2048-bit modulus; signatures DER, 64 or 65 raw bytes, or the modulus size), which Accumulate's own decoder and
	// Verify judge - this code only requires well-formed hex.
	fixedShape := keyType == "ed25519" || keyType == "legacyed25519" || keyType == "rcd1"
	hv := HexValidator{}
	pubkey := pu.CaseInsensitiveGet(sigMap, "publicKey")
	pubkeyStr, ok := pubkey.(string)
	if !ok || pubkeyStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.publicKey missing/invalid"}
	}
	var normalizedPubkey string
	if fixedShape {
		normalizedPubkey, err = hv.RequireHex32(pubkeyStr, "signature.publicKey")
	} else {
		normalizedPubkey, err = hv.NormalizeHex(pubkeyStr, 0)
	}
	if err != nil {
		return SignatureData{}, err
	}
	sig.PublicKey = normalizedPubkey

	signature := pu.CaseInsensitiveGet(sigMap, "signature")
	signatureStr, ok := signature.(string)
	if !ok || signatureStr == "" {
		return SignatureData{}, ValidationError{Msg: "Signature.signature missing/invalid"}
	}
	var normalizedSig string
	if fixedShape {
		normalizedSig, err = hv.RequireHex64(signatureStr, "signature.signature")
	} else {
		normalizedSig, err = hv.NormalizeHex(signatureStr, 0)
	}
	if err != nil {
		return SignatureData{}, err
	}
	sig.Signature = normalizedSig

	// The vote this signature casts. Accumulate omits the field for the zero
	// value, which is accept; any other value is named. Read, never assumed:
	// a key that votes reject is not an acceptance, and counting it as one is
	// how a rejection became a vote in favour.
	vote := protocol.VoteTypeAccept
	if v := pu.CaseInsensitiveGet(sigMap, "vote"); v != nil {
		name, ok := v.(string)
		if !ok {
			return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Signature.vote is %T, not a vote name", v)}
		}
		parsed, ok := protocol.VoteTypeByName(name)
		if !ok {
			return SignatureData{}, ValidationError{Msg: fmt.Sprintf("Signature.vote %q is not a vote Accumulate defines", name)}
		}
		vote = parsed
	}
	sig.Vote = vote.String()

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

	raw, err := rawIfNeeded(sig, outermost)
	if err != nil {
		return SignatureData{}, err
	}
	sig.Raw = raw

	return sig, nil
}

// rawIfNeeded decides whether the record must carry Accumulate's own binary encoding, and returns it (hex) if so.
//
// The record's fields describe an ed25519 signature completely - unless it carries memo or data, which are inside the
// signed metadata hash and which the fields cannot hold. Every other key type has an encoding the fields do not
// describe. The test is exact, not a guess: rebuild the signature from the fields alone and compare its metadata hash
// with the one the delivered signature has. Equal -> the fields are enough and the record is byte-identical to what
// this code wrote before RB8-B (no raw). Different -> carry raw.
//
// The encoding is the OUTERMOST signature as delivered, decoded by protocol.UnmarshalSignatureJSON (Accumulate's own
// decoder) and re-encoded by its own MarshalBinary - the same bytes the vote's evidence carries (signatureBytes).
func rawIfNeeded(sig SignatureData, outermost map[string]interface{}) (string, error) {
	b, err := json.Marshal(outermost)
	if err != nil {
		return "", err
	}
	decoded, err := protocol.UnmarshalSignatureJSON(b)
	if err != nil {
		return "", SignatureUndecodable{Type: sig.Type, Err: err}
	}
	bin, err := decoded.MarshalBinary()
	if err != nil {
		return "", SignatureUndecodable{Type: sig.Type, Err: err}
	}

	keyType := sig.Type
	if sig.Type == "delegated" {
		keyType = sig.InnerType
		if keyType == "" {
			keyType = "ed25519"
		}
	}
	if keyType == "ed25519" {
		fromFields, err := buildFieldSignature(sig)
		if err == nil && bytes.Equal(fromFields.Metadata().Hash(), decoded.Metadata().Hash()) {
			return "", nil
		}
	}
	return hex.EncodeToString(bin), nil
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
