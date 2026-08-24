// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ComputeAnchorSignatureDigest returns the bytes an Accumulate ed25519 signature
// covers: sha256( ED25519Signature{...}.Metadata().Hash() || signedHash ).
//
// This is the same preimage the governance layer's
// SignatureVerifier.ComputeAccumulateDigest builds. Both call
// protocol.ED25519Signature.Metadata().Hash(), so the algorithm lives in the
// protocol package rather than in either caller. The two are pinned to
// identical output by TestPhase2_DigestAgreesWithGovernanceVerifier.
func ComputeAnchorSignatureDigest(s AnchorSignature, signedHashHex string) ([]byte, error) {
	signedHashHex, err := MustHex32Lower(signedHashHex, "signedHash")
	if err != nil {
		return nil, err
	}
	signedHash, _ := hex.DecodeString(signedHashHex)

	pub, err := hex.DecodeString(strings.TrimPrefix(s.PublicKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("signature.publicKey: invalid hex: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signature.publicKey: expected %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}

	signer, err := acc_url.Parse(s.Signer)
	if err != nil {
		return nil, fmt.Errorf("signature.signer %q: %w", s.Signer, err)
	}

	sig := new(protocol.ED25519Signature)
	sig.PublicKey = pub
	sig.Signer = signer
	sig.SignerVersion = s.SignerVersion
	sig.Timestamp = s.Timestamp

	h := sha256.New()
	h.Write(sig.Metadata().Hash())
	h.Write(signedHash)
	return h.Sum(nil), nil
}

// Threshold returns keyCount * num / denom rounded up. It delegates to
// protocol.Rational.Threshold so there is exactly one implementation, and
// rejects degenerate rationals that would admit an under-signed anchor.
func (r Rational) Threshold(keyCount int) (uint64, error) {
	if r.Denominator == 0 {
		return 0, fmt.Errorf("acceptThreshold: zero denominator")
	}
	if r.Numerator == 0 {
		return 0, fmt.Errorf("acceptThreshold: zero numerator would admit an unsigned anchor")
	}
	if r.Numerator > r.Denominator {
		return 0, fmt.Errorf("acceptThreshold: numerator %d exceeds denominator %d", r.Numerator, r.Denominator)
	}
	pr := &protocol.Rational{Numerator: r.Numerator, Denominator: r.Denominator}
	return pr.Threshold(keyCount), nil
}

// VerifyOffline checks one L4 leg with no network access.
//
// It fails closed at every step. Nothing defaults to valid: the function
// returns an error unless every requirement below is met.
//
//	 1. SequencedMessage decodes to a SequencedMessage wrapping a transaction
//	    whose body is a partition anchor.
//	 2. seq.Hash() == SignedHash          (signatures are bound to THIS object)
//	 3. txn.Hash() == AnchorTxHash
//	 4. Routing and the anchor body's MinorBlockIndex / RootChainAnchor /
//	    StateTreeAnchor match the restated fields, so StateTreeAnchor is bound
//	    to what the quorum signed rather than merely asserted beside it.
//	 5. Partition is the anchor's source partition.
//	 6. Threshold == AcceptThreshold.Threshold(#validators active on Partition).
//	 7. Every signature verifies over the digest of SignedHash.
//	 8. Every signer is in ValidatorSet and active on Partition.
//	 9. Distinct verified signers >= Threshold.
func (l4 *Layer4) VerifyOffline() error {
	if l4 == nil {
		return fmt.Errorf("layer4: nil leg (L4 is required; a missing leg is not a passing leg)")
	}
	if l4.Partition == "" {
		return fmt.Errorf("layer4: empty partition")
	}

	// --- 1. decode the signed object -------------------------------------
	if l4.SequencedMessage == "" {
		return fmt.Errorf("layer4[%s]: no sequencedMessage stored; leg cannot be verified offline", l4.Partition)
	}
	raw, err := hex.DecodeString(l4.SequencedMessage)
	if err != nil {
		return fmt.Errorf("layer4[%s]: sequencedMessage invalid hex: %w", l4.Partition, err)
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("layer4[%s]: sequencedMessage does not decode: %w", l4.Partition, err)
	}

	// --- 2. the signatures are bound to this exact object ----------------
	signedHashHex, err := MustHex32Lower(l4.SignedHash, "layer4.signedHash")
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	computedSigned := seq.Hash()
	if lowerHex(hex.EncodeToString(computedSigned[:])) != signedHashHex {
		return fmt.Errorf("layer4[%s]: signedHash mismatch: stored=%s recomputed=%x",
			l4.Partition, signedHashHex, computedSigned[:])
	}

	// --- 3. the delivered transaction ------------------------------------
	tm, ok := seq.Message.(*messaging.TransactionMessage)
	if !ok {
		return fmt.Errorf("layer4[%s]: sequenced message wraps %T, expected a transaction", l4.Partition, seq.Message)
	}
	if tm.Transaction == nil {
		return fmt.Errorf("layer4[%s]: transaction message carries no transaction", l4.Partition)
	}
	anchorTxHashHex, err := MustHex32Lower(l4.AnchorTxHash, "layer4.anchorTxHash")
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	txh := tm.Transaction.Hash()
	if lowerHex(hex.EncodeToString(txh[:])) != anchorTxHashHex {
		return fmt.Errorf("layer4[%s]: anchorTxHash mismatch: stored=%s recomputed=%x",
			l4.Partition, anchorTxHashHex, txh[:])
	}

	// --- 4. the anchor body ----------------------------------------------
	src, mbi, rootAnchor, stateAnchor, err := partitionAnchorFields(tm.Transaction.Body)
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	if !strings.EqualFold(src, l4.Source) {
		return fmt.Errorf("layer4[%s]: source mismatch: stored=%s signed=%s", l4.Partition, l4.Source, src)
	}
	if mbi != l4.MinorBlockIndex {
		return fmt.Errorf("layer4[%s]: minorBlockIndex mismatch: stored=%d signed=%d", l4.Partition, l4.MinorBlockIndex, mbi)
	}
	storedRoot, err := MustHex32Lower(l4.RootChainAnchor, "layer4.rootChainAnchor")
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	if storedRoot != rootAnchor {
		return fmt.Errorf("layer4[%s]: rootChainAnchor mismatch: stored=%s signed=%s", l4.Partition, storedRoot, rootAnchor)
	}
	storedState, err := MustHex32Lower(l4.StateTreeAnchor, "layer4.stateTreeAnchor")
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	if storedState != stateAnchor {
		return fmt.Errorf("layer4[%s]: stateTreeAnchor mismatch: stored=%s signed=%s", l4.Partition, storedState, stateAnchor)
	}

	// Routing, as signed.
	if seq.Source == nil || !strings.EqualFold(seq.Source.String(), src) {
		return fmt.Errorf("layer4[%s]: sequenced source %v does not match anchor source %s", l4.Partition, seq.Source, src)
	}
	if l4.Destination != "" {
		if seq.Destination == nil || !strings.EqualFold(seq.Destination.String(), l4.Destination) {
			return fmt.Errorf("layer4[%s]: destination mismatch: stored=%s signed=%v", l4.Partition, l4.Destination, seq.Destination)
		}
	}
	if seq.Number != l4.SequenceNumber {
		return fmt.Errorf("layer4[%s]: sequenceNumber mismatch: stored=%d signed=%d", l4.Partition, l4.SequenceNumber, seq.Number)
	}

	// --- 5. the signing partition is the anchor's source ------------------
	srcPart, ok := protocol.ParsePartitionUrl(seq.Source)
	if !ok {
		return fmt.Errorf("layer4[%s]: source %v is not a partition URL", l4.Partition, seq.Source)
	}
	if !strings.EqualFold(srcPart, l4.Partition) {
		return fmt.Errorf("layer4[%s]: partition is not the anchor source partition (%s)", l4.Partition, srcPart)
	}

	// --- 6. threshold is the network's own, over the active set -----------
	if len(l4.ValidatorSet) == 0 {
		return fmt.Errorf("layer4[%s]: empty validator set", l4.Partition)
	}
	activeCount := 0
	byKeyHash := make(map[string]ValidatorKey, len(l4.ValidatorSet))
	for i, v := range l4.ValidatorSet {
		pkHex, err := MustHex32Lower(v.PublicKey, fmt.Sprintf("layer4.validatorSet[%d].publicKey", i))
		if err != nil {
			return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
		}
		pk, _ := hex.DecodeString(pkHex)
		sum := sha256.Sum256(pk)
		gotHash := hex.EncodeToString(sum[:])
		if lowerHex(v.PublicKeyHash) != gotHash {
			return fmt.Errorf("layer4[%s]: validatorSet[%d].publicKeyHash is not sha256(publicKey)", l4.Partition, i)
		}
		if _, dup := byKeyHash[gotHash]; dup {
			return fmt.Errorf("layer4[%s]: validatorSet contains duplicate key %s", l4.Partition, pkHex[:16])
		}
		byKeyHash[gotHash] = v
		if isActiveOn(v, l4.Partition) {
			activeCount++
		}
	}
	if activeCount == 0 {
		return fmt.Errorf("layer4[%s]: no validator is active on this partition", l4.Partition)
	}
	wantThreshold, err := l4.AcceptThreshold.Threshold(activeCount)
	if err != nil {
		return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
	}
	if wantThreshold == 0 {
		return fmt.Errorf("layer4[%s]: computed threshold is zero", l4.Partition)
	}
	if l4.Threshold != wantThreshold {
		return fmt.Errorf("layer4[%s]: threshold mismatch: stored=%d, %d/%d over %d active = %d",
			l4.Partition, l4.Threshold, l4.AcceptThreshold.Numerator, l4.AcceptThreshold.Denominator,
			activeCount, wantThreshold)
	}

	// --- 7/8. verify every signature, and place every signer --------------
	if len(l4.Signatures) == 0 {
		return fmt.Errorf("layer4[%s]: no signatures", l4.Partition)
	}
	distinct := make(map[string]struct{}, len(l4.Signatures))
	for i, s := range l4.Signatures {
		digest, err := ComputeAnchorSignatureDigest(s, signedHashHex)
		if err != nil {
			return fmt.Errorf("layer4[%s]: signature[%d]: %w", l4.Partition, i, err)
		}
		pkHex, err := MustHex32Lower(s.PublicKey, fmt.Sprintf("layer4.signatures[%d].publicKey", i))
		if err != nil {
			return fmt.Errorf("layer4[%s]: %w", l4.Partition, err)
		}
		pk, _ := hex.DecodeString(pkHex)
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(s.Signature, "0x"))
		if err != nil {
			return fmt.Errorf("layer4[%s]: signature[%d]: invalid hex: %w", l4.Partition, i, err)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			return fmt.Errorf("layer4[%s]: signature[%d]: expected %d bytes, got %d",
				l4.Partition, i, ed25519.SignatureSize, len(sigBytes))
		}
		if !ed25519.Verify(ed25519.PublicKey(pk), digest, sigBytes) {
			return fmt.Errorf("layer4[%s]: signature[%d] by %s does not verify", l4.Partition, i, pkHex[:16])
		}

		sum := sha256.Sum256(pk)
		keyHash := hex.EncodeToString(sum[:])
		v, known := byKeyHash[keyHash]
		if !known {
			return fmt.Errorf("layer4[%s]: signature[%d] key %s is not in the validator set", l4.Partition, i, pkHex[:16])
		}
		if !isActiveOn(v, l4.Partition) {
			return fmt.Errorf("layer4[%s]: signature[%d] key %s is not active on %s",
				l4.Partition, i, pkHex[:16], l4.Partition)
		}
		distinct[keyHash] = struct{}{}
	}

	// --- 9. quorum, counted over DISTINCT signers -------------------------
	if uint64(len(distinct)) < l4.Threshold {
		return fmt.Errorf("layer4[%s]: quorum not met: %d distinct valid signers < threshold %d (%d signatures supplied)",
			l4.Partition, len(distinct), l4.Threshold, len(l4.Signatures))
	}

	return nil
}

func isActiveOn(v ValidatorKey, partition string) bool {
	for _, p := range v.ActiveOn {
		if strings.EqualFold(p, partition) {
			return true
		}
	}
	return false
}

// partitionAnchorFields reads the fields common to both anchor body types.
// An unrecognised body is an error, never a pass.
func partitionAnchorFields(body protocol.TransactionBody) (source string, mbi uint64, rootAnchor, stateAnchor string, err error) {
	var pa *protocol.PartitionAnchor
	switch b := body.(type) {
	case *protocol.DirectoryAnchor:
		pa = &b.PartitionAnchor
	case *protocol.BlockValidatorAnchor:
		pa = &b.PartitionAnchor
	default:
		return "", 0, "", "", fmt.Errorf("transaction body %v is not a partition anchor", body.Type())
	}
	if pa.Source == nil {
		return "", 0, "", "", fmt.Errorf("anchor has no source")
	}
	return pa.Source.String(), pa.MinorBlockIndex,
		lowerHex(hex.EncodeToString(pa.RootChainAnchor[:])),
		lowerHex(hex.EncodeToString(pa.StateTreeAnchor[:])),
		nil
}
