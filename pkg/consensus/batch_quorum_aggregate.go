package consensus

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
)

// =============================================================================
// Batch quorum aggregation
// =============================================================================
//
// Turns partial BLS attestations from independent validators into the single aggregate the
// on-chain BLSZKVerifierV2 can check.
//
// # WHY THIS FILE EXISTS
//
// The batch path previously signed with the LOCAL validator's key alone (one signature) while
// declaring TotalVotingPower 700 / SignedVotingPower 700 — a full 7-of-7 quorum that had never
// happened. The chain rejected it, so it failed safe, but the tempting "fix" was to wrap that
// single signature in generateBLSZKProof. That would have MINTED a valid ZK proof asserting
// 700/700 from one key: exactly the CRYPTO-007 quorum forgery the authorized-subset
// commitments exist to prevent.
//
// So the rule enforced here is blunt: SignedVotingPower is computed by SUMMING the registered
// power of validators whose signature actually verified. It is never a constant, never the
// total, and never inferred from a count.
//
// # WHY VerifyG1 AND NOT Verify
//
// Partials are produced by bls_zkp.SignV6_1PreExec, which signs HashMessageToG1V2(msg). The
// bls package's Verify() hashes with RFC-9380 ExpandMsgXmd — a different curve point — and so
// reports false for a perfectly good signature. Using it here would silently reject every
// honest attestation and hang the quorum forever.

// BatchAttestationEntry is one validator's partial signature over a batch bundleId.
type BatchAttestationEntry struct {
	ValidatorID  string `json:"validator_id"`
	EVMAddress   string `json:"evm_address"`   // 0x-hex; the registry key
	SignatureHex string `json:"signature_hex"` // compressed G1
	PublicKeyHex string `json:"public_key_hex"`
}

// ValidatorRegistryEntry is the on-chain truth for one validator. Voting power MUST come from
// the anchor's registry, not from anything the attester tells us about itself.
type ValidatorRegistryEntry struct {
	EVMAddress   string
	PublicKeyHex string
	VotingPower  *big.Int
}

// QuorumAggregate is the verified result: an aggregate signature, the aggregate public key it
// verifies under, and the voting power that genuinely signed.
type QuorumAggregate struct {
	AggregateSignatureHex string
	AggregatePublicKeyHex string
	SignedVotingPower     *big.Int
	TotalVotingPower      *big.Int
	Signers               []string // EVM addresses, ascending — deterministic across validators
}

// AggregateBatchAttestations verifies each partial against the registry and folds the survivors
// into one aggregate.
//
// registry is keyed by lowercased EVM address. thresholdNum/thresholdDen express the quorum
// rule (2/3 in production): the aggregate is refused unless
//
//	signedPower * thresholdDen >= totalPower * thresholdNum
//
// Every rejection path returns an error rather than a partial result. A caller that got a
// QuorumAggregate back may rely on it having met threshold — there is no "almost" return.
func AggregateBatchAttestations(
	attestations []BatchAttestationEntry,
	registry map[string]ValidatorRegistryEntry,
	messageHash [32]byte,
	thresholdNum, thresholdDen int64,
) (*QuorumAggregate, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations to aggregate")
	}
	if len(registry) == 0 {
		return nil, fmt.Errorf("empty validator registry — cannot establish voting power")
	}
	if thresholdDen <= 0 || thresholdNum <= 0 || thresholdNum > thresholdDen {
		return nil, fmt.Errorf("nonsensical threshold %d/%d", thresholdNum, thresholdDen)
	}

	// Total power is a property of the REGISTRY, never of who showed up.
	totalPower := big.NewInt(0)
	for _, v := range registry {
		if v.VotingPower != nil {
			totalPower.Add(totalPower, v.VotingPower)
		}
	}
	if totalPower.Sign() == 0 {
		return nil, fmt.Errorf("registry has zero total voting power")
	}

	// The G1 point every partial must have signed. Computed once.
	h := bls_zkp.HashMessageToG1V2(messageHash)

	seen := make(map[string]bool, len(attestations))
	type accepted struct {
		addr string
		sig  *bls.Signature
		pub  *bls.PublicKey
	}
	var good []accepted

	for i, att := range attestations {
		addr := strings.ToLower(strings.TrimSpace(att.EVMAddress))
		if addr == "" {
			return nil, fmt.Errorf("attestation %d has no EVM address", i)
		}

		// Duplicate signers would inflate signed power without inflating real support, and the
		// aggregate pubkey would not match any authorized subset commitment either.
		if seen[addr] {
			return nil, fmt.Errorf("duplicate attestation from %s", addr)
		}
		seen[addr] = true

		reg, ok := registry[addr]
		if !ok {
			return nil, fmt.Errorf("attestation from unregistered validator %s", addr)
		}
		if reg.VotingPower == nil || reg.VotingPower.Sign() <= 0 {
			return nil, fmt.Errorf("validator %s has no voting power in the registry", addr)
		}

		// The public key is taken from the REGISTRY, not from the attestation. An attester
		// supplying its own key could sign with a key it controls and pass verification while
		// contributing power that belongs to a different validator.
		pub, err := publicKeyFromHex(reg.PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("registry pubkey for %s: %w", addr, err)
		}
		// If the attestation carries a key, it must agree — a mismatch means confusion or
		// an attempted substitution, and either way we stop.
		if strings.TrimSpace(att.PublicKeyHex) != "" {
			if !hexEqualFold(att.PublicKeyHex, reg.PublicKeyHex) {
				return nil, fmt.Errorf("validator %s attested with a key that is not its registered one", addr)
			}
		}

		sig, err := signatureFromHex(att.SignatureHex)
		if err != nil {
			return nil, fmt.Errorf("attestation from %s: %w", addr, err)
		}

		// The actual cryptographic check. VerifyG1, not Verify — see file header.
		if !pub.VerifyG1(sig, h) {
			return nil, fmt.Errorf("attestation from %s does not verify against the batch message", addr)
		}

		good = append(good, accepted{addr: addr, sig: sig, pub: pub})
	}

	// Deterministic order so every validator folds identically. Aggregation is commutative, but
	// the Signers list is compared across nodes and must not depend on arrival order.
	sort.Slice(good, func(i, j int) bool { return good[i].addr < good[j].addr })

	signedPower := big.NewInt(0)
	sigs := make([]*bls.Signature, 0, len(good))
	pubs := make([]*bls.PublicKey, 0, len(good))
	signers := make([]string, 0, len(good))
	for _, g := range good {
		signedPower.Add(signedPower, registry[g.addr].VotingPower)
		sigs = append(sigs, g.sig)
		pubs = append(pubs, g.pub)
		signers = append(signers, g.addr)
	}

	// Threshold, by POWER not by count. signedPower*den >= totalPower*num.
	lhs := new(big.Int).Mul(signedPower, big.NewInt(thresholdDen))
	rhs := new(big.Int).Mul(totalPower, big.NewInt(thresholdNum))
	if lhs.Cmp(rhs) < 0 {
		return nil, fmt.Errorf(
			"quorum not met: %s of %s voting power signed, need %d/%d (%d attestation(s))",
			signedPower, totalPower, thresholdNum, thresholdDen, len(good))
	}

	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, fmt.Errorf("aggregating signatures: %w", err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		return nil, fmt.Errorf("aggregating public keys: %w", err)
	}

	// Final self-check: the aggregate must verify under the aggregate key. If this fails the
	// fold is wrong, and submitting would burn gas on a proof the chain will reject.
	if !aggPub.VerifyG1(aggSig, h) {
		return nil, fmt.Errorf("aggregate signature does not verify under the aggregate public key")
	}

	return &QuorumAggregate{
		AggregateSignatureHex: aggSig.Hex(),
		AggregatePublicKeyHex: aggPub.Hex(),
		SignedVotingPower:     signedPower,
		TotalVotingPower:      totalPower,
		Signers:               signers,
	}, nil
}

// SignBatchAttestation produces this validator's partial over a batch message.
//
// Uses SignV6_1PreExec — NOT SignWithDomain. The latter hashes to a different G1 point and
// makes the V2 circuit unsatisfiable; that is the documented cause of the Sepolia test #7
// failure, and it is also why pkg/batch/attestation_broadcaster.go's signing path could never
// have produced a chain-verifiable aggregate.
func SignBatchAttestation(sk *bls.PrivateKey, messageHash [32]byte) (string, error) {
	if sk == nil {
		return "", fmt.Errorf("nil private key")
	}
	sig := bls_zkp.SignV6_1PreExec(sk, messageHash)
	if sig == nil {
		return "", fmt.Errorf("signing returned nil")
	}
	return sig.Hex(), nil
}

func publicKeyFromHex(s string) (*bls.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return nil, fmt.Errorf("malformed hex: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty public key")
	}
	return bls.PublicKeyFromBytes(b)
}

func signatureFromHex(s string) (*bls.Signature, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return nil, fmt.Errorf("malformed signature hex: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty signature")
	}
	// Subgroup check before any pairing: a point off the prime-order subgroup can make
	// verification behave unexpectedly.
	if err := bls.ValidateBLSSignatureSubgroup(b); err != nil {
		return nil, fmt.Errorf("signature failed subgroup check: %w", err)
	}
	return bls.SignatureFromBytes(b)
}

func hexEqualFold(a, b string) bool {
	na := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(a), "0x"))
	nb := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(b), "0x"))
	return na == nb
}
