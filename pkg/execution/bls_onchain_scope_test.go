// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F13: what "ZK-verified on-chain aggregation" and "recorded on-chain" hold for. The deployed BLSZKVerifierV2_1
// checks a BLS12-381 aggregate over H = HashMessageToG1V2(messageHash) - the batch quorum's and, since RB5 D4, the
// batch outcome's (TestTheQuorumProofPathIsAcceptedByTheDeployedVerifiers proves the deployed verifiers on all three
// chains accept that path). The per-result Phase 8 aggregate hashes with RFC 9380 hash_to_curve (RB5-F54) and is
// recorded on Accumulate, in the write-back, where VerifyWriteBackQuorum checks it.

// phase8Quorum is a real Phase 8 fold: five of seven BLS strategies sign one result message, counted against the
// registry as Phase 8 counts it. It returns the fold and the signers' private keys.
func phase8Quorum(t *testing.T) (*attestation.BLSStrategy, *attestation.AggregatedAttestation, []*bls.PrivateKey) {
	t.Helper()
	msg := &attestation.AttestationMessage{IntentID: "f13", TargetChain: "84532", ChainID: "84532", ResultHash: levelHash("f13 result"), AnchorTxHash: "0xf13"}
	registry := map[string]consensus.ValidatorRegistryEntry{}
	var atts []*attestation.Attestation
	var keys []*bls.PrivateKey
	var lead *attestation.BLSStrategy
	for i := 0; i < 7; i++ {
		s, err := attestation.NewBLSStrategyWithNewKey(fmt.Sprintf("validator-%d", i+1), uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: hex.EncodeToString(s.PublicKey()), VotingPower: big.NewInt(100)}
		if i >= 5 {
			continue
		}
		a, err := s.Sign(context.Background(), msg)
		if err != nil {
			t.Fatal(err)
		}
		atts = append(atts, a)
		sk, err := bls.PrivateKeyFromBytes(s.PrivateKeyBytes())
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, sk)
		if lead == nil {
			lead = s
		}
	}
	folded, _, err := foldResultAttestations(context.Background(), lead, msg, atts, registry, attestation.DefaultThresholdConfig())
	if err != nil || !folded.ThresholdMet {
		t.Fatalf("the Phase 8 fold: %v (met %v)", err, folded != nil && folded.ThresholdMet)
	}
	return lead, folded, keys
}

func TestWhichBLSAggregatesTheDeployedVerifiersCheck(t *testing.T) {
	lead, folded, keys := phase8Quorum(t)
	if ok, err := lead.VerifyAggregated(context.Background(), folded); err != nil || !ok {
		t.Fatalf("the Phase 8 aggregate does not verify as Phase 8 verifies it: %v", err)
	}
	sig, err := bls.SignatureFromBytes(folded.AggregatedSignature)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := bls.PublicKeyFromBytes(folded.AggregatedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// The relation the circuit proves is e(sig, G2) = e(HashMessageToG1V2(m), pk). The Phase 8 aggregate satisfies it
	// for neither 32-byte message it could be presented with - its message hash, or the domain-separated digest it
	// actually signed - so no proof the deployed verifier accepts can be made of it.
	domainDigest := sha256.Sum256(append([]byte(lead.Domain()), folded.MessageHash[:]...))
	for name, m := range map[string][32]byte{"message hash": folded.MessageHash, "domain digest": domainDigest} {
		if pub.VerifyG1(sig, bls_zkp.HashMessageToG1V2(m)) {
			t.Fatalf("the Phase 8 aggregate verifies under the contract's hash of its %s: the comments' scope is wrong", name)
		}
	}

	// The same validator keys, over the registry's outcome message, signed as the outcome recorder signs: that
	// aggregate is the circuit's relation, the one recordBatchOutcome has the deployed verifier check.
	outcome := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, [32]byte{0x11}, [32]byte{0x77}, [32]byte{0x44}, testAccSet, testIncarnation)
	var sigs []*bls.Signature
	var pubs []*bls.PublicKey
	for _, sk := range keys {
		hexSig, err := consensus.SignBatchAttestation(sk, outcome)
		if err != nil {
			t.Fatal(err)
		}
		s, err := bls.SignatureFromBytes(mustDecodeHex(t, hexSig))
		if err != nil {
			t.Fatal(err)
		}
		sigs, pubs = append(sigs, s), append(pubs, sk.PublicKey())
	}
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	aggPub, err := bls.AggregatePublicKeys(pubs)
	if err != nil {
		t.Fatal(err)
	}
	if !aggPub.VerifyG1(aggSig, bls_zkp.HashMessageToG1V2(outcome)) {
		t.Fatal("the outcome quorum of the same keys is not the circuit's relation")
	}
	if string(aggPub.Bytes()) != string(pub.Bytes()) {
		t.Fatal("the outcome quorum is not the Phase 8 signers' keys")
	}
}

// "This is what gets recorded on-chain": the Phase 8 aggregate is in the Accumulate write-back, verifiable there.
func TestThePhase8AggregateIsRecordedInTheAccumulateWriteBack(t *testing.T) {
	o := f81Orchestrator(nil, "v")
	c, _, _ := settledWithGateProofs(t, o)
	folded := c.Result.AggregatedAttestation
	got := writtenEntries(t, o, c)
	if got["aggregate_signature"] != hex.EncodeToString(folded.AggregatedSignature) ||
		got["attestation_message_hash"] != hex.EncodeToString(folded.MessageHash[:]) ||
		!strings.Contains(strings.ToLower(got["signature_scheme"]), "9380") {
		t.Fatalf("the write-back does not carry the Phase 8 aggregate: %q %q %q", got["aggregate_signature"], got["attestation_message_hash"], got["signature_scheme"])
	}
	bundle, _, err := o.buildAttestationBundleFromCycle(c)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := o.txBuilder.BuildFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	q, err := WriteBackQuorumFromEntries(tx.Body.DataEntry.ToDoubleHashFormat())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWriteBackQuorum(q); err != nil {
		t.Fatalf("the recorded aggregate does not verify from the write-back's own entries: %v", err)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
