package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB5-F14: a write-back's quorum is verifiable from the entry alone. Seven real BLS strategies, five sign; the
// snapshot is the one Phase 8 builds; the evidence goes into the entry and back out to the verifier.
func writeBackQuorumFixture(t *testing.T, signers int) (*CertenDataEntry, *attestation.AggregatedAttestation) {
	t.Helper()
	msg := &attestation.AttestationMessage{IntentID: "f14-intent", TargetChain: "84532", AnchorTxHash: "0xabc", ResultHash: [32]byte{7}, Timestamp: 1790000000}
	registry := map[string]consensus.ValidatorRegistryEntry{}
	var atts []*attestation.Attestation
	var lead *attestation.BLSStrategy
	for i := 0; i < 7; i++ {
		s, err := attestation.NewBLSStrategyWithNewKey(fmt.Sprintf("validator-%d", i+1), uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: hex.EncodeToString(s.PublicKey()), VotingPower: big.NewInt(100)}
		if i < signers {
			a, err := s.Sign(context.Background(), msg)
			if err != nil {
				t.Fatal(err)
			}
			atts = append(atts, a)
			if lead == nil {
				lead = s
			}
		}
	}
	threshold := attestation.DefaultThresholdConfig()
	// The fold Phase 8 makes: registered keys at registered power.
	folded, _, err := foldResultAttestations(context.Background(), lead, msg, atts, registry, threshold)
	if err != nil {
		t.Fatal(err)
	}
	set, err := registryAttestationSet(registry, threshold.CalculateThresholdWeight, 11832868)
	if err != nil {
		t.Fatal(err)
	}
	agg := &AggregatedAttestation{MessageHash: folded.MessageHash, AggregateSignature: folded.AggregatedSignature}
	if err := quorumEvidence(agg, set, folded, threshold, lead.Domain()); err != nil {
		t.Fatal(err)
	}
	e := &CertenDataEntry{
		AggregateSignature: hex.EncodeToString(agg.AggregateSignature), AttestationMessageHash: hex.EncodeToString(agg.MessageHash[:]),
		ValidatorSetRoot: hex.EncodeToString(agg.ValidatorRoot[:]), AttestationSnapshotID: hex.EncodeToString(agg.SnapshotID[:]),
		ValidatorBitfield: hex.EncodeToString(agg.ValidatorBitfield), TotalPower: agg.TotalVotingPower.String(),
		ThresholdNumerator: agg.ThresholdNumerator, ThresholdDenominator: agg.ThresholdDenominator,
		AttestationMessage: hex.EncodeToString(agg.MessagePreimage), ValidatorSet: validatorSetJSON(agg.Validators),
		SnapshotBlock: agg.SnapshotBlock, MinValidators: agg.MinValidators, SignatureScheme: agg.SignatureScheme, AttestationDomain: agg.AttestationDomain,
	}
	return e, folded
}

func verifyEntry(t *testing.T, e *CertenDataEntry) (*WriteBackQuorumReport, error) {
	t.Helper()
	q, err := WriteBackQuorumFromEntry(e)
	if err != nil {
		return nil, err
	}
	return VerifyWriteBackQuorum(q)
}

func TestAWriteBackQuorumVerifiesFromTheEntryAlone(t *testing.T) {
	e, _ := writeBackQuorumFixture(t, 5)
	rep, err := verifyEntry(t, e)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Signers) != 5 || rep.SignedPower.Int64() != 500 || rep.TotalPower.Int64() != 700 || !strings.Contains(rep.AttestedResult, "f14-intent") {
		t.Fatalf("report %+v", rep)
	}
}

func TestATamperedWriteBackQuorumIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*CertenDataEntry){
		"another message": func(e *CertenDataEntry) {
			e.AttestationMessage = hex.EncodeToString([]byte(`{"intent_id":"forged"}`))
		},
		"a non-signer marked as signing": func(e *CertenDataEntry) { e.ValidatorBitfield = "7f" },
		"a validator's power inflated": func(e *CertenDataEntry) {
			e.ValidatorSet = strings.Replace(e.ValidatorSet, `"power":"100"`, `"power":"900"`, 1)
		},
		"the stated set root":        func(e *CertenDataEntry) { e.ValidatorSetRoot = strings.Repeat("00", 32) },
		"the snapshot block":         func(e *CertenDataEntry) { e.SnapshotBlock++ },
		"a pre-RB5-F54 aggregate":    func(e *CertenDataEntry) { e.SignatureScheme = "" },
		"another signing domain":     func(e *CertenDataEntry) { e.AttestationDomain = "CERTEN_ATTESTATION_V1" },
		"the stated total power":     func(e *CertenDataEntry) { e.TotalPower = "600" },
		"no threshold":               func(e *CertenDataEntry) { e.ThresholdNumerator = 0 },
		"bits beyond the validators": func(e *CertenDataEntry) { e.ValidatorBitfield = "9f" },
	} {
		e, _ := writeBackQuorumFixture(t, 5)
		mutate(e)
		if _, err := verifyEntry(t, e); !errors.Is(err, ErrWriteBackQuorum) {
			t.Fatalf("%s: verified (%v)", name, err)
		}
	}
	// Four of seven is below 700*2/3+1 = 467.
	e, _ := writeBackQuorumFixture(t, 4)
	if _, err := verifyEntry(t, e); !errors.Is(err, ErrWriteBackQuorum) {
		t.Fatalf("a sub-threshold quorum verified: %v", err)
	}
}

// Phase 9 refuses to state a quorum its entries could not establish.
func TestQuorumEvidenceRefusesWhatItCannotStateHonestly(t *testing.T) {
	_, folded := writeBackQuorumFixture(t, 5)
	threshold := attestation.DefaultThresholdConfig()
	if err := quorumEvidence(&AggregatedAttestation{}, nil, folded, threshold, "d"); !errors.Is(err, ErrWriteBackQuorum) {
		t.Fatalf("no snapshot: %v", err)
	}
	other, _ := registryAttestationSet(map[string]consensus.ValidatorRegistryEntry{
		"0x0000000000000000000000000000000000000009": {EVMAddress: "0x0000000000000000000000000000000000000009",
			PublicKeyHex: hex.EncodeToString(make([]byte, 96)), VotingPower: big.NewInt(100)},
	}, threshold.CalculateThresholdWeight, 1)
	if err := quorumEvidence(&AggregatedAttestation{}, other, folded, threshold, "d"); !errors.Is(err, ErrWriteBackQuorum) {
		t.Fatalf("signers outside the snapshot: %v", err)
	}
	folded.MessageHash[0] ^= 1
	if err := quorumEvidence(&AggregatedAttestation{}, nil, folded, threshold, "d"); err == nil {
		t.Fatal("a message that does not hash to the signed one was stated")
	}
}

// Through the real serialization: the entries ToDoubleHashFormat writes to Accumulate parse back and verify, and a
// write-back without the evidence is the named predates state.
func TestAWriteBackQuorumVerifiesFromItsAccumulateEntries(t *testing.T) {
	e, _ := writeBackQuorumFixture(t, 5)
	e.EntryType, e.Version, e.ChainID = "CERTEN_RESULT", "2.0", 84532
	q, err := WriteBackQuorumFromEntries(e.ToDoubleHashFormat())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWriteBackQuorum(q); err != nil {
		t.Fatal(err)
	}
	e.SignatureScheme = ""
	if _, err := WriteBackQuorumFromEntries(e.ToDoubleHashFormat()); !errors.Is(err, ErrWriteBackPredatesEvidence) {
		t.Fatalf("a write-back without its evidence: %v", err)
	}
}
