package execution

import (
	"strings"
	"testing"
)

// SEC-14: the Accumulate write-back must carry the VERIFIABLE quorum aggregate — not just
// self-reported booleans — so a downstream consumer can independently verify the >=2/3 BLS
// aggregate instead of trusting threshold_met. This locks the presence of those entries.
func TestSec14_WriteBackCarriesVerifiableAggregate(t *testing.T) {
	e := &CertenDataEntry{
		EntryType:              "CERTEN_EXECUTION_RESULT",
		Version:                "2.0",
		ValidatorCount:         5,
		SignedPower:            "5",
		ThresholdMet:           true,
		AggregateSignature:     "abcdef0123",
		AttestationMessageHash: "1122334455",
		ValidatorSetRoot:       "deadbeef",
		AttestationSnapshotID:  "cafebabe",
		ValidatorBitfield:      "1f",
		TotalPower:             "7",
		ThresholdNumerator:     2,
		ThresholdDenominator:   3,
	}

	entries := e.ToDoubleHashFormat()
	joined := make([]string, 0, len(entries))
	for _, b := range entries {
		joined = append(joined, string(b))
	}
	blob := strings.Join(joined, "\n")

	required := map[string]string{
		"aggregate_signature":      "abcdef0123",
		"attestation_message_hash": "1122334455",
		"validator_set_root":       "deadbeef",
		"attestation_snapshot_id":  "cafebabe",
		"validator_bitfield":       "1f",
		"total_power":              "7",
		"threshold_numerator":      "2",
		"threshold_denominator":    "3",
	}
	for key, val := range required {
		want := key + "=" + val
		if !strings.Contains(blob, want) {
			t.Errorf("write-back missing verifiable-aggregate entry %q\ngot:\n%s", want, blob)
		}
	}
}
