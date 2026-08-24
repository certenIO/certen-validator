package contracts

import (
	"encoding/json"
	"testing"
)

type g0Like struct {
	Level string `json:"level"`
}

// A nil TYPED pointer must leave its govRoot slot zero.
//
// Every production call site passes a typed pointer (lc.ConsensusProof,
// certenProof.G0Result, ...). A nil typed pointer in an interface is not
// `v == nil`, so the builder used to marshal it to the four bytes "null" and
// commit a constant non-zero hash for a layer that was absent.
func TestTypedNilPayloadLeavesSlotZero(t *testing.T) {
	var typedNil *g0Like

	if b, _ := json.Marshal(typedNil); string(b) != "null" {
		t.Fatalf("premise changed: json.Marshal(typed nil) = %q, want %q", b, "null")
	}
	if interface{}(typedNil) == nil {
		t.Fatal("premise changed: a typed nil pointer compared equal to nil")
	}

	var zero [32]byte
	cases := []struct {
		name string
		got  [32]byte
	}{
		{"L4", NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(typedNil).Build().L4ConsensusProofH},
		{"G0", NewAccumulateGovRootInputsBuilder().SetG0FromJSON(typedNil).Build().G0CanonicalHash},
		{"G1", NewAccumulateGovRootInputsBuilder().SetG1FromJSON(typedNil).Build().G1CanonicalHash},
		{"G2", NewAccumulateGovRootInputsBuilder().SetG2FromJSON(typedNil).Build().G2CanonicalHash},
	}
	for _, c := range cases {
		if c.got != zero {
			t.Errorf("%s: typed-nil payload produced a NON-ZERO slot %x", c.name, c.got)
		}
	}

	// Untyped nil and typed nil must agree, or signer and submitter could
	// diverge purely on how the caller spelled "absent".
	if NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(nil).Build().L4ConsensusProofH !=
		NewAccumulateGovRootInputsBuilder().SetL4ConsensusProofFromJSON(typedNil).Build().L4ConsensusProofH {
		t.Error("untyped nil and typed nil disagree on the L4 slot")
	}
}

// A PRESENT payload must hash exactly as before the fix — the fix must not
// move govRoot for any proof that actually carries its layers.
func TestPresentPayloadHashUnchangedByNilFix(t *testing.T) {
	v := &g0Like{Level: "G0"}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := CanonicalHashGovernance("certen:g0:v1", raw)
	got := NewAccumulateGovRootInputsBuilder().SetG0FromJSON(v).Build().G0CanonicalHash
	if got != want {
		t.Errorf("present payload hash changed: got %x want %x", got, want)
	}
}
