package billing

import (
	"encoding/json"
	"testing"
)

// The proof class must survive onto the wire.
//
// The gateway prices on_cadence and on_demand from SEPARATE cost histories, because an
// on_cadence intent shares one anchor with up to 19 others while an on_demand intent pays for
// its own. Before the class was carried, the gateway took a single median across both
// populations: batched intents were charged for anchor capacity they never used, and expedited
// intents were charged less than their own anchor cost.
//
// An event that loses its class does not fail — it silently joins the unclassified fallback
// pool, so the mispricing returns with nothing to indicate it. These tests pin the field to the
// exact JSON name the gateway's ingest schema validates.

func TestCostEventCarriesProofClassOnTheWire(t *testing.T) {
	for _, class := range []string{"on_cadence", "on_demand"} {
		event, err := NewCostEvent("intent-1", "", "", sampleCost("base", "0xaaa", LegAnchor), nil)
		if err != nil {
			t.Fatal(err)
		}
		event.ProofClass = class

		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]interface{}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		// The gateway validates `proof_class` against an enum; any other spelling is dropped
		// as an unknown property and the event prices as unclassified.
		if got := wire["proof_class"]; got != class {
			t.Fatalf("proof_class on the wire = %v, want %q", got, class)
		}
	}
}

// An unset class must be OMITTED rather than sent as "". The gateway's enum accepts only the
// two real classes, so an empty string would be rejected outright — turning "we do not know the
// class" into a lost measurement, which is strictly worse than an imprecise one.
func TestUnknownProofClassIsOmittedNotEmpty(t *testing.T) {
	event, err := NewCostEvent("intent-1", "", "", sampleCost("base", "0xaaa", LegAnchor), nil)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["proof_class"]; present {
		t.Fatalf("proof_class must be omitted when unknown, got %v", wire["proof_class"])
	}
}

// ProbeConfig is where the class travels from the settle path to the reporter. It is not used to
// probe anything — it rides alongside Leg because both describe the event rather than how to
// measure it — so this guards against it being dropped as "unused probe config".
func TestProbeConfigCarriesProofClass(t *testing.T) {
	cfg := ProbeConfig{Chain: "base", Leg: LegAnchor, ProofClass: "on_cadence"}
	if cfg.ProofClass != "on_cadence" {
		t.Fatalf("ProbeConfig.ProofClass = %q", cfg.ProofClass)
	}
}
