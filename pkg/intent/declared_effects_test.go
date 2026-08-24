package intent

import (
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

// The distinction the whole feature rests on: an intent that declared NOTHING and an intent whose
// commitment we never learned are different facts, and they must not serialise the same way.
//
// Downstream (certen-approval-console, Runbook C) an empty array lets an evidence report tell an
// auditor "this transaction committed to no particular effects, so the question does not arise",
// while a NULL only lets it say "this cannot be shown". Collapsing the two manufactures a claim out
// of silence in an audit record.
func TestDeclaredEffectsFrom(t *testing.T) {
	leg := func(events ...consensus.ExpectedEventPayload) consensus.CCLeg {
		l := consensus.CCLeg{}
		l.ExecutionPayload = &consensus.ExecutionPayload{ExpectedEvents: events}
		return l
	}
	ev := func(topic string) consensus.ExpectedEventPayload {
		return consensus.ExpectedEventPayload{Contract: "0xA0b8", Topic0: topic}
	}

	t.Run("a parsed envelope declaring nothing yields an EMPTY ARRAY, never nil", func(t *testing.T) {
		// The native-transfer case, and the one most likely to be broken by a well-meaning
		// `var declared []T` — which marshals to `null`, not `[]`.
		got, n, err := DeclaredEffectsFrom(&consensus.CrossChainEnvelope{Legs: []consensus.CCLeg{leg()}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 0 {
			t.Fatalf("count = %d, want 0", n)
		}
		if string(got) != "[]" {
			t.Fatalf("got %q, want %q — nil or null here would read as \"unknown\" downstream", got, "[]")
		}
	})

	t.Run("legs with no execution payload still yield an empty array", func(t *testing.T) {
		got, n, err := DeclaredEffectsFrom(&consensus.CrossChainEnvelope{
			Legs: []consensus.CCLeg{{}, {}},
		})
		if err != nil || n != 0 || string(got) != "[]" {
			t.Fatalf("got %q, n=%d, err=%v; want %q, 0, nil", got, n, err, "[]")
		}
	})

	t.Run("an envelope with no legs at all yields an empty array", func(t *testing.T) {
		got, _, err := DeclaredEffectsFrom(&consensus.CrossChainEnvelope{})
		if err != nil || string(got) != "[]" {
			t.Fatalf("got %q, err=%v; want %q", got, err, "[]")
		}
	})

	t.Run("NO envelope yields nil — the honest unknown", func(t *testing.T) {
		got, n, err := DeclaredEffectsFrom(nil)
		if err != nil || n != 0 || got != nil {
			t.Fatalf("got %q, n=%d, err=%v; want nil, 0, nil", got, n, err)
		}
	})

	t.Run("collects across EVERY leg, not just the first", func(t *testing.T) {
		// A commitment is a commitment whichever leg made it, and one attestation covers them all.
		// Reading leg 0 alone would silently drop the rest.
		got, n, err := DeclaredEffectsFrom(&consensus.CrossChainEnvelope{
			Legs: []consensus.CCLeg{
				leg(ev("0xaaa")),
				{}, // a leg with no payload in the middle must not stop the walk
				leg(ev("0xbbb"), ev("0xccc")),
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 3 {
			t.Fatalf("count = %d, want 3", n)
		}
		var out []consensus.ExpectedEventPayload
		if err := json.Unmarshal(got, &out); err != nil {
			t.Fatalf("result is not valid JSON: %v", err)
		}
		want := []string{"0xaaa", "0xbbb", "0xccc"}
		if len(out) != len(want) {
			t.Fatalf("got %d events, want %d", len(out), len(want))
		}
		for i, w := range want {
			if out[i].Topic0 != w {
				t.Fatalf("event %d topic = %q, want %q", i, out[i].Topic0, w)
			}
		}
	})

	t.Run("the encoded shape is what the evidence report reads", func(t *testing.T) {
		// certen-approval-console's src/evidence/gateway.ts reads `contract` and `topic0` off each
		// entry. If these field names ever change, that reader goes quiet rather than failing — so
		// the wire shape is pinned here, on this side of the boundary.
		got, _, err := DeclaredEffectsFrom(&consensus.CrossChainEnvelope{
			Legs: []consensus.CCLeg{leg(ev("0xddf252ad"))},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var out []map[string]any
		if err := json.Unmarshal(got, &out); err != nil {
			t.Fatalf("not valid JSON: %v", err)
		}
		if len(out) != 1 {
			t.Fatalf("got %d entries, want 1", len(out))
		}
		if _, ok := out[0]["contract"]; !ok {
			t.Fatalf("entry has no \"contract\" field: %v", out[0])
		}
		if out[0]["topic0"] != "0xddf252ad" {
			t.Fatalf("topic0 = %v, want 0xddf252ad", out[0]["topic0"])
		}
	})
}
