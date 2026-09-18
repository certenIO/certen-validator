// Copyright 2026 Certen Protocol
//
// The topic constants must be the values Ethereum actually puts in topics[0].

package anchor

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Every Topic* constant must equal the ID go-ethereum derives from the SAME ABI this package parses.
//
// These were computed with sha256 for the life of the file, under a comment that said Ethereum uses
// Keccak256 and that the real value would be supplied "at runtime for accuracy". Nothing supplied it. The
// result was a set of constants that match no log any node has ever emitted, and the only reason nothing
// broke is that the one code path using them is gated on EnabledEvents, which no caller sets.
//
// Deriving the expectation from the ABI rather than restating a hex literal is deliberate: a hand-copied
// expected value would have been just as wrong as the code, and would have agreed with it.
func TestEventTopicsMatchTheABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV3EventsABI))
	if err != nil {
		t.Fatalf("parsing the anchor event ABI: %v", err)
	}

	for name, topic := range map[string]common.Hash{
		"AnchorCreated":           TopicAnchorCreated,
		"ProofExecuted":           TopicProofExecuted,
		"ProofVerificationFailed": TopicProofVerificationFailed,
		"GovernanceExecuted":      TopicGovernanceExecuted,
		"ValidatorRegistered":     TopicValidatorRegistered,
		"ValidatorRemoved":        TopicValidatorRemoved,
		"ThresholdUpdated":        TopicThresholdUpdated,
	} {
		event, ok := parsed.Events[name]
		if !ok {
			t.Fatalf("the ABI declares no %s event", name)
		}
		if topic != event.ID {
			t.Errorf("Topic%s = %s, but the ABI's own id is %s — a filter on this value matches nothing",
				name, topic.Hex(), event.ID.Hex())
		}
	}
}

// A topic filter built from these constants must select the event it names. This is the assertion the
// original code could not have passed.
func TestTopicFilterSelectsTheEventItNames(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAnchorV3EventsABI))
	if err != nil {
		t.Fatal(err)
	}
	w := &EventWatcher{abi: parsed}

	for _, et := range []EventType{
		EventTypeAnchorCreated,
		EventTypeProofExecuted,
		EventTypeProofVerificationFailed,
		EventTypeGovernanceExecuted,
		EventTypeValidatorRegistered,
	} {
		topic := w.getTopicForEventType(et)
		if topic == (common.Hash{}) {
			t.Fatalf("%s has no topic", et)
		}
		// The dispatcher and the filter must agree: a log carrying this topic must parse as this event.
		var matched string
		for _, event := range parsed.Events {
			if event.ID == topic {
				matched = event.Name
			}
		}
		if matched != string(et) {
			t.Errorf("a filter for %s selects logs that parseLog resolves to %q", et, matched)
		}
	}
}
