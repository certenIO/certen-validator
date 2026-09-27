package execution

import (
	"strings"
	"testing"
)

// SEC-12: a committed event whose topic0 is empty or malformed must be REFUSED, never treated as
// satisfied or skipped. The member gate reads committed events from the signed intent only
// (memberLegsFromSignedIntent), so that is where a malformed one is refused.

func sec12Blobs(t *testing.T, topic0 string) [][]byte {
	leg := f77CallLeg(84532, true)
	ep := leg["executionPayload"].(map[string]interface{})
	ep["expectedEvents"] = []interface{}{map[string]interface{}{"contract": f77Target, "topic0": topic0}}
	return signedBlobs(t, "x", leg)
}

func TestSec12_EmptyTopic0_Refused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	if _, _, _, err := memberLegsFromSignedIntent(sec12Blobs(t, ""), 84532); err == nil {
		t.Error("a committed event with an empty topic0 must be refused, not skipped")
	}
}

func TestSec12_MalformedTopic0_Refused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	for _, topic := range []string{"0xZZZZ", "0x1234", rbTopic0().Hex() + "00"} {
		if _, _, _, err := memberLegsFromSignedIntent(sec12Blobs(t, topic), 84532); err == nil {
			t.Errorf("a committed event with the malformed topic0 %q must be refused, not skipped", topic)
		}
	}
}

func TestSec12_ValidTopic0_Accepted(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	legs, _, _, err := memberLegsFromSignedIntent(sec12Blobs(t, rbTopic0().Hex()), 84532)
	if err != nil || len(legs) != 1 || len(legs[0].Events) != 1 || legs[0].Events[0].Topic0 != rbTopic0() {
		t.Fatalf("a well-formed committed event: %v %+v", err, legs)
	}
	if !strings.EqualFold(legs[0].Events[0].Contract.Hex(), f77Target) {
		t.Fatal("contract not carried")
	}
}
