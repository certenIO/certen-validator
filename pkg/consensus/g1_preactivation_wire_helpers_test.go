package consensus

import (
	"encoding/json"
	"testing"
)

// RB9-K defect 1, helpers shared by the wire-level tests and by the throwaway measurement at the rules v14 head (d20f693), which copies
// this file unchanged: raw JSON of a ValidatorBlock whose certificate carries a 2.1-named member of the wrong JSON type.

// wireMembers are the 2.1-named members of a certificate's proof v2, each placed by injectWire.
var wireMembers = []string{"votes", "votes[0].produced.sequenced", "anchors", "transaction", "check.routing",
	"pages[*].partition", "pages[*].roles", "pages[*].history"}

// wireValues are JSON values of a type none of the members above has (a value of the member's own type is not an error either way;
// every value is tried on every member, and what matters is that the 2.0 document is decided as if the member were absent).
var wireValues = []string{`5`, `true`, `"x"`, `{"a":1}`, `[1]`}

func wireObj(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func wireEnc(t *testing.T, m interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// injectWire returns the block's JSON with the member of intent_certificate.proof_v2 set to value, a raw JSON value.
func injectWire(t *testing.T, block []byte, member, value string) []byte {
	t.Helper()
	top := wireObj(t, block)
	ic := wireObj(t, top["intent_certificate"])
	pv := wireObj(t, ic["proof_v2"])
	switch member {
	case "version", "majors", "votes", "anchors", "transaction":
		pv[member] = json.RawMessage(value)
	case "votes[0].produced.sequenced":
		pv["votes"] = json.RawMessage(`[{"authority":"acc://a.acme/book","produced":{"sequenced":` + value + `}}]`)
	case "check.routing":
		chk := wireObj(t, pv["check"])
		chk["routing"] = json.RawMessage(value)
		pv["check"] = wireEnc(t, chk)
	case "pages[*].partition", "pages[*].roles", "pages[*].history":
		var pages []json.RawMessage
		if err := json.Unmarshal(pv["pages"], &pages); err != nil {
			t.Fatal(err)
		}
		key := member[len("pages[*]."):]
		for i := range pages {
			p := wireObj(t, pages[i])
			p[key] = json.RawMessage(value)
			pages[i] = wireEnc(t, p)
		}
		pv["pages"] = wireEnc(t, pages)
	default:
		t.Fatalf("unknown member %q", member)
	}
	ic["proof_v2"] = wireEnc(t, pv)
	top["intent_certificate"] = wireEnc(t, ic)
	return wireEnc(t, top)
}
