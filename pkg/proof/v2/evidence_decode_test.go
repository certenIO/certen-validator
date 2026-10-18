package proofv2

import (
	"encoding/json"
	"strings"
	"testing"
)

// RB9-K defect 1: UnmarshalCertifiedEvidence reads the version first. A document that does not claim "2.1" is decoded into the member set
// the rules v14 binary had, so a key evidence 2.1 added is ignored whatever its JSON type; a document that claims "2.1" is decoded in full.

func certifiedBase(t *testing.T, version string) map[string]json.RawMessage {
	t.Helper()
	ev := &Evidence{Version: version, Account: "acc://a.acme", TxHash: strings.Repeat("ab", 32), Receipt: "00", Majors: 3, Certify: []string{"01"},
		Anchor: PartitionAnchor{Message: "02", Receipt: "03"},
		Pages:  []PageState{{URL: "acc://a.acme/book/1", State: "04", Receipt: "05", ChainError: "x"}, {URL: "acc://a.acme", State: "06", Receipt: "07"}},
		Check:  SetCheck{Majors: 3, Hops: []string{"08"}}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func rawOf(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCertifiedEvidenceIgnoresEvidence21MembersOfAnyTypeInA20Document(t *testing.T) {
	want, _ := json.Marshal(mustEvidence(t, rawOf(t, certifiedBase(t, "2.0"))))
	for _, version := range []string{"2.0", "", "3.0", "2.10", "x"} {
		for _, key := range []string{"votes", "anchors", "transaction", "Votes", "ANCHORS"} {
			for _, v := range []string{`5`, `true`, `"x"`, `{"a":1}`, `[1]`, `[{"produced":{"sequenced":5}}]`} {
				m := certifiedBase(t, version)
				m[key] = json.RawMessage(v)
				chk := map[string]json.RawMessage{}
				_ = json.Unmarshal(m["check"], &chk)
				chk["routing"] = json.RawMessage(v)
				m["check"], _ = json.Marshal(chk)
				var pages []map[string]json.RawMessage
				_ = json.Unmarshal(m["pages"], &pages)
				for _, p := range pages {
					p["partition"], p["roles"], p["history"] = json.RawMessage(v), json.RawMessage(v), json.RawMessage(v)
				}
				m["pages"], _ = json.Marshal(pages)
				ev, err := UnmarshalCertifiedEvidence(rawOf(t, m))
				if err != nil {
					t.Fatalf("version %q, %s = %s: %v (v14's decode ignored the key)", version, key, v, err)
				}
				if ev.Votes != nil || ev.Anchors != nil || ev.Transaction != "" || ev.Check.Routing != nil {
					t.Fatalf("version %q, %s = %s: an evidence 2.1 member was kept", version, key, v)
				}
				for _, p := range ev.Pages {
					if p.Partition != "" || p.Roles != nil || p.History != nil {
						t.Fatalf("version %q, %s = %s: a page's evidence 2.1 member was kept", version, key, v)
					}
				}
				ev.Version = "2.0"
				if got, _ := json.Marshal(ev); string(got) != string(want) {
					t.Fatalf("version %q, %s = %s: the kept members differ from the document's.\n got %.200s\nwant %.200s", version, key, v, got, want)
				}
			}
		}
	}
}

func mustEvidence(t *testing.T, raw []byte) *Evidence {
	t.Helper()
	ev, err := UnmarshalCertifiedEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestCertifiedEvidenceDecodesA21DocumentInFullAndRefusesWhatV14Refused(t *testing.T) {
	m := certifiedBase(t, "2.1")
	m["transaction"] = json.RawMessage(`"0a"`)
	m["votes"] = json.RawMessage(`[{"authority":"acc://a.acme/book","vote":"accept"}]`)
	ev := mustEvidence(t, rawOf(t, m))
	if ev.Transaction != "0a" || len(ev.Votes) != 1 || ev.Votes[0].Vote != "accept" {
		t.Fatalf("a 2.1 document was not decoded in full: %+v", ev)
	}
	for name, mod := range map[string]func(map[string]json.RawMessage){
		"a 2.1 document with votes = 5":       func(m map[string]json.RawMessage) { m["votes"] = json.RawMessage(`5`) },
		"a 2.1 document with anchors = true":  func(m map[string]json.RawMessage) { m["anchors"] = json.RawMessage(`true`) },
		"a 2.1 document with transaction = 5": func(m map[string]json.RawMessage) { m["transaction"] = json.RawMessage(`5`) },
		"a number as version":                 func(m map[string]json.RawMessage) { m["version"] = json.RawMessage(`2.1`) },
		"an object as version":                func(m map[string]json.RawMessage) { m["version"] = json.RawMessage(`{}`) },
		"a v14 member of the wrong type (majors) in a 2.0 document": func(m map[string]json.RawMessage) {
			m["version"], m["majors"] = json.RawMessage(`"2.0"`), json.RawMessage(`"x"`)
		},
		"a v14 member of the wrong type (a page's url) in a 2.0 document": func(m map[string]json.RawMessage) {
			m["version"], m["pages"] = json.RawMessage(`"2.0"`), json.RawMessage(`[{"url":5}]`)
		},
		"a non-object document": nil,
	} {
		b := rawOf(t, certifiedBase(t, "2.1"))
		if mod != nil {
			mm := certifiedBase(t, "2.1")
			mod(mm)
			b = rawOf(t, mm)
		} else {
			b = []byte(`[]`)
		}
		if _, err := UnmarshalCertifiedEvidence(b); err == nil {
			t.Errorf("%s: decoded; v14 (and a full decode) fail it", name)
		}
	}
	if ev, err := UnmarshalCertifiedEvidence([]byte(" null ")); err != nil || ev != nil {
		t.Fatalf("null: %v %v; encoding/json leaves the pointer nil", ev, err)
	}
	// A duplicate key resolves as encoding/json resolves it for the version: the last, whatever its case.
	dup := `{"version":"2.1","Version":"2.0","votes":5}`
	if ev, err := UnmarshalCertifiedEvidence([]byte(dup)); err != nil || ev.Version != "2.0" || ev.Votes != nil {
		t.Fatalf("duplicate version keys: %+v %v", ev, err)
	}
}
