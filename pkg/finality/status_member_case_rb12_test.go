// Copyright 2026 Certen Protocol

package finality

import (
	"strings"
	"testing"
)

// RB12 OPS-A2 item 15: the validator reads a stored status document by exact member name, as proofs_service does.
var statusDocOK = `{"format":"certen-finality-status/1","class":"pending","levelReached":"included","nextLevel":"finalized","seq":3,"state":{"code":"finality_pending","fields":{}},"pinsSha256":"` + strings.Repeat("a", 64) + `"}`

func TestStatusDocumentIsReadByExactMemberName(t *testing.T) {
	if _, err := ParseBuilderStatusDocument([]byte(statusDocOK)); err != nil {
		t.Fatalf("the canonical document: %v", err)
	}
	for _, c := range []struct{ from, to, member string }{
		{`"class"`, `"CLASS"`, "class"},
		{`"class"`, `"Class"`, "class"},
		{`"format"`, `"FORMAT"`, "format"},
		{`"levelReached"`, `"levelreached"`, "levelReached"},
		{`"nextLevel"`, `"NEXTLEVEL"`, "nextLevel"},
		{`"seq"`, `"Seq"`, "seq"},
		{`"state"`, `"STATE"`, "state"},
		{`"pinsSha256"`, `"PINSSHA256"`, "pinsSha256"},
		{`"pinsSha256"`, `"pinsSHA256"`, "pinsSha256"},
	} {
		doc := strings.Replace(statusDocOK, c.from, c.to, 1)
		_, err := ParseBuilderStatusDocument([]byte(doc))
		st, named := AsNamed(err)
		if !named || st.Code != CodeStatusMemberNameCase || st.Fields["member"] != c.member {
			t.Errorf("%s: %v", c.to, err)
			continue
		}
		if strings.Contains(st.Error(), strings.Trim(c.to, `"`)) && strings.Trim(c.to, `"`) != c.member {
			t.Errorf("%s: the stored spelling is echoed: %s", c.to, st.Error())
		}
	}
	// a second spelling beside the exact one is refused too (the exact member does not excuse it)
	dup := strings.Replace(statusDocOK, `"seq":3,`, `"seq":3,"SEQ":4,`, 1)
	if _, err := ParseBuilderStatusDocument([]byte(dup)); err == nil {
		t.Error("a duplicate member in another case was accepted")
	}
	// a member that is no member of the format in any case, and a document that is not an object, stay the strict decode's refusals
	for name, doc := range map[string]string{"unknown member": strings.Replace(statusDocOK, `"seq":3,`, `"seq":3,"extra":1,`, 1), "not an object": `[1]`, "empty": ``} {
		_, err := ParseBuilderStatusDocument([]byte(doc))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if _, named := AsNamed(err); named {
			t.Errorf("%s: %v is not a member-name refusal", name, err)
		}
	}
}
