// Copyright 2026 Certen Protocol

package finality

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Mutation-gate killers for the redaction of status documents (RB12-DBFIX): the depth bound of every container kind, the nil
// pointer, the byte strings, and the two passes of Document.

// depthOf is the container nesting of a redacted value (redactValue returns only map[string]any and []any as containers).
func depthOf(v any) int {
	d := 0
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			if n := depthOf(e); n > d {
				d = n
			}
		}
		return d + 1
	case []any:
		for _, e := range x {
			if n := depthOf(e); n > d {
				d = n
			}
		}
		return d + 1
	}
	return 0
}

type ptrNest struct {
	Next *ptrNest
	Leaf string
}

type anyList []any         // a named slice: not []any, so it is read by reflection
type anyMap map[string]any // a named map: not map[string]any, so it is read by reflection
type blob []byte           // a byte string by another name
type digest20 [20]byte     // a fixed byte string

const nestLevels = 12

func nested(kind string) any {
	switch kind {
	case "map[string]any":
		var v any = fakeURL
		for i := 0; i < nestLevels; i++ {
			v = map[string]any{"n": v}
		}
		return v
	case "[]any":
		var v any = fakeURL
		for i := 0; i < nestLevels; i++ {
			v = []any{v}
		}
		return v
	case "named slice":
		var v any = fakeURL
		for i := 0; i < nestLevels; i++ {
			v = anyList{v}
		}
		return v
	case "named map":
		var v any = fakeURL
		for i := 0; i < nestLevels; i++ {
			v = anyMap{"n": v}
		}
		return v
	case "pointer to struct":
		var p *ptrNest
		for i := 0; i < nestLevels; i++ {
			p = &ptrNest{Next: p, Leaf: fakeURL}
		}
		return p
	}
	panic(kind)
}

func TestRedactValueBoundsTheDepthOfEveryContainerKindAndRedactsWhatIsBelowTheBound(t *testing.T) {
	registerFake(t)
	// a container kind that adds one level of depth per container keeps maxRedactDepth+1 = 9 levels (depths 0..8) and renders what
	// is below as redacted text; a pointer and the struct it points to are two levels of depth for one container
	for kind, want := range map[string]int{"map[string]any": 9, "[]any": 9, "named slice": 9, "named map": 9, "pointer to struct": 4} {
		got := redactValue(nested(kind), 0)
		if d := depthOf(got); d != want {
			t.Errorf("%s nested %d deep keeps %d container levels, want %d", kind, nestLevels, d, want)
		}
		if s := fmt.Sprint(got); strings.Contains(s, fakeKey) {
			t.Errorf("%s: the credential survived: %s", kind, s)
		}
	}
	if maxRedactDepth != 8 {
		t.Fatalf("maxRedactDepth is %d: the expectations above are for 8", maxRedactDepth)
	}
}

func TestRedactValueOfAPointerAStructAndAByteString(t *testing.T) {
	registerFake(t)
	var nilp *ptrNest
	if got := redactValue(nilp, 0); got != nil {
		t.Fatalf("a nil pointer is %v, not nil", got)
	}
	got, ok := redactValue(&ptrNest{Leaf: fakeURL}, 0).(map[string]any)
	if !ok || len(got) != 2 || got["Next"] != nil || strings.Contains(fmt.Sprint(got["Leaf"]), fakeKey) || got["Leaf"] == "" {
		t.Fatalf("a pointer to a struct is its redacted fields: %#v", got)
	}
	for name, b := range map[string]any{"named []byte": blob{1, 2, 3}, "[20]byte": digest20{4, 5}} {
		if got := redactValue(b, 0); fmt.Sprintf("%T%v", got, got) != fmt.Sprintf("%T%v", b, b) {
			t.Errorf("%s is a byte string and is kept as it is: %T %v", name, got, got)
		}
	}
}

// A credential in a member name is not seen by the structural pass (it redacts values and nested map keys), only by the pass over the
// whole document.
func TestDocumentRedactsACredentialInAFieldNameAndRefusesARedactionThatBreaksTheJSON(t *testing.T) {
	registerFake(t)
	at := time.Unix(1_800_000_000, 0)
	st := NewState(CodeVerifierFailed, "chain", uint64(84532), "kind", "x", "cause", "c")
	st.Fields["named "+fakeURL] = 1
	s := BuilderStatusOf("00000000-0000-4000-8000-000000000001", 84532, LevelFinalized, LevelIncluded, nil, st, false, at)
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	noCredential(t, "a document with a credential in a member name", doc)

	// a state so large that the whole-document pass has to cut it: the cut text is not JSON, and that is refused, never stored
	big := NewState(CodeVerifierFailed, "chain", uint64(84532), "kind", "x", "cause", strings.Repeat("plain words ", 8_000))
	s = BuilderStatusOf("00000000-0000-4000-8000-000000000001", 84532, LevelFinalized, LevelIncluded, nil, big, false, at)
	if doc, err := s.Document(); err == nil || !strings.Contains(err.Error(), "cannot be redacted into a valid document") {
		t.Fatalf("a document the redaction would cut: %d bytes, %v", len(doc), err)
	}
}
