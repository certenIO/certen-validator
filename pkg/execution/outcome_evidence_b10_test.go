// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RB10-B10 (V-R10B3 note): a layer-6 document that does not decode names the document and the field, never the internal
// type the decoder happens to use ("Go value of type execution.plain").
func TestTheOutcomeEvidenceDecodeErrorNamesTheDocument(t *testing.T) {
	for _, c := range []struct {
		name, doc string
		want      []string // the error names these
	}{
		{"an array", `[1,2]`, []string{"array", "object"}},
		{"a string", `"x"`, []string{"string", "object"}},
		{"a number", `5`, []string{"number", "object"}},
		{"a field of the wrong type", `{"version":5}`, []string{"version", "number", "string"}},
		{"a nested field of the wrong type", `{"member":{"leaf":7}}`, []string{"member", "leaf", "number"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var ev OutcomeEvidence
			err := json.Unmarshal([]byte(c.doc), &ev)
			if err == nil {
				t.Fatal("decoded")
			}
			msg := err.Error()
			if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(msg, "outcome evidence") {
				t.Fatalf("the error does not name the outcome evidence: %v", err)
			}
			if strings.Contains(msg, "execution.") || strings.Contains(msg, "plain") || strings.Contains(msg, "Go value") || strings.Contains(msg, "Go struct") {
				t.Fatalf("the error names the decoder's internal type: %v", err)
			}
			for _, w := range c.want {
				if !strings.Contains(msg, w) {
					t.Fatalf("the error does not say %q: %v", w, err)
				}
			}
		})
	}
}
