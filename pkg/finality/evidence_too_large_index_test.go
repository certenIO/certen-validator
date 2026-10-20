// Copyright 2026 Certen Protocol

package finality

import "testing"

// A list element above its bound is finality_evidence_too_large{part, count, limit, index}: the codec adds the element's index, so
// the registry lists index as an optional field of the code and the state conforms to it.
func TestAListElementAboveItsBoundIsAConformingEvidenceTooLargeStateWithItsIndex(t *testing.T) {
	var w Writer
	w.U32(2)
	w.LP([]byte{1})
	w.LP([]byte{1, 2, 3, 4, 5})
	_, err := NewReader(w.Bytes(), DefaultLimits()).LPList("p", 4, 3)
	se, ok := AsNamed(err)
	if !ok || se.Code != CodeEvidenceTooLarge {
		t.Fatalf("%v", err)
	}
	if got, ok := se.Fields["index"].(uint64); !ok || got != 1 {
		t.Fatalf("the refusal does not name the element: %v", se.Fields)
	}
	if bad := conforms(loadRegistry(t), se); bad != "" {
		t.Errorf("%s", bad)
	}
}
