// Copyright 2026 Certen Protocol

package adiri_test

import (
	"encoding/json"
	"testing"
)

// RB11-F1-FIX: the finality_adiri5 set.

// ---- finality_adiri5 ----

func TestAdiri5ExpectedStatesConformToTheRegistry(t *testing.T) {
	reg := loadReg(t)
	f := loadSet(t, vectorDir5)
	if f.Format != "finality_adiri5/1" {
		t.Fatalf("format %q", f.Format)
	}
	groups := map[string]int{}
	for _, v := range f.Vectors {
		groups[v.Group]++
		var e struct {
			Code   string         `json:"code"`
			Fields map[string]any `json:"fields"`
		}
		if err := json.Unmarshal([]byte(v.Expect), &e); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if e.Code == "finalized" {
			continue
		}
		if msg := reg.conformsTo(e.Code, e.Fields); msg != "" {
			t.Errorf("%s: %s", v.Name, msg)
		}
	}
	if len(f.Vectors) != 14 || groups["slot"] != 10 || groups["pins"] != 4 {
		t.Fatalf("%d vectors, groups %v", len(f.Vectors), groups)
	}
}

func TestAdiri5VectorsGiveTheirLiteralVerdictsInBothModes(t *testing.T) {
	checkSet(t, loadSet(t, vectorDir5), map[string]int{})
}
