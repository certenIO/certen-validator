// Copyright 2026 Certen Protocol

package synthworld

import "testing"

func TestTheValidWorldVerifies(t *testing.T) {
	w := Assemble(NewParts("valid"))
	v, err := w.Judge()
	if err != nil {
		t.Fatalf("the valid world is refused: %v", err)
	}
	if v.Fields["confirmation_path"] != "honest" || v.Fields["confirmation_route"] != "direct" {
		t.Fatalf("verdict %+v", v)
	}
	t.Logf("evidence %d bytes, fields %v", len(w.Container), v.Fields)
}
