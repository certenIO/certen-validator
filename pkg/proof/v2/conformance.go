// Copyright 2026 Certen Protocol

package proofv2

import "fmt"

// Op edits the decoded base JSON at Path (object keys and array indices): Set replaces the value, Delete removes the
// key, Truncate cuts an array to that length. Exactly one is used.
type Op struct {
	Path     []any `json:"path"`
	Set      any   `json:"set,omitempty"`
	Delete   bool  `json:"delete,omitempty"`
	Truncate *int  `json:"truncate,omitempty"`
}

// ApplyPatch applies a conformance patch to decoded JSON; every harness implements the same three operations.
func ApplyPatch(doc map[string]any, ops []Op) error {
	for _, op := range ops {
		var cur any = doc
		for i, k := range op.Path {
			last := i == len(op.Path)-1
			switch c := cur.(type) {
			case map[string]any:
				ks := k.(string)
				if last {
					switch {
					case op.Delete:
						delete(c, ks)
					case op.Truncate != nil:
						c[ks] = c[ks].([]any)[:*op.Truncate]
					default:
						c[ks] = op.Set
					}
				}
				cur = c[ks]
			case []any:
				ki := toInt(k)
				if last {
					if op.Truncate != nil {
						return fmt.Errorf("truncate inside an array element")
					}
					c[ki] = op.Set
				}
				cur = c[ki]
			default:
				return fmt.Errorf("path %v leaves the document", op.Path)
			}
		}
	}
	return nil
}

func toInt(k any) int {
	switch v := k.(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	panic(fmt.Sprintf("not an index: %v", k))
}
