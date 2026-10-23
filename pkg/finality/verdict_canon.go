// Copyright 2026 Certen Protocol

package finality

// CanonicalValue renders one value of a StateError or Verdict field in the cross-language canonical form (state.go canonValue): an
// integer of any width as a decimal string, a byte string or fixed array as 0x-prefixed lower-case hex, a Level by name, a map with
// sorted keys. It is what a report prints for a verified level's Verdict.Fields.
func CanonicalValue(v any) []byte { return canonValue(v) }
