// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"reflect"
)

// Facts is the ONE typed record of every value a step hands to a later step. It is grouped by the package that produces the values, so that
// the four verify packages never edit the same field, the same struct or the same file:
//
//	Facts.A   facts_a.go    package 2a    steps 1c-14   (settlement path, account, anchor, record, verifier chain, authority level)
//	Facts.B1  facts_b1.go   package 2b-1  steps 15-17, 20 (attest present, headers, attestation transaction, decoded call, message hash)
//	Facts.B2  facts_b2.go   package 2b-2  steps 18, 18b, 19, 22 (AUTH values pre and post, flips, validators, rule IB)
//	Facts.C   facts_c.go    package 2c    steps 21, 23, 24 (registry object, registry link value, rules not judged, level binding)
//
// Rules (checked by the runner and by TestFactsTable):
//  1. A step writes only the group of its owner (the runner compares the other three groups before and after every step and fails the run
//     with a FactsOwnershipError). A step may READ any group whose writer precedes it in ExecOrder.
//  2. Every field of a group is documented in that group's table (factSpecsA ... factSpecsC): the step that WRITES it and the steps that
//     READ it, derived from the specification text. A package adds its fields and its table rows in its own facts_*.go file.
//  3. Fields are exported and plain data (so the ownership check can snapshot them); a field that holds a pointer to a type with
//     unexported state (*types.Transaction, *big.Int) is compared by identity.
//  4. A Facts field is the value a step ESTABLISHED. A step that could not establish it leaves it zero and says why through its PartResult;
//     a later step that needs it must handle the zero value as "not established" (never as a default).
type Facts struct {
	A  FactsA
	B1 FactsB1
	B2 FactsB2
	C  FactsC
}

// FactSpec documents one Facts field: the step that writes it and the steps that read it.
type FactSpec struct {
	Field   string // "A.StateRootN"
	Writer  StepID
	Readers []StepID
	Note    string
}

// factGroups maps a Facts member name to the package that owns it.
var factGroups = []struct {
	Name  string
	Owner Owner
}{{"A", Owner2a}, {"B1", Owner2b1}, {"B2", Owner2b2}, {"C", Owner2c}}

// GroupOwner returns the owner of a Facts group ("A", "B1", "B2", "C").
func GroupOwner(group string) (Owner, bool) {
	for _, g := range factGroups {
		if g.Name == group {
			return g.Owner, true
		}
	}
	return "", false
}

// AllFactSpecs is the documentation of every field of Facts, group by group.
func AllFactSpecs() []FactSpec {
	var out []FactSpec
	for _, t := range [][]FactSpec{factSpecsA, factSpecsB1, factSpecsB2, factSpecsC} {
		out = append(out, t...)
	}
	return out
}

// FactsOwnershipError is returned by RunSteps when a step changed a Facts group that its package does not own.
type FactsOwnershipError struct {
	Step  StepID
	Owner Owner
	Group string
}

func (e *FactsOwnershipError) Error() string {
	o, _ := GroupOwner(e.Group)
	return fmt.Sprintf("contractidentity: step %s (package %s) changed Facts.%s, which belongs to package %s", e.Step, e.Owner, e.Group, o)
}

// snapshotFacts deep-copies Facts (exported plain data; pointers to types with unexported state are kept by identity).
func snapshotFacts(f *Facts) Facts {
	return deepCopy(reflect.ValueOf(*f)).Interface().(Facts)
}

func hasUnexported(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		if !t.Field(i).IsExported() {
			return true
		}
	}
	return false
}

func deepCopy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() || hasUnexported(v.Type().Elem()) {
			return v
		}
		n := reflect.New(v.Type().Elem())
		n.Elem().Set(deepCopy(v.Elem()))
		return n
	case reflect.Struct:
		n := reflect.New(v.Type()).Elem()
		if hasUnexported(v.Type()) {
			n.Set(v)
			return n
		}
		for i := 0; i < v.NumField(); i++ {
			n.Field(i).Set(deepCopy(v.Field(i)))
		}
		return n
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			n.Index(i).Set(deepCopy(v.Index(i)))
		}
		return n
	case reflect.Array:
		n := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			n.Index(i).Set(deepCopy(v.Index(i)))
		}
		return n
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		n := reflect.MakeMapWithSize(v.Type(), v.Len())
		for _, k := range v.MapKeys() {
			n.SetMapIndex(k, deepCopy(v.MapIndex(k)))
		}
		return n
	}
	return v
}

// changedGroups lists the groups of after that differ from before.
func changedGroups(before Facts, after *Facts) []string {
	var out []string
	bv, av := reflect.ValueOf(before), reflect.ValueOf(*after)
	for _, g := range factGroups {
		if !reflect.DeepEqual(bv.FieldByName(g.Name).Interface(), av.FieldByName(g.Name).Interface()) {
			out = append(out, g.Name)
		}
	}
	return out
}
