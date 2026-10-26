// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 EPSILON stage 2, part A: literal-expectation tests for the sites of canon.go, env.go, facts.go and codec.go that the full mutation
// sweep left alive. Every expectation below is written out by hand (or built independently of the code under test).

func canonWant(t *testing.T, v any, want string) {
	t.Helper()
	got, err := Canonical(v)
	if err != nil || string(got) != want {
		t.Fatalf("Canonical(%#v) = %q, %v; want %q", v, got, err, want)
	}
}

func TestMutKill4CanonicalShapes(t *testing.T) {
	var nilBig *big.Int
	var nilPtr *int
	var nilAny any
	var nilStrs []string
	canonWant(t, nil, "null")
	canonWant(t, nilAny, "null")
	canonWant(t, nilBig, "null")
	canonWant(t, nilPtr, "null")
	canonWant(t, nilStrs, "[]")
	canonWant(t, []string{}, "[]")
	canonWant(t, [2]string{"a", "b"}, `["a","b"]`)
	canonWant(t, [0]string{}, "[]")
	canonWant(t, []any{1, "x", true, nil}, `["1","x",true,null]`)
	canonWant(t, big.NewInt(255), `"255"`)
	canonWant(t, int8(-5), `"-5"`)
	canonWant(t, uint64(7), `"7"`)
	canonWant(t, []byte{}, `"0x"`)
	canonWant(t, []byte{1, 0xab}, `"0x01ab"`)
	canonWant(t, [2]byte{0x0a, 0x0b}, `"0x0a0b"`)
	canonWant(t, "<&>", `"<&>"`)
	canonWant(t, map[string]any{"b": 1, "a": []int{1, 2}, "c": nil}, `{"a":["1","2"],"b":"1","c":null}`)
	// a map of many keys is written in bytewise key order
	m := map[string]int{}
	var keys []string
	for i := 0; i < 70; i++ {
		k := fmt.Sprintf("k%d", i*7919%1000)
		if _, dup := m[k]; !dup {
			m[k] = i
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var want strings.Builder
	want.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			want.WriteByte(',')
		}
		fmt.Fprintf(&want, `"%s":"%d"`, k, m[k])
	}
	want.WriteByte('}')
	canonWant(t, m, want.String())
}

func TestMutKill4CanonicalRefusals(t *testing.T) {
	for name, v := range map[string]any{
		"float":              1.5,
		"struct":             struct{ A int }{1},
		"float in a list":    []any{1, 2.5},
		"float in an array":  [1]float64{1},
		"float in a map":     map[string]any{"a": 1.5},
		"non-string map key": map[int]int{1: 1},
		"channel":            make(chan int),
	} {
		if b, err := Canonical(v); err == nil {
			t.Errorf("%s: accepted as %q", name, b)
		}
	}
}

func TestMutKill4EnvAccessors(t *testing.T) {
	stated := &Stated{State: StatedState, Reason: "state_unavailable"}
	e := &Env{}
	if e.SettleStated() != nil || e.AttestStated() != nil {
		t.Fatal("an Env with no container carries a Stated")
	}
	e.Container = &Container{Settle: Part{Tag: TagCaptured, Stated: stated}, Attest: Part{Tag: TagCaptured, Stated: stated}}
	if e.SettleStated() != nil || e.AttestStated() != nil {
		t.Fatal("a captured part reports a Stated")
	}
	e.Container = &Container{Settle: Part{Tag: TagStated, Stated: stated}, Attest: Part{Tag: TagStated, Stated: stated}}
	if e.SettleStated() != stated || e.AttestStated() != stated {
		t.Fatal("a stated part does not report its Stated")
	}
}

func TestMutKill4EnvContextJudgedLevel(t *testing.T) {
	m := &Manifest{Source: "override"}
	e := &Env{Manifest: m}
	if c := e.Context(); c.JudgedAtLevel != "" || c.ManifestSource != "override" {
		t.Fatalf("no facts: %+v", c)
	}
	e.Facts = &Facts{}
	e.Facts.C.Level.JudgedAtLevel = "finalized"
	if c := e.Context(); c.JudgedAtLevel != "finalized" {
		t.Fatalf("facts: %+v", c)
	}
}

func TestMutKill4EnvOpenRefusesAnUnknownCode(t *testing.T) {
	e := &Env{}
	if oe, err := e.Open("settle", "alert", "no_such_state_code", "", nil); err == nil {
		t.Fatalf("an unknown code produced an Open entry %+v", oe)
	}
}

func TestMutKill4PreludeRefusals(t *testing.T) {
	ctx, raw, m := skInputs(t)
	env, st, err := Prelude(ctx, raw, nil)
	if err == nil || env != nil || st != nil {
		t.Fatalf("nil manifest: %v %v %v", env, st, err)
	}
	// a one-byte container is decoded (and refused), not skipped
	env, st, err = Prelude(ctx, []byte{0x43}, m)
	if err != nil || env != nil || st == nil || st.Code != CodeEvidenceMalformed {
		t.Fatalf("one-byte container: %v %v %v", env, st, err)
	}
	env, st, err = Prelude(ctx, raw, m)
	if err != nil || st != nil || env == nil || env.Container == nil || env.Nodes == nil {
		t.Fatalf("valid container: %v %v %v", env, st, err)
	}
}

func TestMutKill4GroupOwnerAndHasUnexported(t *testing.T) {
	if o, ok := GroupOwner("Z"); ok || o != "" {
		t.Fatalf("unknown group: %q %v", o, ok)
	}
	if o, ok := GroupOwner("B1"); !ok || o != Owner2b1 {
		t.Fatalf("B1: %q %v", o, ok)
	}
	type open struct{ A, B int }
	type closed struct {
		A int
		b int
	}
	if hasUnexported(reflect.TypeOf(0)) || hasUnexported(reflect.TypeOf("")) || hasUnexported(reflect.TypeOf(&closed{})) {
		t.Error("a non-struct type reports unexported fields")
	}
	if hasUnexported(reflect.TypeOf(open{})) || !hasUnexported(reflect.TypeOf(closed{})) {
		t.Error("struct classification")
	}
}

func TestMutKill4DeepCopyIsIndependentOfTheOriginal(t *testing.T) {
	type plain struct {
		N int
		S []int
		M map[string]int
		P *int
		A [2]int
		E []int
	}
	x := 1
	orig := plain{N: 1, S: []int{1, 2}, M: map[string]int{"a": 1}, P: &x, A: [2]int{3, 4}}
	cp := deepCopy(reflect.ValueOf(orig)).Interface().(plain)
	orig.S[0], orig.M["a"], *orig.P = 9, 9, 9
	if cp.S[0] != 1 || cp.M["a"] != 1 || *cp.P != 1 || cp.P == orig.P || cp.A != [2]int{3, 4} || cp.N != 1 {
		t.Fatalf("copy shares state with the original: %+v", cp)
	}
	if cp.E != nil {
		t.Fatal("a nil slice became non-nil")
	}
	if got := deepCopy(reflect.ValueOf((*plain)(nil))).Interface().(*plain); got != nil {
		t.Fatal("a nil pointer became non-nil")
	}
	// a type with unexported state is copied by value and kept by identity behind a pointer
	type opaque struct {
		a int
		B int
	}
	if got := deepCopy(reflect.ValueOf(opaque{1, 2})).Interface().(opaque); got != (opaque{1, 2}) {
		t.Fatalf("opaque struct: %+v", got)
	}
	p := &opaque{3, 4}
	if got := deepCopy(reflect.ValueOf(p)).Interface().(*opaque); got != p {
		t.Fatal("a pointer to a type with unexported state was copied")
	}
	b := big.NewInt(5)
	if got := deepCopy(reflect.ValueOf(b)).Interface().(*big.Int); got != b {
		t.Fatal("a *big.Int was copied")
	}
}

func TestMutKill4AsciiNoNULBoundaries(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want bool
	}{{nil, true}, {[]byte("abc"), true}, {[]byte{0x01}, true}, {[]byte{0x7e}, true}, {[]byte{0x7f}, true}, {[]byte{0x80}, false}, {[]byte{0xff}, false}, {[]byte{'a', 0, 'b'}, false}} {
		if asciiNoNUL(c.b) != c.want {
			t.Errorf("asciiNoNUL(%x) != %v", c.b, c.want)
		}
	}
}

func TestMutKill4ConvPassesForeignErrorsAndNamesTheRest(t *testing.T) {
	d := &decoder{r: finality.NewReader(make([]byte, 10), finality.Limits{MaxStringBytes: 16}), total: 10}
	boom := errors.New("boom")
	if got := d.conv(boom, ""); got != boom {
		t.Fatalf("a foreign error was changed: %v", got)
	}
	if _, err := d.fixed(PartContainer, 3); err != nil {
		t.Fatal(err)
	}
	wantState(t, d.conv(&finality.StateError{Code: "some_other_code"}, ""), Malformed(PartContainer, MalformedTruncated, 3, 7, 0))
}

func TestMutKill4EncodeRefusesUnorderedCodesAtIndexOne(t *testing.T) {
	two := func(a, b byte) []Code {
		var x, y Code
		x.Address[19], y.Address[19] = a, b
		return []Code{x, y}
	}
	c := minimal()
	c.Codes = two(2, 1)
	_, err := Encode(c, DefaultLimits())
	wantState(t, err, Malformed(PartCodes, MalformedCodesNotAscending, 1, 0, 0))
	c.Codes = two(1, 1)
	_, err = Encode(c, DefaultLimits())
	wantState(t, err, Malformed(PartCodes, MalformedCodesDuplicate, 1, 0, 0))
	c.Codes = two(1, 2)
	if _, err = Encode(c, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestMutKill4EncodeValidatesTheStatedAndAttestParts(t *testing.T) {
	lim := DefaultLimits()
	stated := func(mod func(s *Stated)) *Container {
		c := minimal()
		s := &Stated{State: StatedState, Reason: "state_unavailable"}
		mod(s)
		c.Settle = Part{Tag: TagStated, Stated: s}
		return c
	}
	refuse := func(c *Container, lim Limits, want *StateError) {
		t.Helper()
		_, err := Encode(c, lim)
		wantState(t, err, want)
	}
	refuse(stated(func(s *Stated) { s.Detail = "a\x00b" }), lim, Malformed(PartSettle, MalformedStringNotAscii, 0, 0, 0))
	refuse(stated(func(s *Stated) { s.State = StatedState + "\x80" }), lim, Malformed(PartSettle, MalformedStringNotAscii, 0, 0, 0))
	refuse(stated(func(s *Stated) { s.Reason = "ab\x80" }), lim, Malformed(PartSettle, MalformedStringNotAscii, 0, 0, 0))
	refuse(stated(func(s *Stated) { s.Reason = "Bad Reason" }), lim, Malformed(PartSettle, MalformedBadStatedReason, 0, 0, 0))
	refuse(stated(func(s *Stated) { s.State = "other" }), lim, Malformed(PartSettle, MalformedBadStatedState, 0, 0, 0))
	// a Stated tag with no Stated, and one that also carries an attest proof
	c := minimal()
	c.Settle = Part{Tag: TagStated}
	refuse(c, lim, Malformed(PartSettle, MalformedUnknownPartTag, 0, 0, 0))
	c = stated(func(s *Stated) {})
	c.Settle.Attest = c.Attest.Attest
	refuse(c, lim, Malformed(PartSettle, MalformedUnknownPartTag, 0, 0, 0))
	// attest proof checks
	c = minimal()
	c.Attest.Attest.Link = 3
	refuse(c, lim, Malformed(PartAttest, MalformedUnknownLink, 0, 0, 0))
	// the first oversized block tx is reported with its own length, not the running total
	small := lim
	small.MaxBlockTxsBytes = 10
	c = minimal()
	c.Attest.Attest.BlockTxs = [][]byte{make([]byte, 11), make([]byte, 5)}
	refuse(c, small, TooLarge(PartBlockTxs, 11, 10))
	c.Attest.Attest.BlockTxs = [][]byte{make([]byte, 6), make([]byte, 5)}
	refuse(c, small, TooLarge(PartBlockTxs, 11, 10))
	c.Attest.Attest.BlockTxs = [][]byte{make([]byte, 5), make([]byte, 5)}
	if _, err := Encode(c, small); err != nil {
		t.Fatal(err)
	}
}

func TestMutKill4CheckStatedReasonsLooksOnlyAtStatedParts(t *testing.T) {
	bad := &Stated{State: StatedState, Reason: "zzz_not_a_builder_reason"}
	c := minimal()
	c.Settle = Part{Tag: TagStated}
	c.Attest.Stated = bad // a captured part is not judged, whatever else it carries
	if st := c.CheckStatedReasons(); st != nil {
		t.Fatalf("judged a part that is not a Stated part: %s", st)
	}
	c.Settle = Part{Tag: TagStated, Stated: bad}
	wantState(t, c.CheckStatedReasons(), Malformed(PartSettle, MalformedUnknownStatedReason, 0, 0, 0))
}

func TestMutKill4EncodeUnvalidatedWritesAttestOnlyForTheAttestPart(t *testing.T) {
	want := EncodeUnvalidated(minimal())
	c := minimal()
	c.Settle.Attest = c.Attest.Attest // a hostile settle part that carries an attest proof is written as a bare captured tag
	if got := EncodeUnvalidated(c); !bytes.Equal(got, want) {
		t.Fatalf("settle part wrote attest bytes:\n got %x\nwant %x", got, want)
	}
	c = minimal()
	c.Attest = Part{Tag: TagCaptured} // a captured attest part without a proof is written as a bare tag
	got := EncodeUnvalidated(c)
	if !bytes.HasSuffix(got, []byte{byte(TagCaptured), 0, 0, 0, 0}) || len(got) >= len(want) {
		t.Fatalf("attest part without proof: %x vs %x", got, want)
	}
}

// A container whose node list holds an empty node must never yield an Env (the node set refuses it); whether the refusal is a named state or,
// as today (finding RB12-F18), a Go error is the owner's decision, so the test pins only that no Env is built.
func TestMutKill4PreludeNeverBuildsAnEnvOverAnEmptyNode(t *testing.T) {
	ctx, _, m := skInputs(t)
	c := g1Container()
	c.Nodes = [][]byte{{}}
	env, st, err := Prelude(ctx, EncodeUnvalidated(c), m)
	if env != nil || (st == nil && err == nil) {
		t.Fatalf("an Env was built over an empty node: %v %v %v", env, st, err)
	}
}
