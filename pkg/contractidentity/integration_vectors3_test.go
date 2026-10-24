// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The vector set s8_int_3 (V2_SPEC_S8 r3.5) closes rows of Freeze item 5 that the nine earlier sets left to unit tests: the container
// constructions at part offsets (VS8-011, VS8-014, VS8-017), the new row VS8-126 (step 18 when the
// container has no code section for an address of row C01, [r3.5:H11]). Every published set is pinned and never edited, so these vectors are a
// new set. Offsets are derived from the decoded base container and checked against the bytes, so a change of the base fails here, not silently.

const vectorSetInt3 = "s8_int_3"

func (a *authorInt) vectors3() []ci.Vector {
	f := a.f
	sp := f.spec
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	first := func(code string, fields map[string]any) ci.Expected {
		return exp(ci.HeadlineRefused, nil, est("first", code, fields))
	}
	malformed := func(part string, index int, reason string, got, want int) ci.Expected {
		return first("evidence_malformed", map[string]any{"part": part, "index": uint64(index), "reason": reason, "got_len": uint64(got), "want_len": uint64(want)})
	}
	u32 := func(n int) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }
	lp := func(s string) []byte { return append(u32(len(s)), s...) }
	setb := func(off int, v byte) ci.Mutation {
		return ci.Mutation{Op: "set_byte", Target: "container", Offset: intp(off), Value: json.RawMessage(`"` + hex.EncodeToString([]byte{v}) + `"`)}
	}
	replace := func(off int, old, nw []byte) ci.Mutation {
		return ci.Mutation{Op: "replace_hex", Target: "container", Offset: intp(off), Old: hex.EncodeToString(old), New: hex.EncodeToString(nw)}
	}

	raw := f.built.Inputs.Container
	c, err := ci.Decode(raw, ci.DefaultLimits())
	if err != nil {
		a.t.Fatal(err)
	}
	if c.Settle.Tag != ci.TagCaptured || c.Attest.Tag != ci.TagCaptured || c.Attest.Attest == nil || len(c.Nodes) < 2 {
		a.t.Fatal("the base container of H0 must have a captured settle part, a captured attest part and at least two nodes")
	}
	lim := ci.DefaultLimits()
	kindLen := len(ci.Kind)
	settleTag := 4 + 4 + kindLen + 8 + 8 + 32 + 4
	for _, cd := range c.Codes {
		settleTag += 20 + 4 + len(cd.Runtime)
	}
	attestTag, link := settleTag+1, settleTag+2
	nodesCount := len(raw) - 4
	for _, n := range c.Nodes {
		nodesCount -= 4 + len(n)
	}
	if raw[settleTag] != byte(ci.TagCaptured) || raw[attestTag] != byte(ci.TagCaptured) || raw[link] != c.Attest.Attest.Link ||
		binary.BigEndian.Uint32(raw[nodesCount:]) != uint32(len(c.Nodes)) || string(raw[8:8+kindLen]) != ci.Kind {
		a.t.Fatal("the offsets derived from the decoded base container do not match its bytes")
	}

	// VS8-011 (step 1): a kind other than contract-identity/v1 is unrecognised with its version; a kind STR of 65 bytes is too large [r3.2:E-a]
	v9 := ci.Kind[:kindLen-1] + "9"
	add("VS8-011.kind_v9", first("evidence_unrecognised", map[string]any{"kind": v9, "version": "v9"}), setb(8+kindLen-1, '9'))
	add("VS8-011.kind_65_bytes", first("evidence_too_large", map[string]any{"part": ci.PartKind, "count": uint64(65), "limit": uint64(lim.MaxKindBytes)}),
		replace(4, append(u32(kindLen), ci.Kind...), append(u32(65), []byte(strings.Repeat("a", 65))...)))

	// VS8-014 (step 1): part tag 3, link 3, a Stated state other than contract_identity_unproven, a reason with upper case, a non-ASCII STR
	add("VS8-014.settle_tag_3", malformed(ci.PartSettle, settleTag+1, ci.MalformedUnknownPartTag, 0, 0), setb(settleTag, 3))
	add("VS8-014.attest_link_3", malformed(ci.PartAttest, link+1, ci.MalformedUnknownLink, 0, 0), setb(link, 3))
	stated := func(parts ...[]byte) []byte {
		b := []byte{byte(ci.TagStated)}
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	captured := []byte{byte(ci.TagCaptured)}
	other := "contract_identity_verified"
	add("VS8-014.stated_state_other", malformed(ci.PartSettle, settleTag+1+4+len(other), ci.MalformedBadStatedState, 0, 0), replace(settleTag, captured, stated(lp(other))))
	upper := "Upper_Case"
	add("VS8-014.stated_reason_upper_case", malformed(ci.PartSettle, settleTag+1+4+len(ci.StatedState)+4+len(upper), ci.MalformedBadStatedReason, 0, 0),
		replace(settleTag, captured, stated(lp(ci.StatedState), lp(upper))))
	nonASCII := "caf\xc3\xa9"
	add("VS8-014.stated_string_not_ascii", malformed(ci.PartSettle, settleTag+1+4+len(nonASCII), ci.MalformedStringNotAscii, 0, 0), replace(settleTag, captured, stated(lp(nonASCII))))

	// VS8-017 (step 1): non-canonical encodings, encode(decode(x)) != x: a count prefix with extra bytes behind it, a count prefix that promises
	// one more element, a length prefix longer than its content
	n, last := len(c.Nodes), c.Nodes[len(c.Nodes)-1]
	add("VS8-017.count_prefix_with_extra_bytes", malformed(ci.PartContainer, len(raw)-4-len(last), ci.MalformedTrailingBytes, 4+len(last), 0), replace(nodesCount, u32(n), u32(n-1)))
	add("VS8-017.count_prefix_promises_one_more", malformed(ci.PartNodes, len(raw), ci.MalformedTruncated, 0, 4), replace(nodesCount, u32(n), u32(n+1)))
	add("VS8-017.length_prefix_longer_than_content", malformed(ci.PartNodes, len(raw)-len(last), ci.MalformedTruncated, len(last), len(last)+1),
		replace(len(raw)-len(last)-4, u32(len(last)), u32(len(last)+1)))

	// VS8-126 (step 18, [r3.5:H11]): the container carries no code section for the anchor A. Step 12 judges the same address from the same
	// section (code_unproven_bytes on code_identity, R), step 18 cannot read the code of C01 (unproven code_not_carried on
	// authorization_attest, U); both are printed and the headline is refused.
	A := hexAddr(sp.Roles.Anchor)
	var carry []string
	for _, s := range sp.Carry {
		if !strings.EqualFold(s, A.Hex()) {
			carry = append(carry, s)
		}
	}
	if len(carry) != len(sp.Carry)-1 {
		a.t.Fatal("the anchor is not in the carry list of the base world")
	}
	add("VS8-126.code_not_carried", exp(ci.HeadlineRefused, map[string]string{ci.JudgedCodeIdentity: "refused", ci.JudgedAuthorizationAttest: "unproven"},
		est(ci.JudgedCodeIdentity, "code_unproven_bytes", map[string]any{"address": A}),
		est(ci.JudgedAuthorizationAttest, "unproven", map[string]any{"part": ci.JudgedAuthorizationAttest, "address": A, "reason": "code_not_carried"})),
		world.Set("carry", carry))
	return out
}

func TestVectorSetInt3IsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &authorInt{t, f}
	vectors := a.vectors3()
	if _, err := os.Stat(setDir(vectorSetInt3)); err != nil && os.Getenv("CERTEN_WRITE_S8_INT3") == "1" {
		if err := world.WriteSet(setDir(vectorSetInt3), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSetInt3))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSetInt3, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ci.RunSet(set, nil, ver) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	checkPublishedBytes(t, f, vectorSetInt3, vectors)
}
