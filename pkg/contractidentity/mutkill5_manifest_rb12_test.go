// Copyright 2026 Certen Protocol

package contractidentity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ethereum/go-ethereum/crypto"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the survivors and uncovered sites of manifest.go.

func mk5Doc(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(embeddedManifest, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func mk5Bytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mk5State(t *testing.T, err error, code string) *StateError {
	t.Helper()
	var se *StateError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("error %v: want state %s", err, code)
	}
	return se
}

func mk5Cause(t *testing.T, err error, code string) string {
	t.Helper()
	se := mk5State(t, err, code)
	c := errors.Unwrap(se)
	if c == nil {
		t.Fatalf("state %v carries no cause", se)
	}
	return c.Error()
}

// mk5Min is a manifest with ONE chain (777) and no row that names a chain, built from the embedded one; policy rows come from owner/setRoot.
func mk5Min(t *testing.T, owner, setRoot string) *Manifest {
	t.Helper()
	doc := mk5Doc(t)
	doc["chains"] = json.RawMessage(`[{"chainId":777}]`)
	doc["deployments"] = json.RawMessage(`[]`)
	doc["accounts"] = json.RawMessage(`[]`)
	doc["eip2935"] = json.RawMessage(`{}`)
	pol := map[string]json.RawMessage{}
	if err := json.Unmarshal(doc["policy"], &pol); err != nil {
		t.Fatal(err)
	}
	pol["owner"], pol["txScan"], pol["setRootHistory"] = json.RawMessage(owner), json.RawMessage(`{}`), json.RawMessage(setRoot)
	doc["policy"] = mk5Bytes(t, pol)
	m, err := parseManifest(mk5Bytes(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMutKill5ParseManifestTables(t *testing.T) {
	for _, key := range []string{"chains", "builds", "deployments", "accounts", "policy", "eip2935", "selectors", "topics", "authSlots"} {
		doc := mk5Doc(t)
		delete(doc, key)
		_, err := parseManifest(mk5Bytes(t, doc))
		if got := mk5Cause(t, err, CodeManifestCorrupt); got != "manifest: table "+key+" is absent" {
			t.Fatalf("absent %s: cause %q", key, got)
		}
		doc = mk5Doc(t)
		doc[key] = json.RawMessage(`"x"`)
		_, err = parseManifest(mk5Bytes(t, doc))
		if got := mk5Cause(t, err, CodeManifestCorrupt); !strings.HasPrefix(got, "manifest: table "+key+": ") {
			t.Fatalf("mistyped %s: cause %q", key, got)
		}
	}
	doc := mk5Doc(t)
	delete(doc, "creationArtifacts")
	if _, err := parseManifest(mk5Bytes(t, doc)); err != nil {
		t.Fatalf("absent creationArtifacts is allowed: %v", err)
	}
	for _, key := range []string{"creationArtifacts", "generations"} {
		doc = mk5Doc(t)
		doc[key] = json.RawMessage(`"x"`)
		_, err := parseManifest(mk5Bytes(t, doc))
		if got := mk5Cause(t, err, CodeManifestCorrupt); !strings.HasPrefix(got, "manifest: table "+key+": ") {
			t.Fatalf("mistyped %s: cause %q", key, got)
		}
	}
	doc = mk5Doc(t)
	tp := map[string]json.RawMessage{}
	if err := json.Unmarshal(doc["topics"], &tp); err != nil {
		t.Fatal(err)
	}
	tp["ProofExecuted"] = json.RawMessage(`"x"`)
	doc["topics"] = mk5Bytes(t, tp)
	_, err := parseManifest(mk5Bytes(t, doc))
	if got := mk5Cause(t, err, CodeManifestCorrupt); !strings.HasPrefix(got, "manifest: topics.ProofExecuted: ") {
		t.Fatalf("mistyped topic: cause %q", got)
	}
	doc = mk5Doc(t)
	doc["eip2935"] = json.RawMessage(`{"abc":{}}`)
	_, err = parseManifest(mk5Bytes(t, doc))
	if got := mk5Cause(t, err, CodeManifestCorrupt); got != `manifest: eip2935 key "abc"` {
		t.Fatalf("eip2935 key: cause %q", got)
	}
	k := "0x" + strings.Repeat("ab", 32)
	doc = mk5Doc(t)
	doc["generations"] = json.RawMessage(`[{"role":"anchor","maskedKeccak":"` + k + `"},{"role":"anchor","maskedKeccak":"` + k + `"}]`)
	_, err = parseManifest(mk5Bytes(t, doc))
	if got := mk5Cause(t, err, CodeManifestCorrupt); got != "manifest: generations repeat (role,maskedKeccak) generations:anchor,"+k {
		t.Fatalf("generations repeat: cause %q", got)
	}
}

func TestMutKill5ParseManifestRawJSON(t *testing.T) {
	_, err := parseManifest([]byte(`{"a":1,"a":2}`))
	if got := mk5Cause(t, err, CodeManifestCorrupt); got != `manifest: duplicate key "a" at ` {
		t.Fatalf("duplicate: %q", got)
	}
	_, err = parseManifest([]byte(`{"a"`))
	if got := mk5Cause(t, err, CodeManifestCorrupt); !strings.Contains(got, "EOF") || strings.Contains(got, "end of JSON input") {
		t.Fatalf("truncated input must fail in the duplicate-key walk: %q", got)
	}
	_, err = parseManifest([]byte(`[1]`))
	if got := mk5Cause(t, err, CodeManifestCorrupt); !strings.Contains(got, "cannot unmarshal array") {
		t.Fatalf("array input: %q", got)
	}
}

func TestMutKill5FindDuplicateKey(t *testing.T) {
	cases := []struct {
		in, path, key string
		found         bool
		err           string
	}{
		{`{"a":1,"a":2}`, "", "a", true, ""},
		{`{"a":{"b":1,"b":2}}`, ".a", "b", true, ""},
		{`{"a":[{"x":1,"x":2}]}`, ".a[]", "x", true, ""},
		{`[1,[2],{"k":3}]`, "", "", false, ""},
		{``, "", "", false, "EOF"},
		{`{x}`, "", "", false, "invalid character 'x'"},
		{`{"a":1`, "", "", false, "EOF"},
		{`[{"a"`, "", "", false, "EOF"},
	}
	for _, c := range cases {
		p, k, f, err := findDuplicateKey([]byte(c.in))
		if p != c.path || k != c.key || f != c.found || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%q: got (%q,%q,%v,%v)", c.in, p, k, f, err)
		}
	}
}

func TestMutKill5SlotRefAndAllowedWrites(t *testing.T) {
	var s SlotRef
	for _, c := range []struct {
		in   string
		want SlotRef
	}{{`17`, SlotRef{"17", 17, true}}, {`"17"`, SlotRef{"17", 17, true}}, {`"account"`, SlotRef{Text: "account"}}} {
		s = SlotRef{}
		if err := json.Unmarshal([]byte(c.in), &s); err != nil || s != c.want {
			t.Errorf("%s: %+v, %v", c.in, s, err)
		}
	}
	for _, in := range []string{`-1`, `true`, `1.5`} {
		if err := json.Unmarshal([]byte(in), &SlotRef{}); err == nil {
			t.Errorf("SlotRef %s accepted", in)
		}
	}
	var a AllowedWrites
	if err := json.Unmarshal([]byte(`"*"`), &a); err != nil || !a.Any || a.Paths != nil {
		t.Errorf("star: %+v %v", a, err)
	}
	a = AllowedWrites{}
	if err := json.Unmarshal([]byte(`["p","q"]`), &a); err != nil || a.Any || len(a.Paths) != 2 || a.Paths[1] != "q" {
		t.Errorf("list: %+v %v", a, err)
	}
	for _, in := range []string{`"x"`, `5`} {
		if err := json.Unmarshal([]byte(in), &AllowedWrites{}); err == nil {
			t.Errorf("AllowedWrites %s accepted", in)
		}
	}
}

func TestMutKill5ManifestLookupsAndSpans(t *testing.T) {
	to := func(v uint64) *uint64 { return &v }
	m := &Manifest{
		accounts:  []Account{{ChainID: 1, Address: "0xAb"}},
		authSlots: []AuthSlot{{ID: "A01"}},
		policy:    Policy{Rules: []Rule{{ID: "R1"}}},
		owners: map[uint64][]OwnerRow{5: {
			{Role: "anchor", Address: "A", ValidFromBlock: 10}, {Role: "anchor", Address: "B", ValidFromBlock: 10}, {Role: "anchor", Address: "C", ValidFromBlock: 20},
		}},
		setRoots: []SetRootRow{{ChainID: 5, Root: "0xaa", ValidFromBlock: 10}, {ChainID: 5, Root: "0xbb", ValidFromBlock: 10}, {ChainID: 5, Root: "0xcc", ValidFromBlock: 20}},
	}
	if a, ok := m.Account(1, "0xab"); !ok || a.ChainID != 1 {
		t.Error("Account hit")
	}
	if a, ok := m.Account(2, "0xab"); ok || a.ChainID != 0 {
		t.Error("Account other chain")
	}
	if a, ok := m.Account(1, "0xcd"); ok || a.Address != "" {
		t.Error("Account other address")
	}
	if r, ok := m.Rule("R9"); ok || r.ID != "" {
		t.Error("Rule miss")
	}
	if r, ok := m.Rule("R1"); !ok || r.ID != "R1" {
		t.Error("Rule hit")
	}
	if s, ok := m.AuthSlot("A02"); ok || s.ID != "" {
		t.Error("AuthSlot miss")
	}
	rows := m.OwnerRows(5, "anchor")
	if len(rows) != 3 || rows[0].Address != "A" || rows[1].Address != "B" || rows[2].Address != "C" {
		t.Errorf("OwnerRows must keep equal-from rows in manifest order: %+v", rows)
	}
	cov := m.OwnerCovering(5, "anchor", 15)
	if len(cov) != 2 || cov[0].Address != "A" || cov[1].Address != "B" {
		t.Errorf("OwnerCovering(15) = %+v", cov)
	}
	sr := m.SetRootRows(5)
	if len(sr) != 3 || sr[0].Root != "0xaa" || sr[1].Root != "0xbb" {
		t.Errorf("SetRootRows order: %+v", sr)
	}
	if r, ok := m.SetRootRowFor(5, 15, "0xAA"); !ok || r.Root != "0xaa" {
		t.Errorf("SetRootRowFor: %+v %v", r, ok)
	}
	for _, c := range []struct {
		to, next *uint64
		end      uint64
		open     bool
	}{{to(10), to(8), 7, false}, {to(5), to(8), 5, false}, {to(10), nil, 10, false}, {nil, to(8), 7, false}, {nil, nil, 0, true}} {
		if e, o := effectiveEnd(1, c.to, c.next); e != c.end || o != c.open {
			t.Errorf("effectiveEnd = %d,%v", e, o)
		}
	}
}

func TestMutKill5MergeRows(t *testing.T) {
	_, err := mergeMapRows(nil, json.RawMessage(`[1]`), "t")
	mk5State(t, err, CodeManifestCorrupt)
	_, err = mergeMapRows(json.RawMessage(`[1]`), json.RawMessage(`{}`), "t")
	mk5State(t, err, CodeManifestCorrupt)
	_, err = mergeMapRows(json.RawMessage(`1`), json.RawMessage(`{}`), "t")
	mk5State(t, err, CodeManifestCorrupt)
	if out, err := mergeMapRows(nil, json.RawMessage(`{"a":1}`), "t"); err != nil || string(out) != `{"a":1}` {
		t.Errorf("empty base: %s %v", out, err)
	}
	key := func(r json.RawMessage) string { return string(r) }
	_, err = mergeArrayRows(nil, json.RawMessage(`{}`), "t", key)
	mk5State(t, err, CodeManifestCorrupt)
	_, err = mergeArrayRows(json.RawMessage(`{}`), json.RawMessage(`[]`), "t", key)
	mk5State(t, err, CodeManifestCorrupt)
	_, err = mergeArrayRows(json.RawMessage(`1`), json.RawMessage(`[]`), "t", key)
	mk5State(t, err, CodeManifestCorrupt)
	if out, err := mergeArrayRows(nil, json.RawMessage(`[1]`), "t", key); err != nil || string(out) != `[1]` {
		t.Errorf("empty base: %s %v", out, err)
	}
}

func TestMutKill5CreationArtifactBytes(t *testing.T) {
	b := []byte("creation code")
	good := CreationArtifact{File: "a.bin", Bytes: len(b), Keccak256: crypto.Keccak256Hash(b).Hex(), SHA256: sha256Hex(b)}
	fsys := fstest.MapFS{"a.bin": {Data: b}}
	try := func(row CreationArtifact) error {
		m := &Manifest{creation: map[string]CreationArtifact{"k": row}}
		_, err := m.CreationArtifactBytes("k", fsys)
		return err
	}
	if err := try(good); err != nil {
		t.Fatalf("good row: %v", err)
	}
	bad := good
	bad.Keccak256 = crypto.Keccak256Hash([]byte("x")).Hex()
	if err := try(bad); !errors.Is(err, ErrCreationArtifactMismatch) {
		t.Errorf("keccak mismatch: %v", err)
	}
	bad = good
	bad.SHA256 = sha256Hex([]byte("x"))
	if err := try(bad); !errors.Is(err, ErrCreationArtifactMismatch) {
		t.Errorf("sha256 mismatch: %v", err)
	}
	bad = good
	bad.Bytes++
	if err := try(bad); !errors.Is(err, ErrCreationArtifactMismatch) {
		t.Errorf("length mismatch: %v", err)
	}
}

func TestMutKill5WithExtensionRefusals(t *testing.T) {
	m, err := parseManifest(embeddedManifest)
	if err != nil {
		t.Fatal(err)
	}
	ext := func(s string) error { _, err := m.WithExtension([]byte(s)); return err }
	if got := mk5Cause(t, ext(`{"a"`), CodeManifestCorrupt); !strings.Contains(got, "EOF") || strings.Contains(got, "end of JSON input") {
		t.Errorf("truncated extension: %q", got)
	}
	if got := mk5Cause(t, ext(`[1]`), CodeManifestCorrupt); !strings.Contains(got, "cannot unmarshal array") {
		t.Errorf("array extension: %q", got)
	}
	for _, c := range []struct{ in, table, key string }{
		{`{"zz":{}}`, "zz", "*"}, {`{"zz":5}`, "zz", "*"}, {`{"zz":{"q":1,"b":2}}`, "zz", "b"},
		{`{"policy":{"rules":[]}}`, "policy.rules", "*"}, {`{"policy":{"rules":[{"id":"R7"}]}}`, "policy.rules", "R7"}, {`{"policy":{"other":1}}`, "policy", "other"},
	} {
		se := mk5State(t, ext(c.in), CodeManifestShadow)
		if se.Fields["table"] != c.table || se.Fields["key"] != c.key {
			t.Errorf("%s: %v", c.in, se.Fields)
		}
	}
	if _, err := m.WithExtension([]byte(`{"schema":"` + ManifestSchema + `","description":"d"}`)); err != nil {
		t.Errorf("schema+description extension: %v", err)
	}
	k := "0x" + strings.Repeat("cd", 32)
	mk5Cause(t, ext(`{"generations":"x"}`), CodeManifestCorrupt)
	mk5Cause(t, ext(`{"generations":[{"role":"anchor","maskedKeccak":"0x12"}]}`), CodeManifestCorrupt)
	if _, err := m.WithExtension([]byte(`{"generations":[{"role":"anchor","maskedKeccak":"` + k + `"}]}`)); err != nil {
		t.Errorf("good generation: %v", err)
	}
	mk5Cause(t, ext(`{"policy":5}`), CodeManifestCorrupt)
	mk5Cause(t, ext(`{"policy":{"owner":5}}`), CodeManifestCorrupt)
	mk5Cause(t, ext(`{"policy":{"owner":{"1":["x"]}}}`), CodeManifestCorrupt)
	mk5Cause(t, ext(`{"policy":{"setRootHistory":5}}`), CodeManifestCorrupt)
	mk5Cause(t, ext(`{"policy":{"setRootHistory":["x"]}}`), CodeManifestCorrupt)
}

func TestMutKill5WithExtensionRowOrder(t *testing.T) {
	m := mk5Min(t, `{"777":[{"role":"anchor","address":"0x1","validFromBlock":5},{"role":"anchor","address":"0x2","validFromBlock":10}]}`,
		`[{"chainId":777,"root":"0x1","validFromBlock":5},{"chainId":777,"root":"0x2","validFromBlock":10}]`)
	ext := func(s string) error { _, err := m.WithExtension([]byte(s)); return err }
	se := mk5State(t, ext(`{"policy":{"owner":{"777":[{"role":"anchor","address":"0x3","validFromBlock":7}]}}}`), CodeManifestShadow)
	if se.Fields["table"] != "policy.owner" || se.Fields["key"] != "777,anchor" {
		t.Errorf("owner shadow: %v", se.Fields)
	}
	se = mk5State(t, ext(`{"policy":{"setRootHistory":[{"chainId":777,"root":"0x3","validFromBlock":7}]}}`), CodeManifestShadow)
	if se.Fields["table"] != "policy.setRootHistory" || se.Fields["key"] != "777" {
		t.Errorf("setRoot shadow: %v", se.Fields)
	}
	if err := ext(`{"policy":{"owner":{"777":[{"role":"anchor","address":"0x3","validFromBlock":11}]},"setRootHistory":[{"chainId":777,"root":"0x3","validFromBlock":11}]}}`); err != nil {
		t.Errorf("rows after the last: %v", err)
	}
	e := mk5Min(t, `{}`, `[]`)
	extE := func(s string) error { _, err := e.WithExtension([]byte(s)); return err }
	if err := extE(`{"policy":{"owner":{"777":[{"role":"anchor","address":"0x1","validFromBlock":0}]},"setRootHistory":[{"chainId":777,"root":"0x1","validFromBlock":0}]}}`); err != nil {
		t.Errorf("first rows at block 0: %v", err)
	}
	if err := extE(`{"policy":{"owner":{}}}`); err != nil {
		t.Errorf("empty owner table: %v", err)
	}
	for _, c := range []struct {
		in   string
		want uint64
	}{
		{`{"chains":[{"chainId":90002},{"chainId":90001}]}`, 90001},
		{`{"eip2935":{"90002":{},"90001":{}}}`, 90001},
		{`{"chains":[{"chainId":90001}],"eip2935":{"90001":{}},"builds":{"":{}},"policy":{"txScan":{"90001":{}},"owner":{"90001":[{"role":"anchor","address":"0x1","validFromBlock":1},{"role":"verifier","address":"0x1","validFromBlock":1}]}}}`, 90001},
	} {
		se := mk5State(t, extE(c.in), CodeManifestUnknown)
		if se.Fields["chain"] != c.want {
			t.Errorf("%s: %v", c.in, se.Fields)
		}
	}
	if err := extE(`{}`); err != nil {
		t.Errorf("a base chain needs no dependent rows: %v", err)
	}
}

func TestMutKill5MustMarshalPanicsOnUnmarshalable(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("mustMarshal of a channel must panic")
		}
	}()
	mustMarshal(make(chan int))
}
