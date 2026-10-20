// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The finality_chain2 consumers (RB11-B2B1). They use only the exported behaviour the vectors describe, so the same files, copied
// byte for byte, are what the TypeScript verifier runs. Every expectation in a vector is a literal written by the generator
// (pkg/finality/vectorgen/chain2.go), never computed from the code under test.

func readSet(t testing.TB, set, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", set, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestChain2ManifestPinsEveryFileItselfChain1AndTheRegistrySnapshot(t *testing.T) {
	manifestRaw := readSet(t, "finality_chain2", "MANIFEST.json")
	var m struct {
		Files      map[string]string `json:"files"`
		Supersedes struct {
			Set                  string `json:"set"`
			ManifestSHA256       string `json:"manifest_sha256"`
			ReplacedExpectations int    `json:"replaced_expectations"`
		} `json:"supersedes"`
		Registry struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"registry"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 9 {
		t.Fatalf("%d files in the manifest", len(m.Files))
	}
	for f, want := range m.Files {
		sum := sha256.Sum256(readSet(t, "finality_chain2", f))
		if want != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: manifest says %s, file hashes to %x", f, want, sum)
		}
	}
	ms := sha256.Sum256(manifestRaw)
	if got := strings.TrimSpace(string(readSet(t, "finality_chain2", "MANIFEST.json.sha256"))); got != hex.EncodeToString(ms[:]) {
		t.Errorf("MANIFEST.json.sha256 %s, manifest hashes to %x", got, ms)
	}
	c1 := sha256.Sum256(readSet(t, "finality_chain1", "MANIFEST.json"))
	if m.Supersedes.Set != "finality_chain1" || m.Supersedes.ManifestSHA256 != hex.EncodeToString(c1[:]) || m.Supersedes.ReplacedExpectations != 13 {
		t.Errorf("supersedes %+v (chain1 manifest %x)", m.Supersedes, c1)
	}
	// RB11-F13: chain2 is a published set and records the registry as it was when the set was generated. The live registry only
	// grows (every chain package registers its own codes), so its hash is pinned in no vector manifest; the registry of that
	// moment is kept byte for byte as testdata/finality/states.at-chain2.json, and the live registry must contain all of it
	// (TestTheLiveRegistryContainsEverythingTheChain2SnapshotDefines).
	snap, err := os.ReadFile(filepath.Join("testdata", "finality", chain2RegistrySnapshot))
	if err != nil {
		t.Fatal(err)
	}
	rs := sha256.Sum256(snap)
	if m.Registry.Path != "testdata/finality/states.json" || m.Registry.SHA256 != hex.EncodeToString(rs[:]) || m.Registry.SHA256 != chain2RegistrySnapshotSHA256 {
		t.Errorf("the manifest records registry %s %s, the snapshot %s hashes to %x, the pinned hash is %s",
			m.Registry.Path, m.Registry.SHA256, chain2RegistrySnapshot, rs, chain2RegistrySnapshotSHA256)
	}
}

// chain2RegistrySnapshot is the registry (testdata/finality/states.json) exactly as it was at framework commit 4377bb3, when
// finality_chain2 was generated; chain2RegistrySnapshotSHA256 is the hash chain2's MANIFEST.json records for it.
const (
	chain2RegistrySnapshot       = "states.at-chain2.json"
	chain2RegistrySnapshotSHA256 = "d0e2d25048ba1dfe40e910538e6870675b2fbe3a4b0b47cdb9b1e0ffb084b73a"
)

// registryContainmentViolations lists everything the snapshot defines that cur does not contain (append-only compatibility): every
// state with its group and scope; every required field still required and every optional field still known; every enum member of
// every enum field (a field the snapshot leaves to enums_defined_by may be given a set later); every conditional_required rule
// (same `when`) with at least its required fields; every pending reason with at least its required fields.
func registryContainmentViolations(snap, cur stateRegistry) []string {
	var out []string
	has := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	whenKey := func(w map[string]string) string {
		keys := make([]string, 0, len(w))
		for k := range w {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k + "=" + w[k] + ";")
		}
		return b.String()
	}
	if snap.Format != cur.Format {
		out = append(out, fmt.Sprintf("format %q became %q", snap.Format, cur.Format))
	}
	for code, s := range snap.States {
		c, ok := cur.States[code]
		if !ok {
			out = append(out, "state "+code+" is missing")
			continue
		}
		if c.Group != s.Group || c.Scope != s.Scope {
			out = append(out, fmt.Sprintf("state %s: group/scope %q/%q became %q/%q", code, s.Group, s.Scope, c.Group, c.Scope))
		}
		for _, f := range s.Required {
			if !has(c.Required, f) {
				out = append(out, fmt.Sprintf("state %s: required field %q is no longer required", code, f))
			}
		}
		for _, f := range s.Optional {
			if !has(c.Optional, f) && !has(c.Required, f) {
				out = append(out, fmt.Sprintf("state %s: optional field %q is no longer known", code, f))
			}
		}
		for field, members := range s.Enums {
			cm, ok := c.Enums[field]
			if !ok {
				out = append(out, fmt.Sprintf("state %s: enum %q is missing", code, field))
				continue
			}
			for _, m := range members {
				if !has(cm, m) {
					out = append(out, fmt.Sprintf("state %s: enum %q lost the member %q", code, field, m))
				}
			}
		}
		for field := range s.EnumsDefinedBy {
			if _, ok := c.Enums[field]; !ok {
				if _, still := c.EnumsDefinedBy[field]; !still {
					out = append(out, fmt.Sprintf("state %s: field %q has neither an enum nor enums_defined_by any more", code, field))
				}
			}
		}
		for _, r := range s.ConditionalRequired {
			found := false
			for _, cr := range c.ConditionalRequired {
				if whenKey(cr.When) != whenKey(r.When) {
					continue
				}
				found = true
				for _, f := range r.Required {
					if !has(cr.Required, f) {
						out = append(out, fmt.Sprintf("state %s: conditional rule %s lost the required field %q", code, whenKey(r.When), f))
					}
				}
			}
			if !found {
				out = append(out, fmt.Sprintf("state %s: conditional rule %s is missing", code, whenKey(r.When)))
			}
		}
	}
	for reason, r := range snap.PendingReasons {
		c, ok := cur.PendingReasons[reason]
		if !ok {
			out = append(out, "pending reason "+reason+" is missing")
			continue
		}
		for _, f := range r.Required {
			if !has(c.Required, f) {
				out = append(out, fmt.Sprintf("pending reason %s: required field %q is no longer required", reason, f))
			}
		}
	}
	sort.Strings(out)
	return out
}

func loadChain2Snapshot(t testing.TB) stateRegistry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "finality", chain2RegistrySnapshot))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != chain2RegistrySnapshotSHA256 {
		t.Fatalf("the chain2 registry snapshot hashes to %x, the pinned hash is %s: the snapshot is specification and never edited", sum, chain2RegistrySnapshotSHA256)
	}
	var r stateRegistry
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTheLiveRegistryContainsEverythingTheChain2SnapshotDefines(t *testing.T) {
	snap := loadChain2Snapshot(t)
	if len(snap.States) != 86 || len(snap.PendingReasons) != 19 {
		t.Fatalf("the snapshot holds %d states and %d pending reasons", len(snap.States), len(snap.PendingReasons))
	}
	if v := registryContainmentViolations(snap, loadRegistry(t)); len(v) != 0 {
		t.Fatalf("the live registry is not an append-only extension of the registry finality_chain2 was generated against:\n%s", strings.Join(v, "\n"))
	}
}

// The containment rule detects each kind of removal; a rule that passes everything would pass the test above vacuously.
func TestTheRegistryContainmentRuleRefusesEveryKindOfRemoval(t *testing.T) {
	snap := loadChain2Snapshot(t)
	clone := func() stateRegistry {
		raw, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		var r stateRegistry
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if v := registryContainmentViolations(snap, clone()); len(v) != 0 {
		t.Fatalf("the snapshot is not contained in itself: %v", v)
	}
	// pick, deterministically, one state that has each kind of content
	var withEnum, withCond, withRequired, withOptional string
	codes := make([]string, 0, len(snap.States))
	for c := range snap.States {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		s := snap.States[c]
		if withEnum == "" && len(s.Enums) > 0 {
			withEnum = c
		}
		if withCond == "" && len(s.ConditionalRequired) > 0 {
			withCond = c
		}
		if withRequired == "" && len(s.Required) > 0 {
			withRequired = c
		}
		if withOptional == "" && len(s.Optional) > 0 {
			withOptional = c
		}
	}
	if withEnum == "" || withCond == "" || withRequired == "" || withOptional == "" {
		t.Fatalf("the snapshot has no state with an enum (%q), a conditional rule (%q), a required (%q) and an optional (%q) field", withEnum, withCond, withRequired, withOptional)
	}
	mutate := map[string]func(r *stateRegistry){
		"a code is dropped": func(r *stateRegistry) { delete(r.States, withRequired) },
		"a required field is dropped": func(r *stateRegistry) {
			s := r.States[withRequired]
			s.Required = s.Required[1:]
			r.States[withRequired] = s
		},
		"a required field is demoted to optional": func(r *stateRegistry) {
			s := r.States[withRequired]
			s.Optional = append(append([]string(nil), s.Optional...), s.Required[0])
			s.Required = s.Required[1:]
			r.States[withRequired] = s
		},
		"an optional field is dropped": func(r *stateRegistry) {
			s := r.States[withOptional]
			s.Optional = s.Optional[1:]
			r.States[withOptional] = s
		},
		"an enum member is dropped": func(r *stateRegistry) {
			s := r.States[withEnum]
			e := map[string][]string{}
			for k, v := range s.Enums {
				e[k] = append([]string(nil), v...)
			}
			for k := range e {
				e[k] = e[k][1:]
				break
			}
			s.Enums = e
			r.States[withEnum] = s
		},
		"an enum is dropped": func(r *stateRegistry) {
			s := r.States[withEnum]
			s.Enums = nil
			r.States[withEnum] = s
		},
		"a conditional rule is dropped": func(r *stateRegistry) {
			s := r.States[withCond]
			s.ConditionalRequired = s.ConditionalRequired[1:]
			r.States[withCond] = s
		},
		"a pending reason is dropped": func(r *stateRegistry) { delete(r.PendingReasons, "epoch_open") },
		"the group changes": func(r *stateRegistry) {
			s := r.States[withRequired]
			s.Group += "x"
			r.States[withRequired] = s
		},
	}
	for name, f := range mutate {
		r := clone()
		f(&r)
		if len(registryContainmentViolations(snap, r)) == 0 {
			t.Errorf("%s: the containment rule accepted it", name)
		}
	}
	// and additions are accepted: a new state, a new optional field, a new enum member
	r := clone()
	r.States["zz_new_code"] = stateSpec{Group: "X", Scope: "spec"}
	s := r.States[withOptional]
	s.Optional = append(append([]string(nil), s.Optional...), "zz_new_field")
	r.States[withOptional] = s
	e := r.States[withEnum]
	en := map[string][]string{}
	for k, v := range e.Enums {
		en[k] = append(append([]string(nil), v...), "zz_new_member")
	}
	e.Enums = en
	r.States[withEnum] = e
	if v := registryContainmentViolations(snap, r); len(v) != 0 {
		t.Errorf("an append-only extension was refused: %v", v)
	}
}

// chain2 differs from chain1 in exactly the superseded expectations (13) and in the vectors it adds; every other member of every
// chain1 vector is identical.
func TestChain2ReissuesChain1VectorForVectorChangingOnlyTheSupersededExpectations(t *testing.T) {
	changed := 0
	for _, f := range []string{"chains.json", "containers.json", "codec_probe.json", "table.json"} {
		var a, b struct {
			Vectors []map[string]json.RawMessage `json:"vectors"`
			Queries []map[string]json.RawMessage `json:"queries"`
		}
		if err := json.Unmarshal(readSet(t, "finality_chain1", f), &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(readSet(t, "finality_chain2", f), &b); err != nil {
			t.Fatal(err)
		}
		old, nw := append(a.Vectors, a.Queries...), append(b.Vectors, b.Queries...)
		if len(nw) < len(old) {
			t.Fatalf("%s: chain2 has %d entries, chain1 %d", f, len(nw), len(old))
		}
		for i := range old {
			for k, ov := range old[i] {
				nv := nw[i][k]
				if k != "expect" {
					if normJSON(t, ov) != normJSON(t, nv) {
						t.Errorf("%s[%d].%s changed: %s -> %s", f, i, k, ov, nv)
					}
					continue
				}
				var oe, ne string
				if err := json.Unmarshal(ov, &oe); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(nv, &ne); err != nil {
					t.Fatal(err)
				}
				if ne != supersededExpect(oe) {
					t.Errorf("%s[%d] expect %s, want %s", f, i, ne, supersededExpect(oe))
				}
				if ne != oe {
					changed++
				}
			}
		}
	}
	if changed != 13 {
		t.Errorf("%d expectations differ between chain1 and chain2, want 13", changed)
	}
}

// normJSON renders a JSON value with sorted keys and no whitespace, so two files that differ only in member order compare equal.
func normJSON(t testing.TB, raw json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestChain2ChainVectorsGiveTheExpectedVerdicts(t *testing.T) {
	var shell struct {
		Vectors []struct {
			Name    string            `json:"name"`
			Leg     CarriedLeg        `json:"leg"`
			Carried CarriedLeg        `json:"carried"`
			Addenda []json.RawMessage `json:"addenda"`
			Expect  string            `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "chains.json"), &shell); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range shell.Vectors {
		seen[v.Name] = true
		t.Run(v.Name, func(t *testing.T) {
			leg, err := v.Leg.Ref()
			if err != nil {
				t.Fatal(err)
			}
			carried, err := v.Carried.Ref()
			if err != nil {
				t.Fatal(err)
			}
			var adds []Addendum
			got := ""
			for _, r := range v.Addenda {
				var a Addendum
				if err := a.UnmarshalJSON(r); err != nil {
					got = canonOf(err)
					break
				}
				adds = append(adds, a)
			}
			if got == "" {
				got = canonOf(CheckLegChain(leg, carried, adds))
			}
			if got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
	for _, want := range []string{"kind_l1_posted_on_sepolia_real_kind", "kind_adiri_l1_posted_real_kind", "kind_level1_refused", "leg_binding_altered_leg_member"} {
		if !seen[want] {
			t.Errorf("vector %q is missing", want)
		}
	}
	// D9: the Sepolia vector uses the real kind string of the table's missing row, not another chain's kind
	if !strings.Contains(string(readSet(t, "finality_chain2", "chains.json")), `"kind": "eth-sepolia/l1_posted/v1"`) {
		t.Error("kind_l1_posted_on_sepolia_real_kind does not carry eth-sepolia/l1_posted/v1")
	}
}

func TestChain2ContainerProbeAndTableVectors(t *testing.T) {
	var cs struct {
		Vectors []struct {
			Name   string            `json:"name"`
			Hex    string            `json:"hex"`
			Limits map[string]uint64 `json:"limits"`
			Expect string            `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "containers.json"), &cs); err != nil {
		t.Fatal(err)
	}
	for _, v := range cs.Vectors {
		t.Run("container/"+v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			c, err := DecodeContainer(raw, limitsFrom(t, v.Limits))
			got := ""
			if err != nil {
				got = canonOf(err)
			} else {
				got = string(canonValue(map[string]any{"kind": c.Header.Kind, "chain": c.Header.Chain, "level": uint64(c.Header.Level),
					"blockNumber": c.Header.BlockNumber, "blockHash": c.Header.BlockHash, "body": c.Body}))
			}
			if got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
	var ps struct {
		Vectors []struct {
			Name   string            `json:"name"`
			Hex    string            `json:"hex"`
			Limits map[string]uint64 `json:"limits"`
			Expect string            `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "codec_probe.json"), &ps); err != nil {
		t.Fatal(err)
	}
	for _, v := range ps.Vectors {
		t.Run("probe/"+v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			if got := canonOf(probeDecode(raw, limitsFrom(t, v.Limits))); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
	var ts struct {
		Queries []struct {
			Chain  uint64 `json:"chain"`
			Level  uint8  `json:"level"`
			Expect string `json:"expect"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "table.json"), &ts); err != nil {
		t.Fatal(err)
	}
	for _, q := range ts.Queries {
		kind, err := KindFor(q.Chain, Level(q.Level))
		got := "kind:" + kind
		if err != nil {
			got = canonOf(err)
		}
		if got != q.Expect {
			t.Errorf("chain %d level %d: got %s, want %s", q.Chain, q.Level, got, q.Expect)
		}
	}
}

func TestChain2StrictJSONVectors(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string `json:"name"`
			Target string `json:"target"`
			Input  string `json:"input"`
			Expect string `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "json.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != 57 {
		t.Fatalf("%d json vectors, want 57", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var err error
			switch v.Target {
			case "addendum":
				var a Addendum
				err = a.UnmarshalJSON([]byte(v.Input))
			case "section":
				_, err = ParseSection([]byte(v.Input))
			case "proofId":
				_, err = ParseProofID(v.Input)
			default:
				t.Fatalf("target %q", v.Target)
			}
			if got := canonOf(err); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
}

func TestChain2HeaderVectors(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string `json:"name"`
			Hex    string `json:"hex"`
			Expect string `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "header.json"), &set); err != nil {
		t.Fatal(err)
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			h, err := ReadHeader(raw)
			got := ""
			if err != nil {
				got = canonOf(err)
			} else {
				wd := "null"
				if h.WithdrawalsRoot != nil {
					wd = `"0x` + hex.EncodeToString(h.WithdrawalsRoot[:]) + `"`
				}
				got = fmt.Sprintf(`{"items":"%d","number":"%s","timestamp":"%s","withdrawalsRoot":%s}`, h.Items,
					strconv.FormatUint(h.Number, 10), strconv.FormatUint(h.Timestamp, 10), wd)
			}
			if got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
}

// With no kind registered, the only thing that can refuse an addendum before "unrecognised" is its own binding to the leg:
// deleting the block-hash or the chain comparison from JudgeAddendum turns a block_mismatch vector into "unrecognised".
func TestChain2JudgeVectorsBindTheContainerToTheLegBlock(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name     string          `json:"name"`
			Leg      CarriedLeg      `json:"leg"`
			Addendum json.RawMessage `json:"addendum"`
			Expect   string          `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "judge.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) < 8 {
		t.Fatalf("only %d judge vectors", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			leg, err := v.Leg.Ref()
			if err != nil {
				t.Fatal(err)
			}
			var a Addendum
			if err := a.UnmarshalJSON(v.Addendum); err != nil {
				t.Fatal(err)
			}
			_, jerr := NewRegistry().JudgeAddendum(leg, a, nil)
			if got := canonOf(jerr); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
}

func TestChain2PinsVectors(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string `json:"name"`
			Text   string `json:"text"`
			Expect string `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "pins.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != 36 {
		t.Fatalf("%d pins vectors, want 36", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			_, err := ParsePinsOverride([]byte(v.Text))
			if got := canonOf(err); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
}

type canonField struct {
	Key   string          `json:"key"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func canonValueOf(t testing.TB, f canonField) any {
	t.Helper()
	var s string
	str := func() string {
		if err := json.Unmarshal(f.Value, &s); err != nil {
			t.Fatalf("%s: %v", f.Key, err)
		}
		return s
	}
	u := func(bits int) uint64 {
		v, err := strconv.ParseUint(str(), 10, bits)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	i := func(bits int) int64 {
		v, err := strconv.ParseInt(str(), 10, bits)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	switch f.Type {
	case "u64":
		return u(64)
	case "u32":
		return uint32(u(32))
	case "u16":
		return uint16(u(16))
	case "u8":
		return uint8(u(8))
	case "int":
		return int(i(64))
	case "i64":
		return i(64)
	case "i32":
		return int32(i(32))
	case "level":
		l, err := ParseLevel(str())
		if err != nil {
			t.Fatal(err)
		}
		return l
	case "bytes32":
		return mustHex32(t, str())
	case "bytes4":
		b, err := hex.DecodeString(str())
		if err != nil || len(b) != 4 {
			t.Fatalf("bytes4 %q", s)
		}
		return [4]byte(b)
	case "bytes":
		b, err := hex.DecodeString(str())
		if err != nil {
			t.Fatal(err)
		}
		return b
	case "bool":
		return str() == "true"
	case "null":
		return nil
	case "string":
		return str()
	case "time":
		tm, err := time.Parse(time.RFC3339, str())
		if err != nil {
			t.Fatal(err)
		}
		return tm
	case "u64list":
		var l []string
		if err := json.Unmarshal(f.Value, &l); err != nil {
			t.Fatal(err)
		}
		out := make([]uint64, len(l))
		for k, e := range l {
			v, err := strconv.ParseUint(e, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
		return out
	case "map":
		var l []canonField
		if err := json.Unmarshal(f.Value, &l); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		for _, e := range l {
			m[e.Key] = canonValueOf(t, e)
		}
		return m
	}
	t.Fatalf("unknown canonical field type %q", f.Type)
	return nil
}

func TestChain2CanonicalFormOfAMixedTypeFieldsMap(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name   string       `json:"name"`
			Code   string       `json:"code"`
			Fields []canonField `json:"fields"`
			Expect string       `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain2", "canonical.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) == 0 {
		t.Fatal("no canonical vectors")
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			st := &StateError{Code: v.Code, Fields: map[string]any{}}
			for _, f := range v.Fields {
				st.Fields[f.Key] = canonValueOf(t, f)
			}
			if got := string(st.Canonical()); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
		})
	}
}

// The generator reproduces finality_chain2 from the pins file as it was at publication (framework commit 4377bb3), kept byte for byte
// as testdata/finality/pins.at-chain2.json; the live embedded file is not an input of any published set.
func TestTheChain2PinsSnapshotIsPinnedByHash(t *testing.T) {
	const want = "507d72b3499fd094f3e14e0ed585edba90c7a7a4c6235c7ccd98d04db7329cca"
	raw, err := os.ReadFile(filepath.Join("testdata", "finality", "pins.at-chain2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != want {
		t.Fatalf("the chain2 pins snapshot hashes to %x, want %s: it is specification and never edited", sum, want)
	}
}
