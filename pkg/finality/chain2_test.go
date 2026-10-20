// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func TestChain2ManifestPinsEveryFileItselfChain1AndTheRegistry(t *testing.T) {
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
	reg, err := os.ReadFile(filepath.Join("testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	rs := sha256.Sum256(reg)
	if m.Registry.Path != "testdata/finality/states.json" || m.Registry.SHA256 != hex.EncodeToString(rs[:]) {
		t.Errorf("the manifest records registry %s %s, the file hashes to %x", m.Registry.Path, m.Registry.SHA256, rs)
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
