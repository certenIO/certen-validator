// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RB12-TS-TWINS-2 (TSB-2): JudgeCase.Run read its numbers with strconv.ParseUint and its bytes with hex.DecodeString and threw every
// error away, so a hand-made world with output_root_index 2^32+1 (read as the clamped maximum), a non-decimal number (read as 0) or a
// non-hex string (read as the bytes before the bad digit) was judged as a different world, silently. A value that cannot be loaded
// is now a named JudgeLoadError carrying the field and the value; a published case is unaffected.

func loadJudgeCaseForParse(t *testing.T) JudgeCase {
	t.Helper()
	b, err := ReadFile(setDir, "judge/synth_19_intermediate_roots.json")
	if err != nil {
		t.Fatal(err)
	}
	var c JudgeCase
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func runLoadError(t *testing.T, c JudgeCase) *JudgeLoadError {
	t.Helper()
	_, err := c.Run(setDir)
	var le *JudgeLoadError
	if !errors.As(err, &le) {
		t.Errorf("want a *JudgeLoadError, got %v", err)
		return &JudgeLoadError{}
	}
	return le
}

func TestJudgeCaseRefusesAnUnloadableWorldByName(t *testing.T) {
	const u64Max = "18446744073709551615"
	for _, c := range []struct {
		name   string
		field  string
		mutate func(*JudgeCase, string)
		bad    []string
		ok     []string
	}{
		{"a.number", "a.number", func(j *JudgeCase, v string) { j.A.Number = v }, []string{"abc", "", "-1", "+5", "0x10", " 5", "5 ", "1_0", "18446744073709551616"}, []string{"0", "007", u64Max}},
		{"a.timestamp", "a.timestamp", func(j *JudgeCase, v string) { j.A.Timestamp = v }, []string{"abc", "", "-1", "18446744073709551616"}, []string{"0", u64Max}},
		{"leg.number", "leg.number", func(j *JudgeCase, v string) { j.Leg.Number = v }, []string{"abc", "", "18446744073709551616"}, []string{u64Max}},
		{"leg.chain", "leg.chain", func(j *JudgeCase, v string) { j.Leg.Chain = v }, []string{"abc", "", "18446744073709551616"}, []string{u64Max}},
		{"output_root_index", "output_root_index", func(j *JudgeCase, v string) { j.OutputRootIndex = v }, []string{"4294967296", "4294967297", "18446744073709551615", "abc", "", "-1", "0x1"}, []string{"0", "4294967295"}},
	} {
		for _, v := range c.bad {
			j := loadJudgeCaseForParse(t)
			c.mutate(&j, v)
			le := runLoadError(t, j)
			if le.Field != c.field || le.Value != v {
				t.Errorf("%s=%q: error names field %q value %q", c.name, v, le.Field, le.Value)
			}
			if !strings.Contains(le.Error(), c.field) {
				t.Errorf("%s=%q: the text %q does not name the field", c.name, v, le.Error())
			}
		}
		for _, v := range c.ok {
			j := loadJudgeCaseForParse(t)
			c.mutate(&j, v)
			if _, err := j.Run(setDir); err != nil {
				t.Errorf("%s=%q must load: %v", c.name, v, err)
			}
		}
	}
}

func TestJudgeCaseRefusesNonHexAndWrongLengthBytesByName(t *testing.T) {
	good := loadJudgeCaseForParse(t)
	hex32 := good.A.Hash
	for _, c := range []struct {
		field  string
		mutate func(*JudgeCase, string)
		bad    []string
	}{
		{"a.hash", func(j *JudgeCase, v string) { j.A.Hash = v }, []string{"0xzz", hex32[:len(hex32)-1], hex32[:len(hex32)-2], strings.ToUpper(hex32[:2]) + hex32[2:], "0x" + strings.Repeat("ab", 33), ""}},
		{"a.state_root", func(j *JudgeCase, v string) { j.A.StateRoot = v }, []string{"0xzz", "0x", "0x" + strings.Repeat("ab", 31)}},
		{"leg.hash", func(j *JudgeCase, v string) { j.Leg.Hash = v }, []string{"0xzz", "0x" + strings.Repeat("ab", 31)}},
		{"leg.header", func(j *JudgeCase, v string) { j.Leg.Header = v }, []string{"0xz", "0xabc"}},
		{"game_proxy", func(j *JudgeCase, v string) { j.GameProxy = v }, []string{"0xzz", "0x" + strings.Repeat("ab", 19), "0x" + strings.Repeat("ab", 21)}},
		{"game_code", func(j *JudgeCase, v string) { j.GameCode = v }, []string{"0xzz", "0xabc"}},
		{"l2_spine[0]", func(j *JudgeCase, v string) { j.L2Spine = []string{v} }, []string{"0xzz"}},
		{"nodes[1]", func(j *JudgeCase, v string) { j.Nodes = []string{"0x", v} }, []string{"0xzz"}},
	} {
		for _, v := range c.bad {
			j := loadJudgeCaseForParse(t)
			c.mutate(&j, v)
			if le := runLoadError(t, j); le.Field != c.field || le.Value != v {
				t.Errorf("%s=%q: error names field %q value %q", c.field, v, le.Field, le.Value)
			}
		}
	}
	// the bare (un-prefixed) form is still read: the field is judged by its digits, not by the prefix
	j := loadJudgeCaseForParse(t)
	j.A.Hash = strings.TrimPrefix(j.A.Hash, "0x")
	if _, err := j.Run(setDir); err != nil {
		t.Fatalf("a bare 32-byte hash loads: %v", err)
	}
}

func TestJudgeCasePublishedWorldIsUnchangedByStrictLoading(t *testing.T) {
	j := loadJudgeCaseForParse(t)
	got, err := j.Run(setDir)
	if err != nil {
		t.Fatal(err)
	}
	var e Expect
	if err := json.Unmarshal(j.Expect, &e); err != nil {
		t.Fatal(err)
	}
	if want := ExpectBytes(e); string(got) != string(want) {
		t.Fatalf("published verdict changed:\n want %s\n got  %s", want, got)
	}
}
