// Copyright 2026 Certen Protocol

package envvar

import (
	"strings"
	"testing"
	"time"
)

func TestUnsetIsTheDefaultAndGarbageIsRefusedByName(t *testing.T) {
	const k = "CERTEN_ENVVAR_TEST"
	t.Setenv(k, "")
	if v, err := Int(k, 7, 1); v != 7 || err != nil {
		t.Fatalf("unset: (%v, %v)", v, err)
	}
	for _, c := range []struct {
		value string
		read  func() error
	}{
		{"seven", func() error { _, err := Int(k, 7, 1); return err }},
		{"0", func() error { _, err := Int(k, 7, 1); return err }},
		{"-1", func() error { _, err := Int64(k, 7, 0); return err }},
		{"1.5", func() error { _, err := Uint64(k, 7, 0); return err }},
		{"NaN", func() error { _, err := Float(k, 1, 0); return err }},
		{"-2", func() error { _, err := Float(k, 1, 0); return err }},
		{"5 minutes", func() error { _, err := Duration(k, time.Second, time.Second); return err }},
		{"500ms", func() error { _, err := Duration(k, time.Second, time.Second); return err }},
		{"30s", func() error { _, err := Seconds(k, time.Second, 1); return err }},
		{"yess", func() error { _, err := Bool(k, true); return err }},
		{"sometimes", func() error { _, err := OneOf(k, "a", "a", "b"); return err }},
	} {
		t.Setenv(k, c.value)
		err := c.read()
		if err == nil || !strings.Contains(err.Error(), k+`="`+c.value+`"`) {
			t.Errorf("%s=%q was not refused by name: %v", k, c.value, err)
		}
	}
}

func TestWellFormedValuesAreRead(t *testing.T) {
	const k = "CERTEN_ENVVAR_TEST"
	for v, want := range map[string]bool{"TRUE": true, "on": true, "1": true, "no": false, "Off": false} {
		t.Setenv(k, v)
		if got, err := Bool(k, !want); got != want || err != nil {
			t.Errorf("Bool(%q) = (%v, %v)", v, got, err)
		}
	}
	t.Setenv(k, " 42 ")
	if n, err := Uint64(k, 1, 1); n != 42 || err != nil {
		t.Errorf("Uint64 = (%v, %v)", n, err)
	}
	t.Setenv(k, "90")
	if d, err := Seconds(k, time.Second, 1); d != 90*time.Second || err != nil {
		t.Errorf("Seconds = (%v, %v)", d, err)
	}
	t.Setenv(k, "ON_DEMAND")
	if v, err := OneOf(k, "on_cadence", "on_cadence", "on_demand"); v != "on_demand" || err != nil {
		t.Errorf("OneOf = (%v, %v)", v, err)
	}
}

func TestCheckNamesEveryRefusal(t *testing.T) {
	t.Setenv("CERTEN_ENVVAR_A", "x")
	t.Setenv("CERTEN_ENVVAR_B", "z")
	err := Check(
		func() error { _, err := Int("CERTEN_ENVVAR_A", 1, 1); return err },
		func() error { return nil },
		func() error { _, err := Bool("CERTEN_ENVVAR_B", false); return err },
	)
	if err == nil || !strings.Contains(err.Error(), "CERTEN_ENVVAR_A") || !strings.Contains(err.Error(), "CERTEN_ENVVAR_B") {
		t.Fatalf("Check did not name both refusals: %v", err)
	}
	if Check(func() error { return nil }) != nil {
		t.Fatal("Check reported a refusal where there was none")
	}
}
