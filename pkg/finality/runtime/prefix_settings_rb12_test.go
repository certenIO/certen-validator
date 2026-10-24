// Copyright 2026 Certen Protocol

package runtime

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT duty (g), corrected by V-INT3b LOW (b): the archive-backfill settings use F14's closed reason (setting_invalid) and variable, and a
// bad one is never fatal: it is the named, non-fatal finality_prefix_disabled (the prefix work of the chains it governs is off; the upgrader and
// all other finality run), never log.Fatal and never the value. Every setting also has an entry in the table the deploy check and the startup
// validation share (RefusedSettings). The full matrix is prefix_isolation_rb12_test.go.
func TestRTBadPrefixSettingsAreNamedByTheClosedF14ReasonAndNeverFatal(t *testing.T) {
	for _, c := range []struct{ env, val string }{
		{EnvPrefixArbScan, "3000"}, // above one eth_getLogs answer
		{EnvPrefixArbScan, "0"},    // below 1
		{EnvPrefixChunk, "2000"},   // above 1024
		{EnvPrefixMax, "-4"},       // not a size
		{EnvPrefixFloor, "later"},  // not a block number
		{EnvPrefixLease, "10"},     // below the 60 s floor
		{EnvPrefixReprobe, "5"},    // below the 3600 s floor
	} {
		t.Run(c.env+"="+c.val, func(t *testing.T) {
			clearPrefixEnv(t)
			t.Setenv(c.env, c.val)
			cfg, err := ConfigFromEnv()
			if err != nil {
				t.Fatalf("a bad prefix setting is not a start failure: %v", err)
			}
			if len(cfg.PrefixDisabled) == 0 {
				t.Fatal("a bad setting is refused by name")
			}
			for _, st := range cfg.PrefixDisabled {
				if st.Code != finality.CodePrefixDisabled || st.Fields["reason"] != finality.DisabledSettingInvalid || st.Fields["variable"] != c.env {
					t.Fatalf("want finality_prefix_disabled{setting_invalid, variable %s}, got %v", c.env, st)
				}
				if strings.Contains(st.Error(), c.val) && len(c.val) > 3 {
					t.Fatalf("the state must not echo the value: %v", st)
				}
			}
			if r := RefusedSettings(); len(r) != 1 || r[0].Key != c.env {
				t.Fatalf("the shared table names the variable: %v", r)
			}
		})
	}
	// the defaults are valid
	clearPrefixEnv(t)
	if cfg, err := ConfigFromEnv(); err != nil || len(cfg.PrefixDisabled) != 0 {
		t.Fatalf("defaults: %v %v", err, cfg.PrefixDisabled)
	}
}
