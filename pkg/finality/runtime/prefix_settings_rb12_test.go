// Copyright 2026 Certen Protocol

package runtime

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT duty (g): the archive-backfill settings go through F14's mechanism: a bad one is the named, non-fatal
// finality_upgrader_disabled{reason: setting_invalid, variable} (never log.Fatal, never the value), and every one of them has an entry in the
// table the deploy check and the startup validation share.
func TestRTBadPrefixSettingsAreNamedByF14AndNeverFatal(t *testing.T) {
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
			t.Setenv(c.env, c.val)
			_, err := ConfigFromEnv()
			if err == nil {
				t.Fatal("a bad setting is refused by name")
			}
			var logged []string
			st := StartFailure(func(f string, a ...any) { logged = append(logged, f) }, err)
			if st.Code != finality.CodeUpgraderDisabled || st.Fields["reason"] != finality.DisabledSettingInvalid || st.Fields["variable"] != c.env {
				t.Fatalf("want finality_upgrader_disabled{setting_invalid, variable %s}, got %v", c.env, st)
			}
			if strings.Contains(st.Error(), c.val) && len(c.val) > 3 {
				t.Fatalf("the state must not echo the value: %v", st)
			}
		})
	}
	// the defaults are valid
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}
