package accumulate

import "testing"

// RB3-F22: LOG_LEVEL is info (default) or debug, and nothing else is accepted - no other level exists.
func TestLogLevelIsInfoOrDebug(t *testing.T) {
	for v, want := range map[string]string{"": "info", "info": "info", "debug": "debug", "DEBUG": "debug"} {
		if v == "" {
			t.Setenv("LOG_LEVEL", "")
		} else {
			t.Setenv("LOG_LEVEL", v)
		}
		got, err := LogLevelFromEnv()
		if v != "" && (err != nil || got != want) {
			t.Errorf("LOG_LEVEL=%q: (%q, %v)", v, got, err)
		}
	}
	for _, bad := range []string{"warn", "error", "trace", "verbose"} {
		t.Setenv("LOG_LEVEL", bad)
		if _, err := LogLevelFromEnv(); err == nil {
			t.Errorf("LOG_LEVEL=%q accepted", bad)
		}
	}
}
