package accumulate

import (
	"os"
	"strings"
	"testing"
)

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

// RB5-F47: the whole decoded intent - every element as a map - is logged at LOG_LEVEL=debug only. Printed at info on
// every discovery pass by all seven nodes, with CometBFT's debug lines it held each container's log retention to about
// six minutes.
func TestTheDecodedIntentIsLoggedOnlyAtDebug(t *testing.T) {
	b, err := os.ReadFile("liteclient_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, unconditional := range []string{`log.Printf("🔍 [DEBUG-`, `log.Printf("✅ [EXTRACT-INTENT] Decoded`} {
		if strings.Contains(src, unconditional) {
			t.Errorf("liteclient_adapter.go prints %s… at every level", unconditional)
		}
	}
	if !strings.Contains(src, `debugf("🔍 [DEBUG-INTENT-DATA]`) {
		t.Error("the final IntentData dump is not logged through debugf")
	}
}
