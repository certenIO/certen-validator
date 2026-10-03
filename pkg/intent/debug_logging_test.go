package intent

import (
	"os"
	"strings"
	"testing"
)

// RB5-F47: the whole incoming transaction is logged at LOG_LEVEL=debug only.
func TestTheConversionInputIsLoggedOnlyAtDebug(t *testing.T) {
	b, err := os.ReadFile("discovery.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, `[DEBUG-CONVERSION-INPUT]`)
	if i < 0 {
		t.Fatal("the conversion-input line is gone")
	}
	if !strings.Contains(src[max(0, i-200):i], "if accumulate.DebugLogging() {") {
		t.Fatal("the conversion-input dump is printed at every level")
	}
}
