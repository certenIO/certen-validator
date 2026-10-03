package consensus

import (
	"bytes"
	"strings"
	"testing"
)

// RB5-F47: CometBFT logs at the validator's LOG_LEVEL. At "info" (and unset) its debug lines - the p2p packet reads that
// were half of every container's log - are not printed; at "debug" they are; another value is refused.
func TestCometBFTLogsAtTheValidatorsLevel(t *testing.T) {
	for _, c := range []struct {
		level     string
		wantDebug bool
	}{{"", false}, {"info", false}, {"debug", true}} {
		t.Setenv("LOG_LEVEL", c.level)
		var buf bytes.Buffer
		l, err := cometLogger(&buf)
		if err != nil {
			t.Fatalf("LOG_LEVEL=%q: %v", c.level, err)
		}
		l.With("module", "p2p").Debug("Read PacketMsg")
		l.Info("finalizing commit of block")
		l.Error("a peer failed")
		out := buf.String()
		if got := strings.Contains(out, "Read PacketMsg"); got != c.wantDebug {
			t.Errorf("LOG_LEVEL=%q: debug line printed=%v, want %v:\n%s", c.level, got, c.wantDebug, out)
		}
		if !strings.Contains(out, "finalizing commit of block") || !strings.Contains(out, "a peer failed") {
			t.Errorf("LOG_LEVEL=%q: an info or error line was not printed:\n%s", c.level, out)
		}
	}
	t.Setenv("LOG_LEVEL", "verbose")
	if _, err := cometLogger(&bytes.Buffer{}); err == nil {
		t.Fatal("an unimplemented LOG_LEVEL was accepted")
	}
}

// The node is built with that logger, not an unfiltered one.
func TestTheNodeUsesTheLeveledLogger(t *testing.T) {
	src := workflowSource(t)
	if strings.Contains(src, "cmtlog.NewTMLogger(") {
		t.Fatal("bft_integration.go builds an unfiltered CometBFT logger")
	}
	if !strings.Contains(src, "tmLogger, err := cometLogger(os.Stdout)") {
		t.Fatal("the CometBFT node is not built with cometLogger")
	}
}
