package consensus

import (
	"strings"
	"testing"
)

// The execution-rules gate exists to replace this failure:
//
//	panic: state.AppHash does not match AppHash after replay.
//	  Got 9B34726E…, expected 8028A10C…
//
// which names neither cause nor remedy and cannot self-recover. These tests pin
// that the gate refuses in exactly the cases that would panic, allows the cases
// that are safe, and that its message is actually actionable.

func TestMatchingVersionStarts(t *testing.T) {
	got, err := checkExecutionRulesVersion(CurrentExecutionRulesVersion, 100)
	if err != nil {
		t.Fatalf("matching version refused to start: %v", err)
	}
	if got != CurrentExecutionRulesVersion {
		t.Fatalf("version = %d, want %d", got, CurrentExecutionRulesVersion)
	}
}

// State written before the field existed carries zero. There is nothing to
// compare against, so adopting the current version is the only workable choice
// — and it is safe because the field ships with the check, so the first run
// after upgrading simply stamps state it already had.
func TestZeroVersionAdoptsCurrentRatherThanRefusing(t *testing.T) {
	got, err := checkExecutionRulesVersion(0, 65)
	if err != nil {
		t.Fatalf("pre-existing state must not be refused: %v", err)
	}
	if got != CurrentExecutionRulesVersion {
		t.Fatalf("adopted version = %d, want %d", got, CurrentExecutionRulesVersion)
	}
}

// The incident's shape: a binary implementing newer rules meets state committed
// under older ones. Starting would replay to a different app hash and panic.
func TestNewerBinaryOnOlderStateRefuses(t *testing.T) {
	_, err := checkExecutionRulesVersion(executionRulesV1, 65)
	if err == nil {
		t.Fatal("a newer binary must refuse state committed under older rules")
	}

	msg := err.Error()
	// The message has to be actionable — the panic it replaces was not.
	for _, want := range []string{
		"execution rules mismatch",
		"height 65",
		"resetting BOTH", // the half-reset is what prolonged the real outage
		"recreates this mismatch",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q; operators need it to act.\ngot: %s", want, msg)
		}
	}
}

// The rollback direction: an operator reverts to a binary older than the state.
// Equally unstartable, and worth a different message because the fix differs
// (roll forward, rather than roll back).
func TestOlderBinaryOnNewerStateRefuses(t *testing.T) {
	_, err := checkExecutionRulesVersion(CurrentExecutionRulesVersion+1, 200)
	if err == nil {
		t.Fatal("an older binary must refuse state committed under newer rules")
	}
	if !strings.Contains(err.Error(), "rolled back past an upgrade") {
		t.Errorf("rollback case should say so explicitly; got: %s", err.Error())
	}
}

// The version must be a real constant, not an accidental zero — a zero would
// make every check a no-op and silently disable the whole mechanism.
func TestCurrentVersionIsSet(t *testing.T) {
	if CurrentExecutionRulesVersion == 0 {
		t.Fatal("CurrentExecutionRulesVersion is 0, which disables every check")
	}
	if CurrentExecutionRulesVersion != executionRulesV5 {
		t.Fatalf("current = %d; if rules changed, bump the constant AND add a "+
			"changelog entry in execution_rules.go", CurrentExecutionRulesVersion)
	}
}
