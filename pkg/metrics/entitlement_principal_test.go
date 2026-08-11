package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The principal label answers "who would have been refused", which on 2026-08-11
// was unanswerable: 11 observed INTENT_CEILING_EXCEEDED evaluations with no way
// to attribute them, because the log line that would have said is emitted on a
// path that does not reliably reach stdout.
//
// The label is also the one place in this file where an untrusted value reaches
// Prometheus, so the tests below are mostly about it NOT becoming a cardinality
// bomb: a caller writing intents for invented principals must not be able to
// mint an unbounded number of series.

func TestPrincipalRecordedForObservedDecision(t *testing.T) {
	entitlementDecisions.Reset()
	RecordEntitlementDecision("checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://alice.acme/data")

	got := testutil.ToFloat64(entitlementDecisions.WithLabelValues(
		"checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://alice.acme/data"))
	if got != 1 {
		t.Fatalf("observed decision not attributed to its principal: got %v", got)
	}
}

func TestPrincipalRecordedForRefusedDecision(t *testing.T) {
	entitlementDecisions.Reset()
	RecordEntitlementDecision("finalizeblock", "refused", "NOT_ENTITLED", "acc://bob.acme/data")

	got := testutil.ToFloat64(entitlementDecisions.WithLabelValues(
		"finalizeblock", "refused", "NOT_ENTITLED", "acc://bob.acme/data"))
	if got != 1 {
		t.Fatalf("refused decision not attributed: got %v", got)
	}
}

// Admitted is the high-volume case: every block, every principal, plus mempool
// rechecks. Labelling it would multiply series by the size of the entitlement
// set to answer a question nobody asks, so it collapses to a constant.
func TestAdmittedDecisionIsNotLabelledByPrincipal(t *testing.T) {
	entitlementDecisions.Reset()
	RecordEntitlementDecision("checktx", "admitted", "", "acc://alice.acme/data")
	RecordEntitlementDecision("checktx", "admitted", "", "acc://bob.acme/data")
	RecordEntitlementDecision("checktx", "admitted", "", "acc://carol.acme/data")

	got := testutil.ToFloat64(entitlementDecisions.WithLabelValues("checktx", "admitted", "none", "-"))
	if got != 3 {
		t.Fatalf("admitted decisions should collapse into one series: got %v, want 3", got)
	}
	if n := testutil.CollectAndCount(entitlementDecisions); n != 1 {
		t.Fatalf("three admitted decisions produced %d series; expected 1", n)
	}
}

// A pathological principal must be truncated rather than stored whole.
func TestOverlongPrincipalIsTruncated(t *testing.T) {
	entitlementDecisions.Reset()
	long := "acc://" + strings.Repeat("x", 500) + ".acme/data"
	RecordEntitlementDecision("checktx", "observed", "NOT_ENTITLED", long)

	if got := testutil.ToFloat64(entitlementDecisions.WithLabelValues(
		"checktx", "observed", "NOT_ENTITLED", long[:maxPrincipalLabel])); got != 1 {
		t.Fatalf("overlong principal not truncated to the bound: got %v", got)
	}
}

// An empty principal is a bug upstream, not a reason to drop the observation —
// the fact that something would have been refused still matters.
func TestEmptyPrincipalBecomesUnknown(t *testing.T) {
	entitlementDecisions.Reset()
	RecordEntitlementDecision("checktx", "observed", "NOT_ENTITLED", "")

	if got := testutil.ToFloat64(entitlementDecisions.WithLabelValues(
		"checktx", "observed", "NOT_ENTITLED", "unknown")); got != 1 {
		t.Fatalf("empty principal should record as unknown, not vanish: got %v", got)
	}
}

// Distinct principals in trouble are distinct series — that is the entire point.
func TestDistinctPrincipalsAreDistinguishable(t *testing.T) {
	entitlementDecisions.Reset()
	RecordEntitlementDecision("checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://alice.acme/data")
	RecordEntitlementDecision("checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://bob.acme/data")
	RecordEntitlementDecision("checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://bob.acme/data")

	if got := testutil.ToFloat64(entitlementDecisions.WithLabelValues(
		"checktx", "observed", "INTENT_CEILING_EXCEEDED", "acc://bob.acme/data")); got != 2 {
		t.Fatalf("bob should have 2 observations: got %v", got)
	}
	if n := testutil.CollectAndCount(entitlementDecisions); n != 2 {
		t.Fatalf("two principals should be two series: got %d", n)
	}
}
