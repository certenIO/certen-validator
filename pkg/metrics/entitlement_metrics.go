// Copyright 2026 Certen Protocol
//
// Entitlement gate metrics.
//
// # WHY THESE EXIST
//
// VerifyEntitlement refuses for reasons that look identical in aggregate and demand opposite
// responses:
//
//	not_entitled   the account may not spend. A customer conversation. Working as designed.
//	stale          the epoch expired because the publisher stopped. An infrastructure failure,
//	               and under `enforce` it refuses EVERY block on EVERY validator — a fleet-wide
//	               halt, not a per-account decision.
//
// Both are correct refusals and both must stay fail-closed: accepting expired evidence would
// hand free execution to anyone able to take the publisher offline, and NotAfterUnix is the
// whole security bound (issued_at was deliberately removed as unenforceable). So the fix is not
// to soften the check but to make the two distinguishable BEFORE the fleet is enforcing —
// paging on one and not the other.
//
// Recorded at both call sites, labelled by which one, because they answer different questions:
// CheckTx measures what this node would have admitted to its mempool, FinalizeBlock measures
// what consensus actually decided. A divergence between them means nodes disagree about
// freshness, which is the shape of a fork.

package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// entitlementDecisions counts every gate evaluation.
	//
	// `decision` separates a refusal that BOUND from one merely observed, so the same series
	// answers "what is being refused now" and "what would be refused if we enforced" — which is
	// the question that has to be answered before enforcing at all.
	//
	// `principal` says WHO, but only for the decisions where that matters. On 2026-08-11 this
	// series showed 11 observed INTENT_CEILING_EXCEEDED evaluations and there was no way to
	// learn which account they belonged to: the log line that would have said is emitted on a
	// path that does not reliably reach stdout (255 admitted decisions produced 98 log lines,
	// and 11 observed produced none). "Something would have been refused and we cannot say
	// what" is not a basis on which to enforce.
	//
	// Admitted decisions carry principal "-" deliberately. They are the high-volume case —
	// every block, every principal, plus mempool rechecks — and labelling them would multiply
	// the series count by the size of the entitlement set for no diagnostic gain, since an
	// admitted decision raises no question. Cardinality is therefore bounded by the number of
	// accounts with a PROBLEM, which is small when things are healthy and grows only when
	// something needs attention.
	entitlementDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "entitlement",
		Name:      "decisions_total",
		Help:      "Entitlement gate evaluations by stage, decision, reason and (for non-admitted) principal",
	}, []string{"stage", "decision", "reason", "principal"})

	// entitlementEpochRemainingSeconds is the countdown to a halt under enforce.
	//
	// Seconds until this node's cached epoch expires. The alertable signal: it decays whether
	// the publisher is failing loudly, silently, or unreachable, so it is true regardless of HOW
	// publishing broke. A publish-success counter is not a substitute — it stays flat and silent
	// in exactly the case that matters.
	//
	// Not clamped at zero. Negative means this node is ALREADY refusing every block, and
	// flooring it would hide the one state that must never be ambiguous.
	entitlementEpochRemainingSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "entitlement",
		Name:      "epoch_remaining_seconds",
		Help:      "Seconds until this node's entitlement epoch expires; negative means already refusing",
	})

	entitlementEpochNumber = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "entitlement",
		Name:      "epoch",
		Help:      "Epoch number this node is currently verifying against",
	})

	entitlementAccounts = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "entitlement",
		Name:      "accounts",
		Help:      "Principals in this node's cached entitlement set",
	})

	// entitlementMode is the sealed consensus policy, as a number so it is alertable.
	//
	// 0=off 1=observe 2=enforce. Exported because the mode is SEALED IN THE LEDGER AT GENESIS
	// and the environment is ignored thereafter: an operator who edits
	// CERTEN_ENTITLEMENT_MODE and redeploys gets a warning log and no behaviour change. This
	// gauge is how you find out what the chain is actually doing rather than what the
	// environment claims.
	entitlementMode = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "entitlement",
		Name:      "mode",
		Help:      "Sealed entitlement policy: 0=off, 1=observe, 2=enforce",
	})
)

// RecordEntitlementDecision records one gate evaluation.
//
// stage is "checktx" or "finalizeblock"; decision is "admitted", "refused" or "observed";
// reason is the verifier's reason, or "" when admitted; principal is the Accumulate account
// the block acts for.
//
// The principal is recorded only for refused and observed decisions — see the note on
// entitlementDecisions for why admitted is deliberately unlabelled.
func RecordEntitlementDecision(stage, decision, reason, principal string) {
	if reason == "" {
		reason = "none"
	}
	// An unbounded label value from an untrusted source is a cardinality bomb: a caller that
	// writes intents for made-up principals could mint a new series per request and exhaust
	// the scraper's memory. Only accounts that appear in a decision worth investigating are
	// labelled, and even those are truncated.
	label := "-"
	if decision != "admitted" {
		label = truncatePrincipal(principal)
	}
	entitlementDecisions.WithLabelValues(stage, decision, reason, label).Inc()
}

// maxPrincipalLabel bounds one label value. Accumulate URLs are already short; this guards
// against a pathological one rather than trimming anything real.
const maxPrincipalLabel = 128

func truncatePrincipal(p string) string {
	if p == "" {
		return "unknown"
	}
	if len(p) > maxPrincipalLabel {
		return p[:maxPrincipalLabel]
	}
	return p
}

// SetEntitlementEpoch reports the cached epoch this node verifies against.
//
// remainingSeconds may be negative; see the gauge's comment.
func SetEntitlementEpoch(epoch uint64, accounts int, remainingSeconds float64) {
	entitlementEpochNumber.Set(float64(epoch))
	entitlementAccounts.Set(float64(accounts))
	entitlementEpochRemainingSeconds.Set(remainingSeconds)
}

// SetEntitlementMode reports the SEALED policy, not the environment's.
func SetEntitlementMode(mode string) {
	switch mode {
	case "enforce":
		entitlementMode.Set(2)
	case "observe":
		entitlementMode.Set(1)
	default:
		entitlementMode.Set(0)
	}
}

// registerEntitlementMetrics is called from RegisterMetrics.
func registerEntitlementMetrics() {
	prometheus.MustRegister(entitlementDecisions)
	prometheus.MustRegister(entitlementEpochRemainingSeconds)
	prometheus.MustRegister(entitlementEpochNumber)
	prometheus.MustRegister(entitlementAccounts)
	prometheus.MustRegister(entitlementMode)
}

// Recommended alert rules:
//
//   - alert: CertenEntitlementEpochExpiring
//     expr: certen_entitlement_epoch_remaining_seconds < 900
//     for: 5m
//     labels: {severity: critical}
//     annotations:
//     summary: "Entitlement epoch expiring on {{ $labels.instance }}"
//     description: "{{ $value }}s of validity left. At zero an enforcing fleet refuses every block."
//
//   - alert: CertenEntitlementExpired
//     expr: certen_entitlement_epoch_remaining_seconds <= 0 and certen_entitlement_mode == 2
//     for: 1m
//     labels: {severity: page}
//     annotations:
//     summary: "ENFORCING with an expired epoch — execution is halted"
//
//     Stale is an infrastructure failure and pages. not_entitled is a customer decision and
//     must NOT page, however many fire — that is the gate working.
//
//   - alert: CertenEntitlementStaleRefusals
//     expr: rate(certen_entitlement_decisions_total{reason="stale"}[5m]) > 0
//     for: 5m
//     labels: {severity: critical}
//     annotations:
//     summary: "Blocks refused for STALE entitlement, not for non-payment"
//
//     Nodes disagreeing about freshness is the shape of a fork. CheckTx judges against wall
//     time and FinalizeBlock against block time, so a persistent divergence is meaningful.
//
//   - alert: CertenEntitlementStageDivergence
//     expr: |
//     rate(certen_entitlement_decisions_total{stage="checktx",decision="refused"}[10m])
//     - rate(certen_entitlement_decisions_total{stage="finalizeblock",decision="refused"}[10m]) > 0.1
//     for: 10m
//     labels: {severity: warning}
