package consensus

import (
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/verification"
)

// =============================================================================
// GATE 1a — the classification table, exhaustively
// =============================================================================
//
// Every row of the Stage 1 rule, as a case. The row that matters most is
// "tx hash + no error + no receipt -> pending", because before Stage 1 it
// produced failed, and it is the ORDINARY case: measured base-sepolia lag is
// ~51s against a 60s submit window.

func TestS1_ClassifyTargetChainOutcome_Table(t *testing.T) {
	submitErr := errors.New("dial tcp: connection refused")

	cases := []struct {
		name string
		res  *verification.AnchorExecutionResult
		err  error
		want TargetChainOutcome
		why  string
	}{
		{
			name: "submission returned an error",
			res:  nil,
			err:  submitErr,
			want: TargetChainFailed,
			why:  "the write did not go out; this is real evidence of failure",
		},
		{
			name: "submission errored even though a result came back",
			res: &verification.AnchorExecutionResult{
				AnchorTxID:               "0xabc",
				AllTransactionsConfirmed: true,
			},
			err:  submitErr,
			want: TargetChainFailed,
			why:  "an explicit error outranks a partially-filled result",
		},
		{
			name: "all transactions confirmed",
			res: &verification.AnchorExecutionResult{
				AnchorTxID:               "0xabc",
				AllTransactionsConfirmed: true,
			},
			err:  nil,
			want: TargetChainConfirmedOutcome,
			why:  "receipts were seen and they succeeded",
		},
		{
			name: "tx hash present, no error, no receipt yet",
			res: &verification.AnchorExecutionResult{
				AnchorTxID:               "0x7f1c",
				GovernanceTxHash:         "0x7f1c",
				AllTransactionsConfirmed: false,
			},
			err:  nil,
			want: TargetChainPending,
			why: "THE REGRESSION THIS STAGE EXISTS FOR. A tx hash with no error is " +
				"pending, not failed — intent 1638327d confirmed 51s after this shape " +
				"was reported as a failure",
		},
		{
			name: "governance hash only, unconfirmed",
			res: &verification.AnchorExecutionResult{
				GovernanceTxHash:         "0x99",
				AllTransactionsConfirmed: false,
			},
			err:  nil,
			want: TargetChainPending,
			why:  "same shape, whichever slot carries the hash",
		},
		{
			name: "no tx hash, no error (never submitted)",
			res:  &verification.AnchorExecutionResult{AllTransactionsConfirmed: false},
			err:  nil,
			want: TargetChainPending,
			why:  "nothing was observed, so nothing is known — absence is not failure",
		},
		{
			name: "no result, no error",
			res:  nil,
			err:  nil,
			want: TargetChainPending,
			why:  "same: no evidence either way",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyTargetChainOutcome(tc.res, tc.err)
			if got != tc.want {
				t.Fatalf("ClassifyTargetChainOutcome = %q, want %q\n  reason: %s", got, tc.want, tc.why)
			}
		})
	}
}

// A timeout must never, by any route, produce failed. Stated as its own test
// because it is the single invariant of this stage: AllTransactionsConfirmed ==
// false means "I did not see a receipt in my window", and a window is not
// evidence.
func TestS1_TimeoutIsNeverFailure(t *testing.T) {
	for _, res := range []*verification.AnchorExecutionResult{
		nil,
		{},
		{AnchorTxID: "0xdead"},
		{AnchorTxID: "0xdead", CreateTxHash: "0xdead", VerifyTxHash: "0xbeef", GovernanceTxHash: "0xfeed"},
		{Network: "base-sepolia", Height: 45937480},
	} {
		if got := ClassifyTargetChainOutcome(res, nil); got == TargetChainFailed {
			t.Fatalf("unconfirmed-without-error classified as %q; a timeout is not evidence of a revert (res=%+v)", got, res)
		}
	}
}

// Receipt status is the only terminal input, and it maps exactly.
func TestS1_OutcomeFromReceiptStatus(t *testing.T) {
	cases := map[uint8]TargetChainOutcome{
		0:   TargetChainPending, // still pending on chain
		1:   TargetChainConfirmedOutcome,
		2:   TargetChainFailed,
		7:   TargetChainPending, // unknown status is not a failure
		255: TargetChainPending,
	}
	for status, want := range cases {
		if got := TargetChainOutcomeFromReceiptStatus(status); got != want {
			t.Fatalf("status %d -> %q, want %q", status, got, want)
		}
	}
}

// The zero value is pending, never failed. This is what keeps an unclassified
// result from being reported as a revert.
func TestS1_ZeroValueNormalizesToPending(t *testing.T) {
	var zero TargetChainOutcome
	if zero.Normalize() != TargetChainPending {
		t.Fatalf("zero value normalized to %q, want %q", zero.Normalize(), TargetChainPending)
	}
	if !zero.IsPending() {
		t.Fatal("zero value must report as pending")
	}
	if zero.IsFailed() {
		t.Fatal("zero value must never report as failed")
	}
	if zero.IsConfirmed() {
		t.Fatal("zero value must never report as confirmed")
	}
	if zero.IsTerminal() {
		t.Fatal("zero value must not be terminal")
	}
	if !TargetChainPending.IsPending() || TargetChainPending.IsTerminal() {
		t.Fatal("pending must be pending and non-terminal")
	}
	if !TargetChainFailed.IsTerminal() || !TargetChainConfirmedOutcome.IsTerminal() {
		t.Fatal("failed and confirmed are terminal")
	}
}

// =============================================================================
// GATE 1b — the gas sentence appears ONLY under failed
// =============================================================================
//
// A one-line regression test for a one-line regression risk. "Gas may have been
// spent on a reverted transaction" is a finding, not a hedge, and printing it
// without a receipt is asserting a cause with no evidence for it.

const gasSentence = "gas may have been spent on a reverted transaction"

func TestS1_GasSentenceOnlyUnderFailed(t *testing.T) {
	const intentID = "1638327d-af2c-439c-a188-be53cdb5c854"
	const txRef = "0x7f1cbe9d"

	for _, tc := range []struct {
		outcome TargetChainOutcome
		txRef   string
		wantGas bool
	}{
		{TargetChainConfirmedOutcome, txRef, false},
		{TargetChainPending, txRef, false},
		{TargetChainPending, "", false},
		{TargetChainOutcomeUnset, txRef, false}, // normalizes to pending
		{TargetChainOutcomeUnset, "", false},
		{TargetChainFailed, txRef, true},
		{TargetChainFailed, "", true},
	} {
		line := RenderTargetChainOutcomeLog(intentID, tc.outcome, tc.txRef, "")
		hasGas := strings.Contains(line, gasSentence)
		if hasGas != tc.wantGas {
			t.Fatalf("outcome=%q txRef=%q: gas sentence present=%v, want %v\n  line: %s",
				tc.outcome, tc.txRef, hasGas, tc.wantGas, line)
		}
	}
}

// A pending line without its transaction hash is unactionable — the operator
// cannot resolve it — so the hash is required, not decorative.
func TestS1_PendingLineCarriesTxHashAndDoesNotClaimFailure(t *testing.T) {
	const intentID = "1638327d-af2c-439c-a188-be53cdb5c854"
	const txRef = "0x7f1cbe9d"

	line := RenderTargetChainOutcomeLog(intentID, TargetChainPending, txRef, "")

	if !strings.Contains(line, txRef) {
		t.Fatalf("pending line omits the tx hash: %s", line)
	}
	if !strings.Contains(line, intentID) {
		t.Fatalf("pending line omits the intent ID, so no terminal line can be joined to it: %s", line)
	}
	if !strings.Contains(line, "PENDING") {
		t.Fatalf("pending line does not say pending: %s", line)
	}
	// The exact phrasing the fleet used to emit for a healthy settlement.
	for _, forbidden := range []string{"did NOT confirm", "FAILED", gasSentence} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("pending line contains failure language %q: %s", forbidden, line)
		}
	}
	// It must name the resolver, or the reader has no reason to expect a sequel.
	if !strings.Contains(line, "proof cycle") {
		t.Fatalf("pending line does not name what will resolve it: %s", line)
	}
}

// The not-submitted shape is informational, not a warning: six of seven
// validators are in it on every single round.
func TestS1_NotSubmittedLineIsNotAWarning(t *testing.T) {
	line := RenderTargetChainOutcomeLog("intent-x", TargetChainPending, "", "")
	for _, forbidden := range []string{"FAILED", "did NOT confirm", gasSentence, "⚠️"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("no-submission line contains %q: %s", forbidden, line)
		}
	}
	if !strings.Contains(line, "no target-chain submission from this node") {
		t.Fatalf("no-submission line does not explain itself: %s", line)
	}
}

// The failed line must still carry the error and the hash, because that is what
// an operator needs to confirm the revert independently.
func TestS1_FailedLineCarriesEvidence(t *testing.T) {
	line := RenderTargetChainOutcomeLog("intent-x", TargetChainFailed, "0xdead", "execution reverted")
	for _, want := range []string{"intent-x", "0xdead", "execution reverted", gasSentence, "FAILED"} {
		if !strings.Contains(line, want) {
			t.Fatalf("failed line missing %q: %s", want, line)
		}
	}
	// With no hash it must say so rather than print an empty field.
	if l := RenderTargetChainOutcomeLog("intent-x", TargetChainFailed, "", "boom"); !strings.Contains(l, "<none>") {
		t.Fatalf("failed line with no tx hash should say <none>: %s", l)
	}
}

// =============================================================================
// TargetChainTxRef — a pending report is only useful with the hash
// =============================================================================

func TestS1_TargetChainTxRef(t *testing.T) {
	if got := TargetChainTxRef(nil); got != "" {
		t.Fatalf("nil result -> %q, want empty", got)
	}
	if got := TargetChainTxRef(&verification.AnchorExecutionResult{}); got != "" {
		t.Fatalf("empty result -> %q, want empty", got)
	}
	if got := TargetChainTxRef(&verification.AnchorExecutionResult{AnchorTxID: "0xaa"}); got != "0xaa" {
		t.Fatalf("anchor hash -> %q, want 0xaa", got)
	}
	// Falls through the slots in order rather than reporting nothing.
	if got := TargetChainTxRef(&verification.AnchorExecutionResult{GovernanceTxHash: "0xbb"}); got != "0xbb" {
		t.Fatalf("governance hash -> %q, want 0xbb", got)
	}
	if got := TargetChainTxRef(&verification.AnchorExecutionResult{VerifyTxHash: "0xcc"}); got != "0xcc" {
		t.Fatalf("verify hash -> %q, want 0xcc", got)
	}
}

// =============================================================================
// 1.2.7 — the dangerous direction
// =============================================================================
//
// Everywhere else in Stage 1, AllTransactionsConfirmed == false now means
// "unresolved". At the batch attestation sites it genuinely means FAILED, and
// those sites state it explicitly on the attestation rather than relying on a
// default. This test pins that: if someone later removes the explicit
// assignment, a real revert quietly becomes "still pending" and the intent is
// reported as in flight forever.
func TestS1_KnownBatchFailureIsNotDowngradedToPending(t *testing.T) {
	att := &PendingAttestation{IntentID: "batch-member-1"}

	// What RunBatchMemberAttestation does for success=false.
	att.TargetChainOutcome = TargetChainFailed
	if att.TargetChainOutcome.IsPending() {
		t.Fatal("a known batch failure must not read as pending")
	}
	if !att.TargetChainOutcome.IsFailed() {
		t.Fatal("a known batch failure must read as failed")
	}

	// And for success=true.
	att.TargetChainOutcome = TargetChainConfirmedOutcome
	if !att.TargetChainOutcome.IsConfirmed() {
		t.Fatal("a settled batch member must read as confirmed")
	}

	// A caller that sets nothing gets pending — never failed. That default is
	// safe ONLY because the known-failure sites are explicit.
	fresh := &PendingAttestation{IntentID: "unclassified"}
	if !fresh.TargetChainOutcome.IsPending() || fresh.TargetChainOutcome.IsFailed() {
		t.Fatal("an unclassified attestation must default to pending, not failed")
	}
}
