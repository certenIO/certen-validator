// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"strings"
)

// G2 outcome binding.
//
// G2's whole reason to exist over G1 is outcome binding - section 1.3: "proves
// a success-only, receipt-proven outcome bound under the execution witness",
// and section 10: "A G2 proof MUST bind a success-only, receipt-proven outcome
// leaf under EXEC_WITNESS."
//
// Two of the four components that decided g2ProofComplete did not verify that.
// They were:
//
//	verified := g1Result.G0ProofComplete &&
//	            g1Result.Receipt.Start != "" && g1Result.Receipt.Anchor != ""
//
//	verified := g1Result.G1ProofComplete && g1Result.ExecWitness != ""
//
// A flag set by an earlier stage, plus a test that a string is not empty. No
// merkle recomputation, and the first inspected G0's receipt rather than an
// outcome leaf. Both returned true for any proof that got that far, which is
// why they also rubber-stamped the payload bypass they were supposed to guard.
//
// This file replaces them with the six checks section 10 and section 2.1
// actually require.

// VerificationState is a tri-state so that "never executed" cannot be read as
// "executed and passed". The zero value is NotRun, which is never a pass.
type VerificationState int

const (
	StateNotRun VerificationState = iota
	StateFailed
	StateVerified
)

func (s VerificationState) String() string {
	switch s {
	case StateVerified:
		return "verified"
	case StateFailed:
		return "failed"
	default:
		return "not-run"
	}
}

// OutcomeBinding is the evidence that a success-only, receipt-proven outcome
// leaf sits under EXEC_WITNESS.
type OutcomeBinding struct {
	State VerificationState `json:"state"`

	OutcomeLeaf   string `json:"outcomeLeaf"`   // ENTRY_HASH, the receipt-proven leaf
	ExecWitness   string `json:"execWitness"`   // the anchor the leaf is proven under
	ExecMBI       int64  `json:"execMBI"`       //
	Status        string `json:"status"`        // delivered / pending / failed
	StatusNo      int64  `json:"statusNo"`      //
	MerkleSteps   int    `json:"merkleSteps"`   // length of the recomputed path
	MessageIDForm string `json:"messageIdForm"` // the acc://<ENTRY_HASH>@<scope> checked

	Checks  []string `json:"checks"`  // what was actually verified, in order
	Failure string   `json:"failure"` // why, when State == StateFailed
}

// Verified reports whether the binding passed. It exists so callers cannot
// accidentally treat StateNotRun as success by reading a bool field.
func (o *OutcomeBinding) Verified() bool { return o != nil && o.State == StateVerified }

func (o *OutcomeBinding) fail(format string, args ...interface{}) *OutcomeBinding {
	o.State = StateFailed
	o.Failure = fmt.Sprintf(format, args...)
	return o
}

func (o *OutcomeBinding) pass(check string) { o.Checks = append(o.Checks, check) }

// verifyOutcomeBinding performs the real check.
//
//	1. an outcome leaf exists, located under EXEC_WITNESS
//	2. it is success-only (section 10) - anything but delivered-success
//	   degrades the proof to G1
//	3. its receipt MERKLE-RECOMPUTES to the anchor (not a non-empty check)
//	4. the receipt-proven leaf is the one under the execution witness G0
//	   derived, not merely a valid receipt somewhere
//	5. ENTRY_HASH equals the receipt-proven leaf (section 7.2)
//	6. the expanded message ID is exactly acc://<ENTRY_HASH>@<scope> (section 2.2)
//
// Every step fails closed. Nothing defaults to verified.
func (g2 *G2Layer) verifyOutcomeBinding(ctx context.Context, g1Result *G1Result) *OutcomeBinding {
	ob := &OutcomeBinding{
		State:       StateNotRun,
		OutcomeLeaf: g1Result.EntryHashExec,
		ExecWitness: g1Result.ExecWitness,
		ExecMBI:     g1Result.ExecMBI,
	}
	fmt.Printf("[G2] [OUTCOME] Verifying outcome binding under EXEC_WITNESS\n")

	// --- 1. an outcome leaf exists ---------------------------------------
	if g1Result.EntryHashExec == "" {
		return ob.fail("no outcome leaf: G0 produced no ENTRY_HASH")
	}
	if g1Result.ExecWitness == "" {
		return ob.fail("no execution witness to bind the outcome leaf under")
	}
	hv := HexValidator{}
	leaf, err := hv.RequireHex32(g1Result.EntryHashExec, "ENTRY_HASH")
	if err != nil {
		return ob.fail("ENTRY_HASH is not a 32-byte hash: %v", err)
	}
	witness, err := hv.RequireHex32(g1Result.ExecWitness, "EXEC_WITNESS")
	if err != nil {
		return ob.fail("EXEC_WITNESS is not a 32-byte hash: %v", err)
	}
	ob.pass("outcome leaf and execution witness present and well-formed")

	// --- 2. success-only (section 10) -------------------------------------
	status, statusNo, err := g2.queryOutcomeStatus(ctx, g1Result)
	if err != nil {
		// Not knowing the outcome is not the same as the outcome being bad,
		// but neither may satisfy G2. Fail closed and say which it was.
		return ob.fail("could not read the transaction outcome status: %v", err)
	}
	ob.Status, ob.StatusNo = status, statusNo
	if !isDeliveredSuccess(status, statusNo) {
		return ob.fail("outcome is %q (statusNo %d); section 10 requires a success-only outcome, "+
			"so this proof degrades to G1", status, statusNo)
	}
	ob.pass(fmt.Sprintf("outcome is success-only (status=%s statusNo=%d)", status, statusNo))

	// --- 3. the receipt MERKLE-RECOMPUTES ---------------------------------
	receipt := g1Result.Receipt
	if err := VerifyReceiptMerkle(receipt, "outcome receipt"); err != nil {
		return ob.fail("outcome receipt does not recompute to its anchor: %v", err)
	}
	ob.MerkleSteps = len(receipt.Entries)
	ob.pass(fmt.Sprintf("outcome receipt merkle-recomputed over %d steps", ob.MerkleSteps))

	// --- 4/5. the recomputed leaf IS the outcome leaf, under THIS witness --
	rStart, err := hv.RequireHex32(receipt.Start, "outcome receipt.start")
	if err != nil {
		return ob.fail("outcome receipt.start invalid: %v", err)
	}
	if !strings.EqualFold(rStart, leaf) {
		return ob.fail("receipt proves leaf %s, but ENTRY_HASH is %s (section 7.2)",
			SafeTruncate(rStart, 16), SafeTruncate(leaf, 16))
	}
	ob.pass("ENTRY_HASH equals the receipt-proven leaf")

	rAnchor, err := hv.RequireHex32(receipt.Anchor, "outcome receipt.anchor")
	if err != nil {
		return ob.fail("outcome receipt.anchor invalid: %v", err)
	}
	if !strings.EqualFold(rAnchor, witness) {
		return ob.fail("receipt anchors to %s, but EXEC_WITNESS is %s; the outcome is not bound "+
			"under the witness G0 derived", SafeTruncate(rAnchor, 16), SafeTruncate(witness, 16))
	}
	ob.pass("outcome leaf is bound under EXEC_WITNESS")

	if receipt.LocalBlock != g1Result.ExecMBI {
		return ob.fail("outcome receipt.localBlock=%d != EXEC_MBI=%d", receipt.LocalBlock, g1Result.ExecMBI)
	}
	ob.pass("outcome receipt block equals EXEC_MBI")

	// --- 6. ENTRY_HASH form of the expanded message ID (section 2.2) ------
	if g1Result.Scope == "" {
		return ob.fail("no scope to form the expanded message ID against")
	}
	want := fmt.Sprintf("acc://%s@%s", leaf, strings.TrimPrefix(g1Result.Scope, "acc://"))
	ob.MessageIDForm = want
	if !messageIDMatches(g1Result.ExpandedMessageID, want) {
		return ob.fail("expanded message ID %q != acc://<ENTRY_HASH>@<scope> %q (section 2.2/7.2)",
			g1Result.ExpandedMessageID, want)
	}
	ob.pass("expanded message ID equals acc://<ENTRY_HASH>@<scope>")

	ob.State = StateVerified
	fmt.Printf("[G2] [OUTCOME] [OK] outcome binding verified (%d checks, %d merkle steps)\n",
		len(ob.Checks), ob.MerkleSteps)
	return ob
}

// queryOutcomeStatus reads the transaction's delivered status.
func (g2 *G2Layer) queryOutcomeStatus(ctx context.Context, g1Result *G1Result) (string, int64, error) {
	if g1Result.ExpandedMessageID == "" {
		return "", 0, fmt.Errorf("no expanded message ID to query")
	}
	resp, err := g2.g1Layer.g0Layer.client.Query(ctx, g1Result.ExpandedMessageID, g2.queryBuilder.BuildMsgIDQuery())
	if err != nil {
		return "", 0, fmt.Errorf("query outcome: %w", err)
	}
	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return "", 0, fmt.Errorf("extract outcome result: %w", err)
	}
	status, _ := pu.CaseInsensitiveGet(result, "status").(string)
	var statusNo int64
	switch v := pu.CaseInsensitiveGet(result, "statusNo").(type) {
	case float64:
		statusNo = int64(v)
	case int64:
		statusNo = v
	case int:
		statusNo = int64(v)
	}
	if status == "" && statusNo == 0 {
		return "", 0, fmt.Errorf("outcome carries no status")
	}
	return status, statusNo, nil
}

// isDeliveredSuccess reports whether an Accumulate transaction status is a
// success-only outcome.
//
// Accumulate status codes follow HTTP conventions: 2xx is delivered-success,
// 4xx/5xx are failures, and "pending"/"remote" are not outcomes yet. Anything
// that is not positively a success is not one.
func isDeliveredSuccess(status string, statusNo int64) bool {
	if !strings.EqualFold(strings.TrimSpace(status), "delivered") {
		return false
	}
	return statusNo >= 200 && statusNo < 300
}

// messageIDMatches compares two acc:// message IDs case-insensitively, tolerant
// of a missing scheme on either side but nothing else.
func messageIDMatches(got, want string) bool {
	// Lowercase BEFORE trimming: trimming first misses an uppercase scheme
	// ("ACC://..."), which would then compare unequal to the same ID.
	norm := func(s string) string {
		return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "acc://")
	}
	return norm(got) == norm(want)
}
