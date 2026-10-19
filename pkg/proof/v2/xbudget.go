// Copyright 2026 Certen Protocol
//
// The evidence budget (docs/proof/G1_CROSS_PARTITION.md D6 g1_closure_exceeds_budget; RB9 Phase C1b-2; RB9-F5 package F5-4, V-E A4).
//
// Evidence travels inside the intent certificate, which is ONE transaction of CERTEN's consensus (CometBFT v0.38.21). pkg/consensus raises the node-local RPC
// body limit so that a transaction of the mempool's size passes the RPC, and judges every transaction against the whole path
// (comet_tx_limits.go, C5-D1); it sets no mempool or block limit of its own, so the chain's own limits bind: the mempool refuses a transaction over max_tx_bytes = 1 MiB
// (cometbft/config/config.go:799, "MaxTxBytes: 1024 * 1024"), and a block holds at most 21 MiB (cometbft/types/params.go:99,
// "MaxBytes: 22020096"). One transaction is the tighter bound. Since the RPC body limit was raised (C5-D1, pkg/consensus/comet_tx_limits.go,
// all 7 validators) the whole path accepts exactly ConsensusTxLimit.
//
// THE TRANSACTION IS EVIDENCE + R. R is everything of the ValidatorBlock that is not the proof v2 document: the vote evidence with its page
// histories (govvote.Evidence), the L1-L4 chained proof carried a second time as lite_client_proof, G0-G2, the authorization record and the
// signatures. MEASURED (evidence/r-rest-of-transaction-measured.md, the proposers' own log, 15 transactions in 26 h): R = N - document =
// 138,579 .. 258,469 bytes (largest 696,611 - 438,142). The previous 96 KiB reserve (98,304) was far below it, so MaxEvidenceBytes = 950,272 did
// not guarantee a transaction under 1 MiB. CertificateReserve is now 320 KiB: the largest measured R (258,469) plus the closure-scaled vote
// evidence of a closure of 8 pages (see below), and TestCertificateBudgetCoversMeasuredR holds evidence-at-the-cap + every measured R inside
// ConsensusTxLimit.
//
// MEASURED ON THE 19 LIVE INTENTS' ANCHORED FORM (pkg/consensus/budget_live_test.go; testdata/g1_live, g1_live_fixedprover and the recorded
// Kermit link answers of g1_live_anchored; compact JSON):
//   - the fixed part of the anchored evidence (everything but the pages, votes and transaction: the one kept certify run and its link, the
//     set check with its hop, the anchors, the routing proof): 18,938 .. 27,626 bytes at a validator set of MeasuredValidators. It no longer
//     holds the minor-root runs since the last major (which are why the real 2.0 evidence of 3cfb04cf held 731,778 bytes, 357,638 of them
//     runs, and why the old FixedEvidenceBytes was 760,000). FixedEvidenceBytes is that maximum plus the signature entries of the records it
//     holds at a validator set of BudgetedValidators instead of MeasuredValidators (each record carries ValidatorSignatureBytes per
//     validator) and the genesis link (V-E A1b, 1,880 bytes measured): 27,626 + 1,880 + 4 records x 165 x (16-3) = 27,626 + 1,880 + 8,580 = 38,086
//     (the test measures the document that already carries the link: 29,507 + 8,580 = 38,087), rounded up to the next 5,000 = 40,000, with no further
//     step. TestBudgetLiveAnchoredMeasured derives it and requires FixedEvidenceBytes to EQUAL the derived value; it is not a guess.
//   - pages and votes together cost about 5.0 KB per closure page (cross-505: 25,311 bytes for 5 pages; deleg-532: 226,154 for 45).
//   - the vote evidence inside R grows with the closure too, up to 7,503 bytes per closure page (same-500; deleg-532: 281,096 for 45 pages =
//     6,246), and the rest of R without it is 141,464 .. 198,492 bytes on these intents (the production R of 3-page intents, which includes
//     their vote evidence, is up to 258,469). RestFlatBytes is the production maximum, VoteEvidenceBytesPerPage the per-page maximum rounded
//     up: a closure of P pages has R <= RestFlatBytes + VoteEvidenceBytesPerPage x P (CertificateEstimate). The reserve covers that for a
//     closure of up to 8 pages; a larger closure is admitted by the evidence cap only while its WHOLE certificate fits, which
//     CheckCertificateFits and CheckClosureBudget judge before anything is signed. The 45-page deleg-532 is evidence 259,053 + R 448,096 =
//     707,149 bytes: inside the limit though R alone is over the reserve.
//
// THE k x V BOUND. What grows is bounded by the update-bearing windows, never by the time since the major (the anchored form keeps the windows
// that apply an update and the last one). Each such window's record carries one signature entry of ValidatorSignatureBytes (165) per
// validator, so the signatures of k windows at V validators take k x V x 165 bytes (UpdateWindowsBytes). MaxUpdateWindows(V) is the largest k
// whose signatures leave room in MaxEvidenceBytes after FixedEvidenceBytes; CheckUpdateWindows refuses above it by the name
// certificate_budget{size,limit}, judged where the caller says.
//
// A certificate over the budget cannot travel in a consensus block: it is the named state g1_closure_exceeds_budget{pages, limit} (the
// evidence alone) or certificate_budget{size,limit} (the whole certificate; the same decision as the transaction path's tx_too_large), never
// a document trimmed to fit. The verifier checks only the evidence (CheckEvidenceBudget, xverify.go): these constants are consensus-visible
// for evidence 2.1, which the v15 gate refuses today.
package proofv2

import (
	"encoding/json"
	"fmt"
	"strconv"
)

const (
	// ConsensusTxLimit is the largest transaction CERTEN's consensus engine accepts (CometBFT mempool.max_tx_bytes; the RPC body limit is raised
	// to carry it, pkg/consensus/comet_tx_limits.go).
	ConsensusTxLimit = 1 << 20
	// CertificateReserve is what the rest of the intent certificate (R) may take of that transaction: the largest measured R (258,469) plus the
	// vote evidence of a closure of 8 pages (V-E A4: at least 320 KiB).
	CertificateReserve = 320 << 10
	// MaxEvidenceBytes is the budget of the encoded evidence document.
	MaxEvidenceBytes = ConsensusTxLimit - CertificateReserve
	// FixedEvidenceBytes is the largest fixed part (everything but the pages, votes and transaction) of the ANCHORED form, measured on the 19
	// live intents and budgeted for BudgetedValidators validators.
	FixedEvidenceBytes = 40_000
	// ValidatorSignatureBytes is one validator's signature entry in a record (measured: 165).
	ValidatorSignatureBytes = 165
	// BudgetedValidators is the validator count FixedEvidenceBytes is budgeted for; the measurement was taken at MeasuredValidators.
	BudgetedValidators = 16
	MeasuredValidators = 3
	// RestFlatBytes is the largest R measured in production (258,469): the part of R that does not grow with the closure and, with it, a
	// 3-page closure's vote evidence.
	RestFlatBytes = 260_000

	// The evidence 2.0 values. A 2.0 document still holds the minor-root runs since the last major, so its fixed part is the 760,000 the
	// old constant measured, and it is judged against the 96 KiB reserve it always had: RB9-F5 invariant 2 (nothing on the 2.0 path
	// tightens or loosens), V-I D2. CheckClosureBudget applies them to a 2.0 capture exactly as it did before F5-4.
	//
	// CertificateReserve20 is the reserve evidence 2.0 was judged with.
	CertificateReserve20 = 96 << 10
	// MaxEvidenceBytes20 is the evidence 2.0 budget (950,272).
	MaxEvidenceBytes20 = ConsensusTxLimit - CertificateReserve20
	// FixedEvidenceBytes20 is the fixed part measured on a real 2.0 evidence (731,778 bytes, rounded up).
	FixedEvidenceBytes20 = 760_000
	// VoteEvidenceBytesPerPage is the largest vote evidence per closure page measured on the live intents (7,503), rounded up.
	VoteEvidenceBytesPerPage = 7_600
)

// CertificateEstimate is the size of the whole certificate for an evidence of evidenceBytes and a closure of pages pages.
func CertificateEstimate(evidenceBytes, pages int) int {
	return evidenceBytes + RestFlatBytes + VoteEvidenceBytesPerPage*pages
}

// certificateBudget is the named state certificate_budget{size,limit}, with where it was judged and the reason.
func certificateBudget(size int, where, format string, a ...any) error {
	return fmt.Errorf("%w: judged at %s: %s", certifyState(StateCertificateBudget, strconv.Itoa(size), strconv.Itoa(ConsensusTxLimit)), where, fmt.Sprintf(format, a...))
}

// CheckCertificateFits judges the whole certificate before it is signed: an evidence of evidenceBytes for a closure of pages pages, with R at
// its measured flat size and its vote evidence at the measured size per page, must be inside ConsensusTxLimit. Over, it is
// certificate_budget{size,limit}; where says the partition and block (or the stage) it was judged at.
func CheckCertificateFits(evidenceBytes, pages int, where string) error {
	if size := CertificateEstimate(evidenceBytes, pages); size > ConsensusTxLimit {
		return certificateBudget(size, where, "the evidence is %d bytes and the rest of the transaction is estimated at %d (%d flat + %d per page x %d pages): %d bytes over the %d the consensus path accepts (tx_too_large)",
			evidenceBytes, size-evidenceBytes, RestFlatBytes, VoteEvidenceBytesPerPage, pages, size-ConsensusTxLimit, ConsensusTxLimit)
	}
	return nil
}

// UpdateWindowsBytes is what the signature entries of k update-bearing windows take at V validators: ValidatorSignatureBytes x V per record x k.
func UpdateWindowsBytes(k, validators int) int {
	return k * validators * ValidatorSignatureBytes
}

// MaxUpdateWindows is the largest number of update windows whose signatures, at V validators, fit MaxEvidenceBytes beside FixedEvidenceBytes and
// otherBytes (the pages, votes and transaction); 0 when none does or V is not positive.
func MaxUpdateWindows(validators, otherBytes int) int {
	room := MaxEvidenceBytes - FixedEvidenceBytes - otherBytes
	if validators <= 0 || room < UpdateWindowsBytes(1, validators) {
		return 0
	}
	return room / UpdateWindowsBytes(1, validators)
}

// CheckUpdateWindows refuses, by certificate_budget{size,limit}, a certify of k update windows at V validators whose signature entries alone,
// with the fixed part and otherBytes, are over MaxEvidenceBytes. size is the transaction that evidence implies (with the reserve).
func CheckUpdateWindows(k, validators, otherBytes int) error {
	sig := UpdateWindowsBytes(k, validators)
	if ev := FixedEvidenceBytes + otherBytes + sig; ev > MaxEvidenceBytes {
		return certificateBudget(ev+CertificateReserve, "the update windows", "k=%d windows x validators=%d x %d bytes = %d bytes of signature entries with the %d-byte fixed part and %d other bytes is over the %d-byte evidence budget (largest k at this V: %d; tx_too_large)",
			k, validators, ValidatorSignatureBytes, sig, FixedEvidenceBytes, otherBytes, MaxEvidenceBytes, MaxUpdateWindows(validators, otherBytes))
	}
	return nil
}

// checkAssembledBudget is the builder's pre-sign check on an assembled evidence 2.1: its links are one update window each (the k of the k x V
// bound, at the report's validator count), and its encoding with the rest of the transaction, scaled by its pages, must fit the path limit.
// partition and block are where the capture judged it.
func checkAssembledBudget(ev *Evidence, validators int, partition string, block uint64) error {
	where := fmt.Sprintf("%s block %d", partition, block)
	if err := CheckUpdateWindows(len(ev.Links), validators, 0); err != nil {
		return fmt.Errorf("%w (%s)", err, where)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode the evidence: %w", err)
	}
	return CheckCertificateFits(len(raw), len(ev.Pages), where)
}

func budgetState(pages int, size int, x xAnchor) error {
	return refusal21(StateClosureExceedsBudget, x.id, x.block, "pages=%d limit=%d: the encoded evidence is %d bytes, over the %d bytes the consensus transaction limit (%d) leaves it",
		pages, MaxEvidenceBytes, size, MaxEvidenceBytes, ConsensusTxLimit)
}

// CheckEvidenceBudget refuses an evidence whose compact JSON encoding is over MaxEvidenceBytes.
func CheckEvidenceBudget(ev *Evidence, x xAnchor) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode the evidence: %w", err)
	}
	if len(raw) > MaxEvidenceBytes {
		return budgetState(len(ev.Pages), len(raw), x)
	}
	return nil
}

// CheckClosureBudget is the capture's check, before the evidence exists, for the document form the capture becomes (version: Version for
// evidence 2.0, Version21 for evidence 2.1; any other value is an error, never a default).
//
// Evidence 2.0 is judged exactly as it was before F5-4 (RB9-F5 invariant 2, V-I D2): the captured pages and votes encoded, plus the 2.0 fixed
// part (FixedEvidenceBytes20), must fit MaxEvidenceBytes20, else g1_closure_exceeds_budget; nothing else is checked.
//
// Evidence 2.1: the same with the anchored form's FixedEvidenceBytes and MaxEvidenceBytes (else g1_closure_exceeds_budget), and the whole
// certificate they imply - the evidence plus R scaled by the closure's pages - must fit ConsensusTxLimit (else certificate_budget{size,limit}).
// partition and block are where the capture judged it.
func CheckClosureBudget(version string, pages []PageState, votes []Vote, partition string, block uint64) error {
	var fixed, limit int
	switch version {
	case Version:
		fixed, limit = FixedEvidenceBytes20, MaxEvidenceBytes20
	case Version21:
		fixed, limit = FixedEvidenceBytes, MaxEvidenceBytes
	default:
		return fmt.Errorf("closure budget: unknown evidence version %q (judged at %s block %d)", version, partition, block)
	}
	size := fixed
	for i := range pages {
		raw, err := json.Marshal(&pages[i])
		if err != nil {
			return err
		}
		size += len(raw)
	}
	raw, err := json.Marshal(votes)
	if err != nil {
		return err
	}
	size += len(raw)
	if size > limit {
		return &NamedState{Code: StateClosureExceedsBudget, Partition: partition, Block: block,
			Detail: fmt.Sprintf("pages=%d limit=%d: the pages and votes encode to %d bytes with the %d-byte fixed part, over the %d bytes the consensus transaction limit (%d) leaves the evidence",
				len(pages), limit, size, fixed, limit, ConsensusTxLimit)}
	}
	if version == Version {
		return nil
	}
	return CheckCertificateFits(size, len(pages), fmt.Sprintf("%s block %d", partition, block))
}

// CertificateTooLarge is certificate_budget{size,limit} for a transaction of size bytes that is over ConsensusTxLimit, judged at where. The
// consensus package uses it for the whole block as it will be broadcast (the members filled after the check counted at their final length), before the block is signed.
func CertificateTooLarge(size int, where string) error {
	return certificateBudget(size, where, "the transaction is %d bytes, %d over the %d the consensus path accepts (tx_too_large)", size, size-ConsensusTxLimit, ConsensusTxLimit)
}
