// Copyright 2026 Certen Protocol

package proofv2

import "testing"

// RB9-F5 package F5-4 (V-E A4): the 15 measured transactions against the budget constants.

// measuredTransactions are the 15 intent-certificate transactions the proposers logged in 26 h (evidence/r-rest-of-transaction-measured.md:
// "ValidatorBlock marshaled: N bytes"), each with the proof v2 document inside it where the measurement pairs one (the stored document at the
// same minutes after the 00:00Z major: 438,142 B at ~535 min, 549,004 B at ~618 min, about 21,000 B at ~4 min). R, the rest of the transaction,
// is N minus that document. The five 08:53-08:54 transactions have no per-intent document; they are paired with the 535-minute document, the
// nearest measurement (a minute apart).
var measuredTransactions = []struct {
	at       string
	n, doc   int
	measured bool // the document of this row was measured per intent
}{
	{"row1 #1 (08:53:41..08:54:21)", 576_721, 438_142, false},
	{"row1 #2", 582_082, 438_142, false},
	{"row1 #3", 584_509, 438_142, false},
	{"row1 #4", 581_490, 438_142, false},
	{"row1 #5", 578_907, 438_142, false},
	{"row2 #1 (08:54:40..08:56:07)", 675_494, 438_142, true},
	{"row2 #2", 675_524, 438_142, true},
	{"row2 #3", 675_581, 438_142, true},
	{"row2 #4", 696_611, 438_142, true},
	{"row2 #5", 676_354, 438_142, true},
	{"row3 #1 (10:18:19, refused)", 763_613, 549_004, true},
	{"row3 #2 (10:18:27, refused)", 758_281, 549_004, true},
	{"row4 #1 (12:04:01)", 195_909, 21_000, true},
	{"row4 #2 (12:04:08)", 200_799, 21_000, true},
	{"row4 #3 (12:04:14)", 272_053, 21_000, true},
}

// The evidence at the cap plus the largest R measured must be inside the path limit, for every one of the 15 measured transactions.
func TestCertificateBudgetCoversMeasuredR(t *testing.T) {
	if len(measuredTransactions) != 15 {
		t.Fatalf("%d measured transactions, want the 15 of evidence/r-rest-of-transaction-measured.md", len(measuredTransactions))
	}
	maxR := 0
	for _, m := range measuredTransactions {
		r := m.n - m.doc
		if r <= 0 {
			t.Fatalf("%s: R = %d - %d is not positive", m.at, m.n, m.doc)
		}
		if m.n > ConsensusTxLimit {
			t.Fatalf("%s: the measured transaction (%d) is itself over the limit", m.at, m.n)
		}
		maxR = max(maxR, r)
		if r > CertificateReserve {
			t.Errorf("%s: R = %d is over CertificateReserve (%d)", m.at, r, CertificateReserve)
		}
		if got := MaxEvidenceBytes + r; got > ConsensusTxLimit {
			t.Errorf("%s: evidence at the cap (%d) + R (%d) = %d is over the path limit %d by %d", m.at, MaxEvidenceBytes, r, got, ConsensusTxLimit, got-ConsensusTxLimit)
		}
	}
	t.Logf("largest measured R = %d; evidence at the cap %d + R = %d <= %d (%d to spare)", maxR, MaxEvidenceBytes, MaxEvidenceBytes+maxR, ConsensusTxLimit, ConsensusTxLimit-MaxEvidenceBytes-maxR)
	if CertificateReserve < 320<<10 {
		t.Fatalf("CertificateReserve %d is under 320 KiB (V-E A4)", CertificateReserve)
	}
	if MaxEvidenceBytes != ConsensusTxLimit-CertificateReserve {
		t.Fatalf("MaxEvidenceBytes %d is not the limit less the reserve", MaxEvidenceBytes)
	}
	// The reserve of the previous revision (96 KiB) is below R: the same arithmetic refuses it, so this test discriminates.
	if old := ConsensusTxLimit - 96<<10; old+maxR <= ConsensusTxLimit {
		t.Fatalf("the 96 KiB reserve would have covered the measured R (%d + %d): the measurement no longer shows what A4 says", old, maxR)
	}
}
