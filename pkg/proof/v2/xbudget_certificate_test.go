// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// RB9-F5 package F5-4 (V-E A4): the whole certificate against the transaction path limit, before it is signed.

func certificateFields(t *testing.T, err error) (code string, size, limit int) {
	t.Helper()
	var cs *CertifyState
	if !errors.As(err, &cs) || len(cs.Fields) != 2 {
		t.Fatalf("not a certificate_budget{size,limit}: %v", err)
	}
	var e1, e2 error
	size, e1 = strconv.Atoi(cs.Fields[0])
	limit, e2 = strconv.Atoi(cs.Fields[1])
	if e1 != nil || e2 != nil {
		t.Fatalf("fields %v are not decimal", cs.Fields)
	}
	return cs.Code, size, limit
}

// The whole certificate is judged before it is signed: the evidence, the rest of the transaction at its measured flat size and the vote
// evidence at its measured size per page, against the transaction limit. One byte over is the named state with its size and limit.
func TestBudgetCertificateIsRefusedByNameBeforeSigning(t *testing.T) {
	pages := 3
	rest := RestFlatBytes + VoteEvidenceBytesPerPage*pages
	atLimit := ConsensusTxLimit - rest
	if err := CheckCertificateFits(atLimit, pages, "test"); err != nil {
		t.Fatalf("a certificate exactly at the limit: %v", err)
	}
	err := CheckCertificateFits(atLimit+1, pages, "partition BVN1 block 50")
	code, size, limit := certificateFields(t, err)
	if code != StateCertificateBudget || size != ConsensusTxLimit+1 || limit != ConsensusTxLimit {
		t.Fatalf("one byte over: %s size=%d limit=%d (%v)", code, size, limit, err)
	}
	if !strings.Contains(err.Error(), "partition BVN1 block 50") || !strings.Contains(err.Error(), "tx_too_large") {
		t.Fatalf("the refusal does not say where it was judged and that it is the tx_too_large decision: %v", err)
	}
	// The same evidence with a bigger closure is over: the vote evidence grows with the pages.
	if CheckCertificateFits(atLimit, pages+1, "test") == nil {
		t.Fatal("one more page of vote evidence must tip the same evidence over the limit")
	}
}

// CheckClosureBudget refuses, by certificate_budget, a closure whose evidence is inside MaxEvidenceBytes but whose certificate (the evidence plus
// the rest of the transaction, which grows with the closure) is not inside the path limit; a closure over the evidence budget keeps its name.
func TestBudgetClosureChecksTheWholeCertificate(t *testing.T) {
	page := PageState{URL: "acc://a.acme/book/1", State: hex.EncodeToString(make([]byte, 2000))}
	many := make([]PageState, 90)
	for i := range many {
		many[i] = page
	}
	err := CheckClosureBudget(many, nil, "BVN1", 50)
	code, size, limit := certificateFields(t, err)
	if code != StateCertificateBudget || size <= limit || limit != ConsensusTxLimit {
		t.Fatalf("90 pages: %s size=%d limit=%d (%v)", code, size, limit, err)
	}
	var ns *NamedState
	if errors.As(err, &ns) {
		t.Fatalf("the evidence of 90 small pages is inside its budget; the refusal must be the certificate's, not %v", ns)
	}
	if !strings.Contains(err.Error(), "BVN1") || !strings.Contains(err.Error(), "50") {
		t.Fatalf("the refusal does not carry the partition and block it was judged at: %v", err)
	}
	if err := CheckClosureBudget(many[:10], nil, "BVN1", 50); err != nil {
		t.Fatalf("10 such pages: %v", err)
	}
}

// k x V: each update-bearing window of the certify carries V validator signature entries of 165 bytes, so the signatures alone grow as
// 165 x V x k. The bound and the refusal above it, by the name certificate_budget.
func TestBudgetUpdateWindowsBound(t *testing.T) {
	if ValidatorSignatureBytes != 165 {
		t.Fatalf("a validator signature entry is %d bytes in the budget, want the measured 165", ValidatorSignatureBytes)
	}
	if got := UpdateWindowsBytes(4, 7); got != 4*7*165 {
		t.Fatalf("4 windows x 7 validators = %d, want %d", got, 4*7*165)
	}
	for _, v := range []int{3, 7, BudgetedValidators, 64} {
		kmax := MaxUpdateWindows(v, 0)
		if kmax < 1 {
			t.Fatalf("V=%d: no update window fits", v)
		}
		if err := CheckUpdateWindows(kmax, v, 0); err != nil {
			t.Fatalf("V=%d k=%d (the largest): %v", v, kmax, err)
		}
		err := CheckUpdateWindows(kmax+1, v, 0)
		code, size, limit := certificateFields(t, err)
		if code != StateCertificateBudget || limit != ConsensusTxLimit || size <= limit {
			t.Fatalf("V=%d k=%d: %s size=%d limit=%d (%v)", v, kmax+1, code, size, limit, err)
		}
		if !strings.Contains(err.Error(), "k="+strconv.Itoa(kmax+1)) || !strings.Contains(err.Error(), "validators="+strconv.Itoa(v)) {
			t.Fatalf("the refusal does not name k and V: %v", err)
		}
	}
	// A larger V leaves fewer windows; the other bytes of the evidence take from the same room.
	if MaxUpdateWindows(64, 0) >= MaxUpdateWindows(7, 0) || MaxUpdateWindows(7, 200_000) >= MaxUpdateWindows(7, 0) {
		t.Fatal("the number of windows must fall as V or the other bytes grow")
	}
}

// The builder's pre-sign check on an assembled evidence: its encoding, its pages, its links (one window each) and the validator count.
func TestBudgetBuilderChecksTheAssembledEvidence(t *testing.T) {
	ev := &Evidence{Version: Version21, Account: "acc://a.acme/data", Pages: []PageState{{URL: "acc://a.acme/data"}}}
	if err := checkAssembledBudget(ev, 7, "BVN1", 50); err != nil {
		t.Fatalf("a small evidence: %v", err)
	}
	ev.Transaction = strings.Repeat("0", ConsensusTxLimit-RestFlatBytes-VoteEvidenceBytesPerPage+1)
	err := checkAssembledBudget(ev, 7, "BVN1", 50)
	if code, _, limit := certificateFields(t, err); code != StateCertificateBudget || limit != ConsensusTxLimit {
		t.Fatalf("an oversize evidence: %v", err)
	}
	// Links stand for update windows: enough of them at a large V are refused by the k x V bound, whatever the rest of the evidence weighs.
	ev.Transaction = ""
	ev.Links = make([]string, MaxUpdateWindows(64, 0)+1)
	if err := checkAssembledBudget(ev, 64, "BVN1", 50); err == nil || !strings.Contains(err.Error(), "k="+strconv.Itoa(len(ev.Links))) {
		t.Fatalf("%d links at V=64: %v", len(ev.Links), err)
	}
}
