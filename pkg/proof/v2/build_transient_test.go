// Copyright 2026 Certen Protocol

package proofv2

import (
	"errors"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-C1b-2-B1: the Directory serves a minor-root record before its validator signatures arrive. The builder (never the verifier) must
// treat a record with NO signature as not yet certified - ErrNotYetCertified, which every caller retries under its existing bound - and
// every other certify failure as the hard failure it was.

// certifyReplay walks the real stored evidence's spine to the start of its last minor-root run and returns that spine and the run, so a
// test can present the final record in any condition and see the exact error the builder's AdvanceEpoch gives.
func certifyReplay(t *testing.T) (*Spine, *api.MinorRootRecord) {
	t.Helper()
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	g, err := genesisValues(ir.Inputs.NetworkRecord, ir.Inputs.GlobalsRecord)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := NewSpine(g, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < fx.ev.Majors; i++ {
		if err := sp.Advance(fx.ar.Majors[i]); err != nil {
			t.Fatal(err)
		}
	}
	for i, h := range fx.ev.Certify {
		mr, err := decodeMinorRoot(h)
		if err != nil {
			t.Fatal(err)
		}
		if i == len(fx.ev.Certify)-1 {
			return sp, mr
		}
		if err := sp.AdvanceEpoch(mr); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("the stored evidence has no certify run")
	return nil, nil
}

func TestCertifyZeroSignaturesIsNotYetCertified(t *testing.T) {
	sp, mr := certifyReplay(t)
	if err := sp.Clone().AdvanceEpoch(mr); err != nil {
		t.Fatalf("the genuine record does not advance the walk: %v", err)
	}
	mr.Signatures = nil // served before its validator signatures arrived
	raw := sp.Clone().AdvanceEpoch(mr)
	if raw == nil || !strings.Contains(raw.Error(), "quorum not met: 0 of ") {
		t.Fatalf("a signature-less record gave %v", raw)
	}
	err := certifyError("certify", raw)
	if !errors.Is(err, ErrNotYetCertified) {
		t.Fatalf("a record with no signature is not ErrNotYetCertified: %v", err)
	}
	if !strings.Contains(err.Error(), "quorum not met: 0 of ") || !strings.HasPrefix(err.Error(), "certify: ") {
		t.Fatalf("the original text was not kept: %v", err)
	}
	// The same mapping serves the set-check walk.
	if err := certifyError("set check", raw); !errors.Is(err, ErrNotYetCertified) || !strings.HasPrefix(err.Error(), "set check: ") {
		t.Fatalf("set check: %v", err)
	}
}

func TestCertifySomeSignaturesStaysAHardFailure(t *testing.T) {
	sp, mr := certifyReplay(t)
	if len(mr.Signatures) < 2 {
		t.Fatalf("the stored record has %d signatures", len(mr.Signatures))
	}
	mr.Signatures = mr.Signatures[:1] // one valid signature, short of the threshold
	raw := sp.Clone().AdvanceEpoch(mr)
	if raw == nil || !strings.Contains(raw.Error(), "quorum not met: 1 of ") {
		t.Fatalf("a record short of the threshold gave %v", raw)
	}
	err := certifyError("certify", raw)
	if errors.Is(err, ErrNotYetCertified) {
		t.Fatalf("a quorum failure with a signature present was made retryable: %v", err)
	}
	if !strings.Contains(err.Error(), "quorum not met: 1 of ") {
		t.Fatalf("text lost: %v", err)
	}
}

func TestCertifyInvalidSignatureAndOtherFailuresStayHard(t *testing.T) {
	sp, mr := certifyReplay(t)
	ed := mr.Signatures[0].(*protocol.ED25519Signature)
	ed.Signature[0] ^= 1
	raw := sp.Clone().AdvanceEpoch(mr)
	if raw == nil || !strings.Contains(raw.Error(), "invalid signature") {
		t.Fatalf("a forged signature gave %v", raw)
	}
	if err := certifyError("certify", raw); errors.Is(err, ErrNotYetCertified) {
		t.Fatalf("an invalid signature was made retryable: %v", err)
	}
	for _, other := range []error{errors.New("root proof does not start at the verified root"), errors.New("incomplete minor root record"),
		errors.New("quorum not met: 10 of 12 validator signatures")} { // 10 is not 0
		if err := certifyError("certify", other); errors.Is(err, ErrNotYetCertified) {
			t.Fatalf("%v was made retryable", other)
		}
	}
}

// The verifiers are untouched: a stored document whose last certify run lost its signatures is still refused by the verdict functions,
// with the same text, and is NOT ErrNotYetCertified (that error exists only on the builder's side).
func TestVerifyStillRefusesASignaturelessRunAndDoesNotMapIt(t *testing.T) {
	fx := load(t)
	mutateMinorRoot(t, &fx.ev.Certify[len(fx.ev.Certify)-1], func(r *api.MinorRootRecord) { r.Signatures = nil })
	_, err := Verify(fx.ev, fx.ar, fx.inc, fx.pin)
	if err == nil || !strings.Contains(err.Error(), "quorum not met") {
		t.Fatalf("a signature-less certify run was not refused: %v", err)
	}
	if errors.Is(err, ErrNotYetCertified) {
		t.Fatalf("the verifier maps a quorum failure to ErrNotYetCertified: %v", err)
	}
}
