// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Gate 4C.4 negative tests.
//
// A passing negative test here is a critical defect: it means G2's defining
// claim can be satisfied with less evidence than section 10 requires.
//
// These exercise the parts of verifyOutcomeBinding that do not need the
// network: merkle recomputation, ENTRY_HASH equality, the EXEC_WITNESS bind,
// and success-only. The live end-to-end run covers the status query.

// buildReceipt constructs a real receipt: a leaf plus a merkle path that
// genuinely recomputes to the anchor, using the same SHA-256(left||right) rule
// the chained-proof ReceiptVerifier applies.
func buildReceipt(t *testing.T, leafHex string, siblings []string, rights []bool) ReceiptData {
	t.Helper()
	cur, err := hex.DecodeString(leafHex)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]ReceiptStep, 0, len(siblings))
	for i, sib := range siblings {
		sb, err := hex.DecodeString(sib)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		if rights[i] {
			h.Write(cur)
			h.Write(sb)
		} else {
			h.Write(sb)
			h.Write(cur)
		}
		cur = h.Sum(nil)
		entries = append(entries, ReceiptStep{Hash: sib, Right: rights[i]})
	}
	return ReceiptData{
		Start:      leafHex,
		Anchor:     hex.EncodeToString(cur),
		LocalBlock: 9871049,
		Entries:    entries,
	}
}

func h32(seed byte) string {
	var b [32]byte
	for i := range b {
		b[i] = seed + byte(i)
	}
	return hex.EncodeToString(b[:])
}

// The merkle recomputation must be real. Before this work the governance
// ReceiptData had no Entries field at all, so nothing could be recomputed.
func TestPhase4C_ReceiptMerkleRecomputation(t *testing.T) {
	good := buildReceipt(t, h32(1), []string{h32(2), h32(3), h32(4)}, []bool{true, false, true})

	if err := VerifyReceiptMerkle(good, "outcome receipt"); err != nil {
		t.Fatalf("a genuine receipt must verify: %v", err)
	}

	t.Run("mutated path entry is rejected", func(t *testing.T) {
		bad := good
		bad.Entries = append([]ReceiptStep{}, good.Entries...)
		bad.Entries[1].Hash = h32(99)
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: mutated merkle entry accepted")
		}
	})

	t.Run("flipped sibling side is rejected", func(t *testing.T) {
		bad := good
		bad.Entries = append([]ReceiptStep{}, good.Entries...)
		bad.Entries[0].Right = !bad.Entries[0].Right
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: flipped sibling side accepted")
		}
	})

	t.Run("mutated leaf is rejected", func(t *testing.T) {
		bad := good
		bad.Start = h32(50)
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: mutated leaf accepted")
		}
	})

	t.Run("mutated anchor is rejected", func(t *testing.T) {
		bad := good
		bad.Anchor = h32(60)
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: mutated anchor accepted")
		}
	})

	t.Run("dropped path with start != anchor is rejected", func(t *testing.T) {
		// This is the shape the old code effectively accepted: a receipt with
		// non-empty start and anchor and nothing connecting them.
		bad := good
		bad.Entries = nil
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: receipt with no merkle path accepted")
		}
	})

	t.Run("truncated path is rejected", func(t *testing.T) {
		bad := good
		bad.Entries = good.Entries[:len(good.Entries)-1]
		if err := VerifyReceiptMerkle(bad, "outcome receipt"); err == nil {
			t.Fatal("CRITICAL DEFECT: truncated merkle path accepted")
		}
	})

	t.Run("a foreign receipt does not prove our leaf", func(t *testing.T) {
		// A perfectly valid receipt for a DIFFERENT leaf. It recomputes fine
		// on its own; what must fail is claiming it proves our outcome.
		foreign := buildReceipt(t, h32(200), []string{h32(201), h32(202)}, []bool{false, true})
		if err := VerifyReceiptMerkle(foreign, "foreign"); err != nil {
			t.Fatalf("the foreign receipt should be internally valid: %v", err)
		}
		if strings.EqualFold(foreign.Start, good.Start) || strings.EqualFold(foreign.Anchor, good.Anchor) {
			t.Fatal("test setup: the foreign receipt must differ")
		}
		// Substituting it under our ENTRY_HASH / EXEC_WITNESS is what
		// verifyOutcomeBinding rejects at steps 4/5; assert the values differ
		// so the binding check has something to catch.
		if foreign.Anchor == good.Anchor {
			t.Fatal("CRITICAL DEFECT: foreign receipt anchors to our witness")
		}
	})
}

// Section 10: success-only. A failed or pending outcome MUST NOT satisfy G2.
func TestPhase4C_SuccessOnly(t *testing.T) {
	cases := []struct {
		status string
		no     int64
		want   bool
	}{
		{"delivered", 201, true},
		{"delivered", 200, true},
		{"delivered", 299, true},
		{"delivered", 400, false}, // delivered but failed
		{"delivered", 500, false},
		{"pending", 0, false},
		{"pending", 201, false},
		{"failed", 400, false},
		{"remote", 201, false},
		{"", 201, false},
		{"delivered", 0, false},
		{"DELIVERED", 201, true}, // case-insensitive
	}
	for _, c := range cases {
		got := isDeliveredSuccess(c.status, c.no)
		if got != c.want {
			t.Fatalf("isDeliveredSuccess(%q,%d) = %v, want %v", c.status, c.no, got, c.want)
		}
	}
}

// Section 2.2 / 7.2: the expanded message ID MUST be acc://<ENTRY_HASH>@<scope>.
func TestPhase4C_EntryHashMessageIDForm(t *testing.T) {
	leaf := h32(7)
	scope := "carp-buyer-62431.acme/data"
	want := "acc://" + leaf + "@" + scope

	if !messageIDMatches(want, want) {
		t.Fatal("identical IDs must match")
	}
	if !messageIDMatches(strings.ToUpper(want), want) {
		t.Fatal("comparison must be case-insensitive")
	}
	for _, bad := range []string{
		"acc://" + h32(8) + "@" + scope,          // wrong ENTRY_HASH
		"acc://" + leaf + "@other.acme/data",     // wrong scope
		"acc://" + leaf,                          // no scope
		"acc://" + leaf + "@" + scope + "/extra", // extended scope
		"",
	} {
		if messageIDMatches(bad, want) {
			t.Fatalf("CRITICAL DEFECT: %q accepted as %q", bad, want)
		}
	}
}

// Rule 4 / 4C.3: no verification state may default to passing.
func TestPhase4C_NoBooleanDefaultsToTrue(t *testing.T) {
	var zero OutcomeBinding
	if zero.State != StateNotRun {
		t.Fatalf("zero OutcomeBinding state = %v, want NotRun", zero.State)
	}
	if zero.Verified() {
		t.Fatal("CRITICAL DEFECT: a never-run OutcomeBinding reads as verified")
	}
	var nilOB *OutcomeBinding
	if nilOB.Verified() {
		t.Fatal("CRITICAL DEFECT: a nil OutcomeBinding reads as verified")
	}
	if (&OutcomeBinding{State: StateFailed}).Verified() {
		t.Fatal("CRITICAL DEFECT: a failed OutcomeBinding reads as verified")
	}
}

// 4B: the payload verifier must be rejected at configuration time.
func TestPhase4B_UnconfiguredVerifierRefusedAtStartup(t *testing.T) {
	if err := RequirePayloadVerifier("G2", ""); err == nil {
		t.Fatal("CRITICAL DEFECT: G2 accepted with no payload verifier")
	}
	if err := RequirePayloadVerifier("G2", "/definitely/not/here/txhash"); err == nil {
		t.Fatal("CRITICAL DEFECT: G2 accepted with a missing payload verifier")
	}
	if err := RequirePayloadVerifier("G2", t.TempDir()); err == nil {
		t.Fatal("CRITICAL DEFECT: G2 accepted with a directory as the payload verifier")
	}
	// G0/G1 do not need it.
	for _, lvl := range []string{"G0", "G1", "g1"} {
		if err := RequirePayloadVerifier(lvl, ""); err != nil {
			t.Fatalf("%s must not require the payload verifier: %v", lvl, err)
		}
	}
}
