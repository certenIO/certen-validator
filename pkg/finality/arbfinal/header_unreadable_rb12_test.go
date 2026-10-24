// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	sw "github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
)

// RB12-ARBFINAL-FIX (BETA finding B-ARB-3, class 8: no error path reuses a name that means something else). finality_block_not_covered
// is the state of a block that is not on the covered spine: above the finalized head (a builder holds such a leg as pending) or below
// the spine. K, the L1 block that holds the confirmation, can be ON the spine and below the head while the framework header reader cannot
// read its header (the light-client reader that walked the spine reads four items, the framework reader seven): that is
// finality_block_header_unreadable{block_number, finalized_exec_number, reason[, index]}, a failure of the evidence that backs off.

const (
	headF   = uint64(12_000_000)
	notCov  = "finality_block_not_covered"
	unread  = "finality_block_header_unreadable"
	finMark = `{"code":"finalized",`
)

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func unreadableText(k uint64, index, reason string) string {
	return `{"code":"` + unread + `","fields":{"block_number":"` + u64(k) + `","finalized_exec_number":"` + u64(headF) + `","index":"` + index + `","reason":"` + reason + `"}}`
}

func notCoveredText(k, top uint64) string {
	return `{"code":"` + notCov + `","fields":{"block_number":"` + u64(k) + `","finalized_exec_number":"` + u64(top) + `"}}`
}

// An odd header at K, for K at the head, one below the head (S = K and S above K), and deeper, in each way the framework reader refuses a
// header the light-client reader accepts (item 4 and 5 not 32 bytes, item 16 a list): the block is named, never "not covered".
func TestAnOddHeaderAtKIsUnreadableAndNeverNotCovered(t *testing.T) {
	cases := []struct {
		name         string
		sBack, kBack uint64
		odd          map[uint64]sw.OddHeader
		want         string
	}{
		{"K is the finalized head (S = K = F)", 0, 0, map[uint64]sw.OddHeader{headF: sw.OddTxRoot31}, unreadableText(headF, "4", "header_item_not_32_bytes")},
		{"K = F-1 with S = K", 1, 0, map[uint64]sw.OddHeader{headF - 1: sw.OddTxRoot31}, unreadableText(headF-1, "4", "header_item_not_32_bytes")},
		{"K = F-1 with S the head", 0, 1, map[uint64]sw.OddHeader{headF - 1: sw.OddReceiptsRoot33}, unreadableText(headF-1, "5", "header_item_not_32_bytes")},
		{"K = F-2 with S = F-1", 1, 1, map[uint64]sw.OddHeader{headF - 2: sw.OddWithdrawalsList}, unreadableText(headF-2, "16", "header_item_is_list")},
		{"K = F-5 (the default world), item 4", 2, 3, map[uint64]sw.OddHeader{headF - 5: sw.OddTxRoot31}, unreadableText(headF-5, "4", "header_item_not_32_bytes")},
		{"K = F-5, item 5", 2, 3, map[uint64]sw.OddHeader{headF - 5: sw.OddReceiptsRoot33}, unreadableText(headF-5, "5", "header_item_not_32_bytes")},
		{"K = F-5, item 16", 2, 3, map[uint64]sw.OddHeader{headF - 5: sw.OddWithdrawalsList}, unreadableText(headF-5, "16", "header_item_is_list")},
		{"K odd as well as the head and S: K is the one named", 2, 3, map[uint64]sw.OddHeader{headF: sw.OddTxRoot31, headF - 2: sw.OddReceiptsRoot33, headF - 5: sw.OddWithdrawalsList}, unreadableText(headF-5, "16", "header_item_is_list")},
	}
	for _, c := range cases {
		p := sw.NewParts("rb12-odd-k")
		p.SBack, p.KBack, p.OddL1 = c.sBack, c.kBack, c.odd
		w := sw.Assemble(p)
		got := outcome(w.Judge())
		if got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, c.want)
		}
		if strings.Contains(got, notCov) {
			t.Errorf("%s: a header that cannot be read is answered with %s", c.name, notCov)
		}
	}
}

// Odd headers anywhere but K are not judged (the framework reader reads K's header only): the leg is finalized.
func TestOddHeadersAnywhereButKDoNotStopTheProof(t *testing.T) {
	p := sw.NewParts("rb12-odd-not-k")
	// K = F-5 is regular; the head, S = F-2 and the blocks between and below are odd
	p.OddL1 = map[uint64]sw.OddHeader{headF: sw.OddTxRoot31, headF - 1: sw.OddReceiptsRoot33, headF - 2: sw.OddWithdrawalsList, headF - 3: sw.OddTxRoot31, headF - 4: sw.OddWithdrawalsList, headF - 6: sw.OddReceiptsRoot33}
	w := sw.Assemble(p)
	got := outcome(w.Judge())
	if !strings.HasPrefix(got, finMark) {
		t.Fatalf("a regular K with odd headers around it: %s", got)
	}
}

// The old meaning is kept for the block that is not on the covered spine: K one above the finalized head, and K below the spine.
func TestKAboveTheHeadOrBelowTheSpineIsStillNotCovered(t *testing.T) {
	w := sw.Assemble(sw.NewParts("rb12-k-above"))
	w.Evidence.ConfBlock = headF + 1
	if err := w.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got, want := outcome(w.Judge()), notCoveredText(headF+1, headF); got != want {
		t.Errorf("K = F+1:\n got  %s\n want %s", got, want)
	}
	b := sw.Assemble(sw.NewParts("rb12-k-below"))
	low := headF - 2 - 3 - 1 // the default spine reaches down to min(K, S) - SpineExtra = F-6
	b.Evidence.ConfBlock = low - 1
	if err := b.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got, want := outcome(b.Judge()), notCoveredText(low-1, headF); got != want {
		t.Errorf("K below the spine:\n got  %s\n want %s", got, want)
	}
}

// The new code is registered with its fields and the framework reader's closed reasons, and a leg whose K header cannot be read is a
// failure that backs off (RB12-GO-INT F17), never pending and never a state of the environment.
func TestTheUnreadableHeaderStateIsRegisteredAndBacksOff(t *testing.T) {
	reg := loadRegistry(t)
	r, ok := reg[unread]
	if !ok {
		t.Fatalf("%s is not in states.json", unread)
	}
	if strings.Join(r.Required, ",") != "block_number,finalized_exec_number,reason" {
		t.Errorf("required fields %v", r.Required)
	}
	if !has(r.Optional, "index") {
		t.Errorf("optional fields %v lack index", r.Optional)
	}
	want := []string{
		string(finality.ReasonHeaderBadItem), string(finality.ReasonHeaderItemIsList), string(finality.ReasonHeaderItemNot32Bytes),
		string(finality.ReasonHeaderItemNotCanonUint), string(finality.ReasonHeaderNotRLPList), string(finality.ReasonHeaderTooFewItems),
		string(finality.ReasonHeaderTrailingBytes),
	}
	got := r.Enums["reason"]
	if len(got) != len(want) {
		t.Fatalf("reasons %v, want the framework header reader's %v", got, want)
	}
	for _, w := range want {
		if !has(got, w) {
			t.Errorf("reason %q of the framework header reader is not in the closed set %v", w, got)
		}
	}
	if arbfinal.CodeBlockHeaderUnreadable != unread {
		t.Errorf("constant %q", arbfinal.CodeBlockHeaderUnreadable)
	}
	if c, known := finality.ClassOfState(unread); !known || c != finality.ClassFailure {
		t.Errorf("class (%q, known %v), want failure", c, known)
	}
	p := sw.NewParts("rb12-odd-k-status")
	p.OddL1 = map[uint64]sw.OddHeader{headF - 5: sw.OddTxRoot31}
	_, err := sw.Assemble(p).Judge()
	st, named := finality.AsNamed(err)
	if !named || st.Code != unread {
		t.Fatalf("verdict %v", err)
	}
	if c := finality.ClassOfStateError(st); c != finality.ClassFailure {
		t.Errorf("class of the returned state: %q", c)
	}
	row := finality.BuilderStatusOf("p", finality.ChainArbitrumSepolia, finality.LevelFinalized, finality.LevelNone, nil, err, false, time.Unix(0, 0))
	if row.Class != finality.BuilderUnavailable || row.State == nil || row.State.Code != unread {
		t.Errorf("the builder row for the refusal: class %q state %+v", row.Class, row.State)
	}
}
