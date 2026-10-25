// Copyright 2026 Certen Protocol
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/finality"
)

// EPS-MUTKILL-6: literal-expectation tests for the printed S7 report and the offline outcome verdict lines.

func goodS7Report() finality.Report {
	rep := finality.Report{
		Block:      finality.BlockRef{Chain: 11155111, Number: 5, Hash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		Levels:     map[finality.Level]finality.LevelStatus{},
		Headline:   finality.LevelFinalized,
		PinsSHA256: "pinsha",
		PinsSource: "psrc",
	}
	for _, l := range finality.Levels {
		rep.Levels[l] = finality.LevelStatus{Status: finality.StatusVerified}
	}
	return rep
}

func TestPrintReportNamesTheBlockByItsFirstSixBytesAndEachRefusalByItsOwnLine(t *testing.T) {
	var out bytes.Buffer
	rep := goodS7Report()
	if code := printReport(&out, rep, "subj", "  a note", "  another note"); code != exitVerified {
		t.Errorf("a verified leg exits %d: %q", code, out.String())
	}
	full := "  S7  chain 11155111  block 5  010203040506…  pins pinsha (psrc)\n  a note\n  another note\n" +
		"  S7    included   verified\n  S7    l1_posted  verified\n  S7    finalized  verified\n" +
		"  S7  level reached: finalized\nVERIFIED (finality)  subj  level finalized\n"
	if out.String() != full {
		t.Errorf("a verified leg: %q, want %q", out.String(), full)
	}

	out.Reset()
	rep = finality.Report{Unsupported: &finality.StateError{Code: "unsupp"}}
	want := fmt.Sprintf("SUMMARY-ONLY (finality)  subj\n  %v\n", rep.Unsupported)
	if code := printReport(&out, rep, "subj"); code != exitSummaryOnly || out.String() != want {
		t.Errorf("an unsupported chain: exit %d %q, want %q", code, out.String(), want)
	}

	out.Reset()
	rep = goodS7Report()
	rep.Levels[finality.LevelIncluded] = finality.LevelStatus{Status: finality.StatusRefused, State: &finality.StateError{Code: "incl"}}
	want = fmt.Sprintf("FAILED (finality)  subj\n  the leg's Settlement does not verify as the included level: %v\n", rep.Levels[finality.LevelIncluded].State)
	if code := printReport(&out, rep, "subj"); code != exitFailed || out.String() != want {
		t.Errorf("a refused included level: exit %d %q, want %q", code, out.String(), want)
	}

	for _, c := range []struct {
		name string
		mut  func(r *finality.Report)
		line string
	}{
		{"finalized block not exposable", func(r *finality.Report) { r.FinalizedBlockState = &finality.StateError{Code: "fbs"} },
			"FAILED (finality)  subj\n  the finalized level is verified but the leg block cannot be exposed for S8: "},
		{"addendum chain broken", func(r *finality.Report) { r.Broken = &finality.StateError{Code: "brk"} },
			"FAILED (finality)  subj\n  the addendum chain does not verify: "},
	} {
		out.Reset()
		rep = goodS7Report()
		c.mut(&rep)
		if code := printReport(&out, rep, "subj"); code != exitFailed || !strings.Contains(out.String(), c.line) {
			t.Errorf("%s: exit %d %q", c.name, code, out.String())
		}
	}
}

func TestOutcomeFileReportsEachUnreadableFileByItsOwnText(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	var out bytes.Buffer
	if code := reportOutcomeFile(context.Background(), &out, missing, ""); code != exitFailed ||
		!strings.HasPrefix(out.String(), "FAILED (outcome)  "+missing+"\n  open ") || strings.Contains(out.String(), "does not decode") {
		t.Errorf("a missing file: exit %d %q", code, out.String())
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := reportOutcomeFile(context.Background(), &out, bad, ""); code != exitFailed ||
		!strings.HasPrefix(out.String(), "FAILED (outcome)  "+bad+"\n  the evidence does not decode: ") {
		t.Errorf("a file that is not JSON: exit %d %q", code, out.String())
	}
}

func TestOutcomeVerdictLinePrintsTheAnchorByItsFirst18CharactersAndTheOnlineFailureByName(t *testing.T) {
	ev := &execution.OutcomeEvidence{Version: "v1", ChainID: 7}
	ev.Anchor.BundleID = "0x0123456789abcdef0123456789abcdef"
	chk := &execution.OutcomeEvidenceCheck{Established: []string{"est"}, NotEstablished: []string{"not est"}}
	chk.Leaf.LeafIndex = 3
	chk.Leaf.Status = execution.OutcomeExecuted

	var out bytes.Buffer
	code := reportOutcomeResult(context.Background(), &out, "subj", ev, chk, nil, "")
	want := "  OUTCOME verified OFFLINE (v1): chain 7 anchor 0x0123456789abcdef…, member 3 status " + fmt.Sprint(chk.Leaf.Status) +
		" (executed, every committed effect proven)\n      ✓ est\n      NOT established offline: not est\n"
	if code != exitVerified || out.String() != want {
		t.Errorf("an offline verdict: exit %d %q, want %q", code, out.String(), want)
	}

	// an online check that cannot reach its endpoint is a named failure after the offline lines, never a quiet success
	out.Reset()
	code = reportOutcomeResult(context.Background(), &out, "subj", ev, chk, nil, "http://127.0.0.1:1")
	if code != exitFailed || !strings.HasPrefix(out.String(), want+"FAILED (outcome online)  subj\n  ") {
		t.Errorf("an unreachable online endpoint: exit %d %q", code, out.String())
	}

	// printOutcomeCheck of no check prints nothing and does not panic
	out.Reset()
	printOutcomeCheck(&out, nil)
	if out.Len() != 0 {
		t.Errorf("no check printed %q", out.String())
	}
}

func TestPinsSelfcheckReportsTheLedgerItRederivedFromTheRootPin(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	e, serr := pins.Sepolia()
	if serr != nil || len(e.Anchors) < 2 {
		t.Fatalf("the embedded Sepolia ledger has %d anchors", len(e.Anchors))
	}
	hash, src := pins.Identity()
	want := fmt.Sprintf("PINS SELFCHECK ok  %d Sepolia ledger anchors re-derived from the root pin (period %d .. %d)  pins %s (%s)\n",
		len(e.Anchors), e.Anchors[0].Period, e.Anchors[len(e.Anchors)-1].Period, hash, src)
	var out, errw bytes.Buffer
	if code := reportPinsSelfcheck(&out, &errw, pins); code != exitVerified || out.String() != want || errw.Len() != 0 {
		t.Errorf("exit %d\n  stdout %q\n  want   %q\n  stderr %q", code, out.String(), want, errw.String())
	}
}
