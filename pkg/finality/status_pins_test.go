// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-DBFIX (RB12_PHASE0 Addendum C item 7): a builder status document records the hash of the pins the builder judged under
// (`pinsSha256`), additively: the document format string stays certen-finality-status/1, a document without the member is byte for byte
// what it was, and the addendum record format is untouched. A consumer verifies under the pins IT trusts and can see whether the
// builder's differ.

func pinsHash(t *testing.T) string {
	t.Helper()
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := p.Identity()
	return h
}

func pendingRow(t *testing.T) BuilderStatus {
	t.Helper()
	pd := &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, Reason: "game_unresolved", ETA: time.Date(2026, 10, 25, 3, 4, 5, 0, time.UTC)}
	return BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelL1Posted, pd, nil, false, time.Unix(1_800_000_000, 0))
}

func TestStatusDocumentRecordsThePinsHashAdditivelyAndRoundTrips(t *testing.T) {
	want := pinsHash(t)
	p, _ := EmbeddedPins()
	rows := map[string]BuilderStatus{
		"pending":  pendingRow(t).WithPins(p),
		"verified": VerifiedBuilderStatus(legID, ChainBaseSepolia, LevelL1Posted, 1, time.Unix(1_800_000_000, 0)).WithPins(p),
	}
	for name, row := range rows {
		raw, err := row.Document()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if string(doc["format"]) != `"`+BuilderStatusFormat+`"` || BuilderStatusFormat != "certen-finality-status/1" {
			t.Fatalf("%s: the format string moved: %s", name, doc["format"])
		}
		if string(doc["pinsSha256"]) != `"`+want+`"` {
			t.Fatalf("%s: pinsSha256 %s, want %s in %s", name, doc["pinsSha256"], want, raw)
		}
		view, err := ParseBuilderStatusDocument(raw)
		if err != nil || view.PinsSHA256 != want || view.Class != row.Class {
			t.Fatalf("%s: %+v %v", name, view, err)
		}
	}
}

func TestStatusDocumentWithoutPinsIsByteForByteWhatItWasAndReadsAsNotRecorded(t *testing.T) {
	row := pendingRow(t)
	raw, err := row.Document()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "pinsSha256") {
		t.Fatalf("a row with no pins identity grew the member: %s", raw)
	}
	view, err := ParseBuilderStatusDocument(raw)
	if err != nil || view.PinsSHA256 != "" {
		t.Fatalf("%+v %v", view, err)
	}
	if got := row.WithPins(nil); got.PinsSHA256 != "" {
		t.Fatalf("no pins, no identity: %q", got.PinsSHA256)
	}
}

func TestStatusDocumentRefusesAMalformedPinsHashBothWays(t *testing.T) {
	for name, bad := range map[string]string{
		"short":     strings.Repeat("a", 63),
		"long":      strings.Repeat("a", 65),
		"uppercase": strings.Repeat("A", 64),
		"not hex":   strings.Repeat("g", 64),
		"prefixed":  "0x" + strings.Repeat("a", 62),
	} {
		row := pendingRow(t)
		row.PinsSHA256 = bad
		if _, err := row.Document(); err == nil {
			t.Errorf("%s: Document accepted pins %q", name, bad)
		}
		raw, _ := pendingRow(t).Document()
		// the member goes last in a real document: append it inside the outermost object
		forged := string(raw)[:len(raw)-1] + `,"pinsSha256":"` + bad + `"}`
		if _, err := ParseBuilderStatusDocument([]byte(forged)); err == nil {
			t.Errorf("%s: the reader accepted pins %q", name, bad)
		}
	}
}

// The upgrader writes every status row of a leg under the pins it judges with, whatever the class of the row.
func TestUpgraderStampsTheRowsItWritesWithItsPinsHash(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	status := newMemStatus()
	cfg := UpgraderConfig{Status: status, Logf: f.logs.Logf, Now: f.clock.Now, Recorder: f.rec, Jitter: func(d time.Duration) time.Duration { return d }}
	u, err := NewUpgrader(f.src, f.store, f.reg, p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep := u.RunOnce(context.Background()); rep.Appended != 2 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	want := pinsHash(t)
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		row := status.row(legID, l)
		if row.Class != BuilderVerified || row.PinsSHA256 != want {
			t.Fatalf("%s: class %s pins %q, want verified under %s", l, row.Class, row.PinsSHA256, want)
		}
	}
	// a pending row too
	pf := newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, _ *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "awaiting_batch_post"}, nil
	}}, UpgraderConfig{}, nil)
	pstatus := newMemStatus()
	pcfg := UpgraderConfig{Status: pstatus, Logf: pf.logs.Logf, Now: pf.clock.Now, Recorder: pf.rec, Jitter: func(d time.Duration) time.Duration { return d }}
	pu, err := NewUpgrader(pf.src, pf.store, pf.reg, p, pcfg)
	if err != nil {
		t.Fatal(err)
	}
	pu.RunOnce(context.Background())
	row := pstatus.row(legID, LevelL1Posted)
	if row.Class != BuilderPending || row.PinsSHA256 != want {
		t.Fatalf("pending row: class %s pins %q", row.Class, row.PinsSHA256)
	}
}
