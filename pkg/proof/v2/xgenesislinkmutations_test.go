// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"

	jm "github.com/certen/independant-validator/internal/jsonmutate"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// RB9-F6 (V-P D5): the robustness loops excuse a mutation of the genesis link only by name, and this test pins the set exactly. The genesis link of
// the REAL Kermit document is mutated at every kind the instrument knows, in BOTH evidence-form loops (judged by the spine entry consensus runs, and
// by the offline walk): exactly one mutation leaves the document verified with the original report, hollow-receipt.End - the receipt re-encoded with its
// End position field zeroed, which merkle.Receipt.Validate does not read (it recomputes Start through Entries to Anchor) - and every other one is refused,
// removal, null, an empty or wrong-typed value and every change to Start, Entries or Anchor among them.
func TestGenesisLinkMutationsAreRefusedExceptTheReceiptEndField(t *testing.T) {
	r := loadReal21(t)
	p, err := Export(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	portable := robustSource{name: "real", raw: raw, judge: portableJudge(raw), walk: jm.WalkSpec{Keep: shallow(2), ArrayLimit: 3}}
	mustRefuse := []string{"remove", "null", "empty-string", "empty-object", "empty-array", "wrong-type-bool", "wrong-type-number", "hex-zeroed", "hex-cut-one-byte",
		"hex-flip-leading-nibble", "hollow-receipt.Start", "hollow-receipt.Anchor", "hollow-receipt.Entries", "hollow-receipt.Entries.0.Hash"}
	for form, mk := range map[string]func(*testing.T, robustSource) (robustSource, bool){"spine": evidenceSource, "offline": evidenceOfflineSource} {
		src, ok := mk(t, portable)
		if !ok {
			t.Fatalf("%s: the real document does not import", form)
		}
		base := src.judge(src.raw)
		if base.Refused {
			t.Fatalf("%s: the unmutated real document is refused: %s", form, base.Err)
		}
		tree, muts := robustMutationsOf(t, src)
		var sel []jm.Mutation
		for _, m := range muts {
			if m.Path.String() == "genesisLink" {
				sel = append(sel, m)
			}
		}
		var accepted, refused []string
		for _, o := range jm.Run(tree, sel, src.judge, 1) {
			switch {
			case o.V.Panicked != "":
				t.Fatalf("%s: %s panics: %s", form, o.M, o.V.Panicked)
			case o.V.Refused:
				refused = append(refused, o.M.Kind)
			default:
				accepted = append(accepted, o.M.Kind)
				if o.V.Report != base.Report {
					t.Errorf("%s: %s is accepted with a different report", form, o.M)
				}
			}
		}
		sort.Strings(accepted)
		if !reflect.DeepEqual(accepted, []string{"hollow-receipt.End"}) {
			t.Errorf("%s: the accepted mutations of the genesis link are %v, want exactly [hollow-receipt.End]", form, accepted)
		}
		have := map[string]bool{}
		for _, k := range refused {
			have[k] = true
		}
		for _, k := range mustRefuse {
			if !have[k] {
				t.Errorf("%s: the mutation %q of the genesis link is not among the refused (refused: %v)", form, k, refused)
			}
		}
	}
}

// By name, in both walks: the real document's genesis link removed, started elsewhere, ended elsewhere or with a step altered is refused with the
// state of what is wrong, and with its End position field changed it is accepted (the field is not read).
func TestRealGenesisLinkDefectsAreNamedByBothWalks(t *testing.T) {
	r := loadReal21(t)
	spine := spineOf(t, r)
	judge := map[string]func(*Evidence) error{
		"offline": func(ev *Evidence) error { _, err := Verify21FromGenesis(ev, r.ar, r.in, r.pin); return err },
		"spine":   func(ev *Evidence) error { _, err := VerifyEvidence21FromSpine(ev, spine, r.pin); return err },
	}
	with := func(edit func(l *merkle.Receipt)) *Evidence {
		ev := r.clone(t)
		if edit == nil {
			ev.GenesisLink = ""
			return ev
		}
		l, err := decodeReceipt(ev.GenesisLink)
		if err != nil {
			t.Fatal(err)
		}
		edit(l)
		b, err := l.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		ev.GenesisLink = hex.EncodeToString(b)
		return ev
	}
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[0] ^= 1; return c }
	for name, c := range map[string]struct {
		ev   *Evidence
		want string
	}{
		"removed":        {with(nil), StateCertifyLinkMissing},
		"start altered":  {with(func(l *merkle.Receipt) { l.Start = flip(l.Start) }), StateCertifyLinkStart},
		"anchor altered": {with(func(l *merkle.Receipt) { l.Anchor = flip(l.Anchor) }), StateCertifyLinkEnd},
		"step altered":   {with(func(l *merkle.Receipt) { l.Entries[0].Hash = flip(l.Entries[0].Hash) }), StateCertifyLinkInvalid},
	} {
		for form, verify := range judge {
			var cs *CertifyState
			if err := verify(c.ev); !errors.As(err, &cs) || cs.Code != c.want || len(cs.Fields) != 1 || cs.Fields[0] != "genesis" {
				t.Errorf("%s, %s walk: %v, want %s{genesis}", name, form, err, c.want)
			}
		}
	}
	// the End position field is not read: the very same bytes verify
	end := with(func(l *merkle.Receipt) { l.End = flip(append(l.End, 0)) })
	if end.GenesisLink == r.ev.GenesisLink {
		t.Fatal("the End edit changed nothing")
	}
	for form, verify := range judge {
		if err := verify(end); err != nil {
			t.Errorf("End changed, %s walk: %v", form, err)
		}
	}
}
