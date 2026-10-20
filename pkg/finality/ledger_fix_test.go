// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// RB11-C2-FIX (review V-C2-A1 D1 and D2): the ledger accepted a block_root pin it had not verified. These probes are the reviewer's,
// re-created: each returned nil at bafc6cb.

// Offsets inside the electra-layout LightClientBootstrap of period 1378 (the embedded root pin, 25,679 bytes): offset(4) |
// current_sync_committee 24,624 | committee branch 6*32 | header (beacon 112 | exec offset 4 | exec branch 4*32) | exec header.
const (
	bootCommitteeBranchAt = 4 + 24624
	bootHeaderAt          = 4 + 24624 + 6*32
	bootParentRootAt      = bootHeaderAt + 16
	bootExecBranchAt      = bootHeaderAt + 112 + 4
)

func embeddedPinsAndLinks(t testing.TB) (*Pins, map[uint64][]byte) {
	t.Helper()
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	links, err := EmbeddedLedgerLinks()
	if err != nil {
		t.Fatal(err)
	}
	return p, links
}

func relink(a *AnchorPin, bootstrap []byte) {
	sum := sha256.Sum256(bootstrap)
	a.LinkSHA256 = hex.EncodeToString(sum[:])
}

func wantLedgerRefusal(t *testing.T, err error, period uint64, reason, inner string) {
	t.Helper()
	s, ok := AsNamed(err)
	if !ok {
		t.Fatalf("want %s at %d, got %v", reason, period, err)
	}
	if s.Code != CodeLedgerExtensionBad || s.Fields["period"] != period || s.Fields["reason"] != reason {
		t.Fatalf("want %s at %d, got %s", reason, period, s.Canonical())
	}
	if inner != "" && s.Fields["inner"] != inner {
		t.Fatalf("want inner %s, got %s", inner, s.Canonical())
	}
}

// A single-entry ledger (the embedded one) is re-derived from its bootstrap: the pinned block_root must be the header's root, the
// header's execution branch and the committee branch must hold, and the header's period must be the entry's.
func TestAReDerivedSingleEntryLedgerChecksItsBootstrapAnchor(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(a *AnchorPin, boot []byte)
		inner string
	}{
		{"bogus_block_root", func(a *AnchorPin, _ []byte) {
			a.BlockRoot = a.BlockRoot[:len(a.BlockRoot)-1] + map[bool]string{true: "1", false: "0"}[!strings.HasSuffix(a.BlockRoot, "1")]
		}, "finality_pin_mismatch"},
		{"committee_branch_byte_flipped", func(a *AnchorPin, boot []byte) { boot[bootCommitteeBranchAt+5] ^= 1; relink(a, boot) }, "finality_bootstrap_invalid"},
		{"header_parent_root_byte_flipped", func(a *AnchorPin, boot []byte) { boot[bootParentRootAt+3] ^= 1; relink(a, boot) }, "finality_pin_mismatch"},
		{"header_exec_branch_byte_flipped", func(a *AnchorPin, boot []byte) { boot[bootExecBranchAt+10] ^= 1; relink(a, boot) }, "finality_bootstrap_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, links := embeddedPinsAndLinks(t)
			e, _ := p.Sepolia()
			boot := append([]byte(nil), links[1378]...)
			c.tweak(&e.Anchors[0], boot)
			links[1378] = boot
			wantLedgerRefusal(t, p.VerifyLedger(links), 1378, string(LedgerRootPinUnverifiable), c.inner)
		})
	}
	t.Run("period_of_the_header_is_not_the_entrys", func(t *testing.T) {
		p, links := embeddedPinsAndLinks(t)
		e, _ := p.Sepolia()
		e.Anchors[0].Period = 1377
		links[1377] = links[1378]
		delete(links, 1378)
		wantLedgerRefusal(t, p.VerifyLedger(links), 1377, string(LedgerRootPinUnverifiable), "finality_bootstrap_invalid")
	})
}

func vectorLedger(t testing.TB) (*Pins, map[uint64][]byte) {
	t.Helper()
	pins, err := ParsePinsOverride(extendRead(t, "pins/main.json"))
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64][]byte{}
	for p := uint64(1378); p <= 1391; p++ {
		links[p] = extendRead(t, "raw/links/"+strconv.FormatUint(p, 10)+".ssz")
	}
	return pins, links
}

const bogusBlockRoot = "0x00000000000000000000000000000000000000000000000000000000000000ab"

// A block_root on an appended entry is never derived (the links directory holds one file per period, the update that derived the
// entry, so there is no bootstrap to judge it by): VerifyLedger refuses it wherever it stands.
func TestABlockRootOnAnAppendedEntryOfTheVectorLedgerIsRefused(t *testing.T) {
	for _, period := range []uint64{1379, 1385, 1391} {
		t.Run(strconv.FormatUint(period, 10), func(t *testing.T) {
			pins, links := vectorLedger(t)
			e, _ := pins.Sepolia()
			for i := range e.Anchors {
				if e.Anchors[i].Period == period {
					e.Anchors[i].BlockRoot = bogusBlockRoot
				}
			}
			wantLedgerRefusal(t, pins.VerifyLedger(links), period, "block_root_on_appended_entry", "")
		})
	}
}

// A bogus root pin of a long ledger is named at the root pin, not at the first link that happens to use it.
func TestABogusRootPinOfTheVectorLedgerIsNamedAtTheRootPin(t *testing.T) {
	pins, links := vectorLedger(t)
	e, _ := pins.Sepolia()
	e.Anchors[0].BlockRoot = bogusBlockRoot
	wantLedgerRefusal(t, pins.VerifyLedger(links), 1378, string(LedgerRootPinUnverifiable), "finality_pin_mismatch")
}

// An extension file that appends an entry carrying a block_root is refused, whichever appended entry carries it.
func TestAnExtensionAppendingABlockRootEntryIsRefused(t *testing.T) {
	for _, period := range []uint64{1387, 1389, 1391} {
		t.Run(strconv.FormatUint(period, 10), func(t *testing.T) {
			base, err := ParsePinsOverride(extendRead(t, "extend/base_1386.json"))
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(extendRead(t, "extend/extend_valid.pins.json"), &m); err != nil {
				t.Fatal(err)
			}
			for _, a := range m["eth_sepolia"].(map[string]any)["anchors"].([]any) {
				if am := a.(map[string]any); uint64(am["period"].(float64)) == period {
					am["block_root"] = bogusBlockRoot
				}
			}
			raw, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			_, links := vectorLedger(t)
			_, err = base.Extend(append(raw, '\n'), links)
			wantLedgerRefusal(t, err, period, "block_root_on_appended_entry", "")
		})
	}
}
