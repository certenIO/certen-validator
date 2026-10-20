// Copyright 2026 Certen Protocol

package finality

import "testing"

// The embedded ledger re-derives from its root pin through the link files embedded beside it.
func TestTheEmbeddedLedgerRederivesFromItsRootPin(t *testing.T) {
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	links, err := EmbeddedLedgerLinks()
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[1378] == nil {
		t.Fatalf("the embedded links are %d files, want the root bootstrap only", len(links))
	}
	if err := p.VerifyLedger(links); err != nil {
		t.Fatal(err)
	}
}

// A root bootstrap with one byte changed is no longer the file the ledger names (link_sha256), so the ledger does not re-derive.
func TestATamperedRootBootstrapIsNotTheRootPin(t *testing.T) {
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	links, err := EmbeddedLedgerLinks()
	if err != nil {
		t.Fatal(err)
	}
	links[1378] = append([]byte(nil), links[1378]...)
	links[1378][100] ^= 1
	err = p.VerifyLedger(links)
	s, ok := AsNamed(err)
	if !ok || s.Code != CodeLedgerExtensionBad || s.Fields["reason"] != string(LedgerRootPinUnverifiable) {
		t.Fatalf("got %v", err)
	}
	delete(links, 1378)
	if s, ok := AsNamed(p.VerifyLedger(links)); !ok || s.Fields["reason"] != string(LedgerRootPinUnverifiable) {
		t.Fatalf("a missing bootstrap: %v", s)
	}
}

// An extension that appends nothing and changes nothing extends its base; one that changes anything else does not.
func TestAnExtensionWithoutNewEntriesIsTheBaseAndAnythingElseIsRefused(t *testing.T) {
	p, err := EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	raw := EmbeddedPinsBytes()
	q, err := p.Extend(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, src := q.Identity(); src[:10] != "extension:" {
		t.Fatalf("source %q", src)
	}
	changed := append([]byte(nil), raw...)
	for i := range changed {
		if i+len(`"published_utc": "2`) < len(changed) && string(changed[i:i+len(`"published_utc": "2`)]) == `"published_utc": "2` {
			changed[i+len(`"published_utc": "2`)] = '3'
			break
		}
	}
	if _, err := p.Extend(changed, nil); err == nil {
		t.Fatal("a changed published_utc extended the pins")
	} else if s, _ := AsNamed(err); s == nil || s.Fields["reason"] != string(LedgerNonLedgerContentDiffers) {
		t.Fatalf("got %v", err)
	}
}
