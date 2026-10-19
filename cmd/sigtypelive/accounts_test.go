package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const addrA = "0x1111111111111111111111111111111111111111"
const addrB = "0x2222222222222222222222222222222222222222"

// A CertenAccountV7_3 has one governing key book, fixed at creation, and authorityLevelOfPage is NONE for any page of
// another book. Ten cases approved by ten different key books therefore need ten accounts: one address for all of them
// would settle one case and revert nine, and that failure appears only on chain, after the batch was paid for.
func TestEachCaseNeedsItsOwnAccount(t *testing.T) {
	adi := "acc://pv2-sig-1.acme"
	cs := liveCases()
	l := liveConfig{Chain: "base-sepolia", Accounts: map[string]string{cs[0].Tag: addrA}}
	if got, err := l.accountFor(adi, cs[0]); err != nil || got != addrA {
		t.Fatalf("account of %s: %q, %v", cs[0].Name, got, err)
	}
	for _, c := range cs[1:] {
		_, err := l.accountFor(adi, c)
		if err == nil || !strings.Contains(err.Error(), c.book(adi)) {
			t.Errorf("%s has no account and must be refused naming its governing book %s, got %v", c.Name, c.book(adi), err)
		}
	}
}

// A bare -account address names one account; with several selected cases it is refused instead of being applied to every
// case, because only one governing book can match it.
func TestBareAccountAddressIsRefusedForManyCasesAndAcceptedForOne(t *testing.T) {
	cs := liveCases()
	if _, err := parseAccounts("", addrA, cs); err == nil || !strings.Contains(err.Error(), "own account") {
		t.Fatalf("a bare address for %d cases must be refused, got %v", len(cs), err)
	}
	m, err := parseAccounts("", addrA, cs[:1])
	if err != nil || m[cs[0].Tag] != addrA {
		t.Fatalf("a bare address for one case: %v, %v", m, err)
	}
	m, err = parseAccounts("", cs[0].Tag+"="+addrA+", "+strings.ToUpper(cs[1].Tag)+"="+addrB, cs)
	if err != nil || m[cs[0].Tag] != addrA || m[cs[1].Tag] != addrB {
		t.Fatalf("tag=address pairs: %v, %v", m, err)
	}
	if _, err := parseAccounts("", cs[0].Tag+"=0xnothex", cs); err == nil {
		t.Fatal("a malformed address must be refused")
	}
}

// The accounts file written by `accounts` is read by rerun, and -account is merged over it.
func TestAccountsFileIsReadAndOverridden(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "accounts.json")
	cs := liveCases()
	if err := os.WriteFile(f, []byte(fmt.Sprintf(`{%q: %q, %q: %q}`, cs[0].Tag, addrA, cs[1].Tag, addrA)), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := parseAccounts(f, cs[1].Tag+"="+addrB, cs)
	if err != nil || m[cs[0].Tag] != addrA || m[cs[1].Tag] != addrB {
		t.Fatalf("%v, %v", m, err)
	}
	if m, err = parseAccounts(filepath.Join(dir, "missing.json"), "", cs); err != nil || len(m) != 0 {
		t.Fatalf("a missing accounts file is an empty set, not an error: %v, %v", m, err)
	}
}

// Every case's governing book must be a canonical book of the ADI, or the factory reverts NotGoverningBook and no account
// can ever exist for it (CertenAccountFactoryV11.isGoverningBookOf).
func TestEveryCaseBookIsCanonicalForTheFactory(t *testing.T) {
	for n := 1; n <= 999; n++ {
		adi := fmt.Sprintf("acc://pv2-sig-%d.acme", n)
		for _, c := range liveCases() {
			if !isCanonicalBookOf(adi, c.authorityBook(adi)) {
				t.Errorf("%s: %s is not a canonical key book of %s", c.Name, c.authorityBook(adi), adi)
			}
		}
	}
	adi := "acc://pv2-sig-1.acme"
	for _, bad := range []string{adi, adi + "/", adi + "/Book", adi + "/book/1", "acc://pv2-sig-2.acme/book", "ACC://pv2-sig-1.acme/book", adi + "book"} {
		if isCanonicalBookOf(adi, bad) {
			t.Errorf("%q must not be a canonical book of %s", bad, adi)
		}
	}
	if isCanonicalBookOf(adi+"/", adi+"//book") || isCanonicalBookOf("", "/book") {
		t.Error("an ADI with a trailing slash or empty must be refused")
	}
}

// canonicalSalt is uint256(keccak256(adiURL)); keccak256 of the empty string is the published vector.
func TestCanonicalSaltIsKeccakOfTheADI(t *testing.T) {
	if got := fmt.Sprintf("%x", canonicalSalt("")); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("canonicalSalt(\"\") = %s", got)
	}
}

// The operator scripts under scripts/ (gitignored: several carry hardcoded testnet keys) declared the five-argument
// createBatchAnchor selector, which the validators' batch path refuses ("declared anchor is not the chain's live anchor").
// Every script present that declares an anchor call must declare the live seven-argument one. The seven-argument form is
// the one buildIntent emits, so the scripts and this tool cannot drift apart unseen.
func TestLocalScriptsDeclareTheLiveBatchSelector(t *testing.T) {
	const live = "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32)"
	in, err := buildIntent("acc://pv2-sig-1.acme", liveCases()[0], addrA, testLeg(t, "base-sepolia"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(in.Blobs[1]), live) {
		t.Fatalf("buildIntent does not declare %s", live)
	}
	re := regexp.MustCompile(`createBatchAnchor\([^)]*\)`)
	var files []string
	for _, pat := range []string{"*.js", "*.mjs"} {
		m, _ := filepath.Glob(filepath.Join("..", "..", "scripts", pat))
		files = append(files, m...)
	}
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, sel := range re.FindAllString(string(b), -1) {
			checked++
			if sel != live {
				t.Errorf("%s declares %s, the live anchor takes %s", f, sel, live)
			}
		}
	}
	t.Logf("%d selector declarations in %d local scripts checked", checked, len(files))
}

// CERTEN reads an intent's ADI as its principal minus the trailing "/data" (pkg/intent/discovery.go), so only an intent
// written to <adi>/data binds to the ADI's CertenAccount; the first run's per-type data accounts made the ADI
// "acc://pv2-sig-1.acme/data-<tag>" and the validators refused every case "account is bound to a different ADI" (RB8-E).
// -data-root writes the intent to <adi>/data, and the body of that account's creation must not be an ambiguous length.
func TestDataRootPutsTheIntentOnTheADIsDataAccount(t *testing.T) {
	dataAtRoot = true
	defer func() { dataAtRoot = false }()
	for n := 1; n <= 999; n++ {
		adi := fmt.Sprintf("acc://pv2-sig-%d.acme", n)
		for _, c := range liveCases() {
			if got := c.data(adi); got != adi+"/data" {
				t.Fatalf("%s: data account %s, want %s/data", c.Name, got, adi)
			}
		}
	}
	// the identities this run uses (n = 11..15, one non-delegated case each) create their /data account
	for n, name := range map[int]string{11: "legacyED25519", 12: "ed25519", 13: "rcd1", 14: "rsaSha256", 15: "ecdsaSha256"} {
		sel, err := liveConfig{Cases: name}.selected()
		if err != nil || len(sel) != 1 {
			t.Fatal(name, err)
		}
		if err := createDataBodyLength(sel[0], fmt.Sprintf("acc://pv2-sig-%d.acme", n)); err != nil {
			t.Errorf("n=%d: %v", n, err)
		}
	}
	// and the guard refuses the 64-byte body that cost the first run a setup (ed25519 under a one-digit number)
	sel, _ := liveConfig{Cases: "ed25519"}.selected()
	if err := createDataBodyLength(sel[0], "acc://pv2-sig-1.acme"); err == nil {
		t.Error("a 64-byte creation body must be refused before it is written")
	}
}

// setup of a selection creates only that selection: the delegating books exist only when the delegated case is selected.
func TestSetupSelectionCoversOnlyTheSelectedCases(t *testing.T) {
	l := liveConfig{Cases: "legacyED25519,btc"}
	sel, err := l.selected()
	if err != nil || len(sel) != 2 {
		t.Fatalf("selected: %v, %v", sel, err)
	}
	for _, c := range sel {
		if c.Delegated {
			t.Errorf("%s must not be delegated", c.Name)
		}
	}
	l = liveConfig{Cases: "delegated-ecdsaSha256"}
	if sel, err = l.selected(); err != nil || len(sel) != 1 || !sel[0].Delegated {
		t.Fatalf("delegated selection: %v, %v", sel, err)
	}
}
