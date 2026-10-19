// Copyright 2026 Certen Protocol
//
// RB9-L: the three defects the TypeScript differential test (RB9-D, 10,000 mutations) found in this verifier, each as the narrow test that
// pins its fix. The wider class (every member of every committed vector, all of the other panics and orderings the audit found) is
// xrobust_test.go; the vectors with the verdict every verifier must reach are testdata/robust1 (cmd/proofv2conformance -robust1).

package proofv2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jm "github.com/certen/independant-validator/internal/jsonmutate"
	"github.com/certen/independant-validator/pkg/ledger"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// vectorDoc reads one committed vector document of a suite.
func vectorDoc(t *testing.T, suite, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", suite, file))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withMutations returns the document with each mutation applied, in order.
func withMutations(t *testing.T, raw []byte, muts ...jm.Mutation) []byte {
	t.Helper()
	tree, err := jm.ParseTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range muts {
		_, tree = m.Apply(tree)
	}
	out, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// refusalOf judges a document as proofverify does and returns the refusal; a panic or a verified document fails the test.
func refusalOf(t *testing.T, what string, raw []byte) error {
	t.Helper()
	var verr error
	v := jm.Guard(func() jm.Verdict {
		p := new(Portable)
		if err := json.Unmarshal(raw, p); err != nil {
			verr = err
			return jm.Verdict{Refused: true, Err: err.Error()}
		}
		_, verr = VerifyPortable(p)
		if verr != nil {
			return jm.Verdict{Refused: true, Err: verr.Error()}
		}
		return jm.Verdict{}
	})
	if v.Panicked != "" {
		t.Fatalf("%s: the verifier panicked: %s", what, v.Panicked)
	}
	if !v.Refused {
		t.Fatalf("%s: the verifier accepted the document", what)
	}
	return verr
}

// DEFECT 1 (pkg/proof/v2/portable.go importAccount): JSON null for the network, globals or routing account of the set check decoded to no
// account and was dereferenced. It is refused as any account of the wrong kind is, naming the account: "<url> is <nil>, not a one-entry
// data account", under the set check's own prefix.
func TestRB9LNullSetCheckAccountIsRefusedNotDereferenced(t *testing.T) {
	raw := vectorDoc(t, "xpartition3", "d2b-directory-page-with-a-bvn-anchor.json")
	for _, c := range []struct{ member, want string }{
		{"network", "set check network: acc://dn.acme/network is <nil>, not a one-entry data account"},
		{"globals", "set check globals: acc://dn.acme/globals is <nil>, not a one-entry data account"},
		{"routing", "set check routing: acc://dn.acme/routing is <nil>, not a one-entry data account"},
	} {
		doc := withMutations(t, raw, jm.Mutation{Path: jm.Path{"evidence", "check", c.member, "account"}, Kind: "null"})
		err := refusalOf(t, c.member+" account null", doc)
		if err.Error() != c.want {
			t.Errorf("%s account null: refused with %q, want %q", c.member, err, c.want)
		}
	}
}

// DEFECT 2 (pkg/proof/v2/evidence.go verifyFrom): evidence that builds on no major block reached (*Spine).Clone on a spine that was never
// kept. VerifyFromSpine refused it before; the genesis entry points now refuse it with the same text, before any spine is built, and the
// consensus entry points agree.
func TestRB9LEvidenceThatBuildsOnNoMajorBlockIsRefused(t *testing.T) {
	const want = "evidence builds on 0 major blocks: the certification needs at least the first"
	raw := vectorDoc(t, "xpartition5", "update-account-auth-remove-op-that-leaves-the-voter.json")
	for _, m := range []jm.Mutation{
		{Path: jm.Path{"evidence", "majors"}, Kind: "zero", Val: json.Number("0")},
		{Path: jm.Path{"evidence", "majors"}, Kind: "remove"},
		{Path: jm.Path{"evidence", "majors"}, Kind: "null"},
	} {
		doc := withMutations(t, raw, m)
		if err := refusalOf(t, "evidence.majors "+m.Kind, doc); err.Error() != want {
			t.Errorf("evidence.majors %s: refused with %q, want %q", m.Kind, err, want)
		}

		// The consensus entry points, from the spine a chain holds, reach the same refusal.
		p := new(Portable)
		if err := json.Unmarshal(doc, p); err != nil {
			t.Fatal(err)
		}
		ev, ar, in, pin, err := Import(p)
		if err != nil {
			t.Fatal(err)
		}
		gen, set, err := AcceptSpineGenesis(in, pin, 5)
		if err != nil {
			t.Fatal(err)
		}
		l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
		cps, sets, err := ExtendSpine(l, ar.Majors, 6)
		if err != nil {
			t.Fatal(err)
		}
		l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
		for name, verify := range map[string]func() (*Report, error){
			"Verify21FromGenesis":       func() (*Report, error) { return Verify21FromGenesis(ev, ar, in, pin) },
			"VerifyEvidence21FromSpine": func() (*Report, error) { return VerifyEvidence21FromSpine(ev, l, pin) },
			"VerifyFromGenesis (2.0)":   func() (*Report, error) { e := *ev; e.Version = Version; return VerifyFromGenesis(&e, ar, in, pin) },
			"VerifyFromSpine (2.0)":     func() (*Report, error) { e := *ev; e.Version = Version; return VerifyFromSpine(&e, l, pin) },
		} {
			var gotErr error
			if v := jm.Guard(func() jm.Verdict { _, gotErr = verify(); return jm.Verdict{} }); v.Panicked != "" {
				t.Fatalf("%s with evidence.majors %s panicked: %s", name, m.Kind, v.Panicked)
			}
			if gotErr == nil || gotErr.Error() != want {
				t.Errorf("%s with evidence.majors %s: %v, want %q", name, m.Kind, gotErr, want)
			}
		}
	}
}

// DEFECT 3 (pkg/proof/v2/xverify.go verify21): the entries of evidence.anchors were judged in the order a Go map is walked, so a document
// with two defective anchors was refused with a different named state from one run to the next. They are judged in ascending byte order of
// their keys; in this document the BVN2 entry (its receipt altered) precedes the BVN4 entry (an anchor of BVN3 under BVN4's key), so the refusal is
// g1_partition_anchor_unavailable{BVN2,70} every time, never g1_foreign_partition_mismatch{BVN3,90}.
func TestRB9LAnchorsAreJudgedInKeyOrder(t *testing.T) {
	raw := vectorDoc(t, "xpartition4", "anchor-wrapper-source-altered.json")
	// Flip a byte of the first step of the BVN2 receipt's path.
	tree, err := jm.ParseTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	step := tree.(map[string]any)["evidence"].(map[string]any)["anchors"].(map[string]any)["acc://bvn-BVN2.acme"].(map[string]any)["receipt"].(map[string]any)["entries"].([]any)[1].(map[string]any)
	h := step["hash"].(string)
	flipped := "00" + h[2:]
	if h[:2] == "00" {
		flipped = "ff" + h[2:]
	}
	doc := withMutations(t, raw, jm.Mutation{Path: jm.Path{"evidence", "anchors", "acc://bvn-BVN2.acme", "receipt", "entries", 1, "hash"}, Kind: "set", Val: flipped})

	const want = "g1_partition_anchor_unavailable{BVN2,70}: the receipt does not prove the anchor transaction into the certified Directory root"
	first := ""
	for i := 0; i < 40; i++ {
		err := refusalOf(t, "two defective anchors", doc)
		if first == "" {
			first = err.Error()
		}
		if err.Error() != first {
			t.Fatalf("run %d refused with %q, run 0 with %q: the refusal is not a function of the document", i, err, first)
		}
	}
	if first != want {
		t.Fatalf("refused with %q, want %q", first, want)
	}
	if !strings.HasPrefix(first, StatePartitionAnchorUnavailable+"{BVN2,70}") {
		t.Fatalf("not the named state of the first anchor in key order: %q", first)
	}
}

// More than one defect, and the refusal names the first of them in a fixed order (RB9-L): the same document is refused with the same text
// whatever order a map is walked in. Each walk over a map that can decide a refusal is over its keys in ascending byte order.

// checkExecutorVersion walks the proven pages in ascending order of their lower-case URLs.
func TestRB9LExecutorVersionRefusalNamesTheFirstLedgerInURLOrder(t *testing.T) {
	ledger := func(partition string, block uint64) *provenAcct {
		l := &protocol.SystemLedger{Url: protocol.PartitionUrl(partition).JoinPath(protocol.Ledger), ExecutorVersion: protocol.ExecutorVersionV1}
		return &provenAcct{acct: l, anchor: &xAnchor{id: partition, block: block}}
	}
	byURL := map[string]*provenAcct{}
	for i, p := range []string{"BVN3", "Directory", "BVN2", "BVN1"} {
		pa := ledger(p, uint64(10*(i+1)))
		byURL[strings.ToLower(pa.acct.GetUrl().String())] = pa
	}
	// In URL order acc://bvn-bvn1.acme/ledger is first; it was proven at block 40.
	const want = "g1_executor_version_unsupported{BVN1,40}: acc://bvn-BVN1.acme/ledger proves executor version 1, before Baikonur (6): the authority set inheritance and the delegation path differ (sig_authority.go:175-178, utils.go:152-154)"
	for run := 0; run < 60; run++ {
		err := checkExecutorVersion(byURL)
		if err == nil || err.Error() != want {
			t.Fatalf("run %d: %v, want %q", run, err, want)
		}
	}
}

// Import judges the portable anchors in ascending order of their keys.
func TestRB9LUnimportableAnchorsAreRefusedInKeyOrder(t *testing.T) {
	raw := vectorDoc(t, "xpartition4", "anchor-wrapper-source-altered.json")
	var muts []jm.Mutation
	for _, k := range []string{"acc://bvn-BVN2.acme", "acc://bvn-BVN4.acme"} {
		muts = append(muts, jm.Mutation{Path: jm.Path{"evidence", "anchors", k, "message"}, Kind: "wrong-type-number", Val: json.Number("7")})
	}
	doc := withMutations(t, raw, muts...)
	var first string
	for run := 0; run < 40; run++ {
		err := refusalOf(t, "two anchors that do not import", doc)
		if run == 0 {
			first = err.Error()
		}
		if err.Error() != first {
			t.Fatalf("run %d: %q, run 0: %q", run, err, first)
		}
	}
	if !strings.HasPrefix(first, "anchor acc://bvn-BVN2.acme: ") {
		t.Fatalf("refused with %q, want the first anchor in key order (acc://bvn-BVN2.acme)", first)
	}
}

// The override table is listed in ascending order of the body type.
func TestRB9LExecutorOverrideTypesAreInAscendingOrder(t *testing.T) {
	first := ExecutorOverrideTypes()
	if len(first) != len(executorOverrides) {
		t.Fatalf("%d types listed, %d overrides", len(first), len(executorOverrides))
	}
	for i := 1; i < len(first); i++ {
		if first[i-1] >= first[i] {
			t.Fatalf("the list is not ascending at %d: %v", i, first)
		}
	}
	for run := 0; run < 40; run++ {
		if got := ExecutorOverrideTypes(); fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("run %d lists %v, run 0 %v", run, got, first)
		}
	}
}

// A transaction that names an authority with no URL (an AddAccountAuthorityOperation whose authority is absent) cannot have been executed
// and cannot be required: it is refused by the decode, never read as a nil URL.
func TestRB9LATransactionNamingAnAuthorityWithNoURLIsRefused(t *testing.T) {
	txn := &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: url.MustParse("acc://rb9l.acme/account")},
		Body:   &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{&protocol.AddAccountAuthorityOperation{}}},
	}
	raw, err := txn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTxn(hex.EncodeToString(raw)); err == nil || err.Error() != "a transaction names an authority with no URL" {
		t.Fatalf("decodeTxn: %v", err)
	}
	// An authority with a URL decodes as before.
	txn.Body = &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{&protocol.AddAccountAuthorityOperation{Authority: url.MustParse("acc://rb9l.acme/book")}}}
	if raw, err = txn.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTxn(hex.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
}

// Accumulate's union decoders (UnmarshalAccount, UnmarshalSignature) return neither a value nor an error for bytes that hold no type - a run
// of zeros. The consensus entry points read hex members the proposer chose, and each of them was handed on as a value and dereferenced.
// Every one is refused, by name, from the spine a chain holds (RB9-L).
func TestRB9LBytesThatHoldNoValueAreRefusedFromTheSpine(t *testing.T) {
	r := loadReal21(t)
	l := spineOf(t, r)
	zeros := func(h string) string { return strings.Repeat("0", len(h)) }
	cases := []struct {
		name string
		edit func(ev *Evidence)
		want string
	}{
		{"the network account's state", func(ev *Evidence) { ev.Check.Set.Network.AccountState = zeros(ev.Check.Set.Network.AccountState) },
			"set check: network account: does not decode as an account: it holds no account"},
		{"the globals account's state", func(ev *Evidence) { ev.Check.Set.Globals.AccountState = zeros(ev.Check.Set.Globals.AccountState) },
			"set check: globals account: does not decode as an account: it holds no account"},
		{"a page's state", func(ev *Evidence) { ev.Pages[0].State = zeros(ev.Pages[0].State) }, ""},
		{"a vote hop's signature", func(ev *Evidence) { ev.Votes[0].Hops[0].Signature = zeros(ev.Votes[0].Hops[0].Signature) }, ""},
	}
	for _, c := range cases {
		ev := r.clone(t)
		c.edit(ev)
		var err error
		if v := jm.Guard(func() jm.Verdict { _, err = VerifyEvidence21FromSpine(ev, l, r.pin); return jm.Verdict{} }); v.Panicked != "" {
			t.Fatalf("%s zeroed: the verifier panicked: %s", c.name, v.Panicked)
		}
		if err == nil {
			t.Fatalf("%s zeroed: the document verified", c.name)
		}
		if c.want != "" && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s zeroed: refused with %q, want it to say %q", c.name, err, c.want)
		}
	}
}
