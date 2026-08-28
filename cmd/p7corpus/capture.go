package main

// Capture: build every corpus signature, submit it, and record what
// accumulate-core says about it.
//
// A signature is built with accumulate-core's own signing.Builder, never by
// hand. PHASE7_RUNBOOK.md rule 4: the canonical encoding is field-tagged,
// omit-if-zero and varint-length, and hand-rolling it is how the field
// strictness bugs happened before. The builder is also the only thing that
// nests DelegatedSignature correctly, which is the whole subject of
// PHASE7_DELEGATION_PLAN section 1.3 - the digest commits to every Delegator
// URL in the chain, so a signature whose nesting is wrong fails EVERY time.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// signaturePlan is one signature the corpus wants to exist, stated before it is
// built so the intent and the result can be compared.
type signaturePlan struct {
	// Seed names the key that signs. Delegators are OUTERMOST FIRST - the
	// order the AuthoritySignature path is read in, and the order a reader
	// walks from the principal's authority down to the key that signed.
	Seed       string
	SignerPage string
	Delegators []string

	// Merkle asks for a signature over the Initiator() merkle digest instead of
	// the metadata digest. Both are accepted by accumulate-core
	// (protocol/signature_utils.go:26-41) and CERTEN implements only the first,
	// so the corpus needs at least one of these or PHASE7_RUNBOOK.md Gate 2's
	// second condition cannot be tested at all.
	Merkle bool

	// Type overrides the signature type, for the fail-closed case.
	Type protocol.SignatureType
}

// caseplan is a whole corpus case: a transaction, the signatures on it, and
// what is expected to happen.
type casePlan struct {
	Case      string
	Shape     string
	Principal string // the ADI whose data account is written to
	Expect    string // "valid" or "refused"

	// RefusalKind names WHY a refusal case must be refused, so Gate 3's
	// requirement that each refusal carry "its own distinct, readable reason"
	// is testable rather than a matter of reading log lines. Empty for a valid
	// case.
	RefusalKind string
	Why         string
	Signatures  []signaturePlan

	// Bootstrap are signatures that satisfy the principal ADI's authority
	// directly, used only to create the case's data account. A refusal case
	// cannot bootstrap with its own signatures.
	Bootstrap []signaturePlan

	// SkipSubmit marks a case the network itself will not carry, so the
	// signature is built and verdicted but never sent. Recorded, not hidden:
	// a case that was not submitted is a weaker specimen than one that was, and
	// the corpus has to say which it is.
	SkipSubmit bool

	// ExpectExec is what the NETWORK must do with the transaction, as distinct
	// from what accumulate-core says about each signature.
	//
	// The two come apart for the first time in case L. A signature can be
	// perfectly valid - CoreVerdict true - while the transaction it is on never
	// executes, because a second authority has not voted. `Expect` is about the
	// signature; this is about readiness, and conflating them is how "the
	// envelope was accepted" came to stand in for "the thing happened".
	//
	// Empty means "delivered", which is every case before L.
	ExpectExec string
}

// trace is what a case produced. Every field is evidence; nothing is inferred.
type trace struct {
	Case  string `json:"case"`
	Shape string `json:"shape"`
	Label string `json:"label"`
	Why   string `json:"why"`

	Expect      string `json:"expect"`
	RefusalKind string `json:"refusalKind,omitempty"`

	// ExpectExec is what the NETWORK was expected to do with the transaction,
	// recorded beside what it actually did. "pending" is a real expectation, not
	// a failure to reach one: case L-partial is a valid signature on a
	// transaction that must NOT execute.
	ExpectExec string `json:"expectExec,omitempty"`

	// KeyIsDirectOnOuterPage records whether the inner signing key ALSO appears
	// directly on the outermost delegator page. Where it does, the case does not
	// discriminate: an implementation that ignores delegation entirely and just
	// looks the key hash up on the page passes it anyway. Measured against the
	// chain rather than assumed, because it decides which cases Gate 3 can rest
	// on - D and F are the delegation cases whose keys are NOT on the outer page.
	KeyIsDirectOnOuterPage *bool `json:"keyIsDirectOnOuterPage,omitempty"`

	Principal       string `json:"principal"`
	TransactionHash string `json:"transactionHash"`

	// The signature, in the shape CERTEN's extractor consumes.
	//
	// Type is the OUTERMOST signature's type - "delegated" for anything wrapped,
	// which is exactly what signature_verifier.go:438 rejects. KeyType is the
	// type of the key signature at the centre, which is what decides whether the
	// cryptography is one we can check at all. Conflating the two is easy and
	// hides every delegated ed25519 signature from a filter looking for
	// "ed25519" - which it did, on the first run of the Gate 1 tests.
	Type            string   `json:"type"`
	KeyType         string   `json:"keyType"`
	Delegators      []string `json:"delegators,omitempty"`
	PublicKey       string   `json:"publicKey"`
	Signature       string   `json:"signature"`
	Signer          string   `json:"signer"`
	SignerVersion   uint64   `json:"signerVersion"`
	Timestamp       uint64   `json:"timestamp"`
	SignerPartition string   `json:"signerPartition"`

	// The verdict, from accumulate-core and nowhere else.
	CoreVerdict bool   `json:"coreVerdict"`
	DigestForm  string `json:"digestForm"`
	Digest      string `json:"digest,omitempty"`

	// What the network did with it.
	Submitted   bool   `json:"submitted"`
	SubmitError string `json:"submitError,omitempty"`
	TxID        string `json:"txID,omitempty"`
	ExecStatus  string `json:"execStatus,omitempty"`
	ExecError   string `json:"execError,omitempty"`
}

type captureResult struct {
	Endpoint       string  `json:"endpoint"`
	ProtocolModule string  `json:"protocolModule"`
	CapturedAt     string  `json:"capturedAt"`
	Traces         []trace `json:"traces"`

	// Pages is every key page the traces name, as the chain reports it. Gate 3
	// resolves delegation paths against these rather than against the network,
	// so the resolution tests run offline and are pinned to one observation.
	Pages map[string]pageState `json:"pages"`
}

func capture(ctx context.Context, c *client, seeds map[string]string, raw map[string]json.RawMessage,
	out string, only string) error {
	cases, err := parseCases(raw)
	if err != nil {
		return err
	}
	r, err := newRouter(ctx, kermit)
	if err != nil {
		return err
	}
	plans, err := buildPlans(cases)
	if err != nil {
		return err
	}

	// A case filter, so a newly added case can be captured without re-submitting
	// every specimen that is already recorded. When one is used the EXISTING
	// traces are loaded and the captured cases replace their entries - a capture
	// of three cases must not silently shrink the corpus to three.
	wanted := map[string]bool{}
	for _, name := range strings.Split(only, ",") {
		if n := strings.TrimSpace(strings.ToUpper(name)); n != "" {
			wanted[n] = true
		}
	}

	res := captureResult{
		Endpoint:       kermit,
		ProtocolModule: protocolModule,
		CapturedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if len(wanted) > 0 {
		if prev, err := readJSON[captureResult](out); err == nil {
			for _, t := range prev.Traces {
				if !wanted[strings.ToUpper(baseCase(t.Case))] {
					res.Traces = append(res.Traces, t)
				}
			}
			res.Pages = prev.Pages
			fmt.Printf("capturing only %v; %d existing trace(s) retained\n",
				sortedKeys(wanted), len(res.Traces))
		}
	}

	for _, p := range plans {
		if len(wanted) > 0 && !wanted[strings.ToUpper(baseCase(p.Case))] {
			continue
		}
		fmt.Printf("== case %s: %s ==\n", p.Case, p.Shape)
		ts, err := runCase(ctx, c, r, seeds, p)
		if err != nil {
			return fmt.Errorf("case %s: %w", p.Case, err)
		}
		res.Traces = append(res.Traces, ts...)
	}
	fmt.Println("== key pages named by the corpus ==")
	pages, err := capturePages(ctx, c, r, res.Traces)
	if err != nil {
		return err
	}
	res.Pages = pages

	if err := writeJSON(out, res); err != nil {
		return err
	}
	fmt.Printf("\nwrote %d traces to %s\n", len(res.Traces), out)
	return nil
}

// buildPlans turns the provisioned structures into the signatures the corpus
// needs. Every delegator list is derived from the manifest's recorded chain,
// not written out by hand, so a re-provision that changes a book name changes
// the plan with it.
func buildPlans(cases map[string]caseSpec) ([]casePlan, error) {
	need := func(name string) (caseSpec, error) {
		cs, ok := cases[name]
		if !ok {
			return caseSpec{}, fmt.Errorf("case %s absent from the manifest", name)
		}
		if cs.Status != "ok" {
			return caseSpec{}, fmt.Errorf("case %s is %q, not ok", name, cs.Status)
		}
		return cs, nil
	}

	// delegatorsFor converts a manifest chain of BOOKS into the chain of PAGES
	// a delegated signature names.
	//
	// The distinction is load-bearing and cost a provisioning round to learn
	// (PHASE7_CORPUS_MANIFEST.md section 6): a page delegates TO A BOOK, but the
	// Delegator field of a DelegatedSignature names the PAGE that did the
	// delegating - accumulate-core loads it with loadSigner and then asks it
	// EntryByDelegate(authority). So for a chain book -> book2 -> book3, the key
	// on book3/1 signs with delegators [book/1, book2/1], outermost first.
	delegatorsFor := func(chain []string) []string {
		out := make([]string, 0, len(chain)-1)
		for _, b := range chain[:len(chain)-1] {
			out = append(out, b+"/1")
		}
		return out
	}

	var plans []casePlan

	// A - 1-of-1 ed25519. The shape all 400 production proofs used, and the one
	// that must not regress. It is not re-signed here: its principal is the
	// production ADI and the corpus checks it by not breaking it.

	b, err := need("B")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "B", Shape: b.Shape, Principal: b.ADI, Expect: "valid",
		Why: "two distinct keys of a 2-of-3 page; the threshold is met by distinct entries",
		Signatures: []signaturePlan{
			{Seed: "b1", SignerPage: b.Page},
			{Seed: "b2", SignerPage: b.Page},
		},
		Bootstrap: []signaturePlan{
			{Seed: "b1", SignerPage: b.Page},
			{Seed: "b2", SignerPage: b.Page},
		},
	})

	// I - the same key twice. Uses case B's page, because I is about ACCOUNTING,
	// not structure: two signatures from one key are ONE acceptance, so a 2-of-3
	// page signed twice by b1 must NOT reach its threshold.
	plans = append(plans, casePlan{
		Case: "I", Shape: "duplicate key signs twice - must count once", Principal: b.ADI,
		Expect: "refused", RefusalKind: "duplicate-key",
		Why: "b1 signs twice on a 2-of-3 page; one key satisfies at most one entry, " +
			"so unique valid keys is 1 and the threshold of 2 is not met",
		Signatures: []signaturePlan{
			{Seed: "b1", SignerPage: b.Page},
			{Seed: "b1", SignerPage: b.Page},
		},
	})

	c, err := need("C")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "C", Shape: c.Shape, Principal: c.ADI, Expect: "valid",
		Why:        "depth-1 delegation; the digest commits to the one delegator URL",
		Signatures: []signaturePlan{{Seed: "c1", SignerPage: c.SigningPage, Delegators: delegatorsFor(c.Chain)}},
		Bootstrap:  []signaturePlan{{Seed: "c1", SignerPage: c.Chain[0] + "/1"}},
	})

	// The merkle-form specimen, on case C's structure. PHASE7_RUNBOOK.md Gate 2
	// requires at least one case valid ONLY under the Initiator() merkle digest;
	// without one, the second half of AcceptedDigests is untested code.
	plans = append(plans, casePlan{
		Case: "C-merkle", Shape: "depth-1 delegation, signed over the Initiator() merkle digest",
		Principal: c.ADI, Expect: "valid",
		Why: "accumulate-core accepts the metadata digest OR the initiator merkle digest " +
			"(protocol/signature_utils.go:26-41); CERTEN implements only the first, so a " +
			"signature in this form is currently counted invalid and reads as a governance rejection",
		Signatures: []signaturePlan{{
			Seed: "c1", SignerPage: c.SigningPage, Delegators: delegatorsFor(c.Chain), Merkle: true,
		}},
		Bootstrap: []signaturePlan{{Seed: "c1", SignerPage: c.Chain[0] + "/1"}},
	})

	// J - the right inner key, the WRONG delegator chain. Built on case E, which
	// is deep enough that a wrong chain is a different chain rather than an
	// empty one.
	e, err := need("E")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "E", Shape: e.Shape, Principal: e.ADI, Expect: "valid",
		Why:        "depth-3 delegation; three delegator URLs inside the signed digest",
		Signatures: []signaturePlan{{Seed: "e1", SignerPage: e.SigningPage, Delegators: delegatorsFor(e.Chain)}},
		Bootstrap:  []signaturePlan{{Seed: "e1", SignerPage: e.Chain[0] + "/1"}},
	})

	wrong := delegatorsFor(e.Chain)
	if len(wrong) < 2 {
		return nil, fmt.Errorf("case E chain is too short to build a wrong chain from")
	}
	// Drop the middle link. The inner key is right and every URL named is real;
	// only the PATH is wrong, which is exactly the claim path binding makes.
	wrong = append([]string{wrong[0]}, wrong[2:]...)
	plans = append(plans, casePlan{
		Case: "J", Shape: "correct inner key, wrong delegator chain - must be refused",
		Principal: e.ADI, Expect: "refused", RefusalKind: "path-binding",
		Why: "the digest commits to the delegator chain, so a signature naming a different " +
			"path is not evidence for the path actually walked - and every URL in this one " +
			"is real, so nothing but the path distinguishes it",
		Signatures: []signaturePlan{{Seed: "e1", SignerPage: e.SigningPage, Delegators: wrong}},
		Bootstrap:  []signaturePlan{{Seed: "e1", SignerPage: e.Chain[0] + "/1"}},
	})

	d, err := need("D")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "D", Shape: d.Shape, Principal: d.ADI, Expect: "valid",
		Why: "2-of-3 where one satisfied entry is direct and the other is delegated; " +
			"the two paths must both count, and count once each",
		Signatures: []signaturePlan{
			{Seed: "d1", SignerPage: d.Page},
			{Seed: "dd1", SignerPage: d.DelegateBook + "/1", Delegators: []string{d.Page}},
		},
		Bootstrap: []signaturePlan{
			{Seed: "d1", SignerPage: d.Page},
			{Seed: "d2", SignerPage: d.Page},
		},
	})

	f, err := need("F")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "F", Shape: f.Shape, Principal: f.Principal, Expect: "valid",
		Why: "the delegated signer lives on a different BVN than the principal, so the " +
			"proof needs a leg per signer partition - one BVN leg cannot cover it",
		Signatures: []signaturePlan{{
			Seed: "f2", SignerPage: f.DelegateBook + "/1", Delegators: []string{f.PrincipalPage},
		}},
		Bootstrap: []signaturePlan{{Seed: "f1", SignerPage: f.PrincipalPage}},
	})

	g, err := need("G")
	if err != nil {
		return nil, err
	}
	gd := delegatorsFor(g.Chain)
	if len(gd) <= protocol.DelegationDepthLimit {
		return nil, fmt.Errorf("case G has %d delegators, which is within the limit of %d - "+
			"it cannot test the refusal", len(gd), protocol.DelegationDepthLimit)
	}
	plans = append(plans, casePlan{
		Case: "G", Shape: g.Shape, Principal: g.ADI, Expect: "refused", RefusalKind: "depth-limit",
		Why: fmt.Sprintf("%d delegators against DelegationDepthLimit = %d; accumulate-core "+
			"refuses at len(delegators) > limit", len(gd), protocol.DelegationDepthLimit),
		Signatures: []signaturePlan{{Seed: "g1", SignerPage: g.SigningPage, Delegators: gd}},
		Bootstrap:  []signaturePlan{{Seed: "g1", SignerPage: g.Chain[0] + "/1"}},
	})

	h, err := need("H")
	if err != nil {
		return nil, err
	}
	// The cycle is book -> book2 -> book, and it produces TWO specimens, because
	// the first attempt at this case got the expectation wrong and Kermit said so.
	//
	// H is one traversal of the cycle. It was expected to be refused and the
	// network DELIVERED it, which is correct: a cycle in the delegation GRAPH is
	// not a cycle in a signature, and a signature naming a finite path through it
	// authorizes normally. The refusal rule in PHASE7_DELEGATION_PLAN section 3.3
	// is about OUR resolution walk, which enumerates delegates and would loop
	// forever on this graph - not about the signature.
	//
	// H-repeat is the specimen that actually tests over-counting: a path that
	// revisits book/1, which Accumulate accepts because every link in it is real.
	// A page satisfied twice by one traversal is one acceptance, not two.
	hPage1, hPage2 := h.Cycle[0]+"/1", h.Cycle[1]+"/1"
	plans = append(plans, casePlan{
		Case: "H", Shape: "one traversal of a delegation cycle - accepted", Principal: h.ADI,
		Expect: "valid",
		Why: "a cycle in the delegation graph is not a cycle in a signature; this path " +
			"visits each page once and Kermit delivers it. The cycle is a hazard for the " +
			"resolution WALK, which must track visited pages or loop forever",
		Signatures: []signaturePlan{{
			Seed: "h1", SignerPage: hPage1, Delegators: []string{hPage1, hPage2},
		}},
		Bootstrap: []signaturePlan{{Seed: "h1", SignerPage: hPage1}},
	})
	plans = append(plans, casePlan{
		Case: "H-repeat", Shape: "a delegation path that goes round the cycle twice",
		Principal: h.ADI, Expect: "valid",
		Why: "Kermit DELIVERS this, so refusing it would be a false governance rejection - " +
			"the failure this phase exists to remove. What it tests instead is over-counting: " +
			"it satisfies the SAME single entry on the principal page as case H, so a longer " +
			"path must grant no more authority than a short one. An implementation that " +
			"credited an acceptance per hop passes H and fails here",
		Signatures: []signaturePlan{{
			Seed: "h1", SignerPage: hPage1,
			Delegators: []string{hPage1, hPage2, hPage1, hPage2},
		}},
		Bootstrap: []signaturePlan{{Seed: "h1", SignerPage: hPage1}},
	})

	k, err := need("K")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "K", Shape: k.Shape, Principal: k.ADI, Expect: "refused", RefusalKind: "unsupported-type",
		Why: "a signature type CERTEN does not support must be refused with its own reason " +
			"code; silently skipping it reads as a threshold shortfall, which reads as " +
			"'the institution did not authorize this'",
		Signatures: []signaturePlan{{Seed: "k1", SignerPage: k.Page, Type: protocol.SignatureTypeBTC}},
		Bootstrap:  []signaturePlan{{Seed: "k1", SignerPage: k.Page}},
	})

	// ---- Phase 8: the authority SET, not one key page --------------------
	//
	// A-K all have one inherited authority whose book has one page, so
	// "the principal's page reached its threshold" and "the account's authority
	// set approved" have the same answer for every one of them. L, M and N are
	// the first cases where they differ.

	l, err := need("L")
	if err != nil {
		return nil, err
	}
	if len(l.SigningPages) != 2 {
		return nil, fmt.Errorf("case L needs two signing pages, has %d", len(l.SigningPages))
	}
	plans = append(plans, casePlan{
		Case: "L", Shape: l.Shape, Principal: l.ADI, Expect: "valid",
		Why: "the account has TWO authorities and userTransactionIsReady is ready only when " +
			"notReady is empty, so BOTH books must vote; an implementation that evaluates one " +
			"key page reports this authorised on half its authority set",
		Signatures: []signaturePlan{
			{Seed: "l1", SignerPage: l.SigningPages[0]},
			{Seed: "l2", SignerPage: l.SigningPages[1]},
		},
	})
	plans = append(plans, casePlan{
		Case: "L-partial", Shape: "two authorities, only ONE signs", Principal: l.ADI,
		Expect: "valid", ExpectExec: "pending",
		Why: "the SIGNATURE is valid and the TRANSACTION is not ready - the distinction case L " +
			"exists to make. Kermit leaves it pending because the second authority never voted, " +
			"so a verifier that called this authorised would be asserting something the network " +
			"itself refused to act on",
		Signatures: []signaturePlan{{Seed: "l1", SignerPage: l.SigningPages[0]}},
	})

	m, err := need("M")
	if err != nil {
		return nil, err
	}
	plans = append(plans, casePlan{
		Case: "M", Shape: m.Shape, Principal: m.ADI, Expect: "valid",
		Why: "the signer is on PAGE 2 of the authority's book, and AuthorityWillVote iterates " +
			"pages 1..PageCount returning on the first that would vote - so any page satisfies " +
			"the book. m2 is deliberately NOT on page 1, so an implementation that reads only " +
			"page 1 cannot pass this by accident",
		Signatures: []signaturePlan{{Seed: "m2", SignerPage: m.SigningPage}},
		Bootstrap:  []signaturePlan{{Seed: "m1", SignerPage: m.PrincipalPage}},
	})

	n, err := need("N")
	if err != nil {
		return nil, err
	}
	if len(n.SigningPages) != 1 {
		return nil, fmt.Errorf("case N needs one signing page, has %d", len(n.SigningPages))
	}
	if len(n.DisabledAuthorities) != 1 {
		return nil, fmt.Errorf("case N needs exactly one disabled authority, has %d",
			len(n.DisabledAuthorities))
	}
	plans = append(plans, casePlan{
		Case: "N", Shape: n.Shape, Principal: n.ADI, Expect: "valid",
		Why: fmt.Sprintf("%s is DISABLED on the account, and userTransactionIsReady skips a "+
			"disabled authority unless the body type RequireAuthorization() - which only "+
			"UpdateAccountAuth does. So this writeData is ready on one authority's vote, and "+
			"an implementation that demanded the disabled one would falsely reject it",
			shortURL(n.DisabledAuthorities[0])),
		Signatures: []signaturePlan{{Seed: "n1", SignerPage: n.SigningPages[0]}},
	})

	return plans, nil
}

// baseCase strips a specimen suffix: "L-partial" and "H-repeat" belong to cases
// L and H. A filter naming L must capture both of L's specimens, or the pair
// that makes the case discriminating comes apart.
func baseCase(name string) string {
	if i := strings.Index(name, "-"); i > 0 {
		return name[:i]
	}
	return name
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
