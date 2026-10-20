package main

// The robustness suite of RB9-L: a crafted portable document is refused, by the same name in every verifier, and never makes one fail.
// Each vector is a document of an earlier suite with ONE member changed (set to null, removed, zeroed, one of two defects of the same
// kind made so that the order the verifier judges them in decides which it names), and carries the verdict every verifier must reach:
// the refusal's exact text (Error()), the part of it a verifier in another language must reproduce (prefix), and, for a named state,
// its code, partition and block. The first six vectors are the defects the TypeScript differential test (RB9-D, ~10,000 mutations)
// found in the Go verifier at 3419863; the others are one per distinct panic or ordering class the audit of pkg/proof/v2 and
// pkg/consensus found.
//
//	go run ./cmd/proofv2conformance -robust1 pkg/proof/v2/testdata/robust1
//
// New files under their own directory and manifest; the earlier suites are never touched by this mode.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// XManifestFormatRobust1 names the robustness suite.
const XManifestFormatRobust1 = "certen-robust1-conformance/1"

// RobustCase is one manifest entry of the robustness suite.
type RobustCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Base is the case, of an earlier suite (or the conformance document, "conformance:network-update"), whose document the vector
	// edits; Edit says in one line what the edit is.
	Base   string `json:"base"`
	Edit   string `json:"edit"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Expect string `json:"expect"` // "refused", or "verified" for a member that is genuinely optional
	// State, Partition and Block are the named state a refusal carries, when it is one; empty for a plain refusal.
	State     string `json:"state,omitempty"`
	Partition string `json:"partition,omitempty"`
	Block     uint64 `json:"block,omitempty"`
	// Wording is the refusal's exact text (Go's Error()). Prefix is the part of it a verifier in another language must reproduce: the whole
	// text where it is the verifier's own, the part that names the member where the rest is the text of a codec (Go's JSON decoder).
	Wording string   `json:"wording,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Report  *XReport `json:"report,omitempty"`
}

// RobustManifest lists the robustness suite. Its own hash is the content of MANIFEST.sha256, beside it.
type RobustManifest struct {
	Format         string       `json:"format"`
	Domain         string       `json:"domain"`
	PortableFormat string       `json:"portableFormat"`
	Cases          []RobustCase `json:"cases"`
}

type robustSpec struct {
	RobustCase
	apply func(doc map[string]any) error
}

// robustBase returns the portable document a vector edits: the document of a case of an earlier suite, or a committed conformance document.
func robustBase(name string) ([]byte, error) {
	if file, ok := strings.CutPrefix(name, "conformance:"); ok {
		for _, dir := range []string{"pkg/proof/v2/testdata/conformance", "../../pkg/proof/v2/testdata/conformance"} {
			f, err := os.Open(filepath.Join(dir, file+".json.gz"))
			if err != nil {
				continue
			}
			defer f.Close()
			z, err := gzip.NewReader(f)
			if err != nil {
				return nil, err
			}
			return io.ReadAll(z)
		}
		return nil, fmt.Errorf("the conformance document %q is not under testdata", file)
	}
	for _, cases := range [][]xworld.Case{xworld.Cases(), xworld.Cases2(), xworld.Cases3(), xworld.Cases3b(), xworld.Cases4(), xworld.Cases5()} {
		for _, c := range cases {
			if c.Name == name {
				_, p, err := c.Document()
				if err != nil {
					return nil, err
				}
				return json.Marshal(p)
			}
		}
	}
	return nil, fmt.Errorf("no case %q in any earlier suite", name)
}

// setMember sets the member at path of a decoded document (an object key, or an array index) to v; a nil v is JSON null.
func setMember(doc map[string]any, path []any, v any) error {
	if memberAt(doc, path...) == nil && len(path) > 0 {
		if _, ok := memberAt(doc, path[:len(path)-1]...).(map[string]any); !ok {
			if _, ok := memberAt(doc, path[:len(path)-1]...).([]any); !ok {
				return fmt.Errorf("the base document has no parent of %v", path)
			}
		}
	}
	return proofv2.ApplyPatch(doc, []proofv2.Op{{Path: path, Set: v}})
}

// deleteMember removes the member at path.
func deleteMember(doc map[string]any, path []any) error {
	return proofv2.ApplyPatch(doc, []proofv2.Op{{Path: path, Delete: true}})
}

// memberAt reads the member at path.
func memberAt(doc map[string]any, path ...any) any {
	var cur any = doc
	for _, k := range path {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[k.(string)]
		case []any:
			cur = c[k.(int)]
		default:
			return nil
		}
	}
	return cur
}

// flipFirstByte returns a hex string differing from h in its first byte.
func flipFirstByte(h string) string {
	if h[:2] == "00" {
		return "ff" + h[2:]
	}
	return "00" + h[2:]
}

func zeroed(doc map[string]any, path ...any) (string, error) {
	h, ok := memberAt(doc, path...).(string)
	if !ok || h == "" {
		return "", fmt.Errorf("the base document has no hex at %v", path)
	}
	return strings.Repeat("0", len(h)), nil
}

// setNull sets the members at paths to JSON null.
func setNull(paths ...[]any) func(map[string]any) error {
	return func(d map[string]any) error {
		for _, p := range paths {
			if err := setMember(d, p, nil); err != nil {
				return err
			}
		}
		return nil
	}
}

// codecFault is the refusal of a value Accumulate's codec cannot decode, about the value Import was reading.
func codecFault(what string) string {
	return what + ": a value Accumulate's codec cannot decode (a member it needs is null or absent)"
}

func robust1Specs() []robustSpec {
	const dn = "d2b-directory-page-with-a-bvn-anchor"
	const noMajors = "evidence builds on 0 major blocks: the certification needs at least the first"
	const conf = "conformance:network-update"
	return []robustSpec{
		// The defects of RB9-D.
		{RobustCase: RobustCase{Name: "set-check-network-account-null", Base: dn, Edit: "evidence/check/network/account = null",
			Description: "the network account of the set check is JSON null: no account at all, refused like any account of the wrong kind (it was dereferenced; defect 1 of RB9-D)",
			Expect:      "refused", Wording: "set check network: acc://dn.acme/network is <nil>, not a one-entry data account"},
			apply: setNull([]any{"evidence", "check", "network", "account"})},
		{RobustCase: RobustCase{Name: "set-check-globals-account-null", Base: dn, Edit: "evidence/check/globals/account = null",
			Description: "the globals account of the set check is JSON null",
			Expect:      "refused", Wording: "set check globals: acc://dn.acme/globals is <nil>, not a one-entry data account"},
			apply: setNull([]any{"evidence", "check", "globals", "account"})},
		{RobustCase: RobustCase{Name: "set-check-routing-account-null", Base: dn, Edit: "evidence/check/routing/account = null",
			Description: "the routing account of the set check is JSON null",
			Expect:      "refused", Wording: "set check routing: acc://dn.acme/routing is <nil>, not a one-entry data account"},
			apply: setNull([]any{"evidence", "check", "routing", "account"})},
		{RobustCase: RobustCase{Name: "evidence-majors-zero", Base: "update-account-auth-remove-op-that-leaves-the-voter", Edit: "evidence/majors = 0",
			Description: "the certification builds on no major block: refused before any spine is built (it dereferenced a spine that was never kept; defect 2 of RB9-D)",
			Expect:      "refused", Wording: noMajors},
			apply: func(d map[string]any) error { return setMember(d, []any{"evidence", "majors"}, json.Number("0")) }},
		{RobustCase: RobustCase{Name: "evidence-majors-absent", Base: "update-account-auth-remove-op-that-leaves-the-voter", Edit: "evidence/majors removed",
			Description: "the member that says how many major blocks the certification builds on is absent: the same refusal as zero",
			Expect:      "refused", Wording: noMajors},
			apply: func(d map[string]any) error { return deleteMember(d, []any{"evidence", "majors"}) }},
		{RobustCase: RobustCase{Name: "anchors-two-defective-first-in-key-order", Base: "anchor-wrapper-source-altered", Edit: "evidence/anchors/acc://bvn-BVN2.acme/receipt/entries/1/hash flipped (the document's BVN4 entry is already defective)",
			Description: "two defective anchors, the BVN2 entry's receipt altered and the BVN4 entry (an anchor of BVN3 under BVN4's key) already refused as g1_foreign_partition_mismatch{BVN3,90}: the anchors are judged in ascending key order, so the named state is BVN2's, every time (it was whichever a map walk met first; defect 3 of RB9-D)",
			Expect:      "refused", State: proofv2.StatePartitionAnchorUnavailable, Partition: "BVN2", Block: 70,
			Wording: "g1_partition_anchor_unavailable{BVN2,70}: the receipt does not prove the anchor transaction into the certified Directory root"},
			apply: func(d map[string]any) error {
				p := []any{"evidence", "anchors", "acc://bvn-BVN2.acme", "receipt", "entries", 1, "hash"}
				h, ok := memberAt(d, p...).(string)
				if !ok {
					return fmt.Errorf("the base document has no %v", p)
				}
				return setMember(d, p, flipFirstByte(h))
			}},

		// Values the codec decodes to nothing.
		{RobustCase: RobustCase{Name: "page-account-null", Base: dn, Edit: "evidence/pages/0/account = null",
			Description: "a proven page's account is JSON null: no account at all (it was re-encoded to binary)",
			Expect:      "refused", Wording: "page acc://pv2-cust-5.acme/data is <nil>, not an account"},
			apply: setNull([]any{"evidence", "pages", 0, "account"})},
		{RobustCase: RobustCase{Name: "vote-hop-signature-holds-no-signature", Base: "production-sequenced-bound", Edit: "evidence/votes/0/hops/0/signature = zeros",
			Description: "the key signature of a vote's cause chain is a run of zero bytes: Accumulate's decoder answers neither a signature nor an error (the nil was handed on and dereferenced)",
			Expect:      "refused", Wording: "vote of acc://pv2-bank-5.acme/book: key signature: it holds no signature"},
			apply: func(d map[string]any) error {
				p := []any{"evidence", "votes", 0, "hops", 0, "signature"}
				z, err := zeroed(d, p...)
				if err != nil {
					return err
				}
				return setMember(d, p, z)
			}},
		{RobustCase: RobustCase{Name: "transaction-names-an-authority-with-no-url", Base: "update-account-auth-add-op-authority-did-not-vote", Edit: "evidence/transaction: the AddAccountAuthority operation's authority absent",
			Description: "the carried transaction adds an authority that has no URL: it cannot have been executed and cannot be required (it was read as a nil URL)",
			Expect:      "refused", State: proofv2.StateTransactionMismatch, Partition: "BVN1", Block: xworld.BlockBVN1,
			Wording: "g1_transaction_mismatch{BVN1,50}: a transaction names an authority with no URL"},
			apply: func(d map[string]any) error {
				h, ok := memberAt(d, "evidence", "transaction").(string)
				if !ok {
					return fmt.Errorf("the base document carries no transaction")
				}
				raw, err := hex.DecodeString(h)
				if err != nil {
					return err
				}
				txn := new(protocol.Transaction)
				if err := txn.UnmarshalBinary(raw); err != nil {
					return err
				}
				body, ok := txn.Body.(*protocol.UpdateAccountAuth)
				if !ok || len(body.Operations) == 0 {
					return fmt.Errorf("the base transaction is %T", txn.Body)
				}
				add, ok := body.Operations[0].(*protocol.AddAccountAuthorityOperation)
				if !ok {
					return fmt.Errorf("the base transaction's first operation is %T", body.Operations[0])
				}
				add.Authority = nil
				out, err := txn.MarshalBinary()
				if err != nil {
					return err
				}
				return setMember(d, []any{"evidence", "transaction"}, hex.EncodeToString(out))
			}},
		{RobustCase: RobustCase{Name: "anchor-message-carries-no-transaction", Base: conf, Edit: "evidence/anchor/message/message/transaction = null",
			Description: "the evidence 2.0 anchor message wraps a transaction message that carries no transaction: the anchor's body type was asked of nothing",
			Expect:      "refused", Wording: "partition anchor carries no transaction body"},
			apply: setNull([]any{"evidence", "anchor", "message", "message", "transaction"})},
		{RobustCase: RobustCase{Name: "anchor-message-names-no-source", Base: conf, Edit: "evidence/anchor/message/source = null",
			Description: "the evidence 2.0 anchor message names no source: the partition was read from nothing",
			Expect:      "refused", Wording: "partition anchor names no source, destination or principal"},
			apply: setNull([]any{"evidence", "anchor", "message", "source"})},

		// Values Accumulate's JSON codec faults on.
		{RobustCase: RobustCase{Name: "codec-anchor-body-member-null", Base: dn, Edit: "evidence/anchor/message/message/transaction/body/rootChainAnchor = null",
			Description: "a member of the anchor's body is JSON null: Accumulate's decoder of a BlockValidatorAnchor dereferences it",
			Expect:      "refused", Wording: codecFault("anchor message")},
			apply: setNull([]any{"evidence", "anchor", "message", "message", "transaction", "body", "rootChainAnchor"})},
		{RobustCase: RobustCase{Name: "codec-validator-member-null", Base: dn, Edit: "evidence/check/network/record/validators/0/publicKeyHash = null",
			Description: "a validator of the network record has a null key hash: Accumulate's decoder of a ValidatorInfo dereferences it",
			Expect:      "refused", Wording: codecFault("set check network")},
			apply: setNull([]any{"evidence", "check", "network", "record", "validators", 0, "publicKeyHash"})},
		{RobustCase: RobustCase{Name: "codec-major-anchor-body-member-null", Base: dn, Edit: "majors/0/anchor/message/transaction/body/stateTreeAnchor = null",
			Description: "a member of a spine record's DirectoryAnchor body is JSON null: Accumulate's decoder of a DirectoryAnchor dereferences it",
			Expect:      "refused", Wording: codecFault("major 1")},
			apply: setNull([]any{"majors", 0, "anchor", "message", "transaction", "body", "stateTreeAnchor"})},
		{RobustCase: RobustCase{Name: "codec-major-signature-member-null", Base: dn, Edit: "majors/0/signatures/0/transactionHash = null",
			Description: "a member of a spine record's validator signature is JSON null: Accumulate's decoder of an ED25519Signature dereferences it",
			Expect:      "refused", Wording: codecFault("major 1")},
			apply: setNull([]any{"majors", 0, "signatures", 0, "transactionHash"})},
		{RobustCase: RobustCase{Name: "codec-certify-run-signature-null", Base: dn, Edit: "evidence/certify/0/signatures/0 = null",
			Description: "a signature of a minor-root run is JSON null: Accumulate's encoder of a MinorRootRecord dereferences it",
			Expect:      "refused", Wording: codecFault("certify run 0")},
			apply: setNull([]any{"evidence", "certify", 0, "signatures", 0})},

		// Receipts with a null step.
		{RobustCase: RobustCase{Name: "spine-network-update-receipt-step-null", Base: conf, Edit: "majors/1/updates/0/receipt/entries/0 = null",
			Description: "a network update's receipt in a spine record has a null step: Accumulate's receipt validation reads the hash of every step",
			Expect:      "refused", Wording: "spine: major block 2: incomplete network update proof"},
			apply: setNull([]any{"majors", 1, "updates", 0, "receipt", "entries", 0})},

		// The order more than one defect is judged in.
		{RobustCase: RobustCase{Name: "anchors-two-unimportable-first-in-key-order", Base: "anchor-wrapper-source-altered", Edit: "evidence/anchors/{acc://bvn-BVN2.acme,acc://bvn-BVN4.acme}/message = 7",
			Description: "two anchors that do not import, the BVN2 and BVN4 entries: the anchors are imported in ascending key order, so the refusal names BVN2's, every time",
			Expect:      "refused", Prefix: "anchor acc://bvn-BVN2.acme: "},
			apply: func(d map[string]any) error {
				for _, k := range []string{"acc://bvn-BVN2.acme", "acc://bvn-BVN4.acme"} {
					if err := setMember(d, []any{"evidence", "anchors", k, "message"}, json.Number("7")); err != nil {
						return err
					}
				}
				return nil
			}},
	}
}

// verifyGuarded verifies a portable document as another language's verifier reads the file; a panic is the error "panic: ...", never a crash.
func verifyGuarded(doc []byte) (rep *proofv2.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			rep, err = nil, fmt.Errorf("PANIC: %v", r)
		}
	}()
	back := new(proofv2.Portable)
	if err := json.Unmarshal(doc, back); err != nil {
		return nil, err
	}
	return proofv2.VerifyPortable(back)
}

// writeRobust1 writes the robustness suite into out and refuses to write a vector the Go verifier does not judge as the manifest says;
// every vector that does not is reported, not only the first.
func writeRobust1(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	m := RobustManifest{Format: XManifestFormatRobust1, Domain: proofv2.DomainG1V4, PortableFormat: proofv2.PortableFormat}
	var problems []string
	for _, s := range robust1Specs() {
		raw, err := robustBase(s.Base)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		if err := s.apply(doc); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		edited, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		rep, verr := verifyGuarded(edited)
		xc := s.RobustCase
		xc.File = s.Name + ".json"
		switch s.Expect {
		case "refused":
			if verr == nil {
				problems = append(problems, fmt.Sprintf("%s: the Go verifier accepted a refused vector", s.Name))
				break
			}
			if strings.HasPrefix(verr.Error(), "PANIC") {
				problems = append(problems, fmt.Sprintf("%s: %v", s.Name, verr))
				break
			}
			var ns *proofv2.NamedState
			named := errors.As(verr, &ns)
			switch {
			case s.State == "" && named:
				problems = append(problems, fmt.Sprintf("%s: refused with the named state %v, the vector names none", s.Name, ns))
			case s.State != "" && (!named || ns.Code != s.State || ns.Partition != s.Partition || ns.Block != s.Block):
				problems = append(problems, fmt.Sprintf("%s: refused with %v, the vector says %s{%s,%d}", s.Name, verr, s.State, s.Partition, s.Block))
			}
			if xc.Wording == "" && xc.Prefix == "" {
				problems = append(problems, fmt.Sprintf("%s: refused with %q, which the vector does not name", s.Name, verr.Error()))
				break
			}
			if xc.Wording != "" && verr.Error() != xc.Wording {
				problems = append(problems, fmt.Sprintf("%s: refused with %q, the vector's wording is %q", s.Name, verr.Error(), xc.Wording))
			}
			if xc.Prefix == "" {
				xc.Prefix = xc.Wording
			}
			if xc.Wording == "" {
				xc.Wording = verr.Error()
			}
			if !strings.HasPrefix(verr.Error(), xc.Prefix) {
				problems = append(problems, fmt.Sprintf("%s: refused with %q, which does not begin %q", s.Name, verr.Error(), xc.Prefix))
			}
		case "verified":
			if verr != nil {
				problems = append(problems, fmt.Sprintf("%s: the Go verifier refused a verified vector: %v", s.Name, verr))
				break
			}
			xc.Report = xreport(rep)
		default:
			return fmt.Errorf("%s: expect %q", s.Name, s.Expect)
		}
		edited = append(edited, 0x0a)
		sum := sha256.Sum256(edited) // the hash of the file's exact bytes
		xc.SHA256 = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(out, xc.File), edited, 0o644); err != nil {
			return err
		}
		m.Cases = append(m.Cases, xc)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d vector(s) are not judged as the suite says:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	mj = append(mj, '\n')
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), mj, 0o644); err != nil {
		return err
	}
	// The vectors are shared with the TypeScript verifier byte for byte; their hashes cover the exact bytes.
	attrs := "# The vectors are shared with the TypeScript verifier byte for byte; their hashes cover the exact bytes.\n* -text\n"
	if err := os.WriteFile(filepath.Join(out, ".gitattributes"), []byte(attrs), 0o644); err != nil {
		return err
	}
	h := sha256.Sum256(mj)
	return os.WriteFile(filepath.Join(out, "MANIFEST.sha256"), []byte(hex.EncodeToString(h[:])+"  manifest.json\n"), 0o644)
}
