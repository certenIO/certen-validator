// Copyright 2026 Certen Protocol

package consensus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	jm "github.com/certen/independant-validator/internal/jsonmutate"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

// RB9-L: what consensus judges of a certificate's proof v2 is refused, never a panic, whatever the certificate holds. A block is built by
// its proposer, so every member of the certificate is chosen by someone who may be Byzantine, and a panic in FinalizeBlock stops every
// validator that judges it. The real stored evidence 2.1 certificate of TestRulesV15AcceptsAVerifiedEvidence21 is mutated at every member
// of the four things judgeProofV2 reads - the certificate (its proof v2, the key page and book it declares and the vote evidence the
// binding reads) and the governance levels G0, G1 and G2 - by internal/jsonmutate: removed, null, the wrong type, empty, a hex member cut,
// flipped or zeroed and, for a binary value (a transaction, a signature), well-formed with each of its fields absent in turn. The
// certificate is decoded as a block's is (IntentCertificateEvidence.UnmarshalJSON, so proofv2.UnmarshalCertifiedEvidence), and judged by
// judgeProofV2 with the REAL verifier, the REAL binding and the REAL govRoot v4.
//
// The preconditions intentInputsV2 enforces before it calls judgeProofV2 are the test's too: a certificate, G0, G1 and G2 present.
//
// For every mutation: no panic; and a certificate that is still accepted commits a govRoot different from the original's (the mutation
// changed what the proposer's signed root is over, so the claim it carries no longer matches: verifyIntentCertificate refuses it), or
// commits the same root over the same report, in which case the member is one judgeProofV2 does not read (craftedUnread).

// craftedCertificate is the JSON the instrument mutates: what judgeProofV2 reads of a block.
type craftedCertificate struct {
	Certificate struct {
		KeyPageURL   string          `json:"key_page_url"`
		KeyBookURL   string          `json:"key_book_url"`
		VoteEvidence json.RawMessage `json:"vote_evidence"`
		ProofV2      json.RawMessage `json:"proof_v2"`
	} `json:"certificate"`
	G0 json.RawMessage `json:"g0"`
	G1 json.RawMessage `json:"g1"`
	G2 json.RawMessage `json:"g2"`
}

// decodeCrafted decodes a crafted document as a block's certificate and governance levels are decoded.
func decodeCrafted(raw []byte) (cert *IntentCertificateEvidence, g0 *govproof.G0Result, g1 *govproof.G1Result, g2 *govproof.G2Result, err error) {
	var wrapper struct {
		Certificate json.RawMessage `json:"certificate"`
		G0          json.RawMessage `json:"g0"`
		G1          json.RawMessage `json:"g1"`
		G2          json.RawMessage `json:"g2"`
	}
	if err = json.Unmarshal(raw, &wrapper); err != nil {
		return nil, nil, nil, nil, err
	}
	if err = json.Unmarshal(wrapper.G0, &g0); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("g0: %w", err)
	}
	if err = json.Unmarshal(wrapper.G1, &g1); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("g1: %w", err)
	}
	if err = json.Unmarshal(wrapper.G2, &g2); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("g2: %w", err)
	}
	cert = new(IntentCertificateEvidence)
	if err = json.Unmarshal(wrapper.Certificate, cert); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("certificate: %w", err)
	}
	return cert, g0, g1, g2, nil
}

// craftedInput is what judgeProofV2 is given of a crafted document, as one string that does not tell null, empty, zero and absent apart;
// "" when the document does not decode.
func craftedInput(raw []byte) string {
	cert, g0, g1, g2, err := decodeCrafted(raw)
	if err != nil {
		return ""
	}
	// The vote evidence reaches judgeProofV2 as raw JSON that ProofV2Root decodes into a govvote.Evidence: what it is given is that value.
	voteInput := string(cert.VoteEvidence)
	var gev govvote.Evidence
	if len(cert.VoteEvidence) > 0 && json.Unmarshal(cert.VoteEvidence, &gev) == nil {
		voteInput = jm.Canonical(gev)
	}
	c := *cert
	c.VoteEvidence = nil
	return jm.Canonical(struct {
		Certificate *IntentCertificateEvidence
		Vote        string
		G0          *govproof.G0Result
		G1          *govproof.G1Result
		G2          *govproof.G2Result
	}{&c, voteInput, g0, g1, g2})
}

// judgeCrafted judges a crafted certificate's proof v2 as consensus does. The report of an accepted one is the govRoot it commits (64 hex
// characters) followed by the report's JSON. A mutated document that decodes to the very input of the original (base) is marked Noop.
func judgeCrafted(w real21World, c real21Cert, base []byte) jm.Judge {
	baseInput := craftedInput(base)
	return func(raw []byte) jm.Verdict {
		same := baseInput != "" && craftedInput(raw) == baseInput
		cert, g0, g1, g2, err := decodeCrafted(raw)
		if err != nil {
			return jm.Verdict{Refused: true, Err: "decode: " + err.Error(), Noop: same}
		}
		if g0 == nil || g1 == nil || g2 == nil {
			return jm.Verdict{Refused: true, Err: "G0, G1 and G2 are all required", Noop: same}
		}
		root, rep, err := judgeProofV2(cert, g0, g1, g2, w.inc, c.operationID, c.accRoot, w.spine, g1Active, nil)
		if err != nil {
			return jm.Verdict{Refused: true, Err: err.Error(), Noop: same}
		}
		j, err := json.Marshal(rep)
		if err != nil {
			return jm.Verdict{Panicked: "harness: the report does not encode: " + err.Error()}
		}
		return jm.Verdict{Report: hex.EncodeToString(root[:]) + string(j), Noop: same}
	}
}

func TestJudgeProofV2RefusesEveryCraftedMemberOfARealCertificate(t *testing.T) {
	w := loadReal21World(t)
	c := real21CertificateFor(t, w, w.clone(t))

	var cc craftedCertificate
	cc.Certificate.KeyPageURL, cc.Certificate.KeyBookURL = c.cert.KeyPageURL, c.cert.KeyBookURL
	cc.Certificate.VoteEvidence = c.cert.VoteEvidence
	pv2, err := json.Marshal(c.cert.ProofV2)
	if err != nil {
		t.Fatal(err)
	}
	cc.Certificate.ProofV2 = pv2
	for _, g := range []struct {
		dst *json.RawMessage
		v   any
	}{{&cc.G0, c.g0}, {&cc.G1, c.g1}, {&cc.G2, c.g2}} {
		if *g.dst, err = json.Marshal(g.v); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(cc)
	if err != nil {
		t.Fatal(err)
	}

	judge := judgeCrafted(w, c, raw)
	base := jm.Guard(func() jm.Verdict { return judge(raw) })
	if base.Panicked != "" || base.Refused {
		t.Fatalf("the unmutated certificate is not accepted by judgeProofV2: panic %q, refusal %q", base.Panicked, base.Err)
	}
	baseRoot, baseReport := base.Report[:64], base.Report[64:]

	tree, err := jm.ParseTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	spec := jm.WalkSpec{ArrayLimit: 3}
	var muts []jm.Mutation
	jm.Walk(tree, spec, func(p jm.Path, v any) { muts = append(muts, jm.MutationsOf(p, v)...) })
	muts = append(muts, jm.WholeDocument()...)
	t.Logf("%d mutations of the certificate and G0-G2 of the real stored evidence 2.1", len(muts))

	outs := jm.Run(tree, muts, judge, runtime.GOMAXPROCS(0))
	byClass := map[string][]string{}
	unread := map[string]string{}
	committed := 0
	for _, o := range outs {
		where := o.M.String()
		switch {
		case o.V.Panicked != "":
			byClass["PANIC "+o.V.Panicked] = append(byClass["PANIC "+o.V.Panicked], where)
		case o.V.Noop:
			if o.V.Refused || o.V.Report != base.Report {
				byClass["The input is the original's and the verdict is not"] = append(byClass["The input is the original's and the verdict is not"], where)
			}
		case o.V.Refused:
		case o.V.Report[:64] != baseRoot:
			committed++ // accepted, and over a different govRoot: the claim the proposer signed no longer matches
		case o.V.Report[64:] == baseReport:
			unread[o.M.Path.Shape()] = where
		default:
			byClass["Accepted over the same govRoot with a different report"] = append(byClass["Accepted over the same govRoot with a different report"], where)
		}
	}
	t.Logf("%d mutations are accepted over a different govRoot; %d members are not read", committed, len(unread))
	classes := make([]string, 0, len(byClass))
	for k := range byClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	for _, k := range classes {
		show := byClass[k]
		if len(show) > 4 {
			show = show[:4]
		}
		t.Errorf("%s\n   %d mutation(s), e.g.\n   %s", k, len(byClass[k]), strings.Join(show, "\n   "))
	}
	checkCraftedUnread(t, unread)
}

// craftedUnread are the members of the crafted document that judgeProofV2 does not read: a certificate judged with one of them removed,
// nulled or replaced is accepted over the same govRoot and the same report. Each is a member shape (array indices are *); the value is the
// reason it does not matter to this judgement.
var craftedUnread = unreadTable(
	ug("the Anchors entry for the transaction's own partition must equal Evidence.Anchor and is set aside when it does "+
		"(xverify.go verify21): a document whose only entries are its own carries nothing that field does not",
		"certificate/proof_v2/anchors", "certificate/proof_v2/anchors/acc://bvn-BVN1.acme"),
	ug("merkle.Receipt carries, besides Start, Entries and Anchor, position fields (StartIndex, EndIndex, End) that Validate does not read; "+
		"a minor-root run's merkle state keeps a HashList the verifier does not read, and a validator signature's TransactionHash is not read "+
		"(the quorum check verifies each signature over the delivered anchor message)",
		"certificate/proof_v2/certify/*"),
	ug("ChainRoot.Anchor is a restatement recomputed from Pending (an empty one is not compared); a chain's Name is read only to find "+
		"the main chain, and for a page the chains the timeline looks up by name (the names are not covered by the chain component of the "+
		"state hash: a finding); the account URL of the network and globals proofs is a label - the set check reads the account by its bytes, "+
		"which are hashed into the receipt and must equal the record the spine derived; stateReceipt.localBlock is bookkeeping of the served receipt",
		"certificate/proof_v2/check/routing/chains/*/anchor", "certificate/proof_v2/check/routing/chains/*/name",
		"certificate/proof_v2/check/routing/stateReceipt/localBlock", "certificate/proof_v2/check/set/globals/accountUrl",
		"certificate/proof_v2/check/set/globals/chains/*/anchor", "certificate/proof_v2/check/set/globals/chains/*/name",
		"certificate/proof_v2/check/set/globals/stateReceipt/localBlock", "certificate/proof_v2/check/set/network/accountUrl",
		"certificate/proof_v2/check/set/network/chains/*/anchor", "certificate/proof_v2/check/set/network/chains/*/name",
		"certificate/proof_v2/check/set/network/stateReceipt/localBlock", "certificate/proof_v2/pages/*/chains/*/anchor",
		"certificate/proof_v2/pages/*/chains/*/name"),
	ug("GoverningFactsFromVoteEvidence (intentcert/bind_v21.go) takes of the intent's vote evidence the governed transaction, the account, "+
		"the authorities and the extra authorities, each signature's bytes, signer and block, and each vote's authority, origin and block; it "+
		"checks them against the proven pages. The version, the vote values, the ids and a fact whose page is not among the proven pages "+
		"(a block comparison with nothing to compare) are not read here, and every fact is re-derived from the evidence by verifyIntentProof "+
		"(govvote.Evidence), which runs after judgeProofV2 and refuses the record the evidence does not reach",
		"certificate/vote_evidence/authorities", "certificate/vote_evidence/authorities/*", "certificate/vote_evidence/authoritySet",
		"certificate/vote_evidence/signatures/*/fact",
		"certificate/vote_evidence/signatures/*/fact/Block", "certificate/vote_evidence/signatures/*/fact/Signer",
		"certificate/vote_evidence/signatures/*/signature",
		"certificate/vote_evidence/version", "certificate/vote_evidence/votes", "certificate/vote_evidence/votes/*",
		"certificate/vote_evidence/votes/*/fact", "certificate/vote_evidence/votes/*/fact/Authority",
		"certificate/vote_evidence/votes/*/fact/Block", "certificate/vote_evidence/votes/*/fact/Origin"),
	ug("members of the governance results that neither the binding reads (G0's entry, receipt start, witness and block are) nor the "+
		"canonical v2 JSON govRoot commits (proof.CanonicalG0JSONV2 / CanonicalG1JSONV2 / CanonicalG2JSONV2) includes: receipt metadata "+
		"(majorBlock), entry counts, message ids and the verifier's printed output",
		"g0/receipt/majorBlock", "g1/authority_snapshot/genesis/receipt/majorBlock", "g1/authority_snapshot/mutations/*/receipt/majorBlock",
		"g1/authority_snapshot/validation/totalEntries", "g1/receipt/majorBlock", "g1/validated_signatures/*/messageID",
		"g1/validated_signatures/*/receipt/majorBlock", "g2/authority_snapshot/genesis/receipt/majorBlock",
		"g2/authority_snapshot/mutations/*/receipt/majorBlock", "g2/authority_snapshot/validation/totalEntries",
		"g2/outcome_leaf/payloadBinding/goVerifierOutput", "g2/receipt/majorBlock", "g2/validated_signatures/*/messageID",
		"g2/validated_signatures/*/receipt/majorBlock"),
)

type unreadGroup struct {
	reason string
	shapes []string
}

func ug(reason string, shapes ...string) unreadGroup { return unreadGroup{reason, shapes} }

func unreadTable(groups ...unreadGroup) map[string]string {
	out := map[string]string{}
	for _, g := range groups {
		for _, s := range g.shapes {
			out[s] = g.reason
		}
	}
	return out
}

func checkCraftedUnread(t *testing.T, observed map[string]string) {
	t.Helper()
	var unlisted []string
	for k := range observed {
		if _, ok := craftedUnread[k]; !ok {
			unlisted = append(unlisted, k)
		}
	}
	sort.Strings(unlisted)
	for _, k := range unlisted {
		t.Errorf("a member that is not listed as unread is judged exactly as before: %s (e.g. %s)", k, observed[k])
	}
	var stale []string
	for k := range craftedUnread {
		if _, ok := observed[k]; !ok {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		t.Errorf("craftedUnread lists %q, which no mutation exercised", k)
	}
}
