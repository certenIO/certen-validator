// Copyright 2026 Certen Protocol

package proof

import (
	"context"
	"encoding/json"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	jm "github.com/certen/independant-validator/internal/jsonmutate"
)

// RB9-L: the vote evidence of a block's certificate is chosen by its proposer, and verifyIntentCertificate reads it with DecodeVoteEvidence,
// VerifyVoteEvidence (govvote.VerifyEvidence: the transaction, every signature, arrival and recorded vote with its receipt, every page's
// history and the authority set it is replayed from) and DeclaredGovernanceOfEvidence. The two live vote evidences of this package
// (Kermit: the RB4 Phase C intent and the delegated case C) are mutated at every member by internal/jsonmutate - removed, null, the wrong
// type, empty, a hex member cut, flipped or zeroed and, for a binary value, well-formed with each of its fields absent in turn - and judged
// exactly as the certificate is judged.
//
// For every mutation: no panic; and either a refusal, or the very input of the original (the decoded evidence is the same value), or a
// member that verification does not read, listed in voteEvidenceUnread with the reason it does not matter. A mutation that is accepted and
// not listed fails, and so does a listed member that no mutation exercised.
func TestVoteEvidenceRefusesEveryCraftedMemberOfTheLiveEvidence(t *testing.T) {
	unread := map[string]string{}
	total := 0
	for _, name := range voteEvidenceFixtures {
		g0, rec, raw := voteEvidenceFixture(t, name)
		var env struct {
			VoteEvidence json.RawMessage `json:"voteEvidence"`
		}
		if err := json.Unmarshal(raw, &env); err != nil || len(env.VoteEvidence) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		doc := []byte(env.VoteEvidence)

		canon := func(b []byte) string {
			var ev govvote.Evidence
			if json.Unmarshal(b, &ev) != nil {
				return ""
			}
			return jm.Canonical(ev)
		}
		baseInput := canon(doc)
		judge := func(b []byte) jm.Verdict {
			same := baseInput != "" && canon(b) == baseInput
			ev, err := DecodeVoteEvidence(b)
			if err != nil {
				return jm.Verdict{Refused: true, Err: "decode: " + err.Error(), Noop: same}
			}
			if err := VerifyVoteEvidence(context.Background(), g0, ev, rec); err != nil {
				return jm.Verdict{Refused: true, Err: err.Error(), Noop: same}
			}
			// The declaration is part of the verdict: an intent that declares none is the value nil, and the older live evidence (case C)
			// holds a transaction with no governance blob, which is a refusal of the declaration - the same one for every mutation that
			// leaves the transaction alone.
			declared, err := DeclaredGovernanceOfEvidence(ev)
			if err != nil {
				return jm.Verdict{Report: "declaration refused: " + err.Error(), Noop: same}
			}
			j, err := json.Marshal(declared)
			if err != nil {
				return jm.Verdict{Panicked: "harness: the declaration does not encode: " + err.Error()}
			}
			return jm.Verdict{Report: string(j), Noop: same}
		}
		base := jm.Guard(func() jm.Verdict { return judge(doc) })
		if base.Panicked != "" || base.Refused {
			t.Fatalf("%s: the unmutated vote evidence is not accepted: panic %q, refusal %q", name, base.Panicked, base.Err)
		}

		tree, err := jm.ParseTree(doc)
		if err != nil {
			t.Fatal(err)
		}
		var muts []jm.Mutation
		jm.Walk(tree, jm.WalkSpec{ArrayLimit: 3}, func(p jm.Path, v any) { muts = append(muts, jm.MutationsOf(p, v)...) })
		muts = append(muts, jm.WholeDocument()...)
		total += len(muts)

		byClass := map[string][]string{}
		for _, o := range jm.Run(tree, muts, judge, runtime.GOMAXPROCS(0)) {
			where := name + ": " + o.M.String()
			switch {
			case o.V.Panicked != "":
				byClass["PANIC "+o.V.Panicked] = append(byClass["PANIC "+o.V.Panicked], where)
			case o.V.Noop:
				if o.V.Refused || o.V.Report != base.Report {
					byClass["The input is the original's and the verdict is not"] = append(byClass["The input is the original's and the verdict is not"], where)
				}
			case o.V.Refused:
			case o.V.Report != base.Report:
				byClass["Accepted with a vote or declaration other than the original's"] = append(byClass["Accepted with a vote or declaration other than the original's"], where)
			default:
				unread[o.M.Path.Shape()] = where
			}
		}
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
	}
	t.Logf("%d mutations of %d live vote evidences; %d member shapes are accepted when altered", total, len(voteEvidenceFixtures), len(unread))
	shapes := make([]string, 0, len(unread))
	for k := range unread {
		shapes = append(shapes, k)
		t.Logf("accepted when altered: %s (e.g. %s)", k, unread[k])
	}
	sort.Strings(shapes)
	for _, k := range shapes {
		if _, ok := voteEvidenceUnread[k]; !ok {
			t.Errorf("a member that is not listed as unread is accepted when altered: %s (e.g. %s)", k, unread[k])
		}
	}
	for k := range voteEvidenceUnread {
		if _, ok := unread[k]; !ok {
			t.Errorf("voteEvidenceUnread lists %q, which no mutation exercised", k)
		}
	}
}

// voteEvidenceUnread are the member shapes (array indices are *) that VerifyVoteEvidence and DeclaredGovernanceOfEvidence do not read: a
// vote evidence altered at one of them is accepted with the same vote and the same declaration. The value is the reason it does not matter.
var voteEvidenceUnread = map[string]string{}
