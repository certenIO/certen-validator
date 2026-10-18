// Command g1shadowcompare is the RB9-E shadow comparison: for each live intent captured by cmd/g1fixture it sets the decision the chain
// takes today (rules v14: G1 of the production prover, the vote record evaluated again from its evidence, the pages v1 replayed) beside
// the decision rules v15 would take after the cross-partition activation (the evidence 2.1 verified from Kermit's genesis, bound to the
// intent's own facts, committed under govRoot v4), page by page and vote by vote. It reads only, needs no network and no database, and
// prints one block per intent and a last line
//
//	DISAGREEMENTS=<n> VERIFICATION_FAILURES=<n> NOT_RUN=<n>
//
// It exits 0 only when all three are zero and something was compared, 1 on any disagreement or verification failure, 3 when there are
// none but some decision was not run, 4 when nothing was compared at all (an empty window is not a zero-disagreement result), 2 on a usage error.
//
// A DISAGREEMENT is a difference between what v1 established and what the 2.1 document proves: a page whose authority-deciding fields differ
// (CrossCheckPages), a page v1 evaluated that the document does not prove, a vote v1 recorded that the document does not carry (or the
// reverse), or a v14 verdict that the v15 verdict contradicts. A VERIFICATION FAILURE is anything that stops the 2.1 decision from being
// reached: a document that does not decode or verify from genesis, a report with anything unproven, a binding or govRoot refusal, a vote
// record that does not evaluate again from its evidence.
//
//	g1shadowcompare -fixtures DIR -incarnation-evidence kermit.json [-pin hex32]
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
)

// fixture is cmd/g1fixture's file (the members this command reads).
type fixture struct {
	Format        string          `json:"format"`
	Name          string          `json:"name"`
	Account       string          `json:"account"`
	TxHash        string          `json:"tx_hash"`
	KeyBook       string          `json:"key_book"`
	KeyPage       string          `json:"key_page"`
	G0            json.RawMessage `json:"g0"`
	G1            json.RawMessage `json:"g1"`
	G2            json.RawMessage `json:"g2"`
	Authorization json.RawMessage `json:"authorization"`
	VoteEvidence  json.RawMessage `json:"vote_evidence"`
	ProofV2       json.RawMessage `json:"proof_v2"`
	Archive       json.RawMessage `json:"archive"`
}

type result struct {
	Name, Account, Tx string
	V14               string   // what the chain decides today
	V15               string   // what rules v15 would decide after the activation
	Pages             int      // pages compared
	Disagree          []string // each a difference
	Failures          []string // each a reason the v15 decision could not be reached
	NotRun            []string
}

func main() {
	dir := flag.String("fixtures", "", "directory holding <name>.json.gz and <name>.capture.json.gz (cmd/g1fixture)")
	window := flag.Bool("window", false, "read every captured intent of a time window through the read-only database session in CERTEN_DB (window.go)")
	since := flag.String("since", "", "window: start, a timestamp Postgres reads (2026-10-18T08:00:00Z)")
	until := flag.String("until", "", "window: end (exclusive)")
	incPath := flag.String("incarnation-evidence", "pkg/proof/testdata/incarnation/kermit.json", "incarnation evidence JSON")
	pinHex := flag.String("pin", "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0", "pinned incarnation, hex32")
	flag.Parse()
	if *dir == "" && !*window {
		fmt.Fprintln(os.Stderr, "g1shadowcompare: -fixtures or -window is required")
		os.Exit(2)
	}
	var code int
	var err error
	if *window {
		if *since == "" || *until == "" || os.Getenv("CERTEN_DB") == "" {
			fmt.Fprintln(os.Stderr, "g1shadowcompare: -window needs -since, -until and CERTEN_DB (a read-only session)")
			os.Exit(2)
		}
		code, err = runWindowMode(*dir, *incPath, *pinHex, *since, *until)
	} else {
		code, err = run(*dir, *incPath, *pinHex)
	}
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func loadIncarnation(incPath, pinHex string) (*proof.IncarnationReport, error) {
	raw, err := os.ReadFile(incPath)
	if err != nil {
		return nil, err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		return nil, fmt.Errorf("incarnation evidence: %w", err)
	}
	incRep, err := inc.Verify()
	if err != nil {
		return nil, fmt.Errorf("the incarnation evidence does not verify: %w", err)
	}
	if b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(pinHex), "0x")); err != nil || len(b) != 32 || !bytes.Equal(b, incRep.Incarnation[:]) {
		return nil, fmt.Errorf("-pin is not the incarnation the evidence verifies to (%x)", incRep.Incarnation)
	}
	return incRep, nil
}

func runWindowMode(dir, incPath, pinHex, since, until string) (int, error) {
	incRep, err := loadIncarnation(incPath, pinHex)
	if err != nil {
		return 0, err
	}
	return runWindow(context.Background(), os.Getenv("CERTEN_DB"), since, until, dir, func() *fixtureEnv { return &fixtureEnv{incRep: incRep} })
}

func run(dir, incPath, pinHex string) (int, error) {
	incRep, err := loadIncarnation(incPath, pinHex)
	if err != nil {
		return 0, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if err != nil {
		return 0, err
	}
	sort.Strings(files)
	var results []*result
	for _, f := range files {
		if strings.HasSuffix(f, ".capture.json.gz") || filepath.Base(f) == "archive.json.gz" {
			continue
		}
		results = append(results, compareOne(context.Background(), f, incRep))
	}
	if len(results) == 0 {
		return 0, fmt.Errorf("no fixture in %s", dir)
	}
	var dis, fail, notRun, pages int
	for _, r := range results {
		fmt.Printf("== %s  %s  tx %s\n", r.Name, r.Account, short(r.Tx))
		fmt.Printf("   v14 (live rule) : %s\n   v15 (G1 rule)   : %s\n   pages compared  : %d\n", r.V14, r.V15, r.Pages)
		for _, d := range r.Disagree {
			fmt.Println("   DISAGREE:", d)
		}
		for _, d := range r.Failures {
			fmt.Println("   VERIFICATION FAILURE:", d)
		}
		for _, d := range r.NotRun {
			fmt.Println("   NOT RUN:", d)
		}
		dis += len(r.Disagree)
		fail += len(r.Failures)
		notRun += len(r.NotRun)
		pages += r.Pages
	}
	fmt.Printf("\n%d intents, %d page comparisons\n", len(results), pages)
	fmt.Printf("DISAGREEMENTS=%d VERIFICATION_FAILURES=%d NOT_RUN=%d\n", dis, fail, notRun)
	switch {
	case dis+fail > 0:
		return 1, nil
	case notRun > 0:
		return 3, nil
	}
	return 0, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func readGz(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	j, err := io.ReadAll(z)
	if err != nil {
		return err
	}
	if raw, ok := v.(*[]byte); ok {
		*raw = j
		return nil
	}
	return json.Unmarshal(j, v)
}

func compareOne(ctx context.Context, path string, incRep *proof.IncarnationReport) *result {
	r := &result{Name: strings.TrimSuffix(filepath.Base(path), ".json.gz")}
	fail := func(f string, a ...any) { r.Failures = append(r.Failures, fmt.Sprintf(f, a...)) }
	var f fixture
	if err := readGz(path, &f); err != nil {
		fail("the fixture does not decode: %v", err)
		return r
	}
	r.Account, r.Tx = f.Account, f.TxHash
	var capRaw []byte
	if err := readGz(strings.TrimSuffix(path, ".json.gz")+".capture.json.gz", &capRaw); err != nil {
		fail("the validators' capture is missing: %v", err)
		return r
	}
	cp, err := proofv2shadow.DecodeCapture(capRaw)
	if err != nil {
		fail("the capture does not decode: %v", err)
		return r
	}

	var g0 proof.G0Result
	var g1 proof.G1Result
	var g2 proof.G2Result
	var rec proof.AuthorizationRecord
	ev21 := new(proofv2.Evidence)
	for _, d := range []struct {
		raw json.RawMessage
		v   any
		n   string
	}{{f.G0, &g0, "G0"}, {f.G1, &g1, "G1"}, {f.G2, &g2, "G2"}, {f.Authorization, &rec, "the vote record"}, {f.ProofV2, ev21, "proof v2"}} {
		if err := json.Unmarshal(d.raw, d.v); err != nil {
			fail("%s does not decode: %v", d.n, err)
			return r
		}
	}
	gev, err := proof.DecodeVoteEvidence(f.VoteEvidence)
	if err != nil {
		fail("the vote evidence does not decode: %v", err)
		return r
	}

	// ---- v14: what the chain decides today, from the intent's own v1 facts
	if err := proof.VerifyVoteEvidence(ctx, &g0, gev, &rec); err != nil {
		fail("the G1 vote record does not evaluate again from its evidence: %v", err)
	}
	av, err := govvote.VerifyEvidence(ctx, gev)
	switch {
	case err != nil:
		fail("v1 cannot evaluate the vote evidence: %v", err)
		r.V14 = "not reached"
	case g1.G1ProofComplete && g1.ThresholdSatisfied && av.Satisfied:
		var as []string
		for _, a := range av.Authorities {
			as = append(as, fmt.Sprintf("%s=%s(by %s)", a.Authority, a.Vote.Vote, a.Vote.By))
		}
		r.V14 = fmt.Sprintf("G1 satisfied: %d authority/ies %s", len(av.Authorities), strings.Join(as, ", "))
	default:
		r.V14 = fmt.Sprintf("G1 NOT satisfied (complete=%v threshold=%v replay=%v)", g1.G1ProofComplete, g1.ThresholdSatisfied, av.Satisfied)
	}

	// ---- v15: the 2.1 document, from genesis, bound to the intent's own facts
	archive := []byte(f.Archive)
	if len(archive) == 0 { // the major records are stored once beside the fixtures (cmd/g1fixture -shared-archive)
		if err := readGz(filepath.Join(filepath.Dir(path), "archive.json.gz"), &archive); err != nil {
			fail("the major records are neither in the fixture nor beside it: %v", err)
			return r
		}
	}
	ar, err := proofv2.UnmarshalArchive(archive)
	if err != nil {
		fail("the major records do not decode: %v", err)
		return r
	}
	rep, err := proofv2.Verify21FromGenesis(ev21, ar, incRep.Inputs, incRep.Incarnation)
	if err != nil {
		fail("the evidence 2.1 does not verify from genesis: %v", err)
		r.V15 = "refused: " + err.Error()
		return r
	}
	for _, u := range rep.Unproven {
		fail("not a verified S3, unproven: %s", u.Error())
	}
	// The operation id enters only the govRoot value, never a decision; the fixture does not carry the validators' (it is computed by the
	// consensus pipeline from the intent's blobs), so the comparator uses a fixed function of the transaction and says so in its header.
	opID := sha256.Sum256([]byte("certen:g1shadowcompare:operation-id:" + strings.ToLower(f.TxHash)))
	root, is21, err := intentcert.ProofV2Root(rep, ev21, &g0, &g1, &g2, f.KeyPage, f.KeyBook, f.VoteEvidence, opID)
	switch {
	case err != nil:
		fail("the binding or govRoot refuses: %v", err)
		r.V15 = "refused: " + err.Error()
	case !is21:
		fail("the document is not evidence 2.1")
	default:
		r.V15 = fmt.Sprintf("verified and bound: %d pages on %s, mode %s, govRoot v4 %x", len(rep.Proven), partitionsOf(rep), rep.AuthorizationMode, root[:8])
	}

	// ---- page by page: v1's replay against what v2 captured, and against what the document proves
	if v1pages, err := govvote.ReplayPageHistories(gev); err != nil {
		fail("v1's page histories do not replay: %v", err)
	} else {
		cc := proofv2shadow.CrossCheckPages(v1pages, cp)
		r.Pages = cc.Compared
		for _, d := range cc.Disagreements {
			r.Disagree = append(r.Disagree, d.String())
		}
		proven := map[string]bool{}
		for _, p := range rep.Proven {
			proven[govvote.CanonicalAccSpelling(p.URL)] = true
		}
		var missing []string
		for k := range v1pages {
			if !proven[k] {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		for _, k := range missing {
			r.Disagree = append(r.Disagree, fmt.Sprintf("%s: v1 evaluated this page, the document does not prove it", k))
		}
	}

	// ---- vote by vote
	r.Disagree = append(r.Disagree, compareVotes(av, ev21.Votes)...)
	// the decisions must agree
	if strings.HasPrefix(r.V14, "G1 satisfied") && !strings.HasPrefix(r.V15, "verified and bound") {
		r.Disagree = append(r.Disagree, "v14 accepts the intent, v15 does not: "+r.V15)
	}
	if !strings.HasPrefix(r.V14, "G1 satisfied") && strings.HasPrefix(r.V15, "verified and bound") {
		r.Disagree = append(r.Disagree, "v15 accepts an intent v14 does not satisfy")
	}
	return r
}

// compareVotes sets the votes v1 recorded beside the votes the 2.1 document carries: a vote v1 recorded that the document lacks, one that
// differs, one decided by a different page, and a document vote v1 did not record are each a disagreement.
func compareVotes(av *govvote.AccountVote, votes []proofv2.Vote) []string {
	var out []string
	v2 := map[string]proofv2.Vote{}
	for _, v := range votes {
		v2[govvote.CanonicalAccSpelling(v.Authority)] = v
	}
	seen := map[string]bool{}
	if av != nil {
		for _, a := range av.Authorities {
			k := govvote.CanonicalAccSpelling(a.Authority)
			if !a.Vote.Voted {
				continue
			}
			seen[k] = true
			v, ok := v2[k]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("%s: v1 recorded a %s vote by %s, the document carries no vote for it", a.Authority, a.Vote.Vote, a.Vote.By))
			case !strings.EqualFold(v.Vote, a.Vote.Vote):
				out = append(out, fmt.Sprintf("%s: v1 %s, document %s", a.Authority, a.Vote.Vote, v.Vote))
			case a.Vote.By != "" && !strings.EqualFold(govvote.CanonicalAccSpelling(v.Origin), govvote.CanonicalAccSpelling(a.Vote.By)):
				out = append(out, fmt.Sprintf("%s: v1 decided by page %s, the document by %s", a.Authority, a.Vote.By, v.Origin))
			}
		}
	}
	var extra []string
	for k := range v2 {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, fmt.Sprintf("%s: the document carries a vote that v1 did not record", k))
	}
	return out
}

func partitionsOf(rep *proofv2.Report) string {
	set := map[string]bool{}
	for _, p := range rep.Proven {
		set[p.Partition] = true
	}
	var ps []string
	for p := range set {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return strings.Join(ps, "+")
}
