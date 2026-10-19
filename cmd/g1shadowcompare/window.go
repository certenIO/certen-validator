package main

// The window mode: every intent the validators captured in a time window, read through a read-only database session. For each, the pages v1
// replayed from the intent's stored vote evidence are set beside the pages the validators captured (proofv2shadow.CrossCheckPages: the
// shadow's own page cross-check, which no validator runs on the live path - RB9-E finding C5-F1), the stored v1 verdict beside the stored
// proof v2 verdict, and the intent's evidence 2.1 decision is taken from a fixture of the same transaction when one exists. A 2.1 document
// cannot be built after the partitions' retention (about 945 s) has passed, so an intent with no fixture has no v15 decision here: it is
// reported NOT_RUN{g1_historical_unavailable}, never counted as agreement.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/proofv2shadow"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type windowRow struct {
	IntentID, Tx, Account, Verdict, BuildErr, CaptureErr, Created string
	Captured                                                      []byte
}

// readWindow lists the intents with a capture in [since, until) (timestamps as Postgres reads them), oldest first.
func readWindow(ctx context.Context, db *sql.DB, since, until string) ([]windowRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT intent_id::text, accum_tx_hash, account_url, coalesce(verdict, ''), coalesce(error, ''),
		coalesce(capture_error, ''), created_at::text, captured FROM proof_v2_shadow
		WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz AND captured IS NOT NULL ORDER BY created_at`, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []windowRow
	for rows.Next() {
		var r windowRow
		if err := rows.Scan(&r.IntentID, &r.Tx, &r.Account, &r.Verdict, &r.BuildErr, &r.CaptureErr, &r.Created, &r.Captured); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// storedV1Evidence reads the intent's G1 vote evidence, vote record and G0 from the stored proof, or says why there is none.
func storedV1Evidence(ctx context.Context, db *sql.DB, intentID string) (*govvote.Evidence, *proof.G0Result, *proof.AuthorizationRecord, string, error) {
	var pid uuid.UUID
	err := db.QueryRowContext(ctx, `SELECT proof_id FROM proof_artifacts WHERE intent_id::text = $1 ORDER BY created_at DESC LIMIT 1`, intentID).Scan(&pid)
	if err == sql.ErrNoRows {
		return nil, nil, nil, "no proof is stored for the intent (it was not certified)", nil
	}
	if err != nil {
		return nil, nil, nil, "", err
	}
	levels, err := proof.GovernanceLevelsFromStorage(ctx, proof.NewPostgresProofStorage(db), pid)
	if err != nil {
		return nil, nil, nil, fmt.Sprintf("proof %s stores no governance levels: %v", pid, err), nil
	}
	var g0 proof.G0Result
	var rec proof.AuthorizationRecord
	var gev *govvote.Evidence
	haveG0, haveRec := false, false
	for _, l := range levels {
		switch l.Level {
		case "G0":
			if err := json.Unmarshal(l.Result, &g0); err == nil {
				haveG0 = true
			}
		case "G1":
			if a := l.Flags[execution.GovLevelAuthorizationKey]; len(a) > 0 && json.Unmarshal(a, &rec) == nil {
				haveRec = true
			}
			if v := l.Flags[execution.GovLevelVoteEvidenceKey]; len(v) > 0 {
				if gev, err = proof.DecodeVoteEvidence(v); err != nil {
					return nil, nil, nil, "", fmt.Errorf("proof %s: the stored vote evidence does not decode: %w", pid, err)
				}
			}
		}
	}
	if gev == nil || !haveG0 || !haveRec {
		return nil, nil, nil, fmt.Sprintf("proof %s stores no vote evidence for G1 (summary-only row)", pid), nil
	}
	return gev, &g0, &rec, "", nil
}

func runWindow(ctx context.Context, dsn, since, until, fixturesDir string, incRepOK func() *fixtureEnv) (int, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var ro string
	if err := db.QueryRowContext(ctx, `SHOW default_transaction_read_only`).Scan(&ro); err != nil || ro != "on" {
		return 0, fmt.Errorf("the session is not read-only (default_transaction_read_only=%q, %v)", ro, err)
	}
	rows, err := readWindow(ctx, db, since, until)
	if err != nil {
		return 0, err
	}
	env := incRepOK()
	// fixtures by transaction hash, for the v15 decision
	byTx := map[string]string{}
	if fixturesDir != "" {
		files, _ := filepath.Glob(filepath.Join(fixturesDir, "*.json.gz"))
		for _, f := range files {
			if strings.HasSuffix(f, ".capture.json.gz") {
				continue
			}
			var fx fixture
			if readGz(f, &fx) == nil {
				byTx[strings.ToLower(fx.TxHash)] = f
			}
		}
	}
	var dis, fail, notRun, compared, pages, agree int
	var notComparable []string
	for _, r := range rows {
		cp, err := proofv2shadow.DecodeCapture(r.Captured)
		if err != nil {
			fmt.Printf("== %s  %s: VERIFICATION FAILURE: the capture does not decode: %v\n", r.IntentID, short(r.Tx), err)
			fail++
			continue
		}
		gev, g0, rec, why, err := storedV1Evidence(ctx, db, r.IntentID)
		if err != nil {
			return 0, err
		}
		if gev == nil {
			// no v1 evidence: only a fixture (cmd/g1fixture) can give the comparison
			if f, ok := byTx[strings.ToLower(r.Tx)]; ok {
				res := compareOne(ctx, f, env.incRep)
				printResult(res)
				dis, fail, notRun, pages = dis+len(res.Disagree), fail+len(res.Failures), notRun+len(res.NotRun), pages+res.Pages
				compared++
				// agreement means both decisions ran and none differed: a decision that was not run is not agreement
				if agrees(len(res.NotRun) == 0, len(res.Disagree), len(res.Failures)) {
					agree++
				}
				continue
			}
			notComparable = append(notComparable, fmt.Sprintf("%s  %s  %s: %s (capture: partitions %d, pages %d)", r.IntentID, short(r.Tx), r.Account, why, len(cp.Partitions), len(cp.Pages)))
			continue
		}
		compared++
		v1pages, err := govvote.ReplayPageHistories(gev)
		var diffs, fails []string
		nPages := 0
		if err != nil {
			fails = append(fails, fmt.Sprintf("v1's page histories do not replay: %v", err))
		} else {
			cc := proofv2shadow.CrossCheckPages(v1pages, cp)
			nPages = cc.Compared
			for _, d := range cc.Disagreements {
				diffs = append(diffs, d.String())
			}
		}
		if err := proof.VerifyVoteEvidence(ctx, g0, gev, rec); err != nil {
			fails = append(fails, fmt.Sprintf("the stored vote record does not evaluate again from its evidence: %v", err))
		}
		av, avErr := govvote.VerifyEvidence(ctx, gev)
		v14 := "G1 satisfied (stored vote record evaluates again)"
		if avErr != nil || !av.Satisfied {
			v14 = fmt.Sprintf("G1 NOT satisfied on replay (%v)", avErr)
			fails = append(fails, v14)
		}
		line := fmt.Sprintf("== %s  %s  %s\n   v14: %s; shadow verdict %q%s\n   pages compared: %d", r.IntentID, short(r.Tx), r.Account, v14, r.Verdict,
			func() string {
				if r.BuildErr != "" {
					return " (" + r.BuildErr + ")"
				}
				return ""
			}(), nPages)
		fmt.Println(line)
		v15Ran := false
		if f, ok := byTx[strings.ToLower(r.Tx)]; ok {
			res := compareOne(ctx, f, env.incRep)
			fmt.Printf("   v15: %s\n", res.V15)
			diffs, fails = append(diffs, res.Disagree...), append(fails, res.Failures...)
			for _, d := range res.NotRun {
				fmt.Println("   NOT RUN:", d)
			}
			notRun += len(res.NotRun)
			v15Ran = len(res.NotRun) == 0
		} else {
			fmt.Println("   v15: NOT RUN{g1_historical_unavailable}: no fixture of this transaction; a 2.1 document needs the partitions' pages inside their retention")
			notRun++
		}
		for _, d := range diffs {
			fmt.Println("   DISAGREE:", d)
		}
		for _, d := range fails {
			fmt.Println("   VERIFICATION FAILURE:", d)
		}
		dis, fail, pages = dis+len(diffs), fail+len(fails), pages+nPages
		// an intent whose v15 decision was NOT RUN is not agreement (the NOT_RUN count carries it)
		if agrees(v15Ran, len(diffs), len(fails)) {
			agree++
		}
	}
	sort.Strings(notComparable)
	for _, n := range notComparable {
		fmt.Println("NOT COMPARABLE:", n)
	}
	fmt.Printf("\nwindow [%s, %s): %d intents with a capture, %d compared (%d page comparisons, %d with both decisions run and no disagreement or failure), %d not comparable\n",
		since, until, len(rows), compared, pages, agree, len(notComparable))
	fmt.Printf("DISAGREEMENTS=%d VERIFICATION_FAILURES=%d NOT_RUN=%d COMPARED=%d\n", dis, fail, notRun, compared)
	code := windowExit(len(rows), compared, dis, fail, notRun, len(notComparable))
	if code == exitNothingCompared {
		fmt.Println("NOTHING COMPARED: an empty window, or one in which no intent could be compared, says nothing about disagreements. It is not a zero-disagreement result.")
	}
	return code, nil
}

// agrees is whether an intent counts as agreement: both decisions ran and nothing differed or failed. A decision that was not run is
// never agreement.
func agrees(bothRan bool, disagreements, failures int) bool {
	return bothRan && disagreements+failures == 0
}

// exitNothingCompared is the exit code of a window that compared nothing (2 is the usage error, 3 the incomplete comparison).
const exitNothingCompared = 4

// windowExit is the window mode's verdict: 0 only when something was compared, nothing differed or failed and every decision ran;
// 1 on any disagreement or verification failure; 4 when nothing was compared at all (an empty window must never pass as zero
// disagreements); 3 when there are no disagreements but some decision was not run or some intent could not be compared.
func windowExit(rows, compared, dis, fail, notRun, notComparable int) int {
	switch {
	case dis+fail > 0:
		return 1
	case rows == 0 || compared == 0:
		return exitNothingCompared
	case notRun+notComparable > 0:
		return 3
	}
	return 0
}

type fixtureEnv struct{ incRep *proof.IncarnationReport }

func printResult(r *result) {
	fmt.Printf("== %s  %s  tx %s\n   v14 (live rule) : %s\n   v15 (G1 rule)   : %s\n   pages compared  : %d\n", r.Name, r.Account, short(r.Tx), r.V14, r.V15, r.Pages)
	for _, d := range r.Disagree {
		fmt.Println("   DISAGREE:", d)
	}
	for _, d := range r.Failures {
		fmt.Println("   VERIFICATION FAILURE:", d)
	}
}
