// Command proofv2report is the proof v2 shadow's exit check (docs/proof/PROOF_V2.md §11): it re-verifies every stored
// v2 proof offline from the stored spine and the pinned incarnation's evidence, and compares every page v2 proved with
// the page v1 replayed for the same intent. It exits 0 only when there are no failures and no disagreements.
//
//	CERTEN_DB=postgres://... proofv2report -incarnation-evidence kermit.json -pin <hex32> [-intent <id>]
//	CERTEN_DB=postgres://... proofv2report -endpoint https://kermit.accumulatenetwork.io/v3 -pin <hex32>
//
// With -endpoint instead of a file, the incarnation evidence is derived live; it must still re-derive the pinned
// identity, so the endpoint is not trusted for it.
//
// Run it with a read-only session (options=-c default_transaction_read_only=on); it never writes.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	_ "github.com/lib/pq"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type page struct {
	version   uint64
	threshold uint64
	keys      []string // key hashes, hex, sorted
}

func (p page) String() string {
	return fmt.Sprintf("version %d, threshold %d, keys %v", p.version, p.threshold, p.keys)
}

func main() {
	incPath := flag.String("incarnation-evidence", "", "incarnation evidence JSON (cmd/incarnation -out)")
	pinHex := flag.String("pin", "", "pinned incarnation, hex32")
	only := flag.String("intent", "", "report one intent")
	endpoint := flag.String("endpoint", "", "derive the incarnation evidence live from this Accumulate v3 endpoint")
	flag.Parse()
	if *incPath == "" && *endpoint != "" {
		p, err := liveIncarnation(*endpoint, *pinHex)
		if err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(2)
		}
		defer os.Remove(p)
		*incPath = p
	}
	code, err := run(os.Getenv("CERTEN_DB"), *incPath, *pinHex, *only)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func run(dsn, incPath, pinHex, only string) (int, error) {
	raw, err := os.ReadFile(incPath)
	if err != nil {
		return 0, err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		return 0, fmt.Errorf("incarnation evidence: %w", err)
	}
	var pin [32]byte
	if b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(pinHex), "0x")); err != nil || len(b) != 32 {
		return 0, fmt.Errorf("-pin must be 32 bytes of hex")
	} else {
		copy(pin[:], b)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	ar, err := loadSpine(db)
	if err != nil {
		return 0, err
	}
	fmt.Printf("spine: %d major records stored\n", len(ar.Majors))

	q := `SELECT intent_id, accum_tx_hash, coalesce(verdict, ''), coalesce(error, ''), coalesce(capture_error, ''), evidence FROM proof_v2_shadow`
	args := []any{}
	if only != "" {
		q += ` WHERE intent_id = $1`
		args = append(args, only)
	}
	rows, err := db.Query(q+` ORDER BY created_at`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var total, verified, failures, pending, agree, disagree, v1missing, accAgree, accPending int
	for rows.Next() {
		var id, tx, verdict, buildErr, captureErr string
		var evRaw []byte
		if err := rows.Scan(&id, &tx, &verdict, &buildErr, &captureErr, &evRaw); err != nil {
			return 0, err
		}
		total++
		switch {
		case verdict == "":
			pending++
			fmt.Printf("PENDING  %s: not built yet\n", id)
			continue
		case verdict == "failed":
			failures++
			fmt.Printf("FAILED   %s: %s\n", id, buildErr)
			continue
		}
		ev := new(proofv2.Evidence)
		if err := json.Unmarshal(evRaw, ev); err != nil {
			failures++
			fmt.Printf("FAILED   %s: stored evidence does not decode: %v\n", id, err)
			continue
		}
		rep, err := proofv2.Verify(ev, ar, inc, pin)
		if err != nil {
			failures++
			fmt.Printf("FAILED   %s: stored evidence does not verify offline: %v\n", id, err)
			continue
		}
		// RB6 acceptance: the spine-derived set's root must be the root every V8.2 anchor of this intent committed.
		roots, err := committedRoots(db, id, tx)
		if err != nil {
			return 0, err
		}
		want := "0x" + hex.EncodeToString(rep.AccumulateSetRoot[:])
		mismatch := false
		for _, r := range roots {
			if !strings.EqualFold(r, want) {
				mismatch = true
				fmt.Printf("FAILED   %s: an anchor committed accumulate set root %s; the spine derives %s\n", id, r, want)
			}
		}
		if mismatch {
			failures++
			continue
		}
		if len(roots) == 0 {
			accPending++
		} else {
			accAgree++
		}
		verified++
		note := ""
		if captureErr != "" {
			note = " (capture: " + captureErr + ")"
		}
		fmt.Printf("VERIFIED %s: certified DN %d, anchor block %d, %d pages, set %s%s\n", id, rep.CertifiedBlock, rep.AnchorBlock, len(rep.Pages), rep.SetVerdict, note)

		v1, err := v1Pages(db, id, tx)
		if err != nil {
			return 0, err
		}
		for _, acct := range rep.Pages {
			kp, ok := acct.(*protocol.KeyPage)
			if !ok {
				continue
			}
			v2 := page{version: kp.Version, threshold: kp.AcceptThreshold}
			for _, k := range kp.Keys {
				v2.keys = append(v2.keys, hex.EncodeToString(k.PublicKeyHash))
			}
			sort.Strings(v2.keys)
			u := strings.ToLower(kp.Url.String())
			old, ok := v1[u]
			switch {
			case !ok:
				v1missing++
				fmt.Printf("           %s: v2 %s; v1 replayed no state for this page\n", u, v2)
			case old.String() == v2.String():
				agree++
			default:
				disagree++
				fmt.Printf("DISAGREE   %s: v1 replay %s; v2 served %s\n", u, old, v2)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	fmt.Printf("\n%d intents: %d verified, %d failed, %d pending; pages: %d agree, %d DISAGREE, %d without a v1 replay\n",
		total, verified, failures, pending, agree, disagree, v1missing)
	fmt.Printf("accumulate set root: %d intents equal to every anchor's committed root, %d with no V8.2 anchor recorded yet\n",
		accAgree, accPending)
	if failures > 0 || disagree > 0 {
		fmt.Println("shadow exit: NOT MET")
		return 1, nil
	}
	fmt.Println("shadow exit: met for these intents (zero failures, zero disagreements)")
	return 0, nil
}

// liveIncarnation derives the incarnation evidence from endpoint, refuses it unless it is the pinned one, and writes it
// to a temporary file for run.
func liveIncarnation(endpoint, pinHex string) (string, error) {
	var pin [32]byte
	if b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(pinHex), "0x")); err != nil || len(b) != 32 {
		return "", fmt.Errorf("-pin must be 32 bytes of hex")
	} else {
		copy(pin[:], b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ev, _, err := proof.ConfiguredIncarnationEvidence(ctx, endpoint, pin, 10*time.Second)
	if err != nil {
		return "", err
	}
	j, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "incarnation-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.Write(j)
	return f.Name(), err
}

// committedRoots returns the accumulate set roots the V8.2 anchors of an intent's proofs committed.
func committedRoots(db *sql.DB, intentID, tx string) ([]string, error) {
	rows, err := db.Query(`
		SELECT DISTINCT ab.accumulate_set_root FROM proof_artifacts pa
		JOIN anchor_batches ab ON ab.id = pa.batch_id
		WHERE (pa.intent_id = $1 OR pa.accum_tx_hash = $2) AND ab.anchor_version = 'v8_2' AND ab.accumulate_set_root IS NOT NULL`, intentID, tx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func loadSpine(db *sql.DB) (*proofv2.Archive, error) {
	rows, err := db.Query(`SELECT major_index, record FROM proof_v2_spine ORDER BY major_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ar := &proofv2.Archive{}
	for rows.Next() {
		var idx int64
		var rec []byte
		if err := rows.Scan(&idx, &rec); err != nil {
			return nil, err
		}
		if idx != int64(len(ar.Majors))+1 {
			return nil, fmt.Errorf("the stored spine skips from major block %d to %d", len(ar.Majors), idx)
		}
		r := new(api.MajorHeaderRecord)
		if err := r.UnmarshalBinary(rec); err != nil {
			return nil, fmt.Errorf("major block %d: %w", idx, err)
		}
		ar.Majors = append(ar.Majors, r)
	}
	return ar, rows.Err()
}

// v1Pages collects every page state v1's G1 replayed for the intent's proofs: each authoritySnapshot's stateExec.
func v1Pages(db *sql.DB, intentID, tx string) (map[string]page, error) {
	rows, err := db.Query(`
		SELECT gl.level_json FROM governance_proof_levels gl
		JOIN proof_artifacts pa ON pa.proof_id = gl.proof_id
		WHERE (pa.intent_id = $1 OR pa.accum_tx_hash = $2) AND gl.level_json IS NOT NULL`, intentID, tx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]page{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			collect(v, out)
		}
	}
	return out, rows.Err()
}

func collect(v any, out map[string]page) {
	switch t := v.(type) {
	case map[string]any:
		if pu, ok := t["page"].(string); ok {
			if st, ok := t["stateExec"].(map[string]any); ok {
				p := page{}
				if f, ok := st["version"].(float64); ok {
					p.version = uint64(f)
				}
				if f, ok := st["threshold"].(float64); ok {
					p.threshold = uint64(f)
				}
				if ks, ok := st["keys"].([]any); ok {
					for _, k := range ks {
						if s, ok := k.(string); ok {
							p.keys = append(p.keys, strings.ToLower(strings.TrimPrefix(s, "0x")))
						}
					}
				}
				sort.Strings(p.keys)
				out[strings.ToLower(pu)] = p
			}
		}
		for _, c := range t {
			collect(c, out)
		}
	case []any:
		for _, c := range t {
			collect(c, out)
		}
	}
}
