// writebackverify checks the quorum a CERTEN write-back states, from the write-back alone (RB5-F14): it reads the
// write-back's data entries from Accumulate and verifies the message, the validator set, the participants, the
// threshold and the aggregate signature with no access to CERTEN's database or validators.
//
//	writebackverify acc://<txid>@certen-protocol.acme/execution-results
//	writebackverify -endpoint https://kermit.accumulatenetwork.io/v3 acc://…
//
// Exit codes mirror cmd/proofverify: 0 verified; 1 the evidence is present and does NOT verify; 2 usage or read
// error; 3 the write-back predates its quorum evidence (a named weaker state, nothing known to be wrong).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/certen/independant-validator/pkg/execution"
)

const (
	exitVerified    = 0
	exitFailed      = 1
	exitUsage       = 2
	exitPredatesEvd = 3
)

func main() {
	endpoint := flag.String("endpoint", "https://kermit.accumulatenetwork.io/v3", "Accumulate v3 endpoint")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Println("usage: writebackverify [-endpoint URL] acc://<txid>@<account>")
		os.Exit(exitUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	entries, err := fetchEntries(ctx, *endpoint, flag.Arg(0))
	if err != nil {
		fmt.Printf("COULD NOT READ  %s\n  %v\n", flag.Arg(0), err)
		os.Exit(exitUsage)
	}
	q, err := execution.WriteBackQuorumFromEntries(entries)
	switch {
	case errors.Is(err, execution.ErrWriteBackPredatesEvidence):
		fmt.Printf("SUMMARY-ONLY  %s\n  %v\n", flag.Arg(0), err)
		os.Exit(exitPredatesEvd)
	case err != nil:
		fmt.Printf("FAILED  %s\n  %v\n", flag.Arg(0), err)
		os.Exit(exitFailed)
	}
	rep, err := execution.VerifyWriteBackQuorum(q)
	if err != nil {
		fmt.Printf("FAILED  %s\n  %v\n", flag.Arg(0), err)
		os.Exit(exitFailed)
	}
	fmt.Printf("VERIFIED  %s\n", flag.Arg(0))
	fmt.Printf("  %d signers %v hold %s of %s voting power (required %s); the aggregate verifies under their keys\n",
		len(rep.Signers), rep.Signers, rep.SignedPower, rep.TotalPower, rep.RequiredPower)
	fmt.Printf("  over the stated message, scheme %s\n", q.SignatureScheme)
	fmt.Printf("  validator set root %s reproduces from the listed validators (snapshot block %d)\n", q.ValidatorSetRoot, q.SnapshotBlock)
	fmt.Printf("  attested message: %s\n", rep.AttestedResult)
	fmt.Printf("  NOT checked here: that the validator set is CERTEN's registered set on chain (compare it with the\n")
	fmt.Printf("  anchor's registry), and the settlement itself (proofverify, writebackverify reads only the write-back).\n")
	os.Exit(exitVerified)
}

// fetchEntries reads a write-back transaction's data entries ("key=value", hex-encoded on the wire).
func fetchEntries(ctx context.Context, endpoint, scope string) ([][]byte, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "query", "params": map[string]any{"scope": scope}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if m, ok := doc.(map[string]any); ok && m["error"] != nil {
		return nil, fmt.Errorf("accumulate: %v", m["error"])
	}
	list := findData(doc)
	if list == nil {
		return nil, fmt.Errorf("the transaction carries no data entries")
	}
	entries := make([][]byte, 0, len(list))
	for _, x := range list {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("a data entry is not a string")
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("a data entry is not hex: %w", err)
		}
		entries = append(entries, b)
	}
	return entries, nil
}

// findData is the first "data" array of strings in the response: the WriteData entry's data.
func findData(v any) []any {
	switch t := v.(type) {
	case map[string]any:
		if d, ok := t["data"].([]any); ok && len(d) > 0 {
			if _, isStr := d[0].(string); isStr {
				return d
			}
		}
		for _, x := range t {
			if d := findData(x); d != nil {
				return d
			}
		}
	case []any:
		for _, x := range t {
			if d := findData(x); d != nil {
				return d
			}
		}
	}
	return nil
}
