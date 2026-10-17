package main

// rerun: the post-deploy mode. After the RB8 deploy (all seven validators at once), every case is submitted again and
// each must be authorised, settle, and verify offline. Nothing is assumed: each stage reads a record.
//
//	sigtypelive rerun -n 1 -account 0x<CertenAccount of acc://pv2-sig-1.acme on Base Sepolia> \
//	    -base https://<validator API base> \
//	    -verify 'proofverify --offline --governance --l5 --proof-id {proof}' [-ssh claude@116.202.214.38]
//
// Stage 1  the intent is written (submitOne): Kermit must deliver it with the case's own signature type.
// Stage 2  GET <base>/api/v1/intent/tx/<txhash> until the lifecycle status is "complete"; "failed", "refused_pending_attestation"
//          or any status that says the signature was refused ends the case as a FAILURE with the status and reason read.
// Stage 3  GET <base>/api/v1/proofs/tx/<txhash> to find the proof id.
// Stage 4  the -verify command, with {proof} and {tx} filled in, must exit 0 (proofverify: 0 verified, 3 summary-only,
//          1 failed - only 0 passes). With -ssh the command runs on that host through the read-only per-command ssh prefix
//          the caller supplies in SSH_AUTH_SOCK; the program does not choose a socket.
//
// The run fails (exit 1) unless every selected case passes every stage.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type lifecycle struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

func httpGetJSON(ctx context.Context, url string, v any) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode == http.StatusOK && v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			return resp.StatusCode, b, fmt.Errorf("%s: not JSON: %w", url, err)
		}
	}
	return resp.StatusCode, b, nil
}

// waitSettled polls the lifecycle record until it is terminal.
func waitSettled(ctx context.Context, base, tx string, within time.Duration) (lifecycle, error) {
	deadline := time.Now().Add(within)
	var last lifecycle
	for time.Now().Before(deadline) {
		var lc lifecycle
		code, body, err := httpGetJSON(ctx, strings.TrimRight(base, "/")+"/api/v1/intent/tx/"+tx, &lc)
		if err != nil {
			return last, err
		}
		switch {
		case code == http.StatusOK:
			last = lc
			switch lc.Status {
			case "complete":
				return lc, nil
			case "failed", "refused_pending_attestation", "executed_proof_unavailable":
				return lc, fmt.Errorf("lifecycle %q (%s %s)", lc.Status, lc.Reason, lc.Error)
			}
		case code != http.StatusNotFound:
			return last, fmt.Errorf("lifecycle read: HTTP %d %s", code, strings.TrimSpace(string(body)))
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return last, fmt.Errorf("not settled within %v (last lifecycle status %q)", within, last.Status)
}

// proofIDs reads the proof ids recorded for an Accumulate transaction hash.
func proofIDs(ctx context.Context, base, tx string) ([]string, error) {
	var raw json.RawMessage
	code, body, err := httpGetJSON(ctx, strings.TrimRight(base, "/")+"/api/v1/proofs/tx/"+tx, &raw)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("proofs read: HTTP %d %s", code, strings.TrimSpace(string(body)))
	}
	var ids []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && (k == "proof_id" || k == "proofId" || k == "id") && len(s) == 36 {
					ids = append(ids, s)
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	walk(v)
	if len(ids) == 0 {
		return nil, fmt.Errorf("no proof id in the proofs record for %s", tx)
	}
	return ids, nil
}

func runVerify(ctx context.Context, l liveConfig, proofID, tx string) error {
	cmdline := strings.NewReplacer("{proof}", proofID, "{tx}", tx).Replace(l.Verify)
	var cmd *exec.Cmd
	if l.SSH != "" {
		cmd = exec.CommandContext(ctx, "/usr/bin/ssh", l.SSH, cmdline)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdline)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verify command failed (only exit 0 = verified passes): %w", err)
	}
	return nil
}

// rerun submits every selected case again and requires it to settle and verify offline.
func (a *app) rerun(ctx context.Context, l liveConfig) error {
	if l.Base == "" || l.Verify == "" {
		return fmt.Errorf("rerun needs -base (validator API base URL) and -verify (the offline verification command, with {proof} and {tx})")
	}
	caps, err := a.submit(ctx, l)
	if err != nil {
		return err
	}
	var failures []string
	for _, cp := range caps {
		fail := func(stage string, err error) {
			fmt.Printf("%-24s FAIL at %s: %v\n", cp.Case, stage, err)
			failures = append(failures, cp.Case+": "+stage+": "+err.Error())
		}
		if cp.Status != "delivered" {
			fail("stage 1 (kermit)", fmt.Errorf("status %q %s", cp.Status, cp.Error))
			continue
		}
		lc, err := waitSettled(ctx, l.Base, cp.TxHash, l.Wait)
		if err != nil {
			fail("stage 2 (settle)", err)
			continue
		}
		ids, err := proofIDs(ctx, l.Base, cp.TxHash)
		if err != nil {
			fail("stage 3 (proof)", err)
			continue
		}
		ok := false
		for _, id := range ids {
			if err := runVerify(ctx, l, id, cp.TxHash); err != nil {
				fail("stage 4 (offline verify, proof "+id+")", err)
				continue
			}
			ok = true
			fmt.Printf("%-24s PASS lifecycle=%s proof=%s tx=%s\n", cp.Case, lc.Status, id, cp.TxHash)
			break
		}
		_ = ok
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d of %d cases did not settle and verify:\n  %s", len(failures), len(caps), strings.Join(failures, "\n  "))
	}
	return nil
}
