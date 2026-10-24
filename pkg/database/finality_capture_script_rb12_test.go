// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/certen/independant-validator/internal/testdb"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL (V-ARCHIVE D1): the operator report pr/rb12-capture-gaps.sh was changed to print the prefix windows, and its two
// new statements were invalid SQL (unquoted literals in an unquoted heredoc) that `bash -n` cannot see. This test RUNS the script against
// the migrated test database with seeded prefix, fill, end, slot and claim rows, and requires the statements to answer.

func scriptBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\usr\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		t.Fatal("Git for Windows' bash is required to run the report script")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to run the report script: %v", err)
	}
	return p
}

func TestRB12CaptureGapsScriptRunsItsPrefixStatementsAgainstTheRealTable(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	const chain = uint64(84532)
	const from = uint64(7_000_000)
	// a prefix window of 10 blocks: 4 filled, 1 proven unavailable (with its slot), 5 open; one claim on its first chunk
	if err := finality.RecordGap(ctx, store, chain, from, from+9, finality.GapCapturePrefix); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{from, from + 1, from + 2, from + 3} {
		if err := finality.RecordGapFill(ctx, store, chain, n, [32]byte{0xaa, byte(n)}, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := finality.RecordGapSlot(ctx, store, chain, from+4, 4242); err != nil {
		t.Fatal(err)
	}
	if err := finality.RecordGapEnd(ctx, store, chain, from+4, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, finality.CaptureKey{Chain: chain, L1Block: from, L1Hash: [32]byte{1}, Item: "gapclaim/7000000"}, []byte("CGCL1-test")); err != nil {
		t.Fatal(err)
	}
	// an Arbitrum window of 1000 blocks whose first 400 were scanned (a gapscan row closes a range without a fill per block)
	const arb = uint64(421614)
	if err := finality.RecordGap(ctx, store, arb, 8_000_000, 8_000_999, finality.GapCapturePrefix); err != nil {
		t.Fatal(err)
	}
	if err := finality.RecordGapScan(ctx, store, arb, 8_000_000, 8_000_399); err != nil {
		t.Fatal(err)
	}
	url, err := testdb.PackageURL("database")
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "pr", "rb12-capture-gaps.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(scriptBash(t), filepath.ToSlash(script))
	psqlDir := `C:\Program Files\PostgreSQL\16\bin`
	cmd.Env = append(os.Environ(), "PSQL_LOCAL_URL="+url, "PATH="+os.Getenv("PATH")+string(os.PathListSeparator)+psqlDir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	text := strings.ReplaceAll(out.String(), "\r", "")
	for _, bad := range []string{"ERROR:", "syntax error", "cannot query"} {
		if strings.Contains(text, bad) {
			t.Fatalf("the report holds %q (a statement of the script is invalid):\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "capture_prefix") || !strings.Contains(strings.ReplaceAll(text, " ", ""), "84532|7000000|7000009|10|4|1|5") {
		t.Fatalf("the prefix window is reported with its filled / gone / open counts (4 / 1 / 5):\n%s", text)
	}
	compact := strings.ReplaceAll(text, " ", "")
	if !strings.Contains(compact, "421614|8000000|8000999|1000|400|0|600") || !strings.Contains(compact, "421614|open|8000400|8000999|600") {
		t.Fatalf("scanned blocks are closed in the windows table (400 filled, 600 open) and in the open runs:\n%s", text)
	}
	if !strings.Contains(text, "gapscan") {
		t.Fatalf("the scan rows are reported:\n%s", text)
	}
	if !strings.Contains(text, "gapclaim") || !strings.Contains(text, "gapslot") {
		t.Fatalf("the claim and slot rows are reported:\n%s", text)
	}
	// the script reports open gap blocks with exit status 1 and a read failure with 2: 2 would mean it could not read
	if ee, ok := runErr.(*exec.ExitError); ok && ee.ExitCode() == 2 {
		t.Fatalf("the script could not read the store:\n%s", text)
	}
}
