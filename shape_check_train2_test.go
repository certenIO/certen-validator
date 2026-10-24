package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// RB12-GO-INT (class 6): the read-only production-shape check embeds the checksum of every migration of the repo, so that its migration
// check (E2) judges the history the code needs. The dbfix branch added migration 00029 and left the table at 00028, so its own selftest
// failed ("30 migration files, 29 embedded") and the check could not have seen 00029 staged. The selftest runs here, so a migration added
// without its row fails a test and not the owner's post-deploy check.
func TestShapeCheckEmbedsTheChecksumOfEveryMigrationOfTheRepo(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("db", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v %v", files, err)
	}
	script, err := filepath.Abs(filepath.Join("pr", "rb11-prod-shape-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bashForScripts(t), filepath.ToSlash(script), "--selftest-migrations", "db/migrations")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("the selftest failed (%v):\n%s", err, out.String())
	}
	want := "selftest ok: " + strconv.Itoa(len(files)) + " migrations"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("selftest output %q, want %q", strings.TrimSpace(out.String()), want)
	}
}
