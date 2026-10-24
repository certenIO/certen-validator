package main

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// RB12-TRAIN3-INT: the shape check warns "unknown CERTEN_FINALITY_ names (ignored by this build)" for a container variable it does not know. A
// setting the build DOES read must be known to it, or the rollback switch the owner document names (CERTEN_FINALITY_ARB_INDEX=off) would be
// reported as a typo. Every CERTEN_FINALITY_ name in the finality code is in the script's lists.
func TestShapeCheckKnowsEveryFinalitySettingTheCodeReads(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("pr", "rb11-prod-shape-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, m := range regexp.MustCompile(`CERTEN_FINALITY_[A-Z0-9_]+`).FindAllString(string(script), -1) {
		known[m] = true
	}
	name := regexp.MustCompile(`"(CERTEN_FINALITY_[A-Z0-9_]+)"`)
	seen := map[string]string{}
	err = filepath.WalkDir(filepath.Join("pkg", "finality"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range name.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = p
		}
		return nil
	})
	if err != nil || len(seen) < 30 {
		t.Fatalf("scanned %d names: %v", len(seen), err)
	}
	for n, p := range seen {
		if known[n] {
			continue
		}
		prefixOfKnown := false // a stem the code completes (CERTEN_FINALITY_ADIRI + _PUBLIC_URLS)
		for k := range known {
			if strings.HasPrefix(k, n+"_") {
				prefixOfKnown = true
			}
		}
		if !prefixOfKnown {
			t.Errorf("%s (read in %s) is not in the shape check's lists: the check would call it an unknown name", n, p)
		}
	}
}
