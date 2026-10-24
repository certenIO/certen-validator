// Copyright 2026 Certen Protocol

package finality

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// RB12-OPS-A1 item 2: pins.go says that the CI job finality-pins-sync compares this constant and the file across the three repositories. The job
// exists in .github/workflows/finality-pins-sync.yml; this test holds the sentence and the workflow together: the job has that name, runs on the
// changes of the files it guards, reads certen-contracts and certen-sdk, and calls the script on the three checkouts. (The comparison itself, and
// its failure by name on a mutated copy of each repository, is tested in certen-contracts: scripts/finality-pins-sync.test.mjs.)
func TestTheFinalityPinsSyncJobPinsGoNamesExists(t *testing.T) {
	src, err := os.ReadFile("pins.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "CI job finality-pins-sync compares this constant and the file across the three repositories") {
		t.Fatal("pins.go no longer names the job")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "finality-pins-sync.yml"))
	if err != nil {
		t.Fatalf("pins.go names the job finality-pins-sync and there is no workflow: %v", err)
	}
	wf := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, re := range []string{
		`(?m)^name: finality-pins-sync$`,
		`(?m)^  finality-pins-sync:$`,
		`(?m)^      - 'pkg/finality/pins\.go'$`,
		`(?m)^      - 'pkg/finality/pins/\*\*'$`,
		`(?m)^      - 'pkg/finality/pins-links/\*\*'$`,
		`repository: certenIO/certen-contracts`,
		`repository: certenIO/certen-sdk`,
		`(?m)^        run: node pr/finality-pins-sync\.mjs --validator \. --sdk sdk --contracts contracts$`,
		`(?m)^        run: cmp contracts/scripts/finality-pins-sync\.mjs pr/finality-pins-sync\.mjs$`,
		`(?m)^      - 'pr/finality-pins-sync\.mjs'$`,
		`FINALITY_PINS_SYNC_TOKEN`,
		`(?m)^            exit 1$`,
	} {
		if !regexp.MustCompile(re).MatchString(wf) {
			t.Errorf("the workflow does not contain %s", re)
		}
	}
	// V-OPS-A1 O1: the token of the cross-repository read never stays in a checkout another repository's code could read it from, and nothing
	// from another repository is executed: every checkout drops its credential, no step runs a file under contracts/ or sdk/ (they are compared
	// as data), and the script that runs is the copy in THIS repository, which the job proves equal to the published one with cmp first.
	checkouts := regexp.MustCompile(`(?m)^      - uses: actions/checkout@v4$`).FindAllString(wf, -1)
	if len(checkouts) != 3 || strings.Count(wf, "persist-credentials: false") != len(checkouts) {
		t.Errorf("%d checkouts and %d persist-credentials: false", len(checkouts), strings.Count(wf, "persist-credentials: false"))
	}
	if regexp.MustCompile(`(?m)^\s*run:.*\b(node|bash|sh|npm|npx|python|go)\b.*\b(contracts|sdk)/`).MatchString(wf) {
		t.Error("a step executes a file of another repository")
	}
	if strings.Contains(wf, "pull_request_target") {
		t.Error("pull_request_target")
	}
	if _, err := os.Stat(filepath.Join("..", "..", "pr", "finality-pins-sync.mjs")); err != nil {
		t.Errorf("the script the workflow runs is not in this repository: %v", err)
	}
	// the files the workflow guards are the files this package embeds
	for _, p := range []string{"pins/finality-pins.json", "pins-links/1378.ssz"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
