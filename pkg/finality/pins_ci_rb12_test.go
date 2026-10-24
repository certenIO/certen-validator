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
		`node contracts/scripts/finality-pins-sync\.mjs --validator \. --sdk sdk --contracts contracts`,
		`FINALITY_PINS_SYNC_TOKEN`,
		`(?m)^            exit 1$`,
	} {
		if !regexp.MustCompile(re).MatchString(wf) {
			t.Errorf("the workflow does not contain %s", re)
		}
	}
	// the files the workflow guards are the files this package embeds
	for _, p := range []string{"pins/finality-pins.json", "pins-links/1378.ssz"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
