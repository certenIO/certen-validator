package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// RB12-TRAIN3-INT: an alert row that names a metric the code does not export never fires. Every certen_finality_ series named in
// pr/rb11-alerts.md is registered under that name (a histogram by its base name; _bucket, _sum and _count are the Prometheus suffixes).
func TestAlertsDocNamesOnlyMetricsTheCodeExports(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("pr", "rb11-alerts.md"))
	if err != nil {
		t.Fatal(err)
	}
	var code strings.Builder
	files, _ := filepath.Glob(filepath.Join("pkg", "metrics", "*.go"))
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		code.Write(b)
	}
	names := regexp.MustCompile("certen_finality_[a-z0-9_]+").FindAllString(string(doc), -1)
	if len(names) < 30 {
		t.Fatalf("only %d series named in the alerts document", len(names))
	}
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(n, "_bucket"), "_sum"), "_count")
		if !strings.Contains(code.String(), `"`+base+`"`) {
			t.Errorf("%s is named in pr/rb11-alerts.md and not exported by pkg/metrics", n)
		}
	}
}
