package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The live fixtures RB9-E captured (pkg/consensus/testdata/g1_live: ten real Kermit intents, cross-partition, cross-identity, header
// authority, disabled authorities, a page changed right after the vote, and the same-partition regressions) set the v14 decision beside
// the v15 decision with zero disagreements and zero verification failures.
const liveDir = "../../pkg/consensus/testdata/g1_live"
const incPath = "../../pkg/proof/testdata/incarnation/kermit.json"
const pin = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

func TestTheLiveFixturesAgreeBetweenTheV14AndV15Decisions(t *testing.T) {
	for _, dir := range []string{liveDir, liveDir + "_fixedprover"} {
		code, err := run(dir, incPath, pin)
		if err != nil || code != 0 {
			t.Fatalf("%s: exit %d, %v: the live fixtures must compare with zero disagreements and zero verification failures", dir, code, err)
		}
	}
}

// The comparator must be able to fail: a copy of a live cross-partition fixture with one page missing from the validators' capture is a
// page v1 evaluated that the capture lacks, and a copy whose 2.1 document lost the foreign authority's vote is a document that does not
// carry a vote v1 recorded. Each is reported, never passed.
func TestTheComparatorReportsWhatDisagrees(t *testing.T) {
	read := func(path string) map[string]json.RawMessage {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		j, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal(j, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	write := func(path string, m map[string]json.RawMessage) {
		j, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		z := gzip.NewWriter(&buf)
		z.Write(j)
		z.Close()
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(src, dst string) {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T) string {
		dir := t.TempDir()
		for _, f := range []string{"archive.json.gz", "cross-508.json.gz", "cross-508.capture.json.gz"} {
			copyFile(filepath.Join(liveDir, f), filepath.Join(dir, f))
		}
		return dir
	}

	t.Run("a page missing from the capture", func(t *testing.T) {
		dir := setup(t)
		c := read(filepath.Join(dir, "cross-508.capture.json.gz"))
		var pages []map[string]json.RawMessage
		if err := json.Unmarshal(c["pages"], &pages); err != nil {
			t.Fatal(err)
		}
		var kept []map[string]json.RawMessage
		for _, p := range pages {
			if !strings.HasSuffix(strings.ToLower(string(p["url"])), `bank-508.acme/book/1"`) {
				kept = append(kept, p)
			}
		}
		if len(kept) != len(pages)-1 {
			t.Fatalf("removed %d pages, want 1", len(pages)-len(kept))
		}
		c["pages"], _ = json.Marshal(kept)
		write(filepath.Join(dir, "cross-508.capture.json.gz"), c)
		code, err := run(dir, incPath, pin)
		if err != nil || code != 1 {
			t.Fatalf("exit %d, %v: a page v1 evaluated and the capture lacks is a disagreement", code, err)
		}
	})

	t.Run("a document without the foreign authority's vote", func(t *testing.T) {
		dir := setup(t)
		f := read(filepath.Join(dir, "cross-508.json.gz"))
		var ev map[string]json.RawMessage
		if err := json.Unmarshal(f["proof_v2"], &ev); err != nil {
			t.Fatal(err)
		}
		var votes []map[string]json.RawMessage
		if err := json.Unmarshal(ev["votes"], &votes); err != nil || len(votes) != 2 {
			t.Fatalf("%d votes, %v", len(votes), err)
		}
		ev["votes"], _ = json.Marshal(votes[:1])
		f["proof_v2"], _ = json.Marshal(ev)
		write(filepath.Join(dir, "cross-508.json.gz"), f)
		code, err := run(dir, incPath, pin)
		if err != nil || code != 1 {
			t.Fatalf("exit %d, %v: a document that lost a vote must not compare clean", code, err)
		}
	})
}
