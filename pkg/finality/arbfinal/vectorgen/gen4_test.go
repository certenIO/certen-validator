// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// publishedSet4 is the fourth published set, relative to the vectorgen package (where the generator tests run).
const publishedSet4 = "../testdata/finality_arb_final4"

// TestGenerate4 writes the fourth set. With ARBFINAL4_OUT and ARBFINAL4_FROM set it writes the set judged from the worlds in ARBFINAL4_FROM
// (the way the set was first published, from the TS-held supplement of BETA); without them it regenerates the set from the published one
// into a temporary directory and requires every file, the README and the manifest included, to be byte-identical to the published files.
func TestGenerate4(t *testing.T) {
	if out := os.Getenv("ARBFINAL4_OUT"); out != "" {
		if err := generate4(out, os.Getenv("ARBFINAL4_FROM")); err != nil {
			t.Fatal(err)
		}
		return
	}
	tmp := t.TempDir()
	if err := generate4(tmp, publishedSet4); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.Walk(publishedSet4, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(publishedSet4, p)
		want, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(tmp, rel))
		if err != nil {
			t.Errorf("%s is published but was not regenerated: %v", rel, err)
			return nil
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the regenerated file differs from the published one", rel)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var regenerated int
	_ = filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			regenerated++
		}
		return nil
	})
	if regenerated != n || n != 17 {
		t.Errorf("%d published files, %d regenerated", n, regenerated)
	}
}
