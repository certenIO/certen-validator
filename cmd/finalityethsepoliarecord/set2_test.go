// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	sepolia1Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia1"
	sepolia2Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia2"
)

// A published set reproduces from its own committed inputs (RB12 OPS-A2 item 19): set 2 is rebuilt from set 1 and the pins it was
// published with (pins/main.json of the set itself), never from the live embedded pins, which grow after a set is published.
//
// What does NOT reproduce, by nature: raw/*/capture.json records the wall-clock build_ms and verify_ms of the run that made it (a
// measurement, not a derivation), and MANIFEST.json(.sha256) hash that file. Those fields are masked and the two MANIFEST files are not
// compared; every other byte of the set, and every other field of capture.json, must be identical.
func TestBuild2WritesTheCommittedSetByteForByte(t *testing.T) {
	tmp := t.TempDir()
	if dir := os.Getenv("PV2_SET2_OUT"); dir != "" { // how the set is regenerated where `go run` is not used
		tmp = dir
	}
	if err := build2Cmd([]string{"-set1", sepolia1Dir, "-out", tmp, "-pins", filepath.Join(sepolia2Dir, "pins", "main.json")}); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		slash := filepath.ToSlash(rel)
		if slash == "MANIFEST.json" || slash == "MANIFEST.json.sha256" {
			return nil
		}
		got, _ := os.ReadFile(p)
		want, err := os.ReadFile(filepath.Join(sepolia2Dir, rel))
		if err != nil {
			t.Errorf("%s: not in the committed set: %v", rel, err)
			return nil
		}
		n++
		if strings.HasSuffix(slash, "/capture.json") {
			if !sameWithoutTimings(t, got, want) {
				t.Errorf("%s: differs from the committed file in more than build_ms and verify_ms", rel)
			}
			return nil
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the generator's bytes differ from the committed file", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("only %d files compared", n)
	}
}

func sameWithoutTimings(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y map[string]any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		t.Fatal("capture.json is not a JSON object")
	}
	for _, m := range []map[string]any{x, y} {
		delete(m, "build_ms")
		delete(m, "verify_ms")
	}
	return reflect.DeepEqual(x, y)
}
