// Copyright 2026 Certen Protocol

// Command s6replayvectors writes an S6 replay-guard conformance set (certen:s6-replay:v1) - the vectors, the bounded
// mutation corpus with Go's verdicts, manifest.json and MANIFEST - to pkg/ethproof/testdata/<set> (or -out). -set
// s6replay1 (the default) is the first set, kept byte-identical; -set s6replay2 is the CertenAccountV7_2 set (RB10-F3); -set s6replay3 the
// named-state binding, canonical-header, envelope and escaped-hex set (RB10-B7).
// It is deterministic and uses no network: regenerating gives byte-identical files (TestS6Replay1Deterministic,
// TestS6Replay2Deterministic).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay2"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay3"
)

func main() {
	set := flag.String("set", "s6replay1", "the set to write: s6replay1, s6replay2 or s6replay3")
	out := flag.String("out", "", "directory to write the set to (default pkg/ethproof/testdata/<set>)")
	flag.Parse()
	var files map[string][]byte
	switch *set {
	case "s6replay1":
		files = s6replay1.Files()
	case "s6replay2":
		files = s6replay2.Files()
	case "s6replay3":
		files = s6replay3.Files()
	default:
		fmt.Fprintf(os.Stderr, "unknown set %q: s6replay1, s6replay2 or s6replay3\n", *set)
		os.Exit(2)
	}
	if *out == "" {
		*out = filepath.Join("pkg", "ethproof", "testdata", *set)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(*out, n), files[n], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Printf("wrote %d files to %s; MANIFEST %s", len(names), *out, files["MANIFEST"])
}
