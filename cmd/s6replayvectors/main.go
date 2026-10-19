// Copyright 2026 Certen Protocol

// Command s6replayvectors writes the S6 replay-guard conformance suite (certen:s6-replay:v1) - the vectors, the bounded
// mutation corpus with Go's verdicts, manifest.json and MANIFEST - to pkg/ethproof/testdata/s6replay1 (or -out). It is
// deterministic and uses no network: regenerating gives byte-identical files (TestS6Replay1Deterministic).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
)

func main() {
	out := flag.String("out", filepath.Join("pkg", "ethproof", "testdata", "s6replay1"), "directory to write the suite to")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	files := s6replay1.Files()
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
