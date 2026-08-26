package main

// p7corpus - Phase 7 corpus trace capture and verdicting.
//
// PHASE7_RUNBOOK.md §1.2 is the rule this program exists to obey: the expected
// verdict for every corpus signature comes from accumulate-core, via
// protocol.VerifyUserSignature, and never from CERTEN's own verifier. A corpus
// verdicted by our own code proves only that we agree with ourselves.
//
// It is also why the signatures are BUILT with accumulate-core's own
// signing.Builder rather than by hand: the canonical encoding is field-tagged,
// omit-if-zero and varint-length, and hand-rolling it is how the field
// strictness bugs happened before (runbook rule 4).

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

type client = jsonrpc.Client

const kermit = "https://kermit.accumulatenetwork.io/v3"

func main() {
	var (
		endpoint = flag.String("endpoint", kermit, "Accumulate v3 endpoint")
		keysPath = flag.String("keys", filepath.Join("scripts", "phase7_corpus", "keys.json"), "corpus key seeds")
		manifest = flag.String("manifest", filepath.Join("scripts", "phase7_corpus", "corpus.json"), "corpus structure manifest")
		out      = flag.String("out", filepath.Join("docs", "l4", "phase7_corpus", "traces.json"), "where to write captured traces")
		stage    = flag.String("stage", "keycheck", "keycheck | partitions | capture")
	)
	flag.Parse()

	traceFile = *out
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	seeds, err := readJSON[map[string]string](*keysPath)
	if err != nil {
		fatal("read keys: %v", err)
	}
	cases, err := readJSON[map[string]json.RawMessage](*manifest)
	if err != nil {
		fatal("read manifest: %v", err)
	}
	c := jsonrpc.NewClient(*endpoint)

	switch *stage {
	case "keycheck":
		fmt.Println("== corpus key derivation, checked against the chain ==")
		if err := checkKeys(ctx, c, seeds, corpusKeyPages(cases)); err != nil {
			fatal("%v", err)
		}
		fmt.Println("all corpus keys derive to a hash the chain actually carries")

	case "partitions":
		if err := reportPartitions(ctx, *endpoint, cases); err != nil {
			fatal("%v", err)
		}

	case "prodpath":
		if err := checkProductionPath(ctx, *endpoint, cases); err != nil {
			fatal("%v", err)
		}

	case "multileg":
		if err := buildMultiLeg(ctx, *endpoint, cases); err != nil {
			fatal("%v", err)
		}

	case "capture":
		if err := capture(ctx, c, seeds, cases, *out); err != nil {
			fatal("%v", err)
		}

	default:
		fatal("unknown stage %q", *stage)
	}
}

// traceFile is where the captured corpus lives, set from the -out flag so the
// stages agree on one path.
var traceFile string

func readJSON[T any](path string) (T, error) {
	var v T
	b, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "p7corpus: "+format+"\n", args...)
	os.Exit(1)
}
