// Copyright 2026 Certen Protocol

package ethproof

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// RB10-B12: no hostile document can crash the process reading S6 evidence
// =============================================================================
//
// DecodeReplayGuardEvidence is what a verifier holding one proof file calls. Its reader read the document by recursion
// over json.Decoder.Token(), and the Go runtime's goroutine stack limit (1 GB) is a FATAL error, not a panic: a document
// of about 6,000,000 nested arrays (12 MB of '[') killed the process with "goroutine stack exceeds 1000000000-byte
// limit". The failure cannot be recovered, so every case here runs in a SUBPROCESS: the test binary re-invokes itself with
// replayDeepChildEnv naming the case, the child decodes the document and prints one result line, and the parent requires
// exit status 0 and the refusal the document earns by the schema (testdata/s6replay4/SPEC.md: depth never decides a
// verdict).
//
// Two entry points are held to it. "reader" is decodeReplayEvidence, the decoder without the size bound
// (MaxReplayEvidenceBytes, testdata/s6replay5/SPEC.md): the reader itself reads a document of 6,000,000 nested arrays and
// refuses it by the schema, whatever the bound in front of it. "public" is DecodeReplayGuardEvidence: documents over the
// bound are refused evidence_too_large without being read, and the deepest document the bound admits is read.

const replayDeepChildEnv = "CERTEN_REPLAY_DEEP_CHILD"

const deepPrefix = `{"version":"certen:s6-replay:v1","zzz":`

// deepCaseDoc builds the document of a case: kind and the nesting count.
func deepCaseDoc(kind string, n int) ([]byte, error) {
	rep := func(s string, k int) []byte { return bytes.Repeat([]byte(s), k) }
	var b bytes.Buffer
	switch kind {
	case "unknown_arrays": // an unknown field holding n nested arrays
		b.WriteString(deepPrefix)
		b.Write(rep("[", n))
		b.Write(rep("]", n))
		b.WriteString("}")
	case "unknown_objects": // an unknown field holding n nested objects
		b.WriteString(deepPrefix)
		b.Write(rep(`{"a":`, n))
		b.WriteString("0")
		b.Write(rep("}", n))
		b.WriteString("}")
	case "top_arrays": // the whole document is n nested arrays
		b.Write(rep("[", n))
		b.Write(rep("]", n))
	case "truncated_arrays": // n arrays opened and never closed
		b.WriteString(deepPrefix)
		b.Write(rep("[", n))
	case "duplicate_innermost": // a duplicate key at the bottom of n nested objects
		b.WriteString(deepPrefix)
		b.Write(rep(`{"a":`, n))
		b.WriteString(`{"b":0,"b":1}`)
		b.Write(rep("}", n))
		b.WriteString("}")
	case "duplicate_after_deep": // the deep value, then a second "version"
		b.WriteString(deepPrefix)
		b.Write(rep("[", n))
		b.Write(rep("]", n))
		b.WriteString(`,"version":"certen:s6-replay:v1"}`)
	default:
		return nil, errors.New("unknown case " + kind)
	}
	return b.Bytes(), nil
}

// TestReplayDecodeDeepChild is the subprocess body. It does nothing unless replayDeepChildEnv names a case
// ("mode:kind:n"); the parent test below sets it. It prints "DEEPRESULT state=.. reason=.. detail=.. peak=<bytes>".
func TestReplayDecodeDeepChild(t *testing.T) {
	spec := os.Getenv(replayDeepChildEnv)
	if spec == "" {
		return
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 3 {
		t.Fatalf("bad case %q", spec)
	}
	mode, kind := parts[0], parts[1]
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Fatalf("bad case %q", spec)
	}
	doc, err := deepCaseDoc(kind, n)
	if err != nil {
		t.Fatal(err)
	}
	decode := DecodeReplayGuardEvidence
	switch mode {
	case "public":
	case "reader":
		decode = decodeReplayEvidence
	default:
		t.Fatalf("bad mode in case %q", spec)
	}
	// the process's memory, sampled while the decode runs: the runtime's own total of memory it holds from the OS
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}}
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			metrics.Read(sample)
			if v := sample[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	ev, derr := decode(doc)
	close(stop)
	<-done
	metrics.Read(sample)
	if v := sample[0].Value.Uint64(); v > peak.Load() {
		peak.Store(v)
	}
	switch {
	case ev != nil:
		fmt.Printf("DEEPRESULT state=decoded reason= detail= len=%d peak=%d\n", len(doc), peak.Load())
	case derr == nil:
		fmt.Printf("DEEPRESULT state=nil-nil reason= detail= len=%d peak=%d\n", len(doc), peak.Load())
	default:
		var re *ReplayError
		if !errors.As(derr, &re) {
			fmt.Printf("DEEPRESULT state=other reason= detail=%s len=%d peak=%d\n", strings.ReplaceAll(derr.Error(), " ", "_"), len(doc), peak.Load())
			return
		}
		fmt.Printf("DEEPRESULT state=%s reason=%s detail=%s len=%d peak=%d\n", re.State, re.Reason, strings.ReplaceAll(re.Detail, " ", "_"), len(doc), peak.Load())
	}
}

type deepResult struct{ state, reason, detail string }

// runDeepChild runs one case in a subprocess of this test binary and returns its result line and its peak memory.
func runDeepChild(t *testing.T, mode, kind string, n int) (deepResult, uint64) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplayDecodeDeepChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), replayDeepChildEnv+"="+mode+":"+kind+":"+strconv.Itoa(n))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	took := time.Since(start)
	if err != nil {
		tail := stderr.String()
		if len(tail) > 1500 {
			tail = tail[:1500]
		}
		t.Fatalf("%s %s depth %d: the reader killed the process after %s: %v\nstderr: %s", mode, kind, n, took.Round(time.Millisecond), err, tail)
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if !strings.HasPrefix(line, "DEEPRESULT ") {
			continue
		}
		var res deepResult
		var peak uint64
		var length string
		for _, f := range strings.Fields(strings.TrimPrefix(line, "DEEPRESULT ")) {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "state":
				res.state = v
			case "reason":
				res.reason = v
			case "detail":
				res.detail = strings.ReplaceAll(v, "_", " ")
			case "len":
				length = v
			case "peak":
				peak, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		t.Logf("%s %s depth %d (%s bytes): %s/%s %q in %s, peak memory %d MiB", mode, kind, n, length, res.state, res.reason, res.detail, took.Round(time.Millisecond), peak>>20)
		return res, peak
	}
	t.Fatalf("%s %s depth %d: the child printed no result:\n%s", mode, kind, n, stdout.String())
	return deepResult{}, 0
}

// deepestAdmitted is the nesting count of the deepest closed "unknown_arrays" document that is still within
// MaxReplayEvidenceBytes.
const deepestAdmitted = (MaxReplayEvidenceBytes - len(deepPrefix) - 1) / 2

// The memory budgets of the cases, in bytes of the runtime's own total (memory held from the OS) at its peak. Measured on
// go1.25.1 windows/amd64 (RB10-B12): the reader holds about 120 bytes per nesting level of an array chain (722 MiB at
// 6,000,000 levels, 2552 MiB at 20,000,000 - which is why the reader-level cases stop at 6,000,000: the bound in front of
// the reader admits at most about 2,100,000 levels, 4 MiB).
const (
	deepBudgetReader = 1 << 30
	deepBudgetPublic = 1 << 29
)

// TestReplayDecodeDeepDocumentsAreRefusedNotFatal: documents far deeper than any recursion Go's stack can carry are read
// to the end and judged by the schema (or by the duplicate-key and syntax rules), as the shallow ones are. The 6,000,000
// reader case is the one that killed the recursive reader.
func TestReplayDecodeDeepDocumentsAreRefusedNotFatal(t *testing.T) {
	const unknown = "$.zzz is no field of the format"
	tooLarge := func(n int) string { return fmt.Sprintf("the evidence is %d bytes", n) }
	for _, c := range []struct {
		mode, kind string
		n          int
		reason     string
		detail     string // exact for a schema refusal, a fragment for a syntax refusal and the size bound
		budget     uint64
	}{
		{"reader", "unknown_arrays", 1_000_000, ReasonUnknownField, unknown, deepBudgetReader},
		{"reader", "unknown_arrays", 6_000_000, ReasonUnknownField, unknown, deepBudgetReader},
		{"reader", "unknown_objects", 1_000_000, ReasonUnknownField, unknown, deepBudgetReader},
		{"reader", "top_arrays", 6_000_000, ReasonWrongType, "$ is not an object", deepBudgetReader},
		{"reader", "truncated_arrays", 6_000_000, ReasonMalformedJSON, "EOF", deepBudgetReader},
		{"reader", "duplicate_innermost", 1_000_000, ReasonMalformedJSON, `duplicate key "b"`, deepBudgetReader},
		{"reader", "duplicate_after_deep", 6_000_000, ReasonMalformedJSON, `duplicate key "version"`, deepBudgetReader},
		// the public entry point: the deepest document the size bound admits is read and refused by the schema
		{"public", "unknown_arrays", deepestAdmitted, ReasonUnknownField, unknown, deepBudgetPublic},
		// and 6,000,000 and 20,000,000 levels (12 MB and 40 MB) are refused for their size, without being read
		{"public", "unknown_arrays", 6_000_000, ReasonEvidenceTooLarge, tooLarge(len(deepPrefix) + 2*6_000_000 + 1), deepBudgetPublic},
		{"public", "unknown_arrays", 20_000_000, ReasonEvidenceTooLarge, tooLarge(len(deepPrefix) + 2*20_000_000 + 1), deepBudgetPublic},
		{"public", "truncated_arrays", 6_000_000, ReasonEvidenceTooLarge, tooLarge(len(deepPrefix) + 6_000_000), deepBudgetPublic},
	} {
		c := c
		t.Run(fmt.Sprintf("%s_%s_%d", c.mode, c.kind, c.n), func(t *testing.T) {
			res, peak := runDeepChild(t, c.mode, c.kind, c.n)
			if res.state != ReplayUnproven || res.reason != c.reason {
				t.Errorf("judged %s/%s %q, want %s/%s", res.state, res.reason, res.detail, ReplayUnproven, c.reason)
			}
			if c.reason == ReasonUnknownField || c.reason == ReasonWrongType {
				if res.detail != c.detail {
					t.Errorf("detail %q, want %q", res.detail, c.detail)
				}
			} else if !strings.Contains(res.detail, c.detail) {
				t.Errorf("detail %q does not name %q", res.detail, c.detail)
			}
			if peak > c.budget {
				t.Errorf("peak memory %d MiB exceeds the %d MiB budget of this case", peak>>20, c.budget>>20)
			}
		})
	}
}
