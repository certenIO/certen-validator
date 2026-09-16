package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/execution"
)

func writeCandidates(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "candidates.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadCandidatesParsesAndDeduplicates(t *testing.T) {
	tx1 := "0x" + strings.Repeat("a", 64)
	tx2 := "0x" + strings.Repeat("b", 64)
	path := writeCandidates(t, strings.Join([]string{
		"# the verify legs, exported from the gateway",
		"84532," + tx1,
		"",
		"  11155111 , 0x" + strings.ToUpper(tx2[2:]) + "  # mixed case and spacing",
		"84532," + tx1 + "   # the same candidate twice",
	}, "\n"))

	got, err := readCandidates(path)
	if err != nil {
		t.Fatalf("readCandidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(got), got)
	}
	if got[0].ChainID != 84532 || got[0].TxHash != tx1 {
		t.Fatalf("first candidate = %+v", got[0])
	}
	// Hashes are normalised, so the same transaction written two ways is one candidate.
	if got[1].ChainID != 11155111 || got[1].TxHash != "0x"+strings.ToLower(tx2[2:]) {
		t.Fatalf("second candidate = %+v", got[1])
	}
}

// A malformed line fails the run. Skipping it quietly would mean the operator's list and the tool's work
// no longer match, and nothing would say so.
func TestReadCandidatesRefusesMalformedInput(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no chain id", "0x" + strings.Repeat("a", 64)},
		{"chain id is not a number", "base-sepolia,0x" + strings.Repeat("a", 64)},
		{"truncated hash", "84532,0xdeadbeef"},
		{"missing 0x", "84532," + strings.Repeat("a", 64)},
		{"extra field", "84532,0x" + strings.Repeat("a", 64) + ",verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readCandidates(writeCandidates(t, tc.body)); err == nil {
				t.Fatalf("accepted malformed input %q", tc.body)
			}
		})
	}
}

// The resolver is built from exactly the chains the candidate list names, each once.
func TestChainIDsOfIsDeduplicatedInFirstSeenOrder(t *testing.T) {
	got := chainIDsOf([]execution.BackfillCandidate{
		{ChainID: 84532}, {ChainID: 11155111}, {ChainID: 84532},
	})
	if len(got) != 2 || got[0] != 84532 || got[1] != 11155111 {
		t.Fatalf("chainIDsOf = %v", got)
	}
}
