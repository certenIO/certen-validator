package consensus

import "testing"

// Phase 7 observes one transaction per entry, so an empty entry is a receipt poll that can never
// resolve. A BATCH member legitimately has no create or verify transaction — the anchor and its
// quorum attestation are paid ONCE for the whole tree — so those slots are empty and used to
// fail the whole cycle, taking Phase 8 and Phase 9 down with it. Every batched intent settled on
// chain and was never written back to acc://certen-protocol.acme/execution-results.
func TestNonEmptyTxHashes_DropsMissingEntries(t *testing.T) {
	// A batch member: only the governance/settlement hash exists.
	got := nonEmptyTxHashes("", "", "0xabc123")
	if len(got) != 1 || got[0] != "0xabc123" {
		t.Fatalf("batch member should yield exactly its settlement hash, got %v", got)
	}

	// The per-intent path populates all three and must be unaffected.
	got = nonEmptyTxHashes("0xaaa", "0xbbb", "0xccc")
	if len(got) != 3 {
		t.Fatalf("per-intent path must keep all three hashes, got %v", got)
	}

	// A reverted member has nothing at all: Phase 7 must be given an empty list, not a list of
	// empty strings.
	if got = nonEmptyTxHashes("", "", ""); len(got) != 0 {
		t.Fatalf("a member with no transaction must yield no entries, got %v", got)
	}
}

// Chain-prefixed forms must still reduce to the raw hash rather than being dropped.
func TestNonEmptyTxHashes_HandlesChainPrefixed(t *testing.T) {
	got := nonEmptyTxHashes("", "", "Ethereum Sepolia:0xdeadbeef")
	if len(got) != 1 || got[0] != "0xdeadbeef" {
		t.Fatalf("chain-prefixed hash should reduce to the raw hash, got %v", got)
	}
}
