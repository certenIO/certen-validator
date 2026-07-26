package execution

import (
	"reflect"
	"testing"
)

// Executor paths do not agree on how they record transaction hashes. Some fill
// the three per-leg fields, some fill only TxHash, and the multi-chain path
// packs everything into comma-joined, chain-prefixed strings. The cost hook
// read the leg fields verbatim, so on the other paths every candidate filtered
// out and nothing was reported — silently. The chain then never accumulated
// measured cost data and stayed unpriceable, with no error to explain it.

func TestExtractTxHashesHandlesEveryExecutorShape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"bare hash", "0xabc123abc123abc123abc123abc123abc123", []string{"0xabc123abc123abc123abc123abc123abc123"}},
		{
			"chain prefixed",
			"Ethereum Sepolia:0xabc123abc123abc123abc123abc123abc123",
			[]string{"0xabc123abc123abc123abc123abc123abc123"},
		},
		{
			"chain and leg prefixed",
			"Ethereum Sepolia:leg-1:0xabc123abc123abc123abc123abc123abc123",
			[]string{"0xabc123abc123abc123abc123abc123abc123"},
		},
		{
			"multi-chain comma joined",
			"Ethereum Sepolia:leg-1:0xaaa123abc123abc123abc123abc123abc123," +
				"Base Sepolia:leg-2:0xbbb123abc123abc123abc123abc123abc123",
			[]string{
				"0xaaa123abc123abc123abc123abc123abc123",
				"0xbbb123abc123abc123abc123abc123abc123",
			},
		},
		{
			"failure sentinels dropped",
			"Base Sepolia:create_failed_base,Ethereum Sepolia:0xccc123abc123abc123abc123abc123abc123",
			[]string{"0xccc123abc123abc123abc123abc123abc123"},
		},
		{
			"non-EVM base58 signature kept",
			"Solana Devnet:5Nx8kQwPqR3vT7yZ1aB2cD4eF6gH8jK9mN0pQ2rS4tU6",
			[]string{"5Nx8kQwPqR3vT7yZ1aB2cD4eF6gH8jK9mN0pQ2rS4tU6"},
		},
		{
			"duplicates collapsed",
			"Ethereum Sepolia:0xddd123abc123abc123abc123abc123abc123,Ethereum Sepolia:0xddd123abc123abc123abc123abc123abc123",
			[]string{"0xddd123abc123abc123abc123abc123abc123"},
		},
		{"all sentinels yields nothing", "create_failed_base,verify_skipped_solana", nil},
	}

	for _, c := range cases {
		got := extractTxHashes(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: extractTxHashes(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

type legPair = struct {
	leg    string
	txHash string
}

func TestAnyMeasurable(t *testing.T) {
	if anyMeasurable([]legPair{{"anchor", ""}, {"verify", "create_failed_base"}}) {
		t.Error("legs with only empties and sentinels must not count as measurable")
	}
	if !anyMeasurable([]legPair{{"anchor", ""}, {"verify", "Ethereum Sepolia:0xabc123abc123abc123abc123abc123abc123"}}) {
		t.Error("a prefixed real hash must count as measurable")
	}
}

// The regression that produced zero cost events: leg fields empty, primary set.
func TestPrimaryTxHashIsUsedWhenLegFieldsAreEmpty(t *testing.T) {
	legs := []legPair{{"anchor", ""}, {"verify", ""}, {"vault_execute", ""}}
	if anyMeasurable(legs) {
		t.Fatal("precondition: leg fields should be empty")
	}
	primary := "0xeee123abc123abc123abc123abc123abc123"
	if !looksLikeTxHash(primary) {
		t.Fatal("primary hash should be considered a real hash")
	}
	if got := extractTxHashes(primary); len(got) != 1 || got[0] != primary {
		t.Errorf("fallback extraction = %v, want [%s]", got, primary)
	}
}

func TestLooksLikeTxHashRejectsSentinels(t *testing.T) {
	for _, bad := range []string{
		"", "create_failed_base", "verify_skipped_solana", "pending", "none", "not_executed", "0xshort",
	} {
		if looksLikeTxHash(bad) {
			t.Errorf("looksLikeTxHash(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{
		"0xabc123abc123abc123abc123abc123abc123",
		"5Nx8kQwPqR3vT7yZ1aB2cD4eF6gH8jK9mN0pQ2rS4tU6",
	} {
		if !looksLikeTxHash(good) {
			t.Errorf("looksLikeTxHash(%q) = false, want true", good)
		}
	}
}
