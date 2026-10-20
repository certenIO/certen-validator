// Copyright 2026 Certen Protocol

package finality

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// RB11-GATE-A, level 1: the L6 gate (ethproof.VerifySettlement) decodes a header with go-ethereum's types.Header, whose number is
// a big.Int of any width, while the positional reader of the framework refuses a number wider than 8 bytes. A header changed
// only in its number keeps its transaction and receipt roots, so the L6 proofs still verify under the re-hashed block hash and
// DeriveIncluded has to refuse it by name at the header reader, not accept a block number the leg cannot be bound to.
func TestDeriveIncludedRefusesAHeaderWhoseVerifiedNumberIsWiderThanEightBytes(t *testing.T) {
	real := realSettlement(t, "base_sepolia_47368146")
	s := *real.Included
	content, rest, err := rlp.SplitList(s.Header)
	if err != nil || len(rest) != 0 {
		t.Fatalf("%v %d", err, len(rest))
	}
	var items []rlp.RawValue
	for len(content) > 0 {
		_, _, tail, err := rlp.Split(content)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, rlp.RawValue(append([]byte(nil), content[:len(content)-len(tail)]...)))
		content = tail
	}
	if len(items) < 15 {
		t.Fatalf("%d header items", len(items))
	}
	wide, err := rlp.EncodeToBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err != nil {
		t.Fatal(err)
	}
	items[8] = wide
	s.Header, err = rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	s.BlockHash = crypto.Keccak256Hash(s.Header)
	if _, _, err := s.Verify(); err != nil {
		t.Fatalf("the re-hashed header must still pass the L6 gate for this test to reach the header reader: %v", err)
	}
	_, err = DeriveIncluded(ChainBaseSepolia, &s)
	wantNamed(t, err, CodeEvidenceMalformed, "part", "header", "reason", ReasonHeaderItemNotCanonUint, "index", 8)
	// and the unchanged settlement still derives its own block
	b, err := DeriveIncluded(ChainBaseSepolia, real.Included)
	if err != nil || b.Number != 47368146 || b.Chain != ChainBaseSepolia {
		t.Fatalf("%+v %v", b, err)
	}
}
