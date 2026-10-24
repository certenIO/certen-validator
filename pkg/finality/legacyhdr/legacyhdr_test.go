// Copyright 2026 Certen Protocol

package legacyhdr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// The three chains of the 191 legacy legs, as real captured blocks (Base Sepolia 119, Sepolia 65, Arbitrum Sepolia 7).
var chainFixtures = []struct {
	name    string
	fixture string
	chain   uint64
}{
	{"base-sepolia", "base_sepolia_47368146", 84532},
	{"ethereum-sepolia", "sepolia_11792612", 11155111},
	{"arbitrum-sepolia", "arbitrum_sepolia_315455204", 421614},
}

const (
	testProof  = "11111111-2222-3333-4444-555555555555"
	testBundle = "66666666-7777-8888-9999-000000000000"
)

// legacy is the legacy component 5 of a real settled leg (every member of the production component but the header), its Leg, and the
// real header it lost.
type legacy struct {
	leg    Leg
	header []byte
	comp   map[string]any
}

func legacyOf(t *testing.T, fixture string) legacy {
	t.Helper()
	s := finalitytest.Settlement(t, fixture)
	comp := finalitytest.ProductionLegacyExecutionProof(t, s)
	l, err := ParseLeg(testProof, testBundle, mustJSON(t, comp))
	if err != nil {
		t.Fatalf("%s: the production legacy component does not parse: %v", fixture, err)
	}
	return legacy{leg: l, header: append([]byte(nil), s.Included.Header...), comp: comp}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// wantInvalid asserts err is finality_included_invalid for the test proof carrying the check (when non-empty) and the leg's chain and block.
func wantInvalid(t *testing.T, what string, err error, l Leg, check string) {
	t.Helper()
	n, ok := finality.AsNamed(err)
	if !ok || n.Code != finality.CodeIncludedInvalid {
		t.Fatalf("%s: want finality_included_invalid, got %v", what, err)
	}
	if fmt.Sprint(n.Fields["proof_id"]) != testProof {
		t.Fatalf("%s: proof_id %v", what, n.Fields["proof_id"])
	}
	if check == "" {
		return
	}
	if n.Fields["check"] != check {
		t.Fatalf("%s: check = %v, want %s (%v)", what, n.Fields["check"], check, err)
	}
	if n.Fields["chain"] != l.Chain || n.Fields["block"] != l.BlockNumber {
		t.Fatalf("%s: the state is not judged at chain %d block %d: %v", what, l.Chain, l.BlockNumber, err)
	}
}

func TestParseLegReadsTheProductionLegacyComponentOfEachChain(t *testing.T) {
	for _, c := range chainFixtures {
		t.Run(c.name, func(t *testing.T) {
			lg := legacyOf(t, c.fixture)
			l := lg.leg
			if l.Chain != c.chain || l.ProofID != testProof || l.BundleID != testBundle {
				t.Fatalf("leg = %+v", l)
			}
			if l.BlockNumber == 0 || l.BlockHash == (common.Hash{}) || l.TxHash == (common.Hash{}) || l.Tx == nil || l.Receipt == nil {
				t.Fatalf("leg is incomplete: %+v", l)
			}
			if got := (finality.CaptureKey{Chain: c.chain, L1Block: l.BlockNumber, L1Hash: l.BlockHash, Item: ItemLegacyHeader}); l.Key() != got {
				t.Fatalf("key = %v, want %v", l.Key(), got)
			}
			if err := finality.CheckCaptureItem(ItemLegacyHeader); err != nil {
				t.Fatalf("the capture item is not a valid name: %v", err)
			}
			if strings.HasPrefix(ItemLegacyHeader, "hdr") {
				t.Fatalf("the item %q would be listed with the Base L1 header rows (prefix hdr)", ItemLegacyHeader)
			}
		})
	}
}

func TestParseLegRefusesWhatItCannotReadByName(t *testing.T) {
	base := legacyOf(t, "base_sepolia_47368146")
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		has    string
	}{
		{"no chain_id", func(m map[string]any) { delete(m, "chain_id") }, "chain_id"},
		{"chain_id not decimal", func(m map[string]any) { m["chain_id"] = "base" }, "chain_id"},
		{"chain_id zero", func(m map[string]any) { m["chain_id"] = "0" }, "chain_id"},
		{"chain_id a number", func(m map[string]any) { m["chain_id"] = 84532 }, "does not decode"},
		{"no block_number", func(m map[string]any) { delete(m, "block_number") }, "block_number"},
		{"block_number negative", func(m map[string]any) { m["block_number"] = -1 }, "block_number"},
		{"block_number fractional", func(m map[string]any) { m["block_number"] = 1.5 }, "block_number"},
		{"no block_hash", func(m map[string]any) { delete(m, "block_hash") }, "block_hash"},
		{"block_hash short", func(m map[string]any) { m["block_hash"] = "0x1234" }, "does not decode"},
		{"block_hash zero", func(m map[string]any) { m["block_hash"] = common.Hash{}.Hex() }, "block_hash"},
		{"no tx_hash", func(m map[string]any) { delete(m, "tx_hash") }, "tx_hash"},
		{"no transactions_root", func(m map[string]any) { delete(m, "transactions_root") }, "transactions_root"},
		{"no receipts_root", func(m map[string]any) { delete(m, "receipts_root") }, "receipts_root"},
		{"no tx proof", func(m map[string]any) { delete(m, "tx_inclusion_proof") }, "tx_inclusion_proof"},
		{"no receipt proof", func(m map[string]any) { delete(m, "receipt_inclusion_proof") }, "receipt_inclusion_proof"},
		{"proof not an object", func(m map[string]any) { m["tx_inclusion_proof"] = "x" }, "does not decode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]any{}
			if err := json.Unmarshal(mustJSON(t, base.comp), &m); err != nil {
				t.Fatal(err)
			}
			c.mutate(m)
			_, err := ParseLeg(testProof, testBundle, mustJSON(t, m))
			wantInvalid(t, c.name, err, Leg{}, "")
			if !strings.Contains(err.Error(), c.has) {
				t.Fatalf("%s: the cause does not name %q: %v", c.name, c.has, err)
			}
		})
	}
	if _, err := ParseLeg(testProof, testBundle, json.RawMessage(`[1]`)); err == nil {
		t.Fatal("a component that is not an object parsed")
	}
}

func TestVerifyAcceptsTheRealHeaderOfEachChainAndBuildsTheNewShapeSettlement(t *testing.T) {
	for _, c := range chainFixtures {
		t.Run(c.name, func(t *testing.T) {
			lg := legacyOf(t, c.fixture)
			if err := lg.leg.Verify(lg.header); err != nil {
				t.Fatalf("the leg's own header is refused: %v", err)
			}
			// the Settlement is the value a new-shape bundle holds, and derives level 1 like it
			s := lg.leg.Settlement(lg.header)
			block, err := finality.DeriveIncluded(c.chain, s)
			if err != nil {
				t.Fatalf("DeriveIncluded: %v", err)
			}
			if block.Number != lg.leg.BlockNumber || block.Hash != [32]byte(lg.leg.BlockHash) || !bytes.Equal(block.HeaderRLP, lg.header) {
				t.Fatalf("derived block %+v", block)
			}
			// the header is copied: changing the caller's slice does not change the settlement
			lg.header[0] ^= 0xff
			if bytes.Equal(s.Header, lg.header) {
				t.Fatal("the Settlement aliases the caller's header")
			}
		})
	}
}

func TestVerifyRefusesEachWayAHeaderOrTheStoredComponentCanBeWrong(t *testing.T) {
	base := legacyOf(t, "base_sepolia_47368146")
	other := legacyOf(t, "arbitrum_sepolia_315455204")
	flip := func(h common.Hash) common.Hash { h[31] ^= 1; return h }
	junk := []byte{0xc2, 0x01, 0x02} // an RLP list of two bytes: not a header
	cases := []struct {
		name   string
		leg    func(l Leg) Leg
		header []byte
		check  string
	}{
		{"empty header", nil, nil, CheckHeaderSize},
		{"header one byte past the bound", nil, make([]byte, MaxHeaderRLP+1), CheckHeaderSize},
		{"header exactly at the bound is size-valid and fails on its hash", nil, make([]byte, MaxHeaderRLP), CheckHeaderHash},
		{"a header of another block", nil, other.header, CheckHeaderHash},
		{"the right hash over bytes that are not a header", func(l Leg) Leg { l.BlockHash = crypto.Keccak256Hash(junk); return l }, junk, CheckHeaderParse},
		{"the stored block number is off by one", func(l Leg) Leg { l.BlockNumber++; return l }, base.header, CheckBlockNumber},
		{"the stored transactions_root differs from the header's", func(l Leg) Leg { l.TransactionsRoot = flip(l.TransactionsRoot); return l }, base.header, CheckStoredRoots},
		{"the stored receipts_root differs from the header's", func(l Leg) Leg { l.ReceiptsRoot = flip(l.ReceiptsRoot); return l }, base.header, CheckStoredRoots},
		{"the stored tx proof resolves from another root", func(l Leg) Leg {
			p := *l.Tx
			p.ExpectedRoot = flip(p.ExpectedRoot)
			l.Tx = &p
			return l
		}, base.header, CheckInclusion},
		{"the stored receipt proof has another leaf", func(l Leg) Leg {
			p := *l.Receipt
			p.LeafValue = append([]byte(nil), p.LeafValue...)
			p.LeafValue[len(p.LeafValue)-1] ^= 1
			l.Receipt = &p
			return l
		}, base.header, CheckInclusion},
		{"the stored tx proof is for another index", func(l Leg) Leg {
			p := *l.Tx
			p.LeafIndex++
			l.Tx = &p
			return l
		}, base.header, CheckInclusion},
		{"the proven transaction is not the stored tx_hash", func(l Leg) Leg { l.TxHash = flip(l.TxHash); return l }, base.header, CheckInclusion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := base.leg
			if c.leg != nil {
				l = c.leg(l)
			}
			err := l.Verify(c.header)
			wantInvalid(t, c.name, err, l, c.check)
		})
	}
	// the unmodified leg still verifies after the table (nothing above mutated the shared proofs)
	if err := base.leg.Verify(base.header); err != nil {
		t.Fatalf("the base leg no longer verifies: %v", err)
	}
}
