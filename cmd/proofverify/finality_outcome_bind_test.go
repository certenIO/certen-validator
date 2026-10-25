// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX (Addendum C item 8): an exported outcome evidence file is the Settlement source of a portable document's finality
// section. The pair must be one pair: the outcome's chain and the block that holds its recorded transaction are the document's carried
// leg, or the verifier refuses by name (outcome_not_bound{field}) before it judges a single addendum - and the report says which
// transaction it judged and that the document, which names no settlement transaction, cannot bind that transaction itself.

func outcomeDoc(t *testing.T, carried finality.BlockRef) (string, *legSettlement) {
	t.Helper()
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	s := finality.Settlement{Chain: leg.chain, Included: leg.s}
	s.Subject, _ = finality.SubjectOfSettlement(leg.s)
	section := finality.NewSection(carried, chainFor(t, s, uuid.New(), finality.LegBindingOf(block), finality.LevelL1Posted))
	raw, err := json.Marshal(map[string]any{"finality": section})
	if err != nil {
		t.Fatal(err)
	}
	return writeDoc(t, raw), leg
}

func TestOutcomeFileIsBoundToTheDocumentsCarriedLegByChainBlockNumberAndBlockHash(t *testing.T) {
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, field string
		mutate      func(*finality.BlockRef)
	}{
		{"another chain", "chain", func(b *finality.BlockRef) { b.Chain = finality.ChainSepolia }},
		{"another block number", "block_number", func(b *finality.BlockRef) { b.Number++ }},
		{"another block hash", "block_hash", func(b *finality.BlockRef) { b.Hash[31] ^= 1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			carried := block
			carried.HeaderRLP = nil
			c.mutate(&carried)
			path, leg := outcomeDoc(t, carried)
			code, out := verifyFileWith(t, path, baseRegistry(), leg)
			want := "outcome_not_bound{field=" + c.field + ","
			if code != exitFailed || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want FAILED naming %s\n%s", code, want, out)
			}
			if strings.Contains(out, "VERIFIED") || strings.Contains(out, "level reached") {
				t.Fatalf("addenda were judged against an outcome that is not the document's leg:\n%s", out)
			}
		})
	}
}

func TestOutcomeFileReportNamesTheTransactionItJudgedAndWhatBindsIt(t *testing.T) {
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	carried := block
	carried.HeaderRLP = nil
	path, leg := outcomeDoc(t, carried)
	code, out := verifyFileWith(t, path, baseRegistry(), leg)
	ev := loadFixture(t, 84532)
	if code != exitVerified {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"outcome settlement transaction " + strings.ToLower(ev.Member.Leaf.Tx) + " on chain 84532 in block " + fmt.Sprint(ev.Member.Leaf.BlockNumber),
		"bound to the document's carried leg by chain, block number and block hash",
		"outcome_tx_unbound{reason=document_names_no_settlement_tx}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the report does not say %q:\n%s", want, out)
		}
	}
}
