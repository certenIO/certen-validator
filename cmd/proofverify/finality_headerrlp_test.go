// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
)

// R12-OUTCOME-TX. C1: the Settlement an outcome evidence file names is its MEMBER's settlement (leaf block, leaf transaction), not the
// block of the registry write that recorded the outcome. A2: the finality member may carry the settlement header (leg.headerRlp), so a
// holder of the exported file alone judges the leg.

func TestOutcomeFileSettlementIsTheMembersAndNotTheRecordersBlock(t *testing.T) {
	ev := loadFixture(t, 84532)
	if ev.Record.BlockNumber == ev.Member.Leaf.BlockNumber {
		t.Fatal("the fixture must hold the recording in another block than the settlement")
	}
	leg, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	block, err := finality.DeriveIncluded(leg.chain, leg.s)
	if err != nil {
		t.Fatal(err)
	}
	if block.Number != ev.Member.Leaf.BlockNumber || leg.outcome.tx != common.HexToHash(ev.Member.Leaf.Tx) {
		t.Fatalf("settlement %+v, outcome %+v: not the leaf's block and transaction", block, leg.outcome)
	}
	// a document whose leg is the SETTLEMENT block verifies against it although the recording lies in another block
	path, leg := outcomeDoc(t, func() finality.BlockRef { b := block; b.HeaderRLP = nil; return b }())
	if code, out := verifyFileWith(t, path, baseRegistry(), leg); code != exitVerified {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// a document whose leg is the RECORDING block is not this outcome's settlement
	rec := block
	rec.HeaderRLP = nil
	rec.Number = ev.Record.BlockNumber
	rec.Hash = common.HexToHash(ev.Record.BlockHash)
	path, leg = outcomeDoc(t, rec)
	if code, out := verifyFileWith(t, path, baseRegistry(), leg); code != exitFailed || !strings.Contains(out, "outcome_not_bound{field=block_number,") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestOutcomeFileMembersThatHoldNoSettlementAreNamedAndStatus12AreAccepted(t *testing.T) {
	for _, status := range []uint8{3, 4} {
		ev := loadFixture(t, 84532)
		ev.Member.Leaf.Status = status
		_, err := settlementFromOutcomeFile(writeEvidence(t, ev))
		n, ok := finality.AsNamed(err)
		if !ok || n.Code != finality.CodeIncludedUnavailable || fmt.Sprint(n.Fields["reason"]) != string(finality.IncludedNoSettlement) {
			t.Errorf("status %d: %v", status, err)
		}
	}
	ev := loadFixture(t, 84532)
	ev.Member.Leaf.Status = 2
	if _, err := settlementFromOutcomeFile(writeEvidence(t, ev)); err != nil {
		t.Errorf("status 2 (a settled transaction with a shortfall) is a settlement: %v", err)
	}
	ev = loadFixture(t, 84532)
	ev.Member.Transaction = nil
	if _, err := settlementFromOutcomeFile(writeEvidence(t, ev)); err == nil || !strings.Contains(err.Error(), "no settlement inclusion") {
		t.Errorf("a member without its inclusion: %v", err)
	}
}

func TestOutcomeFileTamperedLeafIsRefusedAgainstTheInclusion(t *testing.T) {
	cases := map[string]struct {
		mutate func(*execution.OutcomeEvidence)
		want   string
	}{
		"leaf block hash":   {func(e *execution.OutcomeEvidence) { e.Member.Leaf.BlockHash = e.Record.BlockHash }, "header hashes to"},
		"leaf block number": {func(e *execution.OutcomeEvidence) { e.Member.Leaf.BlockNumber++ }, "is not block"},
		"leaf transaction":  {func(e *execution.OutcomeEvidence) { e.Member.Leaf.Tx = e.Record.Tx }, "transaction hashes to"},
	}
	for name, c := range cases {
		ev := loadFixture(t, 84532)
		c.mutate(ev)
		if _, err := settlementFromOutcomeFile(writeEvidence(t, ev)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func headerDoc(t *testing.T, section finality.Section) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"format": "certen-proof-v2-accumulate-portable/1", "finality": section})
	if err != nil {
		t.Fatal(err)
	}
	return writeDoc(t, raw)
}

func TestFinalityFileAloneJudgesALegThatCarriesItsHeader(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	other := finalitytest.Settlement(t, "telcoin_adiri_498759")
	pid := uuid.New()
	block := s.Block()
	good := finality.NewSectionWithHeader(block, chainFor(t, s, pid, finality.LegBindingOf(block), finality.LevelL1Posted, finality.LevelFinalized))
	if good.Leg.HeaderRLP != hex.EncodeToString(s.Included.Header) {
		t.Fatal("NewSectionWithHeader did not carry the header")
	}

	t.Run("a real vector leg is judged end to end with no Settlement source, and level 1 is not claimed", func(t *testing.T) {
		code, out := verifyFileWith(t, headerDoc(t, good), baseRegistry(), nil)
		if code != exitVerified || !strings.Contains(out, "level reached: finalized") || !strings.Contains(out, "finalized_block") {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if !strings.Contains(out, "included   pending") || !strings.Contains(out, string(finality.IncludedNoSettlement)) || !strings.Contains(out, "not the settlement transaction") {
			t.Fatalf("level 1 is not reported honestly:\n%s", out)
		}
	})
	t.Run("one level present: the other is pending in the file", func(t *testing.T) {
		one := finality.NewSectionWithHeader(block, chainFor(t, s, pid, finality.LegBindingOf(block), finality.LevelL1Posted))
		code, out := verifyFileWith(t, headerDoc(t, one), baseRegistry(), nil)
		if code != exitVerified || !strings.Contains(out, "level reached: l1_posted") || !strings.Contains(out, "no_evidence_in_file") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a chain forged under another D0 is refused at own_hash even with the header", func(t *testing.T) {
		wrong := block
		wrong.Number++
		forged := finality.NewSectionWithHeader(block, chainFor(t, s, pid, finality.LegBindingOf(wrong), finality.LevelFinalized))
		code, out := verifyFileWith(t, headerDoc(t, forged), baseRegistry(), nil)
		if code != exitFailed || !strings.Contains(out, finality.CheckOwnHash) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a header of another block is leg_binding on blockHash", func(t *testing.T) {
		bad := good
		bad.Leg.HeaderRLP = hex.EncodeToString(other.Included.Header)
		for _, src := range []*legSettlement{nil, {chain: finality.ChainBaseSepolia, s: s.Included, source: "test"}} {
			code, out := verifyFileWith(t, headerDoc(t, bad), baseRegistry(), src)
			if code != exitFailed || !strings.Contains(out, finality.CheckLegBinding) || !strings.Contains(out, "blockHash") {
				t.Fatalf("exit %d\n%s", code, out)
			}
		}
	})
	t.Run("a block number other than the header's is leg_binding on blockNumber", func(t *testing.T) {
		bad := good
		bad.Leg.BlockNumber++
		code, out := verifyFileWith(t, headerDoc(t, bad), baseRegistry(), nil)
		if code != exitFailed || !strings.Contains(out, finality.CheckLegBinding) || !strings.Contains(out, "blockNumber") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("with a Settlement source the behaviour is unchanged and the carried header equals the Settlement's block", func(t *testing.T) {
		leg := &legSettlement{chain: finality.ChainBaseSepolia, s: s.Included, source: "test"}
		code, out := verifyFileWith(t, headerDoc(t, good), baseRegistry(), leg)
		if code != exitVerified || !strings.Contains(out, "level reached: finalized") || !strings.Contains(out, "Settlement source: test") || strings.Contains(out, string(finality.IncludedNoSettlement)) {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a header that is not a block header, or not lower-case hex, is refused by name", func(t *testing.T) {
		for _, h := range []string{"c0", "ABCD", "abc", "zz"} {
			bad := good
			bad.Leg.HeaderRLP = h
			code, out := verifyFileWith(t, headerDoc(t, bad), baseRegistry(), nil)
			if code != exitFailed {
				t.Fatalf("header %q: exit %d\n%s", h, code, out)
			}
		}
	})
}

func TestParseSectionReadsTheOptionalHeaderStrictly(t *testing.T) {
	s := finalitytest.Settlement(t, "base_sepolia_47368146")
	block := s.Block()
	leg := func(extra string) []byte {
		return []byte(`{"format":"certen-finality-addenda/1","leg":{"chain":84532,"blockNumber":` + "1" + `,"blockHash":"` + strings.Repeat("11", 32) + `"` + extra + `},"addenda":[]}`)
	}
	if sec, err := finality.ParseSection(leg(`,"headerRlp":"c0c0"`)); err != nil || sec.Leg.HeaderRLP != "c0c0" {
		t.Fatalf("a leg with a header: %+v %v", sec, err)
	}
	if sec, err := finality.ParseSection(leg(``)); err != nil || sec.Leg.HeaderRLP != "" {
		t.Fatalf("a leg without one: %+v %v", sec, err)
	}
	for name, extra := range map[string]string{
		"empty":     `,"headerRlp":""`,
		"upper":     `,"headerRlp":"C0C0"`,
		"odd":       `,"headerRlp":"c0c"`,
		"number":    `,"headerRlp":1`,
		"null":      `,"headerRlp":null`,
		"oversized": `,"headerRlp":"` + strings.Repeat("00", finality.MaxLegHeaderBytes+1) + `"`,
		"unknown":   `,"headerRLP":"c0"`,
	} {
		if _, err := finality.ParseSection(leg(extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the header the composer emits parses back to the bound block
	sec := finality.NewSectionWithHeader(block, nil)
	raw, _ := json.Marshal(sec)
	back, err := finality.ParseSection(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ref, err := back.Leg.Ref(); err != nil || ref.Number != block.Number || ref.Hash != block.Hash || len(ref.HeaderRLP) == 0 {
		t.Fatalf("%+v %v", ref, err)
	}
	// a leg without a header renders without the member (a verifier that predates it reads the document unchanged)
	if raw, _ := json.Marshal(finality.NewSection(block, nil)); strings.Contains(string(raw), "headerRlp") {
		t.Fatalf("a header-less leg renders a headerRlp member: %s", raw)
	}
}
