// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// Mutation-gate killers (RB12-DBFIX) for the Settlement source read from an exported outcome evidence file, and for the reading of
// the portable document: each thing that is wrong with the file is refused by name, in the order the reader judges it.

func TestSettlementFromOutcomeFileRefusesEachDefectOfTheFileByName(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := settlementFromOutcomeFile(filepath.Join(dir, "absent.json")); err == nil || !os.IsNotExist(err) {
		t.Errorf("an absent file: %v", err)
	}
	if _, err := settlementFromOutcomeFile(write("garbage.json", "{not json")); err == nil || !strings.Contains(err.Error(), "does not decode") {
		t.Errorf("a file that is not JSON: %v", err)
	}
	for _, chain := range []int64{0, -5} {
		ev := loadFixture(t, 84532)
		ev.ChainID = chain
		if _, err := settlementFromOutcomeFile(writeEvidence(t, ev)); err == nil || !strings.Contains(err.Error(), "names chain") {
			t.Errorf("chain %d: %v", chain, err)
		}
	}
	// chain 1 is a chain: the file is judged on its header and transaction, not on which chain it names
	one := loadFixture(t, 84532)
	one.ChainID = 1
	if leg, err := settlementFromOutcomeFile(writeEvidence(t, one)); err != nil || leg.chain != 1 || leg.outcome == nil || leg.outcome.chain != 1 {
		t.Errorf("chain 1: %+v %v", leg, err)
	}
	// a header that is not RLP
	junk := loadFixture(t, 84532)
	junk.Record.Inclusion.Header = []byte{0x01}
	if _, err := settlementFromOutcomeFile(writeEvidence(t, junk)); err == nil || !strings.Contains(err.Error(), "header does not decode") {
		t.Errorf("a header that is not RLP: %v", err)
	}
	// the record names another block number than the header holds
	other := loadFixture(t, 84532)
	other.Record.BlockNumber++
	if _, err := settlementFromOutcomeFile(writeEvidence(t, other)); err == nil || !strings.Contains(err.Error(), "is not block") {
		t.Errorf("a record that names another block number: %v", err)
	}
	// the Settlement of a good file names the transaction, block and chain the report prints
	good, err := settlementFromOutcomeFile(fixturePath(84532))
	if err != nil {
		t.Fatal(err)
	}
	ev := loadFixture(t, 84532)
	if good.outcome == nil || good.outcome.chain != 84532 || good.outcome.blockNumber != ev.Record.BlockNumber || !strings.EqualFold(good.outcome.tx.Hex(), ev.Record.Tx) ||
		!strings.EqualFold(good.outcome.blockHash.Hex(), ev.Record.BlockHash) {
		t.Errorf("%+v", good.outcome)
	}
}

func TestReportFinalityFileRefusesAFileItCannotReadOrParse(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := reportFinalityFile(&out, filepath.Join(t.TempDir(), "absent.json"), finality.Default, pins, nil); code != exitFailed || !strings.Contains(out.String(), "FAILED (finality)") {
		t.Errorf("an absent document: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := reportFinalityFile(&out, writeDoc(t, []byte("not json")), finality.Default, pins, nil); code != exitFailed || !strings.Contains(out.String(), "not a portable document") {
		t.Errorf("a document that is not JSON: exit %d\n%s", code, out.String())
	}
}
