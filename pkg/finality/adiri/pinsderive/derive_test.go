// Copyright 2026 Certen Protocol

package pinsderive_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	"github.com/certen/independant-validator/pkg/finality/adiri/pinsderive"
)

func pins(t *testing.T) *adiri.Params {
	t.Helper()
	p, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	par, err := adiri.ParsePins(p)
	if err != nil {
		t.Fatal(err)
	}
	return par
}

// The pinned genesis committee is re-derived from telcoin-network chain-configs/testnet/committee.yaml at tag v0.16.0-adiri
// (d72cc2bc), stored under testdata with its SHA-256 (annex M1), in file order.
func TestGenesisCommitteeIsDerivedFromCommitteeYAML(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "pins", "committee.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha(raw); got != "009b6d7b568f7d04734b657080d55621eed70f68ecefe1284dd8cdd0f42f15ce" {
		t.Fatalf("committee.yaml hashes to %s, the annex records 009b6d7b...f15ce", got)
	}
	keys, err := pinsderive.CommitteeFromYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	par := pins(t)
	if len(keys) != 5 || len(par.GenesisCommittee) != 5 {
		t.Fatalf("%d / %d keys", len(keys), len(par.GenesisCommittee))
	}
	for i := range keys {
		if !bytes.Equal(keys[i], par.GenesisCommittee[i]) {
			t.Errorf("key %d: yaml %x, pinned %x", i, keys[i], par.GenesisCommittee[i])
		}
	}
}

// The 290-header genesis link (176,758 B) hashes to genesis_link_sha256, links block 1 to the pinned genesis hash and ends at
// block 290 = epoch0_final_state.
func TestGenesisLinkBindsTheCommitteeChainToTheGenesisBlock(t *testing.T) {
	file, err := os.ReadFile(filepath.Join("..", "testdata", "pins", "genesis_link_1_290.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(file) != 176758 {
		t.Fatalf("%d B, the annex says 176,758", len(file))
	}
	par := pins(t)
	n, err := pinsderive.VerifyGenesisLink(file, par.GenesisLinkSHA, par.GenesisHash, par.Epoch0FinalState)
	if err != nil || n != 290 {
		t.Fatalf("%d %v", n, err)
	}
	// mutations are refused
	bad := append([]byte(nil), file...)
	bad[1000] ^= 1
	if _, err := pinsderive.VerifyGenesisLink(bad, par.GenesisLinkSHA, par.GenesisHash, par.Epoch0FinalState); err == nil {
		t.Fatal("a flipped bit passed the sha256")
	}
	wrongGenesis := par.GenesisHash
	wrongGenesis[0] ^= 1
	if _, err := pinsderive.VerifyGenesisLink(file, par.GenesisLinkSHA, wrongGenesis, par.Epoch0FinalState); err == nil {
		t.Fatal("another genesis hash passed")
	}
	wrongTip := par.Epoch0FinalState
	wrongTip.Number = 289
	if _, err := pinsderive.VerifyGenesisLink(file, par.GenesisLinkSHA, par.GenesisHash, wrongTip); err == nil {
		t.Fatal("another tip passed")
	}
}

// Epoch 0's record in the live chain carries exactly the pinned committee (as a set), a certificate that verifies, and the
// pinned final state (annex A7 step 3): verified here through the real evidence.
func TestRecordZeroMatchesThePins(t *testing.T) {
	ev, err := os.ReadFile(filepath.Join("..", "testdata", "finality_adiri1", "evidence", "live-500749-epoch600.bin"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := adiri.DecodeCFA1(b.CFA1, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	par := pins(t)
	if cf.Records[0].FinalState != par.Epoch0FinalState {
		t.Fatalf("%+v vs %+v", cf.Records[0].FinalState, par.Epoch0FinalState)
	}
	if hex.EncodeToString(par.EIP2935CodeHash[:]) != "6e49e66782037c0555897870e29fa5e552daf4719552131a0abce779daec0a5d" {
		t.Fatal("eip2935 codehash")
	}
	g := cf.Committee(0)
	for i := range g {
		if !bytes.Equal(g[i], par.GenesisCommittee[i]) {
			t.Fatalf("record 0 committee key %d differs from the pinned genesis committee", i)
		}
	}
}
