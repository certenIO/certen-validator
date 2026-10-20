// Copyright 2026 Certen Protocol

package ethl1

import (
	"sort"
	"strings"
	"testing"
)

// TestFaultFieldNamesMatchSpec pins the field names of every L1-head code to the lists of V2_SPEC_S7 section 7 (and R11-sepolia
// "Named states" where the spec elides them), so a renamed or dropped field fails here before the TypeScript port can drift.
func TestFaultFieldNamesMatchSpec(t *testing.T) {
	var z32 [32]byte
	cases := []struct {
		f    *Fault
		code string
		want string // sorted, comma-separated
		over bool   // extra fields allowed (the spec writes "...")
	}{
		{NetworkMismatch(1, 2), "finality_network_mismatch", "chain_id,want_chain_id", false},
		{ForkUnsupported(1, 2, "gloas"), "finality_fork_unsupported", "epoch,layout,slot", false},
		{EvidenceMalformed("p", 1, "r", 2, 3), "finality_evidence_malformed", "got_len,index,part,reason,want_len", false},
		{PinUnknown(1, 2, z32), "finality_pin_unknown", "kind,period,root", false},
		{PinMismatch(1, z32, z32), "finality_pin_mismatch", "got_root,period,want_root", false},
		{PinWindow(1, 2, 3), "finality_pin_window", "anchor_epoch,finalized_epoch,wsp_epochs", false},
		{BootstrapInvalid("c", 1), "finality_bootstrap_invalid", "check,slot", false},
		{LinkInvalid(0, "c", 1, 2, 3), "finality_link_invalid", "check,index", true},
		{ParticipationInsufficient(0, 1, 342, 512), "finality_participation_insufficient", "committee,index,participants,required", false},
		{SignatureInvalid(0, 1, [4]byte{}, 2), "finality_signature_invalid", "fork_version,index,participants,signature_slot", false},
		{PeriodGap(1, 2), "finality_period_gap", "signature_period,store_period", false},
		{BlockNotCovered(1, 2), "finality_block_not_covered", "block_number,finalized_exec_number", false},
		{LedgerBehind(1, 2), "finality_ledger_behind", "ledger_head_period,needed_period", false},
		{HeaderChainBroken("l1", 1, z32, z32, "hash"), "finality_header_chain_broken", "at_number,got_hash,reason,spine,want_hash", false},
		{EvidenceTooLarge("p", 1, 2), "finality_evidence_too_large", "count,limit,part", false},
		{L1FinalityUnproven("finality_pin_window"), "l1_finality_unproven", "reason", false},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.f.Code != c.code {
			t.Errorf("%s: code %q", c.code, c.f.Code)
		}
		var have []string
		for k := range c.f.Fields {
			have = append(have, k)
		}
		sort.Strings(have)
		got := strings.Join(have, ",")
		if c.over {
			for _, w := range strings.Split(c.want, ",") {
				if _, ok := c.f.Fields[w]; !ok {
					t.Errorf("%s: required field %s missing (have %s)", c.code, w, got)
				}
			}
		} else if got != c.want {
			t.Errorf("%s: fields %s, spec says %s", c.code, got, c.want)
		}
		seen[c.code] = true
	}
	for _, code := range AllCodes() {
		if !seen[code] {
			t.Errorf("code %s has no field-name pin", code)
		}
	}
}

func TestCheckNetwork(t *testing.T) {
	p := Pins{Network: Network{ChainID: SepoliaChainID}}
	if err := CheckNetwork(p, SepoliaChainID); err != nil {
		t.Fatal(err)
	}
	err := CheckNetwork(p, 1)
	f, ok := err.(*Fault)
	if !ok || f.Code != CodeNetworkMismatch {
		t.Fatalf("got %v", err)
	}
}
