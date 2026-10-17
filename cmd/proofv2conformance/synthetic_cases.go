package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/intentcert"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// Document is an additional base in the manifest: a whole document, the verdict every verifier must reach on it, and one
// tampered twin per attack.
type Document struct {
	Name   string  `json:"name"`
	File   string  `json:"file"`
	Expect string  `json:"expect"`
	Report *Report `json:"report"`
	Cases  []Case  `json:"cases"`
	// GovRootRefusal is the message govRoot v3 must refuse the verified proof with.
	GovRootRefusal string `json:"govRootRefusal"`
}

var syntheticAttacks = []attack{
	{"update-removed", "the network update dropped from major block 2 (the set it installed is still relied on)", func(d map[string]any) error {
		return set(get(d, "majors", 1).v, "updates", []any{})
	}},
	{"update-record-altered", "the update's record altered (a different validator set than the receipt proves)", func(d map[string]any) error {
		return flipHexMid(get(d, "majors", 1, "updates", 0, "transaction", "body", "entry", "data", 0))
	}},
	{"update-receipt-altered", "a step of the update's receipt changed", func(d map[string]any) error {
		return flipHex(get(d, "majors", 1, "updates", 0, "receipt", "entries", 0, "hash"))
	}},
	{"update-principal-swapped", "the update presented as a write to another account", func(d map[string]any) error {
		return set(get(d, "majors", 1, "updates", 0, "transaction", "header").v, "principal", "acc://dn.acme/other")
	}},
	{"post-update-signer-forged", "the new validator's signature on major block 2 forged", func(d map[string]any) error {
		return flipHex(get(d, "majors", 1, "signatures", 2, "signature"))
	}},
	{"quorum-short", "major block 2 left with one signature", func(d map[string]any) error {
		sigs := get(d, "majors", 1, "signatures").v.([]any)
		return set(get(d, "majors", 1).v, "signatures", sigs[:1])
	}},
	{"certify-quorum-short", "the certifying anchor left with one signature", func(d map[string]any) error {
		c := lastOf(get(d, "evidence", "certify"))
		sigs := get(c, "signatures").v.([]any)
		return set(c, "signatures", sigs[:1])
	}},
	{"main-height-understated", "the network account's main chain height understated (the update unaccounted)", func(d map[string]any) error {
		cm := get(d, "evidence", "check", "network", "chains", 0).v.(map[string]any)
		p := cm["pending"].([]any)
		cm["pending"] = []any{p[1]}
		return nil
	}},
	{"main-height-overstated", "the network account's main chain height overstated (an update that never happened)", func(d map[string]any) error {
		cm := get(d, "evidence", "check", "network", "chains", 0).v.(map[string]any)
		p := cm["pending"].([]any)
		cm["pending"] = append(p, strings.Repeat("ab", 32))
		return nil
	}},
	{"network-entry-altered", "the proven network account's validator set altered", func(d map[string]any) error {
		return flipHexMid(get(d, "evidence", "check", "network", "account", "entry", "data", 0))
	}},
	{"network-record-genesis", "the decoded network record replaced by the genesis record (the update ignored)", func(d map[string]any) error {
		g := get(d, "genesis", "network").v
		return set(get(d, "evidence", "check", "network").v, "record", g)
	}},
	{"receipt-step", "a step of the transaction's receipt changed", func(d map[string]any) error {
		return flipHex(get(d, "evidence", "receipt", "entries", 1, "hash"))
	}},
	{"anchor-block-altered", "the partition anchor names another block", func(d map[string]any) error {
		return bump(get(d, "evidence", "anchor", "message", "message", "transaction", "body", "minorBlockIndex"))
	}},
	{"archive-short", "one major block fewer than the evidence builds on", func(d map[string]any) error {
		ms, _ := d["majors"].([]any)
		d["majors"] = ms[:len(ms)-1]
		return nil
	}},
	{"major-1-altered", "major block 1's anchor altered", func(d map[string]any) error {
		return bump(get(d, "majors", 0, "anchor", "message", "transaction", "body", "minorBlockIndex"))
	}},
	{"pin-other", "another incarnation pinned", func(d map[string]any) error {
		return flipHex(get(d, "pin"))
	}},
	{"genesis-record-altered", "the genesis network record altered", func(d map[string]any) error {
		return flipHexMid(get(d, "genesis", "networkRecord"))
	}},
}

// syntheticDocuments writes the synthetic document and its tampered twins, and returns its manifest entry.
func syntheticDocuments(write func(name string, doc any) error) ([]Document, error) {
	p, err := syntheticDocument()
	if err != nil {
		return nil, err
	}
	pev, par, pin, ppin, err := proofv2.Import(p)
	if err != nil {
		return nil, err
	}
	rep, err := proofv2.VerifyFromGenesis(pev, par, pin, ppin)
	if err != nil {
		return nil, fmt.Errorf("the synthetic document does not verify: %w", err)
	}
	if rep.Validators != 4 || rep.Majors != 2 {
		return nil, fmt.Errorf("the update was not applied: %d validators over %d major blocks", rep.Validators, rep.Majors)
	}
	// A set that changed after genesis is asserted, not derived from genesis here, and govRoot v3 refuses it by name: the proof is
	// otherwise verified. Every verifier must refuse it the same way.
	gin := govRootV3Inputs(rep, pev)
	_, _, refusal := intentcert.GovRootV3(gin)
	if refusal == nil || !strings.Contains(refusal.Error(), "validator_set_asserted, not verified") {
		return nil, fmt.Errorf("govRoot v3 over a set that changed after genesis: %v", refusal)
	}
	if p.GovRootV3Inputs, err = intentcert.PortableGovRootV3Inputs(gin); err != nil {
		return nil, err
	}
	if _, _, again := intentcert.GovRootV3FromPortable(rep, pev, p.GovRootV3Inputs); again == nil || again.Error() != refusal.Error() {
		return nil, fmt.Errorf("govRoot v3 from the portable inputs gave %v, from the results %v", again, refusal)
	}
	base, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if err := write("network-update.json.gz", p); err != nil {
		return nil, err
	}
	cases, err := attackCases(base, syntheticAttacks)
	if err != nil {
		return nil, err
	}
	return []Document{{Name: "network-update", File: "network-update.json.gz", Expect: "verified", Cases: cases, Report: &Report{
		Incarnation: fmt.Sprintf("%x", rep.Incarnation), Majors: rep.Majors, CertifiedBlock: rep.CertifiedBlock,
		CertifiedRoot: fmt.Sprintf("%x", rep.CertifiedRoot), CheckBlock: rep.CheckBlock, SetVerdict: string(rep.SetVerdict),
		Validators: rep.Validators, Threshold: rep.Threshold, Partition: rep.Partition, AnchorBlock: rep.AnchorBlock, Pages: len(rep.Pages),
	}, GovRootRefusal: refusal.Error()}}, nil
}
