// Copyright 2026 Certen Protocol

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Cross-check of the Lighthouse answer. publicnode serves Lighthouse light-client objects as Beacon API JSON whatever the
// Accept header says, so the SSZ bytes of Lodestar are compared field by field with the JSON of Lighthouse (the committee keys,
// the branches, the beacon header fields, the execution block hash and number, the sync aggregate and the signature slot).

func jstr(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func jobj(m map[string]any, path ...string) map[string]any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	mm, _ := cur.(map[string]any)
	return mm
}

func jlist(m map[string]any, path ...string) []string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	arr, _ := cur.([]any)
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i], _ = x.(string)
	}
	return out
}

func hexEq(what, got string, want []byte) error {
	if strings.ToLower(got) != "0x"+hex.EncodeToString(want) {
		return fmt.Errorf("%s: lighthouse %.80s, lodestar 0x%x", what, got, want)
	}
	return nil
}

func u64LE(b []byte) string { return fmt.Sprint(binary.LittleEndian.Uint64(b)) }

// checkHeader compares one Electra-layout LightClientHeader (the whole SSZ header) with the Beacon API JSON header.
func checkHeader(what string, ssz []byte, j map[string]any) error {
	if len(ssz) < electraHeaderFix+584 {
		return fmt.Errorf("%s: header of %d bytes", what, len(ssz))
	}
	if got := jstr(j, "beacon", "slot"); got != u64LE(ssz[0:8]) {
		return fmt.Errorf("%s: slot lighthouse %s lodestar %s", what, got, u64LE(ssz[0:8]))
	}
	for _, f := range []struct {
		name string
		off  int
	}{{"parent_root", 16}, {"state_root", 48}, {"body_root", 80}} {
		if err := hexEq(what+" beacon."+f.name, jstr(j, "beacon", f.name), ssz[f.off:f.off+32]); err != nil {
			return err
		}
	}
	ex := ssz[electraHeaderFix:]
	if err := hexEq(what+" execution.block_hash", jstr(j, "execution", "block_hash"), ex[execBlockHashAt:execBlockHashAt+32]); err != nil {
		return err
	}
	if got := jstr(j, "execution", "block_number"); got != u64LE(ex[execBlockNumberAt:]) {
		return fmt.Errorf("%s: block_number lighthouse %s lodestar %s", what, got, u64LE(ex[execBlockNumberAt:]))
	}
	if err := hexEq(what+" execution.state_root", jstr(j, "execution", "state_root"), ex[52:84]); err != nil {
		return err
	}
	br := jlist(j, "execution_branch")
	if len(br) != 4 {
		return fmt.Errorf("%s: execution_branch has %d nodes", what, len(br))
	}
	for i, n := range br {
		if err := hexEq(fmt.Sprintf("%s execution_branch[%d]", what, i), n, ssz[116+32*i:148+32*i]); err != nil {
			return err
		}
	}
	return nil
}

func checkCommittee(what string, ssz []byte, j map[string]any) error {
	keys := jlist(j, "pubkeys")
	if len(keys) != 512 {
		return fmt.Errorf("%s: %d pubkeys", what, len(keys))
	}
	for i, k := range keys {
		if err := hexEq(fmt.Sprintf("%s pubkey %d", what, i), k, ssz[i*48:i*48+48]); err != nil {
			return err
		}
	}
	return hexEq(what+" aggregate_pubkey", jstr(j, "aggregate_pubkey"), ssz[512*48:512*48+48])
}

func checkBranch(what string, ssz []byte, nodes []string) error {
	if len(nodes)*32 != len(ssz) {
		return fmt.Errorf("%s: lighthouse %d nodes, lodestar %d bytes", what, len(nodes), len(ssz))
	}
	for i, n := range nodes {
		if err := hexEq(fmt.Sprintf("%s[%d]", what, i), n, ssz[i*32:i*32+32]); err != nil {
			return err
		}
	}
	return nil
}

func crossCheckBootstrap(ssz, lighthouseBody []byte) error {
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(lighthouseBody, &env); err != nil || env.Data == nil {
		return redactedErr("lighthouse bootstrap is not Beacon API JSON: %v: %.120s", err, lighthouseBody)
	}
	hdrOff := int(binary.LittleEndian.Uint32(ssz[0:4]))
	if hdrOff != 4+24624+192 {
		return fmt.Errorf("lodestar bootstrap first offset %d", hdrOff)
	}
	if err := checkHeader("bootstrap header", ssz[hdrOff:], jobj(env.Data, "header")); err != nil {
		return err
	}
	if err := checkCommittee("bootstrap committee", ssz[4:4+24624], jobj(env.Data, "current_sync_committee")); err != nil {
		return err
	}
	return checkBranch("bootstrap committee branch", ssz[4+24624:hdrOff], jlist(env.Data, "current_sync_committee_branch"))
}

func crossCheckUpdates(parts [][]byte, lighthouseBody []byte) error {
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(lighthouseBody, &env); err != nil || len(env.Data) != len(parts) {
		var arr []struct {
			Data map[string]any `json:"data"`
		}
		if err2 := json.Unmarshal(lighthouseBody, &arr); err2 != nil || len(arr) != len(parts) {
			return redactedErr("lighthouse updates are not the expected Beacon API JSON (%d parts): %v: %.120s", len(parts), err, lighthouseBody)
		}
		env.Data = nil
		for _, a := range arr {
			env.Data = append(env.Data, a.Data)
		}
	}
	for i, u := range parts {
		j := env.Data[i]
		what := fmt.Sprintf("update[%d]", i)
		attOff := int(binary.LittleEndian.Uint32(u[0:4]))
		finOff := int(binary.LittleEndian.Uint32(u[24820:24824]))
		if attOff != electraUpdFixed || finOff <= attOff || finOff > len(u) {
			return fmt.Errorf("%s: offsets %d %d", what, attOff, finOff)
		}
		if err := checkHeader(what+" attested", u[attOff:finOff], jobj(j, "attested_header")); err != nil {
			return err
		}
		if err := checkHeader(what+" finalized", u[finOff:], jobj(j, "finalized_header")); err != nil {
			return err
		}
		if err := checkCommittee(what+" next committee", u[4:4+24624], jobj(j, "next_sync_committee")); err != nil {
			return err
		}
		if err := checkBranch(what+" next branch", u[4+24624:4+24624+192], jlist(j, "next_sync_committee_branch")); err != nil {
			return err
		}
		if err := checkBranch(what+" finality branch", u[24824:24824+224], jlist(j, "finality_branch")); err != nil {
			return err
		}
		agg := u[24824+224 : 24824+224+160]
		if err := hexEq(what+" sync_committee_bits", jstr(j, "sync_aggregate", "sync_committee_bits"), agg[:64]); err != nil {
			return err
		}
		if err := hexEq(what+" sync_committee_signature", jstr(j, "sync_aggregate", "sync_committee_signature"), agg[64:]); err != nil {
			return err
		}
		if got := jstr(j, "signature_slot"); got != u64LE(u[electraUpdFixed-8:electraUpdFixed]) {
			return fmt.Errorf("%s: signature_slot lighthouse %s", what, got)
		}
	}
	return nil
}
