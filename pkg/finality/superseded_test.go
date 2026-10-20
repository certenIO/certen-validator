// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/json"
	"strings"
	"testing"
)

// chain1Superseded maps the canonical text of every finality_chain1 expectation that carried a Go sentence in its `reason` to
// the canonical text with the closed enum token (RB11-B2B1). finality_chain1 itself is byte-identical and never edited
// (a golden is specification); finality_chain2 re-issues each of these ten expectations, and the chain1 tests judge them
// through supersededExpect so that every OTHER chain1 expectation still holds exactly as written.
var chain1Superseded = map[string]string{
	`{"code":"finality_addendum_malformed","fields":{"field":"level","reason":"level \"included\" is derived and never stored (stored levels: l1_posted, finalized)"}}`:                                  `{"code":"finality_addendum_malformed","fields":{"field":"level","reason":"level_not_stored"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`:       `{"code":"finality_evidence_malformed","fields":{"got_len":"0","part":"header.level","reason":"level_not_stored","want_len":"2"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`:       `{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"header.level","reason":"level_not_stored","want_len":"2"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"header.level","reason":"only levels l1_posted (2) and finalized (3) are carried; included is derived","want_len":"2"}}`:       `{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"header.level","reason":"level_not_stored","want_len":"2"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"25","index":"2","part":"header.kind","reason":"a STR is ASCII with no NUL","want_len":"25"}}`:                                            `{"code":"finality_evidence_malformed","fields":{"got_len":"25","index":"2","part":"header.kind","reason":"str_not_ascii_or_nul","want_len":"25"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"probe.end","reason":"trailing bytes","want_len":"0"}}`:                                                                        `{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"probe.end","reason":"trailing_bytes","want_len":"0"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes are not strictly ascending by keccak256 and unique","want_len":"0"}}`:                `{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"1","part":"probe.nodes","reason":"nodes_not_ascending_unique","want_len":"0"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.list","reason":"count exceeds the remaining bytes","want_len":"16"}}`:                                                   `{"code":"finality_evidence_malformed","fields":{"got_len":"4","part":"probe.list","reason":"count_exceeds_remaining","want_len":"16"}}`,
	`{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"level","reason":"included (1) is derived and never stored; only l1_posted (2) and finalized (3) have kinds","want_len":"2"}}`: `{"code":"finality_evidence_malformed","fields":{"got_len":"1","part":"level","reason":"level_not_stored","want_len":"2"}}`,
}

func supersededExpect(old string) string {
	if n, ok := chain1Superseded[old]; ok {
		return n
	}
	return old
}

// The supersession is exact: every entry is an expectation that really occurs in finality_chain1 (nine distinct texts cover the
// ten vectors: header_level_0/1/4, header_kind_has_nul, the four probe vectors, kind_level1_refused and the table's level 1
// query), each pair differs ONLY in the value of `reason`, and the new value is a member of the registry's closed set.
func TestTheChain1SupersessionIsExactlyTheMessageTextExpectations(t *testing.T) {
	reg := loadRegistry(t)
	files := []string{"chains.json", "containers.json", "codec_probe.json", "table.json"}
	var all strings.Builder
	for _, f := range files {
		all.Write(readVectors(t, f))
	}
	body := all.String()
	changedVectors := 0
	for old, nw := range chain1Superseded {
		// the file holds the canonical text with its JSON string escapes
		enc, _ := json.Marshal(old)
		if !strings.Contains(body, string(enc[1:len(enc)-1])) && !strings.Contains(body, strings.ReplaceAll(string(enc[1:len(enc)-1]), `&`, "&")) {
			t.Errorf("superseded expectation is not in finality_chain1: %s", old)
		}
		changedVectors += strings.Count(body, string(enc[1:len(enc)-1]))
		var o, n struct {
			Code   string            `json:"code"`
			Fields map[string]string `json:"fields"`
		}
		if err := json.Unmarshal([]byte(old), &o); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(nw), &n); err != nil {
			t.Fatal(err)
		}
		if o.Code != n.Code || len(o.Fields) != len(n.Fields) {
			t.Errorf("only the reason may change: %s -> %s", old, nw)
		}
		for k, v := range o.Fields {
			if k != "reason" && n.Fields[k] != v {
				t.Errorf("field %s changed: %s -> %s", k, old, nw)
			}
		}
		found := false
		for _, m := range reg.States[o.Code].Enums["reason"] {
			found = found || m == n.Fields["reason"]
		}
		if !found {
			t.Errorf("%s: the new reason %q is not in the closed set", o.Code, n.Fields["reason"])
		}
	}
	if changedVectors != 10 {
		t.Errorf("%d finality_chain1 vectors carry a superseded expectation, want 10", changedVectors)
	}
}
