package proof

import (
	"strings"
	"testing"
)

// RB8-E. The unedited output of the production govproof binary (/app/govproof --level G1, certen-validator-1 at RB8-B,
// 2026-10-18) for three transactions Kermit delivered in the live run, each approved by a different kind of key:
//
//	btc    key hash "57bedd15..." (20 bytes) on acc://pv2-sig-1.acme/book-btc/1
//	eth    key hash "e486a781..." (20 bytes) on acc://pv2-sig-1.acme/book-eth/1
//	deleg  an ecdsaSha256 key in book-dinner, delegated through acc://pv2-sig-1.acme/book-deleg/1
//
// G1 itself judged all three satisfied. What refused them was the next step, recording who decided: the recorder refused
// the 20-byte hashes ("which is not a key hash"). These replay that step on the real G1 output.
func TestGovernanceDecision_RecordsTheLiveG1OfEveryKeyHashWidth(t *testing.T) {
	for _, tc := range []struct{ file, wantEntry string }{
		{"rb8e_live_g1_btc.json", "key:57bedd15a79b1c23f0fba46cf7958c04cea3e2ce"},
		{"rb8e_live_g1_eth.json", "key:e486a781e7c038fb6b572c10cf6cefc36786eab0"},
		{"rb8e_live_g1_deleg.json", "key:8a968721a85817e326753709204645e562e63c6a8a62acc7644aa9d27a9b2402"},
	} {
		rec, g0 := decisionOf(t, tc.file)
		if !rec.Satisfied {
			t.Fatalf("%s: G1 did not judge the transaction satisfied", tc.file)
		}
		gdr, err := GovernanceDecisionRecord(g0, rec)
		if err != nil {
			t.Errorf("%s: the decision cannot be recorded: %v", tc.file, err)
			continue
		}
		if !strings.Contains(string(gdr), tc.wantEntry) {
			t.Errorf("%s: the recorded decision does not count %s", tc.file, tc.wantEntry)
		}
		if GovernanceCommitment(gdr) == ([32]byte{}) {
			t.Errorf("%s: zero commitment", tc.file)
		}
	}
}
