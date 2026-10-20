// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"testing"
)

// mutRules is a deliberately wrong verifier, defined only in test code: it switches checks off (or takes the signing-domain
// fork version from the attested epoch, the go-ethereum beacon/light reading). The mutation tests require the vector that
// exists for a rule to change verdict when that rule is off, which proves the vector exercises the rule and the rule exists.
type mutRules struct {
	off                map[string]bool
	domainFromAttested bool
}

func (m mutRules) skip(c string) bool { return m.off[c] }
func (m mutRules) domainEpoch(as, ss uint64) uint64 {
	if m.domainFromAttested {
		return epochOf(as)
	}
	return specRules{}.domainEpoch(as, ss)
}

func offSet(checks ...string) mutRules {
	m := mutRules{off: map[string]bool{}}
	for _, c := range checks {
		m.off[c] = true
	}
	return m
}

type mutation struct {
	name  string
	r     mutRules
	cases []string
}

// runMutations runs every case of every mutation on the verifier with that rule switched off and requires a changed verdict (the
// canonical bytes, code and fields); the unmutated verifier must still return the recorded verdict.
func runMutations(t *testing.T, muts []mutation) {
	t.Helper()
	cs := cases(t)
	out := func(h FinalizedHead, f *Fault) []byte {
		if f != nil {
			return headOutput(h, f)
		}
		return headOutput(h, nil)
	}
	for _, m := range muts {
		for _, id := range m.cases {
			c, ok := cs[id]
			if !ok {
				t.Errorf("mutation %q: case %s is not in the set", m.name, id)
				continue
			}
			want := canonicalExpect(t, c.Expect)
			h0, f0 := verifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c), specRules{})
			if got := out(h0, f0); !bytes.Equal(got, want) {
				t.Errorf("%s: unmutated verifier returned %s, want %s", id, got, want)
			}
			h1, f1 := verifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c), m.r)
			got := out(h1, f1)
			t.Logf("MUTATION %q on %s: mutated verifier returns %.120s", m.name, id, got)
			if bytes.Equal(got, want) {
				t.Errorf("mutation %q: vector %s still returns its recorded verdict; the vector does not exercise the rule", m.name, id)
			}
		}
	}
}

// TestMutationChecks (set v1) switches the rules of the C1A vectors off one at a time.
func TestMutationChecks(t *testing.T) {
	runMutations(t, []mutation{
		{"drop the 342 floor", offSet(chkFloor), []string{"adv_participation_341", "adv_link_participation_341", "adv_synth_341_valid_signature"}},
		{"take the signing-domain fork version from the attested epoch", mutRules{domainFromAttested: true}, []string{"synth_valid_fork_boundary_domain"}},
		{"skip the per-period ledger rule", offSet(chkLedgerFirstLearn, chkLedgerRotation, chkLedgerFinalSigner), []string{"adv_learned_committee_not_ledger"}},
		{"skip the window rule", offSet(chkWindow), []string{"adv_window_exceeded"}},
		{"skip the finality branch", offSet(chkFinalityBranch), []string{"adv_forged_finality_branch_node", "adv_attested_state_root_altered"}},
		{"skip the next-committee branch", offSet(chkNextBranch), []string{"adv_link_next_committee_branch_forged", "adv_link_next_committee_forged"}},
	})
}

// TestProductionRulesSkipNothing pins the production mode: the only rules implementation outside test files skips no check
// and takes the signing-domain epoch from signature_slot - 1 (saturating at 0).
func TestProductionRulesSkipNothing(t *testing.T) {
	for _, c := range []string{chkFloor, chkFinalityBranch, chkNextBranch, chkNextMismatch, chkPeriodRuleNextKnown, chkPeriodRuleNextUnknown,
		chkLedgerFirstLearn, chkLedgerRotation, chkLedgerFinalSigner, chkWindow, chkFinalNotFinality, chkExecBranch} {
		if (specRules{}).skip(c) {
			t.Errorf("production rules skip %s", c)
		}
	}
	if got := (specRules{}).domainEpoch(999999, 32*10+1); got != 10 {
		t.Errorf("domain epoch of signature_slot 321 = %d, want 10", got)
	}
	if got := (specRules{}).domainEpoch(0, 0); got != 0 {
		t.Errorf("domain epoch of signature_slot 0 = %d, want 0", got)
	}
}
