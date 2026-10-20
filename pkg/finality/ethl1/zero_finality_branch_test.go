// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"testing"
)

// zeroFinalityBranch returns lb with every node of its finality branch overwritten by zeros, and the decoded update of the
// result; it fails the test unless the decoded branch is then all zero.
func zeroFinalityBranch(t *testing.T, index int, lb LB) (LB, updateObj) {
	t.Helper()
	w := &walker{}
	u, f := w.parseUpdate(index, lb)
	if f != nil {
		t.Fatalf("link %d does not parse: %v", index, f)
	}
	k := -1
	for i, n := range u.FinalityBranch {
		if n != ([32]byte{}) {
			k = i
			break
		}
	}
	if k < 0 {
		t.Fatalf("link %d: the finality branch is already all zero", index)
	}
	out := LB{Layout: lb.Layout, SSZ: append([]byte(nil), lb.SSZ...)}
	at := bytes.Index(out.SSZ, u.FinalityBranch[k][:])
	if at < 0 {
		t.Fatalf("link %d: the first finality-branch node is not in the link bytes", index)
	}
	for j := k; j < len(u.FinalityBranch); j++ {
		off := at + 32*(j-k)
		if off+32 > len(out.SSZ) || !bytes.Equal(out.SSZ[off:off+32], u.FinalityBranch[j][:]) {
			break
		}
		for x := off; x < off+32; x++ {
			out.SSZ[x] = 0
		}
	}
	z, f := w.parseUpdate(index, out)
	if f != nil {
		t.Fatalf("link %d with a zeroed branch does not parse: %v", index, f)
	}
	if !branchAllZero(z.FinalityBranch) {
		t.Fatalf("link %d: zeroing did not make the decoded finality branch all zero", index)
	}
	return out, z
}

// TestALinkWithAnAllZeroFinalityBranchIsNamedNotFinality pins the refusal of a link whose finality branch is all zero. The
// branch is not under the signature, so the link still carries a valid aggregate; without the explicit refusal the next check
// (the Merkle branch of the finalized header) would refuse the same link under another name, finality_branch. The mutation gate
// found this line equivalent only because no vector reached it (independent review V-C1A item N called it subsumed).
func TestALinkWithAnAllZeroFinalityBranchIsNamedNotFinality(t *testing.T) {
	useSet(t, vectorDirV2)
	for _, id := range []string{"valid_k1_chain", "valid_k1_fulu_chain_to_gloas"} {
		c, ok := cases(t)[id]
		if !ok {
			t.Fatalf("case %s is not in the set", id)
		}
		lc := loadLC(t, c)
		if len(lc.Links) == 0 {
			t.Fatalf("%s: no links", id)
		}
		want := canonicalExpect(t, c.Expect)
		h0, f0 := verifyFinalizedHead(loadPins(t, c.Pins), lc, specRules{})
		if got := headOutput(h0, errOrNil(f0)); !bytes.Equal(got, want) {
			t.Fatalf("%s: unmodified evidence returned %s, want %s", id, got, want)
		}
		const idx = 0
		zeroed, _ := zeroFinalityBranch(t, idx, lc.Links[idx])
		mod := lc
		mod.Links = append([]LB(nil), lc.Links...)
		mod.Links[idx] = zeroed
		h1, f1 := verifyFinalizedHead(loadPins(t, c.Pins), mod, specRules{})
		if f1 == nil {
			t.Fatalf("%s: a link with an all-zero finality branch verified: %+v", id, h1)
		}
		if f1.Code != CodeLinkInvalid || f1.Fields["check"] != "not_finality" || f1.Fields["index"] != idx {
			t.Errorf("%s: an all-zero finality branch on link %d returned %s, want %s check not_finality at index %d", id, idx, f1.CanonicalJSON(), CodeLinkInvalid, idx)
		}
	}
}

// errOrNil keeps a nil *Fault from becoming a non-nil error interface.
func errOrNil(f *Fault) error {
	if f == nil {
		return nil
	}
	return f
}
