package intentcert

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// G0 and G1 of the fixture's own transaction bind; each fact that names another transaction, root, block or page is
// refused by name.
func TestBindProofV2(t *testing.T) {
	rep, _ := verifiedKermit(t)
	h := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	page := rep.Pages[0].GetUrl().String()
	good := func() (*proof.G0Result, *proof.G1Result) {
		g0 := &proof.G0Result{EntryHashExec: h(rep.TxHash), ExecWitness: h(rep.AnchorRootChainAnchor), ExecMBI: int64(rep.AnchorBlock)}
		g0.Receipt.Start = g0.EntryHashExec
		g1 := &proof.G1Result{}
		g1.AuthoritySnapshot.Page = page
		return g0, g1
	}
	g0, g1 := good()
	if err := BindProofV2(rep, g0, g1, page); err != nil {
		t.Fatalf("the fixture's own facts: %v", err)
	}
	other := h([32]byte{9})
	for _, c := range []struct {
		name, want string
		edit       func(*proof.G0Result, *proof.G1Result) string
	}{
		{"another transaction", "G0 proves entry", func(g0 *proof.G0Result, _ *proof.G1Result) string {
			g0.EntryHashExec, g0.Receipt.Start = other, other
			return page
		}},
		{"a receipt from elsewhere", "receipt starts at", func(g0 *proof.G0Result, _ *proof.G1Result) string { g0.Receipt.Start = other; return page }},
		{"another root", "witness", func(g0 *proof.G0Result, _ *proof.G1Result) string { g0.ExecWitness = other; return page }},
		{"another block", "execution block", func(g0 *proof.G0Result, _ *proof.G1Result) string { g0.ExecMBI++; return page }},
		{"G1 on another page", "not the page G1 validated against", func(_ *proof.G0Result, g1 *proof.G1Result) string {
			g1.AuthoritySnapshot.Page = "acc://other.acme/book/1"
			return page
		}},
		{"an unproven key page", "not among the pages", func(_ *proof.G0Result, g1 *proof.G1Result) string {
			g1.AuthoritySnapshot.Page = "acc://other.acme/book/1"
			return "acc://other.acme/book/1"
		}},
	} {
		g0, g1 := good()
		kp := c.edit(g0, g1)
		if err := BindProofV2(rep, g0, g1, kp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
