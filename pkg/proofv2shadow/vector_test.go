// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"compress/gzip"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// A capture of a real, recent Kermit transaction (certen-protocol.acme/billing-receipts, BVN1 block 14699674, captured live
// 2026-10-17 21:10 UTC by cmd/proofv2xcollect through the production wiring): every page the Collector captured passes
// through the state root of the block it was read at, its chain roots bind, and the roles and the vote it recorded are the ones
// the transaction's own record shows.
func TestRealCaptureOfARecentTransaction(t *testing.T) {
	f, err := os.Open("testdata/capture_billing_receipts_bvn1_14699674.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeCapture(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Partition != "BVN1" || c.Block != 14699674 || len(c.Pages) != 5 {
		t.Fatalf("capture: %s block %d, %d pages", c.Partition, c.Block, len(c.Pages))
	}
	rootHex := c.Partitions["BVN1"].StateRoot
	var root [32]byte
	b, _ := hex.DecodeString(rootHex)
	copy(root[:], b)
	for _, p := range c.Pages {
		acct, pc, err := proofv2.VerifyPageAt(&p.PageState, root)
		if err != nil {
			t.Fatalf("%s: %v", p.URL, err)
		}
		if !pc.Bound || !strings.EqualFold(acct.GetUrl().String(), p.URL) || p.Block != 14699674 || p.Partition != "acc://bvn-BVN1.acme" {
			t.Fatalf("%s: bound %v block %d on %s", p.URL, pc.Bound, p.Block, p.Partition)
		}
	}
	// The roles: the signing page is an authority page, the voter, the initiator and the certified key page; the book's other
	// page is an authority page only.
	roles := map[string][]proofv2.PageRole{}
	for _, p := range c.Pages {
		roles[strings.ToLower(p.URL)] = p.Roles
	}
	want := []proofv2.PageRole{proofv2.RoleAuthorityPage, proofv2.RoleVoter, proofv2.RoleInitiatorSigner, proofv2.RoleCertifiedKeyPage}
	got := roles["acc://certen-protocol.acme/book/2"]
	if len(got) != len(want) {
		t.Fatalf("book/2 roles %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("book/2 roles %v, want %v", got, want)
		}
	}
	if len(roles["acc://certen-protocol.acme/book/1"]) != 1 || roles["acc://certen-protocol.acme/book/1"][0] != proofv2.RoleAuthorityPage {
		t.Fatalf("book/1 roles %v", roles["acc://certen-protocol.acme/book/1"])
	}
	if len(c.Votes) != 1 || c.Votes[0].Authority != "acc://certen-protocol.acme/book" || c.Votes[0].Origin != "acc://certen-protocol.acme/book/2" ||
		c.Votes[0].Transport.Kind != proofv2.TransportInline || len(c.Votes[0].Hops) != 1 || c.Votes[0].Hops[0].Page != "acc://certen-protocol.acme/book/2" {
		t.Fatalf("votes: %+v", c.Votes)
	}
	// Decoded as pages, the key page holds what the record says.
	kp := mustAccount(t, c, "acc://certen-protocol.acme/book/2").(*protocol.KeyPage)
	if kp.AcceptThreshold == 0 && kp.Version == 0 {
		t.Fatal("the key page decoded empty")
	}
}

func mustAccount(t *testing.T, c *Capture, u string) protocol.Account {
	t.Helper()
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, u) {
			a, err := decodeAccount(&p.PageState, mustURL(u))
			if err != nil {
				t.Fatal(err)
			}
			return a
		}
	}
	t.Fatalf("%s not captured", u)
	return nil
}
