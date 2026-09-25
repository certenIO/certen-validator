// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The L1-L3 receipts must form ONE unbroken chain: each receipt starts at the
// value the layer below it reached, and ends at the value the layer above it
// consumes. A receipt that recomputes but starts or ends somewhere else proves
// a different statement, and a verifier that checks only that each receipt
// recomputes accepts a proof assembled from unrelated parts.
//
// Every case below is built from real stored proofs and is internally
// consistent in every way the verifier checked before these links were
// enforced: each receipt recomputes, each pairing holds, and each L4 leg is a
// genuine quorum over the fields it restates. What each case lacks is a link.

func loadStoredProof(t *testing.T, name string) *ChainedProof {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	p := new(ChainedProof)
	if err := json.Unmarshal(raw, p); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return p
}

// trivialReceipt is a receipt that recomputes by construction: with no steps,
// start and anchor are the same value.
func trivialReceipt(v string, localBlock uint64) Receipt {
	return Receipt{Start: v, Anchor: v, LocalBlock: localBlock}
}

func requireRejected(t *testing.T, p *ChainedProof, wantSubstr string) {
	t.Helper()
	err := NewProofVerifier(false).Verify(context.Background(), p)
	if err == nil {
		t.Fatalf("CRITICAL DEFECT: verifier accepted a proof whose receipts do not chain (want error containing %q)", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("rejected for the wrong reason:\n  got:  %v\n  want: ...%s...", err, wantSubstr)
	}
	t.Logf("rejected: %v", err)
}

func TestReceiptLinks_StoredProofsStillVerify(t *testing.T) {
	for _, f := range []string{"proof_bvn1.json", "proof_bvn3.json"} {
		t.Run(f, func(t *testing.T) {
			if err := NewProofVerifier(false).Verify(context.Background(), loadStoredProof(t, f)); err != nil {
				t.Fatalf("a genuine stored proof must verify: %v", err)
			}
		})
	}
}

// The graft: BVN1's transaction, BVN1's signed anchor, and BVN3's proof's
// entire Directory side. The Directory root is quorum-signed and so is the BVN
// root; nothing shows the one contains the other.
func TestReceiptLinks_RejectsGraftedDirectorySide(t *testing.T) {
	x := loadStoredProof(t, "proof_bvn1.json")
	y := loadStoredProof(t, "proof_bvn3.json")

	p := loadStoredProof(t, "proof_bvn1.json")
	p.Layer2.DNIndex = y.Layer2.DNIndex
	p.Layer2.DNMinorBlockIndex = y.Layer2.DNMinorBlockIndex
	p.Layer2.DNRootChainAnchor = y.Layer2.DNRootChainAnchor
	p.Layer2.RootReceipt = y.Layer2.RootReceipt
	p.Layer2.BptReceipt = y.Layer2.BptReceipt
	p.Layer2.BVNStateTreeAnchor = x.Layer2.BVNStateTreeAnchor // still bound to BVN1's signed anchor
	p.Layer3 = y.Layer3
	p.Layer4DN = y.Layer4DN

	requireRejected(t, p, "L2 root receipt must start at the BVN root chain anchor")
}

func TestReceiptLinks_RejectsSubstitutedReceipts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *ChainedProof)
		want   string
	}{
		{
			// Both L2 receipts replaced by one self-consistent, stepless receipt.
			name: "L2 receipts replaced",
			mutate: func(p *ChainedProof) {
				v := strings.Repeat("11", 32)
				p.Layer2.RootReceipt = trivialReceipt(v, p.Layer2.RootReceipt.LocalBlock)
				p.Layer2.BptReceipt = trivialReceipt(v, p.Layer2.BptReceipt.LocalBlock)
			},
			want: "L2 root receipt must start at the BVN root chain anchor",
		},
		{
			// The receipt starts in the right place but ends at a root that is
			// not the one the Directory quorum signed.
			name: "L2 root receipt ends elsewhere",
			mutate: func(p *ChainedProof) {
				v := p.Layer1.BVNRootChainAnchor
				p.Layer2.RootReceipt = trivialReceipt(v, p.Layer2.RootReceipt.LocalBlock)
				p.Layer2.BptReceipt = trivialReceipt(v, p.Layer2.BptReceipt.LocalBlock)
			},
			want: "L2 root receipt must end at the DN root chain anchor",
		},
		{
			// The bpt receipt is swapped for the root receipt: same anchor, same
			// block, recomputes - and proves nothing about the BVN state tree.
			name: "L2 bpt receipt is the root receipt",
			mutate: func(p *ChainedProof) {
				p.Layer2.BptReceipt = p.Layer2.RootReceipt
			},
			want: "L2 bpt receipt must start at the BVN state tree anchor",
		},
		{
			name: "L3 receipts replaced",
			mutate: func(p *ChainedProof) {
				v := strings.Repeat("22", 32)
				p.Layer3.RootReceipt = trivialReceipt(v, p.Layer3.RootReceipt.LocalBlock)
				p.Layer3.BptReceipt = trivialReceipt(v, p.Layer3.BptReceipt.LocalBlock)
			},
			want: "L3 root receipt must start at the DN root chain anchor",
		},
		{
			name: "L3 bpt receipt is the root receipt",
			mutate: func(p *ChainedProof) {
				p.Layer3.BptReceipt = p.Layer3.RootReceipt
			},
			want: "L3 bpt receipt must start at the DN state tree anchor",
		},
		{
			// The receipts' block labels are not hashed, so they must be bound
			// to the fields that name the same block.
			name: "L2 receipts relabelled to another DN block",
			mutate: func(p *ChainedProof) {
				p.Layer2.RootReceipt.LocalBlock++
				p.Layer2.BptReceipt.LocalBlock++
			},
			want: "L2 root receipt must be recorded at the DN block",
		},
		{
			name: "L3 receipts relabelled to another DN block",
			mutate: func(p *ChainedProof) {
				p.Layer3.RootReceipt.LocalBlock++
				p.Layer3.BptReceipt.LocalBlock++
			},
			want: "L3 root receipt must be recorded at the DN block",
		},
	}
	for _, f := range []string{"proof_bvn1.json", "proof_bvn3.json"} {
		for _, c := range cases {
			t.Run(f+"/"+c.name, func(t *testing.T) {
				p := loadStoredProof(t, f)
				c.mutate(p)
				requireRejected(t, p, c.want)
			})
		}
	}
}

// An additional partition leg goes through the same links as the principal's.
// Here BVN3's leg is recorded as anchored into BVN1's Directory root, carrying
// BVN1's L2 receipts - which recompute, and start at BVN1's root, not BVN3's.
func TestReceiptLinks_RejectsAdditionalLegWithBorrowedReceipts(t *testing.T) {
	p := loadStoredProof(t, "proof_bvn1.json")
	y := loadStoredProof(t, "proof_bvn3.json")

	leg := PartitionLeg{
		Partition: y.Layer4BVN.Partition,
		Layer1:    y.Layer1,
		Layer2:    y.Layer2,
		Layer4BVN: y.Layer4BVN,
	}
	leg.Layer2.DNIndex = p.Layer2.DNIndex
	leg.Layer2.DNMinorBlockIndex = p.Layer2.DNMinorBlockIndex
	leg.Layer2.DNRootChainAnchor = p.Layer2.DNRootChainAnchor
	leg.Layer2.RootReceipt = p.Layer2.RootReceipt
	leg.Layer2.BptReceipt = p.Layer2.BptReceipt
	if err := p.AddLeg(leg); err != nil {
		t.Fatal(err)
	}

	requireRejected(t, p, "L2 root receipt must start at the BVN root chain anchor")
}
