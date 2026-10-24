// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture/capturetest"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// verifyAssembledLeg is the acceptance of WP-S8-3b: the container that E1 and E2 assemble over the H0 world of every chain, plain and with
// rich storage, must VERIFY. It takes the Verifier as a parameter. The real one (pkg/contractidentity steps 2b-1 and 2b-2 behind
// NewVerifier, on pv2/rb12-s8-skeleton) is plugged in by one file, attest_verify_real_test.go:
//
//	func TestE1AssembledLegVerifiesWithTheRealVerifier(t *testing.T) { verifyAssembledLeg(t, realVerifier(t)) }
//
// where realVerifier builds ci.NewVerifier over the merged registrars. Until that file exists the container is judged by miniCheckLeg below
// (the checks the real steps make on the attestation: link, leaves, census, flips, thresholds, blob tie).
func verifyAssembledLeg(t *testing.T, v ci.Verifier) {
	t.Helper()
	for _, chain := range chains {
		for _, rich := range []bool{false, true} {
			var edit = capturetest.Enrich
			if !rich {
				edit = nil
			}
			fc := newFakeChainWith(t, chain, "h0", edit)
			src, _ := fc.source(honest)
			container, _, _, _ := wholeLeg(t, fc, src)
			rep, err := v.Verify(fc.w.Ctx, container, fc.w.Manifest)
			if err != nil {
				t.Fatalf("%d rich=%v: Verify: %v", chain, rich, err)
			}
			for _, p := range rep.Parts {
				if p.Status == ci.StatusRefused {
					t.Fatalf("%d rich=%v: part %s refused: %+v", chain, rich, p.Part, p.State)
				}
			}
			for _, name := range []string{ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow} {
				found := false
				for _, p := range rep.Parts {
					if p.Part == name {
						found = true
						if p.Status != ci.StatusVerified {
							t.Fatalf("%d rich=%v: part %s is %s: %+v", chain, rich, name, p.Status, p.State)
						}
					}
				}
				if !found {
					t.Fatalf("%d rich=%v: the report has no part %s", chain, rich, name)
				}
			}
			if k := rep.Headline.Kind; k == ci.HeadlineRefused || k == ci.HeadlineUnproven {
				t.Fatalf("%d rich=%v: headline %s", chain, rich, k)
			}
		}
	}
}

// miniCheckLeg re-checks the attestation part of a container the way steps 15-20 and 22 do, with the strict reads and the codec only.
func miniCheckLeg(t *testing.T, fc *fakeChain, container []byte) {
	t.Helper()
	lim := ci.DefaultLimits()
	c, err := ci.Decode(container, lim)
	if err != nil || c.Attest.Tag != ci.TagCaptured || c.Settle.Tag != ci.TagCaptured {
		t.Fatalf("decode: %v", err)
	}
	ap := c.Attest.Attest
	ns, err := ci.NewNodeSet(c.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	hv, err1 := finality.ReadHeader(ap.HeaderV)
	hp, err2 := finality.ReadHeader(ap.HeaderVParent)
	sh, err3 := finality.ReadHeader(fc.w.Ctx.Settlement.Header)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	// step 16: the header link (spine descending from the parent of the settlement header to B_v) and the parent
	if hp.Hash != hv.ParentHash || hp.Number+1 != hv.Number {
		t.Fatal("headerVParent is not the parent of headerV")
	}
	if ap.Link != ci.LinkSpine || len(ap.Spine) == 0 {
		t.Fatalf("link %d spine %d", ap.Link, len(ap.Spine))
	}
	want, num := sh.ParentHash, sh.Number-1
	for i, raw := range ap.Spine {
		h, err := finality.ReadHeader(raw)
		if err != nil || h.Hash != want || h.Number != num {
			t.Fatalf("spine[%d] is not block %d with the hash the child names", i, num)
		}
		want, num = h.ParentHash, num-1
	}
	if !bytes.Equal(ap.Spine[len(ap.Spine)-1], ap.HeaderV) {
		t.Fatal("the spine does not end at headerV")
	}
	// step 17: the leaves under the header's roots, the census, the call
	for kind, root := range map[string]common.Hash{"tx": hv.TransactionRoot, "receipt": hv.ReceiptsRoot} {
		leaf := ap.TxLeaf
		if kind == "receipt" {
			leaf = ap.ReceiptLeaf
		}
		got, err := ci.ReadIndexedLeaf(root, ns, uint64(ap.TxIndex), lim.MaxNodeBytes)
		if err != nil || !bytes.Equal(got, leaf) {
			t.Fatalf("%s leaf under the header root: %v", kind, err)
		}
	}
	if _, err := ci.VerifyBlockTxs(hv.TransactionRoot, ap.BlockTxs, int(ap.TxIndex), ap.TxLeaf, lim); err != nil {
		t.Fatalf("the transaction list: %v", err)
	}
	anchor, _ := fc.w.Manifest.Deployment(fc.w.Spec.Chain, "anchor")
	A := common.HexToAddress(anchor.Address)
	facts := fc.facts(t)
	rl, err := ethproof.DecodeReceiptLeaf(ap.ReceiptLeaf)
	if err != nil || !rl.Succeeded() {
		t.Fatalf("receipt: %v", err)
	}
	top, _ := fc.w.Manifest.Topic("ProofExecuted")
	logged := false
	for _, l := range rl.Logs {
		logged = logged || (l.Address == A && len(l.Topics) >= 2 && l.Topics[0] == common.HexToHash(top.Topic0) && l.Topics[1] == facts.AnchorID)
	}
	if !logged {
		t.Fatal("the receipt has no ProofExecuted of the anchor for the anchor id")
	}
	call, err := ci.DecodeComprehensiveProofCall(txData(t, ap.TxLeaf), ci.DefaultABILimits())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := ci.DecodeZKBlob(call.BLS.AggregateSignature)
	if err != nil || blob.MessageHash != call.BLS.MessageHash || blob.PubkeyCommitment == ([32]byte{}) {
		t.Fatalf("blob tie: %v", err)
	}
	// step 18 and 19: the flips and the thresholds at both stations
	read := func(root [32]byte, s common.Hash) common.Hash {
		acc, err := ci.ReadAccount(root, ns, A)
		if err != nil || !acc.Exists {
			t.Fatalf("anchor account: %v", err)
		}
		v, err := ci.ReadSlot(acc.StorageRoot, ns, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rec := ci.MappingSlotAt(ci.KeyBytes32(facts.AnchorID), 1)
	pre10, post10 := read(hp.StateRoot, ci.MemberSlot(rec, 10)), read(hv.StateRoot, ci.MemberSlot(rec, 10))
	byteAt := func(w common.Hash, i int) byte { return w[31-i] }
	if byteAt(pre10, 21) != 0 || byteAt(post10, 21) != 1 || byteAt(pre10, 20) != 1 || byteAt(post10, 20) != 1 {
		t.Fatalf("flip F2: pre %x post %x", pre10, post10)
	}
	if read(hp.StateRoot, ci.MemberSlot(rec, 0)) != facts.AnchorID {
		t.Fatal("record bundleId is not the anchor id")
	}
	uc := ci.MappingSlotAt(ci.KeyBytes32(facts.OperationID), 18)
	if read(hp.StateRoot, uc) != (common.Hash{}) || read(hv.StateRoot, uc) != common.BigToHash(common.Big1) {
		t.Fatal("flip F1: usedCommitments[operationID] is not 0 before and 1 after")
	}
	for i, want := range map[uint64]int64{15: 2, 16: 3} {
		for _, root := range [][32]byte{hp.StateRoot, hv.StateRoot} {
			if read(root, ci.SlotIndex(i)) != common.BigToHash(big.NewInt(want)) {
				t.Fatalf("anchor threshold slot %d is not %d", i, want)
			}
		}
	}
}

func txData(t *testing.T, leaf []byte) []byte {
	t.Helper()
	var tx types.Transaction
	if err := tx.UnmarshalBinary(leaf); err != nil {
		t.Fatal(err)
	}
	return tx.Data()
}

func TestE1AssembledLegPassesTheMiniChecks(t *testing.T) {
	for _, chain := range chains {
		for _, rich := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/rich=%v", chain, rich), func(t *testing.T) {
				var edit = capturetest.Enrich
				if !rich {
					edit = nil
				}
				fc := newFakeChainWith(t, chain, "h0", edit)
				src, _ := fc.source(honest)
				container, _, _, _ := wholeLeg(t, fc, src)
				miniCheckLeg(t, fc, container)
			})
		}
	}
}

// TestE1AssemblyReachesTheVerifier proves the plumbing of verifyAssembledLeg: the verifier is handed the exact container, the leg's context and
// the manifest. It does NOT stand in for the real verifier (see verifyAssembledLeg).
func TestE1AssemblyReachesTheVerifier(t *testing.T) {
	calls := 0
	verifyAssembledLeg(t, ci.VerifierFunc(func(lc ci.LegContext, container []byte, m *ci.Manifest) (ci.Report, error) {
		calls++
		c, err := ci.Decode(container, ci.DefaultLimits())
		if err != nil || m == nil || lc.Settlement == nil || c.Chain != lc.Chain {
			t.Errorf("the verifier was not given the leg: %v", err)
		}
		var parts []ci.PartResult
		for _, n := range []string{ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow} {
			parts = append(parts, ci.PartResult{Part: n, Status: ci.StatusVerified})
		}
		return ci.Report{Headline: ci.Headline{Kind: ci.HeadlineVerified}, Parts: parts}, nil
	}))
	if calls != len(chains)*2 {
		t.Fatalf("the verifier was called %d times", calls)
	}
}
