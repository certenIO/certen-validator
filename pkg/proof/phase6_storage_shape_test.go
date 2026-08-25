// Copyright 2026 Certen Protocol
//
// Phase 6 step 1.3 — pin the shape of what actually gets STORED, so the change
// this phase makes is visible rather than incidental.
//
// `batch_transactions.chained_proof` is json.Marshal(CertenProof.LiteClientProof)
// — see pkg/intent/discovery.go, which serialises exactly that value. Its
// nested `complete_proof` object is the travelling artifact: a verifier handed
// that one column should be able to finish the job with no second query.
//
// IMPORTANT — how these goldens differ from the govRoot goldens in
// pkg/execution/contracts/phase6_invariant_test.go:
//
//	govRoot goldens  are the SPECIFICATION. A change there is a defect; revert.
//	storage goldens  are a CHARACTERIZATION. Phase 6 deliberately changes them
//	                 by adding layer4Bvn / layer4Dn, and each change must be an
//	                 explicit, commented edit — never a silent drift.
//
// Adding a key here does NOT move the govRoot: the L1/L2/L3 slots are raw
// 32-byte hashes (SetL1AccountHash / SetL2BPTRoot / SetL3BlockHash) and the L4
// slot is json.Marshal of ConsensusProof alone. CompleteProof itself is never
// hashed. TestP6_GovRootInvariant_GoldenSlots is the blocking proof of that.
package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// p6ShapeFixture is a minimal but complete ChainedProof: enough L1-L3 to
// populate every CompleteProof field, and both L4 legs.
func p6ShapeFixture() *chained_proof.ChainedProof {
	rcpt := func(start, anchor string) chained_proof.Receipt {
		return chained_proof.Receipt{
			Start:      start,
			Anchor:     anchor,
			LocalBlock: 40001,
			Entries:    []chained_proof.ReceiptStep{{Hash: "abcd", Right: true}},
		}
	}
	return &chained_proof.ChainedProof{
		Input: chained_proof.ProofInput{
			Account: "acc://certen-demo.acme/data",
			TxHash:  "8888888888888888888888888888888888888888888888888888888888888888",
			BVN:     "bvn1",
		},
		Layer1: chained_proof.Layer1{
			TxChainIndex:       7,
			BVNMinorBlockIndex: 40001,
			BVNRootChainAnchor: "3333333333333333333333333333333333333333333333333333333333333333",
			Leaf:               "8888888888888888888888888888888888888888888888888888888888888888",
			Receipt:            rcpt("8888", "3333"),
		},
		Layer2: chained_proof.Layer2{
			DNIndex:            11,
			DNMinorBlockIndex:  50001,
			DNRootChainAnchor:  "6666666666666666666666666666666666666666666666666666666666666666",
			BVNStateTreeAnchor: "2222222222222222222222222222222222222222222222222222222222222222",
			RootReceipt:        rcpt("3333", "6666"),
			BptReceipt:         rcpt("2222", "6666"),
		},
		Layer3: chained_proof.Layer3{
			DNRootChainIndex:                      13,
			DNAnchorMinorBlockIndex:               50001,
			DNConsensusHeight:                     50002,
			DNSelfAnchorRecordedAtMinorBlockIndex: 50003,
			DNStateTreeAnchor:                     "5555555555555555555555555555555555555555555555555555555555555555",
			RootReceipt:                           rcpt("6666", "7777"),
			BptReceipt:                            rcpt("5555", "7777"),
		},
		Layer4BVN: p6ShapeLeg("BVN1", 2),
		Layer4DN:  p6ShapeLeg("Directory", 3),
	}
}

// p6ShapeLeg is a structurally complete L4 leg.
//
// It deliberately does NOT reuse testLeg from l4_govroot_test.go: that helper
// carries signatures only, because the govRoot summary reduces a leg to its
// signer list and never sees the rest. This file is about the opposite half —
// the evidence — so the leg has to carry the validator set and the signed
// bytes, or the shape it pins is not the shape that gets stored.
//
// The values are structural, not cryptographic. Whether this evidence VERIFIES
// is Gate 5's question, and Gate 5 answers it with the real fixtures in
// working-proof_do_not_edit/testdata, whose signatures are genuine.
func p6ShapeLeg(partition string, signers int) *chained_proof.Layer4 {
	sigs := make([]chained_proof.AnchorSignature, 0, signers)
	vset := make([]chained_proof.ValidatorKey, 0, signers)
	for i := 0; i < signers; i++ {
		pk := fmt.Sprintf("%02x%062x", 0xa0+i, i+1)
		sum := sha256.Sum256([]byte(pk))
		sigs = append(sigs, chained_proof.AnchorSignature{
			PublicKey: pk,
			Signature: strings.Repeat("11", 64),
			Signer:    "acc://dn.acme/network",
			Timestamp: 1,
		})
		vset = append(vset, chained_proof.ValidatorKey{
			PublicKey:     pk,
			PublicKeyHash: hex.EncodeToString(sum[:]),
			ActiveOn:      []string{partition},
		})
	}
	return &chained_proof.Layer4{
		Partition:        partition,
		Source:           "acc://dn.acme",
		Destination:      "acc://bvn-BVN1.acme",
		AnchorPool:       "acc://dn.acme/anchors",
		AnchorIndex:      9,
		SequenceNumber:   3,
		AnchorTxHash:     strings.Repeat("ab", 32),
		SignedHash:       strings.Repeat("cd", 32),
		SequencedMessage: strings.Repeat("ef", 352),
		MinorBlockIndex:  12345,
		RootChainAnchor:  strings.Repeat("12", 32),
		StateTreeAnchor:  strings.Repeat("34", 32),
		Signatures:       sigs,
		ValidatorSet:     vset,
		Threshold:        uint64(signers),
		AcceptThreshold:  chained_proof.Rational{Numerator: 2, Denominator: 3},
		NetworkVersion:   0,
	}
}

func p6StoredBlob(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	complete := ChainedProofToCompleteProof(p6ShapeFixture())
	if complete == nil {
		t.Fatal("ChainedProofToCompleteProof returned nil")
	}
	// This is exactly what discovery.go stores into batch_transactions.
	adapter := NewCertenProofAdapter(complete, &ProofRequest{
		RequestID:       "phase6-shape",
		ProofType:       "chained_l1_l2_l3",
		TransactionHash: "8888888888888888888888888888888888888888888888888888888888888888",
		AccountURL:      "acc://certen-demo.acme/data",
	}, "validator-1")
	cp := adapter.ToCertenProof()
	if cp == nil || cp.LiteClientProof == nil {
		t.Fatal("adapter produced no LiteClientProof")
	}
	raw, err := json.Marshal(cp.LiteClientProof)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	return top
}

func keysOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not an object: %v", err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func assertKeys(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: key set changed\n  want %v\n  got  %v", label, want, got)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: key set changed\n  want %v\n  got  %v", label, want, got)
			return
		}
	}
}

// TestP6_StoredBlobShape pins the stored blob's key sets.
//
// These were measured at f98544c against a live row and reproduce exactly:
// the top level is LiteClientProofData; complete_proof is lcproof.CompleteProof.
func TestP6_StoredBlobShape(t *testing.T) {
	top := p6StoredBlob(t)

	gotTop := make([]string, 0, len(top))
	for k := range top {
		gotTop = append(gotTop, k)
	}
	sort.Strings(gotTop)

	// LiteClientProofData. account_data / receipt_data are omitempty and absent
	// on this path, which is also true of the live rows.
	assertKeys(t, "chained_proof (top level)", gotTop, []string{
		"account_hash",
		"block_hash",
		"bpt_root",
		"complete_proof",
		"consensus_proof",
		"proof_valid",
		"validation_level",
	})

	// UPDATED BY PHASE 6 STEP 4 — layer4Bvn and layer4Dn added.
	//
	// Before, the travelling artifact carried the L4 conclusions
	// (consensus_proof) and not the evidence for them, so a verifier handed
	// this column could read what L4 concluded and could not check it. These
	// two keys are the fix, and they are the ONLY difference: no existing key
	// was renamed, retyped or removed, so every reader of this blob keeps
	// working.
	assertKeys(t, "complete_proof", keysOf(t, top["complete_proof"]), []string{
		"account_hash",
		"account_url",
		"block_hash",
		"block_height",
		"bpt_proof",
		"bpt_root",
		"bvn_anchor_proof",
		"combined_receipt",
		"consensus_proof",
		"dn_anchor_proof",
		"layer4Bvn",
		"layer4Dn",
		"main_chain_proof",
		"partition",
		"verified",
	})
}

// TestP6_StoredBlobCarriesL4Evidence is Gate 4, and it is the inverse of the
// measurement that opened this phase.
//
// Against the live row for proof b7a48634-733a-4999-84eb-06d2c84db112 the same
// substring probe returned signature=f, validatorSet=f, publicKeyHash=f: the
// stored proof could be believed, not checked. All four must now be present.
//
// Presence is NOT verification, and this test does not claim to be Gate 5 —
// TestP6_StoredProofVerifiesOffline runs the real ProofVerifier over a proof
// read back out of PostgreSQL, and the mutation tests beside it prove the
// verifier is actually running. This test only pins that the evidence made it
// into the column that travels.
func TestP6_StoredBlobCarriesL4Evidence(t *testing.T) {
	top := p6StoredBlob(t)
	raw, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(raw)

	for _, needle := range []string{"signature", "validatorSet", "publicKeyHash", "sequencedMessage"} {
		if !contains(blob, needle) {
			t.Errorf("GATE 4 FAILED: %q is absent from the stored blob — the travelling artifact "+
				"still carries the L4 conclusion without the evidence for it", needle)
		}
	}

	// Gate P6.9 — size within budget. Measured at ~12.7 KB before this phase
	// and ~18.7 KB after on a live proof; the fixture here is smaller because
	// its receipts are short. The ceiling is what matters: a jsonb column that
	// stays well under 32 KB.
	if len(blob) >= 32*1024 {
		t.Errorf("stored blob is %d bytes, over the 32 KB budget", len(blob))
	}
	t.Logf("stored blob is %d bytes and carries the full L4 evidence", len(blob))
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
