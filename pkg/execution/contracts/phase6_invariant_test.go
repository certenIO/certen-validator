// Copyright 2026 Certen Protocol
//
// Phase 6 characterization tests — the regression net for "this phase changes
// no hash".
//
// Phase 6 completes proof PERSISTENCE: it stores the L4 signatures, validator
// set and signed bytes beside the summary so a stored proof can be verified
// offline. It must not touch the govRoot preimage. These two tests are what
// makes that claim checkable rather than asserted:
//
//	TestP6_GovRootInvariant_GoldenSlots  pins all ten govRoot slots and the
//	                                     root itself to hex literals.
//	TestP6_CanonicalShapesUnchanged      pins the field NAME, ORDER and JSON
//	                                     TAG of every struct that is inside a
//	                                     govRoot preimage.
//
// The golden constants below are the SPECIFICATION, not a snapshot. If an edit
// moves one, the edit is wrong — revert it. Never re-baseline these values to
// make a test pass: the constants are what every already-signed TX2 on the
// fleet committed to, and moving them reverts those transactions on any node
// that has not upgraded.
//
// Why hardcoded literals and not a computed expectation: an expectation derived
// from the same code path under test passes no matter what moved. These were
// produced once, at commit f98544c, and are typed in by hand.
package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// The fixture — fixed, hardcoded, and deliberately NOT read from the network.
// =============================================================================

// fixedTime is the only time value in the fixture. time.Time marshals as
// RFC3339 with nanoseconds, so it must be a literal for the goldens to be
// reproducible.
func fixedTime() time.Time {
	return time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
}

func mustHex32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("fixture hex %q is not 32 bytes: %v", s, err)
	}
	return b
}

// p6FixtureConsensusProof is the L4 govRoot payload.
//
// The version string is a LITERAL, not lcproof.L4GovRootVersion. Bumping that
// constant moves every govRoot, which is exactly the event this test exists to
// catch — reading the constant would let the bump pass silently.
func p6FixtureConsensusProof() *lcproof.ConsensusProof {
	return &lcproof.ConsensusProof{
		Version: "certen:l4gov:v1",
		BVN: lcproof.L4LegSummary{
			Partition:       "BVN1",
			SignedHash:      "1111111111111111111111111111111111111111111111111111111111111111",
			StateTreeAnchor: "2222222222222222222222222222222222222222222222222222222222222222",
			RootChainAnchor: "3333333333333333333333333333333333333333333333333333333333333333",
			MinorBlockIndex: 40001,
			Threshold:       2,
			Signers: []string{
				"aa00000000000000000000000000000000000000000000000000000000000001",
				"bb00000000000000000000000000000000000000000000000000000000000002",
			},
		},
		DN: lcproof.L4LegSummary{
			Partition:       "Directory",
			SignedHash:      "4444444444444444444444444444444444444444444444444444444444444444",
			StateTreeAnchor: "5555555555555555555555555555555555555555555555555555555555555555",
			RootChainAnchor: "6666666666666666666666666666666666666666666666666666666666666666",
			MinorBlockIndex: 50001,
			Threshold:       3,
			Signers: []string{
				"cc00000000000000000000000000000000000000000000000000000000000003",
				"dd00000000000000000000000000000000000000000000000000000000000004",
				"ee00000000000000000000000000000000000000000000000000000000000005",
			},
		},
	}
}

func p6FixtureG0() *certenproof.G0Result {
	lbt := fixedTime()
	mb := int64(77)
	end := "7777777777777777777777777777777777777777777777777777777777777777"
	return &certenproof.G0Result{
		EntryHashExec:     "e0e0e0e0",
		TXID:              "t0t0t0t0",
		TxHash:            "8888888888888888888888888888888888888888888888888888888888888888",
		ExecMBI:           40001,
		ExecWitness:       "9999999999999999999999999999999999999999999999999999999999999999",
		Scope:             "acc://certen-demo.acme/data",
		Chain:             "main",
		ExpandedMessageID: "acc://msg.acme/1",
		Principal:         "acc://certen-demo.acme",
		Receipt: certenproof.GovReceiptData{
			Start:          "aaaa",
			Anchor:         "bbbb",
			LocalBlock:     40001,
			LocalBlockTime: &lbt,
			MajorBlock:     &mb,
			End:            &end,
		},
		G0ProofComplete: true,
	}
}

func p6FixtureG1() *certenproof.G1Result {
	return &certenproof.G1Result{
		G0Result:              *p6FixtureG0(),
		UniqueValidKeys:       2,
		RequiredThreshold:     2,
		ThresholdSatisfied:    true,
		ExecutionSuccess:      true,
		TimingValid:           true,
		G1ProofComplete:       true,
		ConcurrencyEnabled:    false,
		WorkerCount:           4,
		ProcessingTimeMs:      123,
		CryptographicSecurity: true,
		Ed25519Verified:       2,
		AuditTrailEvents:      3,
		BundleIntegrityHash:   "cccc",
	}
}

func p6FixtureG2() *certenproof.G2Result {
	return &certenproof.G2Result{
		G1Result:        *p6FixtureG1(),
		PayloadVerified: true,
		EffectVerified:  true,
		G2ProofComplete: true,
		SecurityLevel:   "A+++",
	}
}

// p6FixtureInputs assembles the ten govRoot slots from the fixture above,
// through the SAME builder production uses.
func p6FixtureInputs(t *testing.T) AccumulateGovRootInputs {
	t.Helper()
	var opID [32]byte
	copy(opID[:], mustHex32(t, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"))

	return NewAccumulateGovRootInputsBuilder().
		SetL1AccountHash(mustHex32(t, "1010101010101010101010101010101010101010101010101010101010101010")).
		SetL2BPTRoot(mustHex32(t, "2020202020202020202020202020202020202020202020202020202020202020")).
		SetL3BlockHash(mustHex32(t, "3030303030303030303030303030303030303030303030303030303030303030")).
		SetL4ConsensusProofFromJSON(p6FixtureConsensusProof()).
		SetG0FromJSON(p6FixtureG0()).
		SetG1FromJSON(p6FixtureG1()).
		SetG2FromJSON(p6FixtureG2()).
		SetKeypageURL("acc://certen-demo.acme/book/1").
		SetKeybookURL("acc://certen-demo.acme/book").
		SetOperationIDBytes32(opID).
		Build()
}

// =============================================================================
// Gate 1.1 — the govRoot invariant.
// =============================================================================

// Golden slot values, captured at f98544c (pre-Phase-6) from the fixture above.
// These are the specification. Do not regenerate them to make a test pass.
const (
	goldenL1AccountHash     = "1010101010101010101010101010101010101010101010101010101010101010"
	goldenL2BPTRoot         = "2020202020202020202020202020202020202020202020202020202020202020"
	goldenL3BlockHash       = "3030303030303030303030303030303030303030303030303030303030303030"
	goldenL4ConsensusProofH = "b694a71ebdc527d89e95f8eeb23e3f27ccccbd228581e191d9e83b1136e0609e"
	goldenG0CanonicalHash   = "e18988df840826dc1cfc0ede80638f3b75e3e9332e32035357c669d657e3aad0"
	goldenG1CanonicalHash   = "77cea92dd9bb59eede7afbee263b0184858842b5ce7ef5c143f54468e0d88e17"
	goldenG2CanonicalHash   = "a7de5dba73033220013eb62d1baf811d6a4f9a857d98d6152c836b257439ec5d"
	goldenKeypageURLHash    = "c47824d6d9196ac9f37c99522c258be5345f5ef1d75d39e38aa88674b8e85ea2"
	goldenKeybookURLHash    = "d889757af291d457154013488ee23ed1c081a519aa0a27d0c122f7a1de4e3e08"
	goldenOperationID       = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	goldenGovRoot           = "bb293c644b31c0c2361ebd79a10a4996af870f430c6fc88c6b91f57d48b8cb59"
)

func TestP6_GovRootInvariant_GoldenSlots(t *testing.T) {
	inp := p6FixtureInputs(t)

	slots := []struct {
		name   string
		got    [32]byte
		golden string
	}{
		{"L1AccountHash", inp.L1AccountHash, goldenL1AccountHash},
		{"L2BPTRoot", inp.L2BPTRoot, goldenL2BPTRoot},
		{"L3BlockHash", inp.L3BlockHash, goldenL3BlockHash},
		{"L4ConsensusProofH", inp.L4ConsensusProofH, goldenL4ConsensusProofH},
		{"G0CanonicalHash", inp.G0CanonicalHash, goldenG0CanonicalHash},
		{"G1CanonicalHash", inp.G1CanonicalHash, goldenG1CanonicalHash},
		{"G2CanonicalHash", inp.G2CanonicalHash, goldenG2CanonicalHash},
		{"KeypageURLHash", inp.KeypageURLHash, goldenKeypageURLHash},
		{"KeybookURLHash", inp.KeybookURLHash, goldenKeybookURLHash},
		{"OperationID", inp.OperationID, goldenOperationID},
	}

	for _, s := range slots {
		got := hex.EncodeToString(s.got[:])
		if got != s.golden {
			t.Errorf("govRoot slot %s MOVED\n  golden %s\n  got    %s\n"+
				"A Phase 6 edit widened a canonical struct. Revert that edit; do NOT update this constant.",
				s.name, s.golden, got)
		}
	}

	root := ComputeAccumulateGovRoot(inp)
	gotRoot := hex.EncodeToString(root[:])
	if gotRoot != goldenGovRoot {
		t.Fatalf("govRoot MOVED\n  golden %s\n  got    %s\n"+
			"Every TX2 already signed on the fleet commits to the golden value. Revert, do not re-baseline.",
			goldenGovRoot, gotRoot)
	}
	t.Logf("govRoot invariant holds: %s", gotRoot)
}

// =============================================================================
// Gate 1.2 — the canonical-shape test.
// =============================================================================

// fieldSpec is one struct field as it appears in the wire format.
type fieldSpec struct {
	Name string
	Tag  string
}

// shapeOf reflects a struct's fields in DECLARATION ORDER. Order matters:
// json.Marshal emits fields in declaration order, so reordering two fields
// moves the hash exactly as adding one does.
func shapeOf(t *testing.T, v interface{}) []fieldSpec {
	t.Helper()
	rt := reflect.TypeOf(v)
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		t.Fatalf("shapeOf: %v is not a struct", rt)
	}
	out := make([]fieldSpec, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		out = append(out, fieldSpec{Name: f.Name, Tag: f.Tag.Get("json")})
	}
	return out
}

func assertShape(t *testing.T, label string, v interface{}, golden []fieldSpec) {
	t.Helper()
	got := shapeOf(t, v)
	if len(got) != len(golden) {
		t.Errorf("%s: field COUNT changed: golden %d, got %d\n  golden %+v\n  got    %+v\n"+
			"This struct is inside a govRoot preimage. Store evidence beside it, never inside it.",
			label, len(golden), len(got), golden, got)
		return
	}
	for i := range golden {
		if got[i] != golden[i] {
			t.Errorf("%s: field %d changed: golden {%s `json:%q`}, got {%s `json:%q`}\n"+
				"Renaming, retagging or reordering a field of this struct moves the govRoot.",
				label, i, golden[i].Name, golden[i].Tag, got[i].Name, got[i].Tag)
		}
	}
}

func TestP6_CanonicalShapesUnchanged(t *testing.T) {
	// ConsensusProof — the L4 govRoot payload itself.
	//
	// CHANGED IN PHASE 7, DELIBERATELY AND ONCE. BVNs was added so the root
	// commits to EVERY signer partition's quorum, not only the principal's;
	// governance can span partitions, and a root that committed to one leg of a
	// two-leg proof would attest to less than the proof carries, silently.
	//
	// Two things make this a legitimate golden update rather than the drift this
	// test exists to stop, and both are checked, not asserted:
	//
	//   - L4GovRootVersion is bumped v1 -> v2 in the same change, which is what
	//     that field is for. TestP7_GovRootVersionIsV2 pins it.
	//   - The v1 preimage still reproduces bit-for-bit. BVNs is omitempty, so a
	//     v1-shaped payload marshals exactly as before and every historical root
	//     stays recomputable. TestP7_V1GovRootStillReproduces proves it, and
	//     TestP6_GovRootInvariant_GoldenSlots - whose fixture pins the v1 version
	//     as a literal - passes unchanged.
	//
	// Adding a field here WITHOUT both of those is the defect. Revert it.
	assertShape(t, "lcproof.ConsensusProof", lcproof.ConsensusProof{}, []fieldSpec{
		{"Version", "v"},
		{"BVN", "bvn"},
		{"BVNs", "bvns,omitempty"},
		{"DN", "dn"},
	})

	assertShape(t, "lcproof.L4LegSummary", lcproof.L4LegSummary{}, []fieldSpec{
		{"Partition", "partition"},
		{"SignedHash", "signedHash"},
		{"StateTreeAnchor", "stateTreeAnchor"},
		{"RootChainAnchor", "rootChainAnchor"},
		{"MinorBlockIndex", "minorBlockIndex"},
		{"Threshold", "threshold"},
		{"Signers", "signers"},
	})

	assertShape(t, "proof.G0Result", certenproof.G0Result{}, []fieldSpec{
		{"EntryHashExec", "entry_hash_exec"},
		{"TXID", "txid"},
		{"TxHash", "tx_hash"},
		{"ExecMBI", "exec_mbi"},
		{"ExecWitness", "exec_witness"},
		{"Scope", "scope"},
		{"Chain", "chain"},
		{"ExpandedMessageID", "expanded_message_id"},
		{"Principal", "principal"},
		{"Receipt", "receipt"},
		{"G0ProofComplete", "g0_proof_complete"},
	})

	// GovReceiptData is nested inside G0Result, so it is inside the G0/G1/G2
	// canonical hash too. Phase 7 persists receipt entries and must not widen
	// this struct to do it.
	assertShape(t, "proof.GovReceiptData", certenproof.GovReceiptData{}, []fieldSpec{
		{"Start", "start"},
		{"Anchor", "anchor"},
		{"LocalBlock", "localBlock"},
		{"LocalBlockTime", "localBlockTime"},
		{"MajorBlock", "majorBlock"},
		{"End", "end"},
	})

	assertShape(t, "proof.G1Result", certenproof.G1Result{}, []fieldSpec{
		{"G0Result", ""},
		{"AuthoritySnapshot", "authority_snapshot"},
		{"ValidatedSignatures", "validated_signatures"},
		{"UniqueValidKeys", "unique_valid_keys"},
		{"RequiredThreshold", "required_threshold"},
		{"ThresholdSatisfied", "threshold_satisfied"},
		{"ExecutionSuccess", "execution_success"},
		{"TimingValid", "timing_valid"},
		{"G1ProofComplete", "g1_proof_complete"},
		{"ConcurrencyEnabled", "concurrency_enabled"},
		{"WorkerCount", "worker_count"},
		{"ProcessingTimeMs", "processing_time_ms"},
		{"CryptographicSecurity", "cryptographic_security"},
		{"SecurityReport", "security_report"},
		{"Ed25519Verified", "ed25519_verified"},
		{"AuditTrailEvents", "audit_trail_events"},
		{"BundleIntegrityHash", "bundle_integrity_hash"},
	})

	assertShape(t, "proof.G2Result", certenproof.G2Result{}, []fieldSpec{
		{"G1Result", ""},
		{"OutcomeLeaf", "outcome_leaf"},
		{"PayloadVerified", "payload_verified"},
		{"EffectVerified", "effect_verified"},
		{"G2ProofComplete", "g2_proof_complete"},
		{"SecurityLevel", "security_level"},
	})
}

// =============================================================================
// Stage 2 — the types on the OTHER side of the line
// =============================================================================
//
// Everything pinned above is INSIDE a govRoot preimage: widening it moves every
// govRoot ever signed. The two types pinned below are the opposite, and that
// distinction is the entire design of Stage 2:
//
//	GovReceiptEvidence  NOT hashed. Carries the merkle path BESIDE the summary.
//	                    May be widened freely.
//	GovernanceProof     NOT hashed. The govRoot commits to G0Result, G1Result
//	                    and G2Result marshalled INDIVIDUALLY (v6_1_signing.go),
//	                    never to this wrapper.
//
// They are pinned anyway — not because a change here breaks a hash, but so a
// future reader cannot mistake which side of the line they are on. The trap is
// real and adjacent: GovReceiptData, pinned above, looks almost identical and IS
// inside the hash. Putting Entries there is the obvious move and it is wrong.
//
// If this test fails, check FIRST whether the field was added to the right
// struct. If it was, updating the golden here is allowed — and it is explicitly
// NOT allowed for anything in TestP6_CanonicalShapesUnchanged.
func TestS2_EvidenceShapesAreNotHashed(t *testing.T) {
	assertShape(t, "proof.GovReceiptEvidence (NOT HASHED)", certenproof.GovReceiptEvidence{}, []fieldSpec{
		{"Level", "level"},
		{"Start", "start"},
		{"Anchor", "anchor"},
		{"LocalBlock", "localBlock"},
		{"Entries", "entries"},
	})

	assertShape(t, "proof.GovernanceProof (NOT HASHED)", certenproof.GovernanceProof{}, []fieldSpec{
		{"Level", "level"},
		{"SpecVersion", "spec_version"},
		{"GeneratedAt", "generated_at"},
		{"G0", "g0,omitempty"},
		{"G1", "g1,omitempty"},
		{"G2", "g2,omitempty"},
		{"Receipts", "receipts,omitempty"},
	})
}

// The hashed bytes must not move when receipt evidence is present.
//
// The shape test proves the hashed structs did not change SHAPE. This proves the
// separation holds by VALUE: marshal the same G0Result out of a wrapper carrying
// a full merkle path and out of one carrying none, and require the bytes to be
// identical. If someone later routes the evidence into G0Result "just for
// convenience", the shape test catches the declaration and this catches the
// value.
func TestS2_HashedBytesUnmovedByReceiptEvidence(t *testing.T) {
	withEvidence := &certenproof.GovernanceProof{
		Level:       certenproof.GovLevelG0,
		SpecVersion: certenproof.GovernanceSpecVersion,
		GeneratedAt: fixedTime(),
		G0:          p6FixtureG0(),
		Receipts: []certenproof.GovReceiptEvidence{{
			Level:      "G0",
			Start:      "aaaa",
			Anchor:     "bbbb",
			LocalBlock: 40001,
			Entries: []certenproof.ReceiptStep{
				{Hash: "1111111111111111111111111111111111111111111111111111111111111111", Right: true},
				{Hash: "2222222222222222222222222222222222222222222222222222222222222222"},
			},
		}},
	}

	bare, err := json.Marshal(p6FixtureG0())
	if err != nil {
		t.Fatalf("marshal bare G0: %v", err)
	}
	carried, err := json.Marshal(withEvidence.G0)
	if err != nil {
		t.Fatalf("marshal carried G0: %v", err)
	}
	if !bytes.Equal(bare, carried) {
		t.Fatalf("G0Result bytes differ when receipt evidence is attached to the wrapper.\n"+
			"  bare:    %s\n  carried: %s\n"+
			"The evidence has leaked into the hashed struct. Revert that edit; do not re-baseline.",
			bare, carried)
	}
	if len(withEvidence.Receipts[0].Entries) != 2 {
		t.Fatal("fixture lost its merkle path")
	}
}
