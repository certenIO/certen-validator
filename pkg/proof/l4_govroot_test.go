package proof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// Phase 5 verification - binding L4 into the governance root.
//
// L4ConsensusProofH was thirty-two zero bytes in every govRoot ever signed,
// because nothing populated LiteClientProof.ConsensusProof and
// SetL4ConsensusProofFromJSON returns early on nil. The chain committed to
// L1-L3 and G0-G2 but not to the validator quorum that signed the anchors.
//
// The govRoot hash is bound to Go struct layout (CanonicalJSONMarshal is
// json.Marshal), so these tests pin the properties that make the change safe
// to deploy: determinism, order-independence, and signer/submitter agreement.

func testLeg(partition string, signers []string) *chained_proof.Layer4 {
	sigs := make([]chained_proof.AnchorSignature, 0, len(signers))
	for _, pk := range signers {
		sigs = append(sigs, chained_proof.AnchorSignature{PublicKey: pk})
	}
	return &chained_proof.Layer4{
		Partition:       partition,
		SignedHash:      "aa" + partition,
		StateTreeAnchor: "bb" + partition,
		RootChainAnchor: "cc" + partition,
		MinorBlockIndex: 12345,
		Threshold:       2,
		Signatures:      sigs,
	}
}

func testProofWithL4(bvn, dn *chained_proof.Layer4) *CertenProof {
	return &CertenProof{
		LiteClientProof: &LiteClientProofData{
			ConsensusProof: BuildL4ConsensusProof(bvn, dn),
		},
	}
}

// P5.2 - the slot is no longer zero.
func TestP5_L4SlotIsNoLongerZero(t *testing.T) {
	bvn := testLeg("BVN1", []string{"11aa", "22bb"})
	dn := testLeg("Directory", []string{"33cc", "44dd", "55ee"})

	payload := BuildL4ConsensusProof(bvn, dn)
	if payload == nil {
		t.Fatal("expected an L4 payload")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	h := contracts.HashL4ConsensusProof(raw)
	if h == ([32]byte{}) {
		t.Fatal("CRITICAL: L4ConsensusProofH is still zero - the chain does not commit to L4")
	}
	t.Logf("L4ConsensusProofH = %s", hex.EncodeToString(h[:]))

	// And the builder must still produce ZERO when L4 is genuinely absent,
	// rather than inventing a commitment.
	if BuildL4ConsensusProof(nil, dn) != nil {
		t.Fatal("a missing BVN leg must not produce a partial L4 commitment")
	}
	if BuildL4ConsensusProof(bvn, nil) != nil {
		t.Fatal("a missing DN leg must not produce a partial L4 commitment")
	}
}

// P5.3 - determinism. Two nodes building the same proof must hash identically.
func TestP5_PayloadIsDeterministic(t *testing.T) {
	bvn := testLeg("BVN1", []string{"11aa", "22bb"})
	dn := testLeg("Directory", []string{"33cc", "44dd", "55ee"})

	var first string
	for i := 0; i < 20; i++ {
		raw, err := json.Marshal(BuildL4ConsensusProof(bvn, dn))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = string(raw)
			continue
		}
		if string(raw) != first {
			t.Fatalf("CRITICAL: payload is nondeterministic across builds\n got  %s\n want %s", raw, first)
		}
	}
}

// P5.4 - signer ORDER must not affect the hash.
//
// This is the single most dangerous property. Signature order is whatever the
// API returned and is not stable between two queries for the same anchor. If
// order leaked into the hash, two honest validators reading identical chain
// data would compute different govRoots, producing an intermittent and
// unreproducible TX2 revert.
func TestP5_SignerOrderDoesNotAffectTheHash(t *testing.T) {
	orderings := [][]string{
		{"11aa", "22bb", "33cc"},
		{"33cc", "11aa", "22bb"},
		{"22bb", "33cc", "11aa"},
		{"33cc", "22bb", "11aa"},
	}

	var want string
	for i, order := range orderings {
		dn := testLeg("Directory", order)
		raw, err := json.Marshal(BuildL4ConsensusProof(testLeg("BVN1", []string{"aa11", "bb22"}), dn))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			want = string(raw)
			continue
		}
		if string(raw) != want {
			t.Fatalf("CRITICAL: signer order changed the payload — this yields intermittent TX2 reverts\n"+
				"order %v produced:\n %s\nexpected:\n %s", order, raw, want)
		}
	}

	// Duplicates must collapse: the quorum is a SET of distinct signers.
	dup := testLeg("Directory", []string{"11aa", "11aa", "22bb"})
	uniq := testLeg("Directory", []string{"11aa", "22bb"})
	a, _ := json.Marshal(BuildL4ConsensusProof(testLeg("BVN1", []string{"x"}), dup))
	b, _ := json.Marshal(BuildL4ConsensusProof(testLeg("BVN1", []string{"x"}), uniq))
	if string(a) != string(b) {
		t.Fatalf("CRITICAL: duplicate signers changed the payload\n %s\n %s", a, b)
	}

	// Case must not matter either - public keys arrive in mixed case.
	lower := testLeg("Directory", []string{"aabb", "ccdd"})
	upper := testLeg("Directory", []string{"AABB", "CCDD"})
	c, _ := json.Marshal(BuildL4ConsensusProof(testLeg("BVN1", []string{"x"}), lower))
	d, _ := json.Marshal(BuildL4ConsensusProof(testLeg("BVN1", []string{"x"}), upper))
	if string(c) != string(d) {
		t.Fatalf("CRITICAL: public key case changed the payload\n %s\n %s", c, d)
	}
}

// P5.5 - a mutated leg MUST change the hash, or the commitment is vacuous.
func TestP5_MutatedLegChangesTheHash(t *testing.T) {
	base := BuildL4ConsensusProof(
		testLeg("BVN1", []string{"11aa", "22bb"}),
		testLeg("Directory", []string{"33cc", "44dd"}))
	baseRaw, _ := json.Marshal(base)
	baseHash := contracts.HashL4ConsensusProof(baseRaw)

	mutations := []struct {
		name  string
		apply func(*lcproof.ConsensusProof)
	}{
		{"BVN stateTreeAnchor", func(c *lcproof.ConsensusProof) { c.BVN.StateTreeAnchor = "deadbeef" }},
		{"DN stateTreeAnchor", func(c *lcproof.ConsensusProof) { c.DN.StateTreeAnchor = "deadbeef" }},
		{"BVN signedHash", func(c *lcproof.ConsensusProof) { c.BVN.SignedHash = "deadbeef" }},
		{"DN threshold", func(c *lcproof.ConsensusProof) { c.DN.Threshold = 99 }},
		{"BVN minor block", func(c *lcproof.ConsensusProof) { c.BVN.MinorBlockIndex = 999 }},
		{"a dropped signer", func(c *lcproof.ConsensusProof) { c.DN.Signers = c.DN.Signers[:1] }},
		{"an added signer", func(c *lcproof.ConsensusProof) { c.DN.Signers = append(c.DN.Signers, "99ff") }},
		{"a substituted signer", func(c *lcproof.ConsensusProof) { c.DN.Signers[0] = "99ff" }},
		// The mutated version is DERIVED from the live constant, not a literal.
		//
		// It used to be the literal "certen:l4gov:v2", chosen because v1 was
		// current. Phase 7 bumped the constant to v2, so the "mutation" became
		// the base value and this case silently stopped mutating anything - it
		// reported that the govRoot does not commit to the version, when in fact
		// the test had stopped changing it. Deriving the value means the case
		// keeps working through every future bump.
		{"the version tag", func(c *lcproof.ConsensusProof) {
			c.Version = lcproof.L4GovRootVersion + ":mutated"
		}},
		// A leg beyond the principal's must be committed to as well - a root that
		// ignored it would attest to one leg of a two-leg proof.
		{"an added partition leg", func(c *lcproof.ConsensusProof) {
			extra := c.BVN
			extra.Partition = "BVN2"
			c.BVNs = append(c.BVNs, extra)
		}},
		{"swapped legs", func(c *lcproof.ConsensusProof) { c.BVN, c.DN = c.DN, c.BVN }},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			var clone lcproof.ConsensusProof
			raw, _ := json.Marshal(base)
			if err := json.Unmarshal(raw, &clone); err != nil {
				t.Fatal(err)
			}
			m.apply(&clone)
			mutRaw, _ := json.Marshal(&clone)
			if contracts.HashL4ConsensusProof(mutRaw) == baseHash {
				t.Fatalf("CRITICAL: mutating %q did not change L4ConsensusProofH — "+
					"the govRoot does not actually commit to it", m.name)
			}
		})
	}
}

// P5.1 - the signer and the EVM submitter must agree, bit for bit.
//
// They call the same builder on the same field of the same object, so this
// asserts the property directly rather than trusting that arrangement.
func TestP5_SignerAndSubmitterAgree(t *testing.T) {
	p := testProofWithL4(
		testLeg("BVN1", []string{"11aa", "22bb"}),
		testLeg("Directory", []string{"55ee", "33cc", "44dd"})) // deliberately unsorted

	build := func() [32]byte {
		gb := contracts.NewAccumulateGovRootInputsBuilder().
			SetL4ConsensusProofFromJSON(p.LiteClientProof.ConsensusProof)
		return gb.Build().L4ConsensusProofH
	}

	signerSide := build()
	submitterSide := build()

	if signerSide != submitterSide {
		t.Fatalf("CRITICAL: signer and submitter disagree\n signer    %x\n submitter %x", signerSide, submitterSide)
	}
	if signerSide == ([32]byte{}) {
		t.Fatal("CRITICAL: L4 slot is zero on both sides — L4 is not committed")
	}
	t.Logf("both sides agree: L4ConsensusProofH = %x", signerSide)
}

// P5.6 - the govRoot MOVES versus today. This is the deploy-gate evidence, not
// a regression: it is why the fleet must upgrade atomically.
func TestP5_GovRootMovesVersusZeroL4(t *testing.T) {
	// The pre-Phase-5 baseline is NOT a zero slot, which an earlier version of
	// this test assumed by passing an untyped nil literal. Production passes a
	// typed *ConsensusProof; a nil typed pointer is not `v == nil`, so the
	// builder marshalled it to "null" and committed hash("null"). Model that,
	// or "the govRoot moves" is measured against a root nothing ever signed.
	var absent *lcproof.ConsensusProof

	withoutL4 := contracts.NewAccumulateGovRootInputsBuilder().Build()
	withoutL4.L4ConsensusProofH = contracts.HashL4ConsensusProof([]byte("null"))
	oldRoot := contracts.ComputeAccumulateGovRoot(withoutL4)

	// And the slot must now be zero for that same typed-nil input, so absence
	// is distinguishable from a committed quorum.
	fixed := contracts.NewAccumulateGovRootInputsBuilder().
		SetL4ConsensusProofFromJSON(absent).Build()
	if fixed.L4ConsensusProofH != ([32]byte{}) {
		t.Fatalf("a typed-nil L4 payload must leave the slot zero, got %x", fixed.L4ConsensusProofH)
	}

	p := testProofWithL4(
		testLeg("BVN1", []string{"11aa", "22bb"}),
		testLeg("Directory", []string{"33cc", "44dd", "55ee"}))
	withL4 := contracts.NewAccumulateGovRootInputsBuilder().
		SetL4ConsensusProofFromJSON(p.LiteClientProof.ConsensusProof).Build()
	newRoot := contracts.ComputeAccumulateGovRoot(withL4)

	if oldRoot == newRoot {
		t.Fatal("CRITICAL: govRoot is unchanged by committing L4 — the slot is not reaching the root")
	}
	t.Logf("govRoot moves: %x -> %x  (fleet must upgrade atomically)", oldRoot[:8], newRoot[:8])
}

// The fail-closed guard must reject anything short of complete L4 evidence.
func TestP5_RequireL4CommittedFailsClosed(t *testing.T) {
	good := testProofWithL4(
		testLeg("BVN1", []string{"11aa", "22bb"}),
		testLeg("Directory", []string{"33cc", "44dd"}))
	if err := RequireL4Committed(good); err != nil {
		t.Fatalf("a complete L4 payload must pass: %v", err)
	}

	cases := []struct {
		name string
		make func() *CertenProof
	}{
		{"nil proof", func() *CertenProof { return nil }},
		{"nil lite client proof", func() *CertenProof { return &CertenProof{} }},
		{"nil L4 payload", func() *CertenProof {
			return &CertenProof{LiteClientProof: &LiteClientProofData{}}
		}},
		{"missing BVN leg", func() *CertenProof {
			return testProofWithL4(nil, testLeg("Directory", []string{"33cc", "44dd"}))
		}},
		{"missing DN leg", func() *CertenProof {
			return testProofWithL4(testLeg("BVN1", []string{"11aa", "22bb"}), nil)
		}},
		{"no version tag", func() *CertenProof {
			p := good
			c := *p.LiteClientProof.ConsensusProof
			c.Version = ""
			return &CertenProof{LiteClientProof: &LiteClientProofData{ConsensusProof: &c}}
		}},
		{"zero threshold", func() *CertenProof {
			c := *good.LiteClientProof.ConsensusProof
			c.DN.Threshold = 0
			return &CertenProof{LiteClientProof: &LiteClientProofData{ConsensusProof: &c}}
		}},
		{"fewer signers than threshold", func() *CertenProof {
			c := *good.LiteClientProof.ConsensusProof
			c.DN.Signers = c.DN.Signers[:1]
			return &CertenProof{LiteClientProof: &LiteClientProofData{ConsensusProof: &c}}
		}},
		{"both legs same partition", func() *CertenProof {
			c := *good.LiteClientProof.ConsensusProof
			c.BVN.Partition = c.DN.Partition
			return &CertenProof{LiteClientProof: &LiteClientProofData{ConsensusProof: &c}}
		}},
		{"empty stateTreeAnchor", func() *CertenProof {
			c := *good.LiteClientProof.ConsensusProof
			c.BVN.StateTreeAnchor = ""
			return &CertenProof{LiteClientProof: &LiteClientProofData{ConsensusProof: &c}}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := RequireL4Committed(tc.make()); err == nil {
				t.Fatalf("CRITICAL: %q was accepted — a zero or partial L4 slot would be signed", tc.name)
			}
		})
	}
}

// End-to-end: a REAL proof built from live Kermit must commit a non-zero L4
// slot, and the two legs must be signed by different partitions.
//
// Everything above uses synthetic legs. This proves the wiring works on the
// data the fleet actually sees.
func TestP5_LiveProofCommitsNonZeroL4(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ep := "https://kermit.accumulatenetwork.io/v3"
	const (
		account = "acc://carp-buyer-62431.acme/data"
		txHash  = "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0"
		bvn     = "bvn1"
	)

	b := chained_proof.NewProofBuilder(jsonrpc.NewClient(ep), false)
	cp, err := b.BuildProof(context.Background(), chained_proof.ProofInput{
		Account: account, TxHash: txHash, BVN: bvn,
	})
	if err != nil {
		t.Fatalf("build live proof: %v", err)
	}

	complete := ChainedProofToCompleteProof(cp)
	if complete.ConsensusProof == nil {
		t.Fatal("CRITICAL: a complete L1-L4 proof produced no L4 payload")
	}

	p := &CertenProof{LiteClientProof: &LiteClientProofData{
		CompleteProof:  complete,
		ConsensusProof: complete.ConsensusProof,
	}}
	if err := RequireL4Committed(p); err != nil {
		t.Fatalf("CRITICAL: live L4 payload rejected by the guard: %v", err)
	}

	in := contracts.NewAccumulateGovRootInputsBuilder().
		SetL4ConsensusProofFromJSON(p.LiteClientProof.ConsensusProof).Build()
	if in.L4ConsensusProofH == ([32]byte{}) {
		t.Fatal("CRITICAL: live proof still yields a ZERO L4 slot")
	}

	c := complete.ConsensusProof
	t.Logf("live L4 committed: %x", in.L4ConsensusProofH[:16])
	t.Logf("  version = %s", c.Version)
	t.Logf("  BVN  %-10s threshold=%d signers=%d stateTreeAnchor=%s",
		c.BVN.Partition, c.BVN.Threshold, len(c.BVN.Signers), c.BVN.StateTreeAnchor[:16])
	t.Logf("  DN   %-10s threshold=%d signers=%d stateTreeAnchor=%s",
		c.DN.Partition, c.DN.Threshold, len(c.DN.Signers), c.DN.StateTreeAnchor[:16])

	// The legs must bind the layers beneath them, or L4 commits to something
	// unrelated to this transaction.
	if c.BVN.StateTreeAnchor != cp.Layer2.BVNStateTreeAnchor {
		t.Fatalf("L4 BVN leg does not bind L2: %s != %s", c.BVN.StateTreeAnchor, cp.Layer2.BVNStateTreeAnchor)
	}
	if c.DN.StateTreeAnchor != cp.Layer3.DNStateTreeAnchor {
		t.Fatalf("L4 DN leg does not bind L3: %s != %s", c.DN.StateTreeAnchor, cp.Layer3.DNStateTreeAnchor)
	}
	if c.BVN.Partition == c.DN.Partition {
		t.Fatal("both legs signed by the same partition")
	}
}
