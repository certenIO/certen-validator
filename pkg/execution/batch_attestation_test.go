package execution

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func attesterID() BatchAttesterIdentity {
	return BatchAttesterIdentity{
		ValidatorID: "validator-1",
		EVMAddress:  "0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D",
	}
}

func addMember(t *testing.T, s *BatchStack, id string, height uint64, target byte, value int64) {
	t.Helper()
	if err := s.Mempool.Add(&PendingBatchIntent{
		IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: 11155111,
		Account:     common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
		OperationID: opid(byte(len(id))),
		Legs: []LegExecution{{
			LegID: "l0", ChainID: 11155111, Target: tgt(target), Value: big.NewInt(value),
		}},
		CommitHeight: height,
	}); err != nil {
		t.Fatal(err)
	}
}

// derivedBundle returns what a stack would derive for a period — the proposer's value.
func derivedBundle(t *testing.T, s *BatchStack, cutoff uint64) string {
	t.Helper()
	members := s.Mempool.PeekForPeriod(11155111, cutoff, DefaultBatchPeriodBlocks)
	inputs := make([]BatchLeafInput, 0, len(members))
	for _, m := range members {
		in, err := m.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}
	tree, err := BuildBatchTree(11155111, inputs, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	return "0x" + hex.EncodeToString(tree.BundleID[:])
}

// =============================================================================
// THE security property
// =============================================================================

// A proposer whose batch this validator cannot reproduce must be refused. Without this, a
// malicious proposer could insert a leaf draining an ADI's account and collect six honest
// signatures over it — a genuine quorum authorising a theft.
func TestAttest_RefusesBundleIdMismatch(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)

	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID:      11155111,
		CutoffHeight: 100,
		// A bundleId this validator's mempool cannot possibly produce.
		BundleID:   "0x" + strings.Repeat("ab", 32),
		ProposerID: "validator-2",
	}, attesterID())

	if resp.Error == "" {
		t.Fatal("a batch this validator did not reproduce MUST NOT be signed")
	}
	if resp.SignatureHex != "" {
		t.Fatal("no signature may be returned on refusal")
	}
	if !strings.Contains(resp.Error, "bundleId mismatch") {
		t.Fatalf("expected a bundleId mismatch refusal, got: %s", resp.Error)
	}
}

// The subtle attack: the proposer's batch is ALMOST ours — same period, but with one extra
// member we have never seen. The root changes, so the bundleId changes, so we must refuse.
func TestAttest_RefusesWhenProposerHasAnExtraMember(t *testing.T) {
	// Proposer's view: two members.
	proposer := stackForChain(t, 11155111)
	addMember(t, proposer, "alpha", 100, 0xAA, 1000)
	addMember(t, proposer, "evil", 100, 0xBB, 999999) // the injected leaf
	proposerBundle := derivedBundle(t, proposer, 100)

	// Our view: only the legitimate member.
	us := stackForChain(t, 11155111)
	addMember(t, us, "alpha", 100, 0xAA, 1000)

	resp := us.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100, BundleID: proposerBundle, ProposerID: "validator-2",
	}, attesterID())

	if resp.Error == "" {
		t.Fatal("an injected member changes the root; this MUST be refused")
	}
	if resp.SignatureHex != "" {
		t.Fatal("no signature may be returned when membership differs")
	}
}

// Same members but a different value on one leg — the executionCommitment changes, so the leaf
// changes, so the root changes. Must be refused.
func TestAttest_RefusesWhenAMemberWasTampered(t *testing.T) {
	proposer := stackForChain(t, 11155111)
	addMember(t, proposer, "alpha", 100, 0xAA, 999999) // tampered amount
	proposerBundle := derivedBundle(t, proposer, 100)

	us := stackForChain(t, 11155111)
	addMember(t, us, "alpha", 100, 0xAA, 1000) // what we actually saw

	resp := us.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100, BundleID: proposerBundle,
	}, attesterID())

	if resp.Error == "" || resp.SignatureHex != "" {
		t.Fatal("a tampered member must be refused")
	}
}

// A different cutoff height selects a different member set AND feeds the bundleId derivation
// directly, so it must not be signed either.
func TestAttest_RefusesDifferentCutoffHeight(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	bundleAt100 := derivedBundle(t, s, 100)

	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 200, BundleID: bundleAt100,
	}, attesterID())

	if resp.Error == "" || resp.SignatureHex != "" {
		t.Fatal("a bundleId derived at a different height must not be attested")
	}
}

// =============================================================================
// Refusals that keep the quorum honest rather than merely safe
// =============================================================================

func TestAttest_RefusesWhenNothingPending(t *testing.T) {
	s := stackForChain(t, 11155111)
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100, BundleID: "0x" + strings.Repeat("11", 32),
	}, attesterID())
	if resp.Error == "" {
		t.Fatal("a validator with nothing pending cannot attest to a batch")
	}
}

func TestAttest_RefusesMalformedAndUnsafeRequests(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	good := derivedBundle(t, s, 100)

	cases := []struct {
		name string
		req  *BatchAttestationRequest
		me   BatchAttesterIdentity
	}{
		{"nil request", nil, attesterID()},
		{"zero cutoff", &BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 0, BundleID: good}, attesterID()},
		{"malformed bundleId", &BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: "nothex"}, attesterID()},
		{"short bundleId", &BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: "0xdeadbeef"}, attesterID()},
		{"unconfigured chain", &BatchAttestationRequest{ChainID: 8453, CutoffHeight: 100, BundleID: good}, attesterID()},
		{"no attester identity", &BatchAttestationRequest{ChainID: 11155111, CutoffHeight: 100, BundleID: good},
			BatchAttesterIdentity{ValidatorID: "v"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := s.HandleBatchAttestationRequest(c.req, c.me)
			if resp.Error == "" {
				t.Fatal("must be refused")
			}
			if resp.SignatureHex != "" {
				t.Fatal("a refusal must never carry a signature")
			}
		})
	}
}

// Attesting must NOT consume the mempool: if the proposer never lands the batch, this
// validator still needs its members for the fallback path.
func TestAttest_DoesNotConsumeMempool(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	good := derivedBundle(t, s, 100)

	for i := 0; i < 3; i++ {
		s.HandleBatchAttestationRequest(&BatchAttestationRequest{
			ChainID: 11155111, CutoffHeight: 100, BundleID: good,
		}, attesterID())
	}
	if s.Mempool.PendingCount() != 1 {
		t.Fatalf("attesting must not consume members, pending=%d", s.Mempool.PendingCount())
	}
}

// The happy path is only reachable with a real BLS key loaded, which unit tests do not have.
// What IS asserted here: agreement gets PAST the bundleId check and fails only at signing —
// proving the comparison itself succeeds for a batch we genuinely reproduced.
func TestAttest_AgreementReachesSigning(t *testing.T) {
	s := stackForChain(t, 11155111)
	addMember(t, s, "alpha", 100, 0xAA, 1000)
	addMember(t, s, "beta", 100, 0xBB, 2000)
	good := derivedBundle(t, s, 100)

	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100, BundleID: good,
	}, attesterID())

	if resp.BundleID != good {
		t.Fatalf("attester derived %s, proposer %s — they must agree", resp.BundleID, good)
	}
	if strings.Contains(resp.Error, "bundleId mismatch") {
		t.Fatalf("a reproduced batch must pass the comparison, got: %s", resp.Error)
	}
	// Without a loaded key the only acceptable failure is at the signing step.
	if resp.Error != "" &&
		!strings.Contains(resp.Error, "BLS key") &&
		!strings.Contains(resp.Error, "private key") &&
		!strings.Contains(resp.Error, "validator-set root") {
		t.Fatalf("unexpected refusal for an agreed batch: %s", resp.Error)
	}
}
