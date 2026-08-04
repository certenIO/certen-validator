package execution

import (
	"encoding/hex"
	"testing"
)

// odStack builds a BatchStack whose mempool holds the given members. The orchestrator map is
// seeded so OrchestratorFor(chain) succeeds; these tests never reach chain I/O because every
// refusal under test happens before signing.
func odStack(t *testing.T, chainID int64, members ...*PendingBatchIntent) *BatchStack {
	t.Helper()
	m := NewBatchMempool(BatchMempoolConfig{})
	for _, p := range members {
		if err := m.AddOnDemand(p); err != nil {
			t.Fatalf("AddOnDemand: %v", err)
		}
	}
	return &BatchStack{
		Mempool:       m,
		Orchestrators: map[int64]*BatchOrchestrator{chainID: {}},
	}
}

func odIdentity() BatchAttesterIdentity {
	return BatchAttesterIdentity{ValidatorID: "validator-1", EVMAddress: "0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d"}
}

func hex32(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

// The not-ready signal. A peer that has not yet processed the round must say so with a code the
// proposer can retry on, NOT a generic refusal it would count as a disagreement.
func TestOnDemandHandlerRefusesUnheldMemberWithNotHeldCode(t *testing.T) {
	s := odStack(t, odChain) // empty mempool

	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     odChain,
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32([32]byte{9}),
		ProposerID:  "validator-2",
	}, odIdentity())

	if resp.Code != CodeMemberNotHeld {
		t.Fatalf("Code = %q, want %q — the proposer would treat a peer that is merely behind as "+
			"a disagreement and burn a quorum attempt", resp.Code, CodeMemberNotHeld)
	}
	if resp.SignatureHex != "" {
		t.Fatal("a refusal must not carry a signature")
	}
}

// The security boundary: a proposer naming a bundleId this validator did not derive is refused,
// and refused with a code that is NOT retryable.
func TestOnDemandHandlerRefusesBundleMismatch(t *testing.T) {
	p := odMember(1, odChain, 105)
	s := odStack(t, odChain, p)

	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     odChain,
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32([32]byte{0xAA}), // not what this validator derives
		ProposerID:  "validator-2",
	}, odIdentity())

	if resp.Code != CodeBundleMismatch {
		t.Fatalf("Code = %q, want %q", resp.Code, CodeBundleMismatch)
	}
	if resp.SignatureHex != "" {
		t.Fatal("signed a batch it did not reproduce — the whole boundary is broken")
	}
	// It must still report what it derived, so the disagreement is diagnosable.
	if resp.BundleID == "" {
		t.Error("refusal did not report the attester's own derived bundleId")
	}
}

// THE property that makes a proposer unable to influence the derivation: the height comes from
// the attester's own member. A proposer cannot supply one — there is no field for it — and the
// attester must not infer one from anything in the request.
func TestOnDemandHandlerRebuildsAtItsOwnCommitHeight(t *testing.T) {
	// Two validators holding the SAME intent at DIFFERENT heights must disagree.
	mine := odMember(1, odChain, 105)
	theirs := odMember(1, odChain, 106)

	s := odStack(t, odChain, mine)
	theirTree := odTreeFor(t, theirs)

	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     odChain,
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32(theirTree.BundleID),
		ProposerID:  "validator-2",
	}, odIdentity())

	if resp.Code != CodeBundleMismatch {
		t.Fatalf("Code = %q, want %q — the attester adopted the proposer's view of the height",
			resp.Code, CodeBundleMismatch)
	}
	myTree := odTreeFor(t, mine)
	if resp.BundleID != hex32(myTree.BundleID) {
		t.Fatalf("attester derived %s, want its own %s", resp.BundleID, hex32(myTree.BundleID))
	}
}

// A chain this validator cannot anchor on is a configuration problem, not a race.
func TestOnDemandHandlerRefusesUnconfiguredChain(t *testing.T) {
	s := odStack(t, odChain, odMember(1, odChain, 105))

	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     999999, // no orchestrator
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32([32]byte{1}),
	}, odIdentity())

	if resp.Code != CodeConfigMismatch {
		t.Fatalf("Code = %q, want %q", resp.Code, CodeConfigMismatch)
	}
}

func TestOnDemandHandlerRejectsMalformedInput(t *testing.T) {
	s := odStack(t, odChain, odMember(1, odChain, 105))
	cases := map[string]*OnDemandAttestationRequest{
		"bad opID":  {ChainID: odChain, OperationID: "0xzz", BundleID: hex32([32]byte{1})},
		"zero opID": {ChainID: odChain, OperationID: hex32([32]byte{}), BundleID: hex32([32]byte{1})},
		"bad bundle": {ChainID: odChain, OperationID: hex32([32]byte{1}),
			BundleID: "not-hex"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			resp := s.HandleOnDemandAttestationRequest(req, odIdentity())
			if resp.Error == "" {
				t.Fatal("malformed request was accepted")
			}
			if resp.SignatureHex != "" {
				t.Fatal("malformed request produced a signature")
			}
		})
	}
}

// An attester with no EVM identity cannot have its signature attributed to a registry entry, so
// it must decline rather than contribute a partial that resolves to zero voting power.
func TestOnDemandHandlerRefusesWithoutAttesterIdentity(t *testing.T) {
	s := odStack(t, odChain, odMember(1, odChain, 105))
	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     odChain,
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32([32]byte{1}),
	}, BatchAttesterIdentity{ValidatorID: "validator-1"})

	if resp.Code != CodeNotReady {
		t.Fatalf("Code = %q, want %q", resp.Code, CodeNotReady)
	}
}

// The on-demand handler must not be able to see period members: an intent in the period pool is
// settling under a period anchor, and co-signing it as a one-member batch would double-spend
// its leaf.
func TestOnDemandHandlerCannotAttestAPeriodMember(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.Add(odMember(1, odChain, 105)); err != nil { // PERIOD pool
		t.Fatalf("Add: %v", err)
	}
	s := &BatchStack{Mempool: m, Orchestrators: map[int64]*BatchOrchestrator{odChain: {}}}

	resp := s.HandleOnDemandAttestationRequest(&OnDemandAttestationRequest{
		ChainID:     odChain,
		OperationID: hex32([32]byte{1}),
		BundleID:    hex32([32]byte{1}),
	}, odIdentity())

	if resp.Code != CodeMemberNotHeld {
		t.Fatalf("Code = %q, want %q — the on-demand handler reached into the period pool",
			resp.Code, CodeMemberNotHeld)
	}
}

// =============================================================================
// The period handler must keep behaving exactly as before
// =============================================================================

// Codes are ADDITIVE. The period handler's decisions are unchanged; it merely labels them.
func TestPeriodHandlerStillRefusesUnheldWithNotHeldCode(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	s := &BatchStack{
		Mempool:       m,
		Orchestrators: map[int64]*BatchOrchestrator{odChain: {}},
		PeriodBlocks:  DefaultBatchPeriodBlocks,
	}

	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID:      odChain,
		CutoffHeight: 100,
		PeriodBlocks: DefaultBatchPeriodBlocks,
		BundleID:     hex32([32]byte{1}),
	}, odIdentity())

	if resp.Code != CodeMemberNotHeld {
		t.Fatalf("period handler Code = %q, want %q", resp.Code, CodeMemberNotHeld)
	}
	if resp.Error == "" {
		t.Error("the human-readable Error must survive alongside the code")
	}
}

func TestPeriodHandlerLabelsWidthMismatchAsConfig(t *testing.T) {
	s := &BatchStack{
		Mempool:       NewBatchMempool(BatchMempoolConfig{}),
		Orchestrators: map[int64]*BatchOrchestrator{odChain: {}},
		PeriodBlocks:  100,
	}
	resp := s.HandleBatchAttestationRequest(&BatchAttestationRequest{
		ChainID:      odChain,
		CutoffHeight: 100,
		PeriodBlocks: 5, // different width
		BundleID:     hex32([32]byte{1}),
	}, odIdentity())

	if resp.Code != CodeConfigMismatch {
		t.Fatalf("Code = %q, want %q", resp.Code, CodeConfigMismatch)
	}
}
