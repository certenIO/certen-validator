package execution

import (
	"encoding/json"
	"strings"
	"testing"
)

// The attestation request MUST NOT carry member data.
//
// Peers rebuild membership from their own mempools; that independent reconstruction is the only
// thing preventing a malicious proposer from having six honest validators sign a root that
// drains an ADI's account. If someone later adds members to this struct "so the peer doesn't
// have to look them up", the attester would validate the proposer's data against itself, the
// boundary would silently vanish, and every OTHER test would still pass.
//
// This test is the tripwire. It fails on the field being added, not on behaviour changing.
func TestWireFormat_CarriesNoMemberData(t *testing.T) {
	b, err := json.Marshal(&BatchAttestationRequest{
		ChainID: 11155111, CutoffHeight: 100,
		BundleID: "0xdead", ProposerID: "validator-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}

	allowed := map[string]bool{
		"chain_id": true, "cutoff_height": true, "bundle_id": true, "proposer_id": true,
		// period_blocks is the window WIDTH, not membership. It is allowed only because the
		// attester REFUSES a width that differs from its own configuration rather than adopting
		// it (HandleBatchAttestationRequest), so a proposer cannot use it to widen what the peer
		// selects. If that refusal is ever removed, this entry must come out with it.
		"period_blocks": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Fatalf("BatchAttestationRequest gained field %q. If this carries member data, the "+
				"attester's independent reconstruction is bypassed and the quorum can be made to "+
				"sign a batch nobody verified. Add it to `allowed` ONLY if it cannot influence "+
				"what the peer builds.", k)
		}
	}

	// Named explicitly so the intent survives a careless edit to `allowed`.
	for _, banned := range []string{"members", "leaves", "leaf", "inputs", "intents", "root", "legs"} {
		if _, present := fields[banned]; present {
			t.Fatalf("request carries %q — peers must derive this themselves, never accept it", banned)
		}
	}
}

// The proposer must not be able to construct a request whose bundleId disagrees with the tree
// it was built from.
func TestNewBatchAttestationRequest_BindsToTree(t *testing.T) {
	if _, err := NewBatchAttestationRequest(nil, 100, DefaultBatchPeriodBlocks, "v1"); err == nil {
		t.Fatal("nil tree must be refused")
	}
	tree := &BatchTree{ChainID: 11155111, BundleID: [32]byte{0xAB, 0xCD}}
	if _, err := NewBatchAttestationRequest(tree, 0, DefaultBatchPeriodBlocks, "v1"); err == nil {
		t.Fatal("zero cutoff must be refused")
	}
	req, err := NewBatchAttestationRequest(tree, 100, DefaultBatchPeriodBlocks, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.BundleID, "0xabcd") {
		t.Fatalf("bundleId not taken from the tree: %s", req.BundleID)
	}
	if req.ChainID != 11155111 {
		t.Fatal("chainID not taken from the tree")
	}
}

func TestBatchAttestationPeersFromEnv(t *testing.T) {
	t.Setenv("ATTESTATION_PEERS", " http://validator-2:8080 , http://validator-3:8080/ ,, ")
	got := BatchAttestationPeersFromEnv()
	if len(got) != 2 {
		t.Fatalf("expected 2 peers, got %d (%v)", len(got), got)
	}
	if got[1] != "http://validator-3:8080" {
		t.Fatalf("trailing slash not trimmed: %q", got[1])
	}
	t.Setenv("ATTESTATION_PEERS", "")
	if len(BatchAttestationPeersFromEnv()) != 0 {
		t.Fatal("unset must yield no peers")
	}
}
