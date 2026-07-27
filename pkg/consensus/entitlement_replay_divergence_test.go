package consensus

import (
	"encoding/json"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/commitment"
	"io"
	"log"
	"testing"
	"time"
)

// THE INCIDENT, 2026-07-27.
//
// Flipping CERTEN_ENTITLEMENT_MODE from observe to enforce and restarting the
// fleet bricked all seven validators for ~2h and cost the chain its history:
//
//	panic: state.AppHash does not match AppHash after replay.
//	  Got 9B34726E…, expected 8028A10C…
//
// The mechanism, in three steps:
//
//  1. appHash(H) = SHA256( appHash(H-1) || sorted(unique bundle-ids in block H) )
//  2. A tx rejected by the entitlement gate returns BEFORE
//     `blockBundles = append(...)`, so rejection removes a bundle-id from that set.
//  3. The gate's verdict is read from the ENVIRONMENT, not from committed state.
//
// So an env var decides the app hash. Replaying history under a different mode
// than it was committed under yields a different hash, and CometBFT panics
// before the node can serve.
//
// These tests pin the hazard. They are expected to PASS today — they assert the
// divergence exists. Once the entitlement policy moves into committed state
// (docs/design/entitlement-consensus-policy.md), the mode can no longer differ
// between two nodes or between a node and its own past, and
// TestReplayUnderADifferentModeDivergesFromCommittedHash becomes impossible to
// construct — which is the point.

func newGateTestApp(cfg EntitlementConfig, committed []byte, blockTime time.Time) *ValidatorApp {
	return &ValidatorApp{
		logger:           log.New(io.Discard, "", 0),
		validatorBlocks:  make(map[string]*ValidatorBlock),
		committedAppHash: committed,
		chainID:          "certen-test",
		entitlement:      cfg,
		currentBlockTime: blockTime,
	}
}

// A ValidatorBlock that satisfies VerifyValidatorBlockInvariants, so the tx
// reaches the entitlement gate rather than being refused earlier for shape.
func invariantValidBlockJSON(t *testing.T, bundleID, principal string) []byte {
	t.Helper()
	vb := ValidatorBlock{
		ValidatorID:         "validator-1",
		BundleID:            bundleID,
		OperationCommitment: "op-1",
		Timestamp:           time.Unix(gateNow, 0).UTC().Format(time.RFC3339),
		BlockHeight:         1,
		GovernanceProof: GovernanceProof{
			OrganizationADI: principal,
			AuthorizationLeaves: []AuthorizationLeaf{{
				KeyPage: "acc://payer.acme/book/1", KeyHash: "0xkh",
				Role: "DEFAULT_SIGNER", Signature: "0xleafsig",
			}},
			// derived below
			BLSAggregateSignature: "0xsig",
			BLSValidatorSetPubKey: "0xpub",
		},
		CrossChainProof: CrossChainProof{
			OperationID:          "op-1",
			CrossChainCommitment: "0xcc",
			ChainTargets: []ChainTarget{{
				Chain:           "ethereum-sepolia",
				ContractAddress: "0xcontract",
				Commitment:      "0xtargetcommit",
				Expiry:          time.Unix(gateNow+3600, 0).UTC().Format(time.RFC3339),
			}},
		},
		ExecutionProof: ExecutionProof{
			Stage:               ExecutionStagePre,
			ValidatorSignatures: []string{"0xvsig"},
		},
		AccumulateAnchorReference: AccumulateAnchorReference{
			AccountURL:  principal,
			TxHash:      "0xtx",
			BlockHeight: 1,
		},
	}
	// bundle_id and merkle_root are DERIVED; the invariants recompute and compare
	// them, so the fixture must use the same functions rather than placeholders.
	leaves := make([]interface{}, len(vb.GovernanceProof.AuthorizationLeaves))
	for i, l := range vb.GovernanceProof.AuthorizationLeaves {
		leaves[i] = l
	}
	root, err := commitment.ComputeGovernanceMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	vb.GovernanceProof.MerkleRoot = root
	bundleHash, err := commitment.ComputeBundleID(vb.GovernanceProof, vb.CrossChainProof)
	if err != nil {
		t.Fatal(err)
	}
	vb.BundleID = bundleHash

	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// short renders a hash for logs without assuming a length. An enforce-mode block
// whose only tx was rejected stages an EMPTY hash, which FinalizeBlock later
// normalizes to 32 zero bytes — so the raw staged value can legitimately be nil.
func short(h []byte) string {
	if len(h) == 0 {
		return "<empty>"
	}
	return fmt.Sprintf("%x", h[:min(8, len(h))])
}

// Drive one block exactly as FinalizeBlock does: process each tx, then stage the
// app hash from whatever bundle-ids survived.
func runBlock(app *ValidatorApp, height uint64, txs ...[]byte) ([]byte, []abcitypes.ExecTxResult) {
	app.currentBlockHeight = height
	app.blockBundles = app.blockBundles[:0]
	results := make([]abcitypes.ExecTxResult, 0, len(txs))
	for _, tx := range txs {
		results = append(results, app.processValidatorTransaction(tx))
	}
	return app.stageAppHash(app.blockBundles), results
}

// The core defect: the SAME block produces two different app hashes depending on
// an environment variable. That is a consensus rule taking input from outside
// consensus.
func TestModeAloneChangesTheAppHash(t *testing.T) {
	cfg, _, _, _ := gateFixture(t, activeLeaf(gatePayer))
	blockTime := time.Unix(gateNow, 0).UTC()
	// A principal with NO entitlement evidence — accepted under observe,
	// refused under enforce.
	tx := invariantValidBlockJSON(t, "bundle-A", "acc://stranger.acme/data")

	observe := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)
	hObserve, codesObserve := runBlock(observe, 1, tx)

	enforce := newGateTestApp(EntitlementConfig{Mode: EntitlementEnforce, Keys: cfg.Keys}, nil, blockTime)
	hEnforce, codesEnforce := runBlock(enforce, 1, tx)

	if codesObserve[0].Code != 0 {
		t.Fatalf("observe should accept, got code %d: %s", codesObserve[0].Code, codesObserve[0].Log)
	}
	if codesEnforce[0].Code != 4 {
		t.Fatalf("enforce should reject with code 4, got %d: %s", codesEnforce[0].Code, codesEnforce[0].Log)
	}
	if string(hObserve) == string(hEnforce) {
		t.Fatal("app hashes matched — the hazard this test pins would be gone (good, but update the test)")
	}
	t.Logf("observe appHash=%s", short(hObserve))
	t.Logf("enforce appHash=%s  <- an env var moved the consensus hash", short(hEnforce))
}

// The outage itself: commit a block under one mode, then "restart" the node with
// a different mode and replay the same block. The recomputed hash no longer
// matches what was committed, which is precisely what CometBFT panics on.
func TestReplayUnderADifferentModeDivergesFromCommittedHash(t *testing.T) {
	cfg, _, _, _ := gateFixture(t, activeLeaf(gatePayer))
	blockTime := time.Unix(gateNow, 0).UTC()
	tx := invariantValidBlockJSON(t, "bundle-A", "acc://stranger.acme/data")

	// Original commit, under observe.
	original := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)
	committedHash, _ := runBlock(original, 1, tx)

	// Restart: same persisted chain head, mode changed by an operator edit.
	restarted := newGateTestApp(EntitlementConfig{Mode: EntitlementEnforce, Keys: cfg.Keys}, nil, blockTime)
	replayedHash, _ := runBlock(restarted, 1, tx)

	if string(replayedHash) == string(committedHash) {
		t.Fatal("replay matched — mode is no longer consensus-affecting; update this test")
	}
	t.Logf("committed %s != replayed %s — this is the panic", short(committedHash), short(replayedHash))
}

// The control: with the mode held fixed, replay is deterministic. This is the
// property the fix must preserve, and it proves the divergence above is caused
// by the mode and nothing else about the harness.
func TestReplayUnderTheSameModeIsDeterministic(t *testing.T) {
	cfg, _, _, _ := gateFixture(t, activeLeaf(gatePayer))
	blockTime := time.Unix(gateNow, 0).UTC()
	tx := invariantValidBlockJSON(t, "bundle-A", "acc://stranger.acme/data")

	for _, mode := range []EntitlementMode{EntitlementOff, EntitlementObserve, EntitlementEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			a := newGateTestApp(EntitlementConfig{Mode: mode, Keys: cfg.Keys}, nil, blockTime)
			first, _ := runBlock(a, 1, tx)

			b := newGateTestApp(EntitlementConfig{Mode: mode, Keys: cfg.Keys}, nil, blockTime)
			second, _ := runBlock(b, 1, tx)

			if string(first) != string(second) {
				t.Fatalf("same mode replayed to a different hash: %s != %s", short(first), short(second))
			}
		})
	}
}
