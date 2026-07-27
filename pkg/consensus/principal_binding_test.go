package consensus

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/entitlement"
)

// PRINCIPAL BINDING — the question the entitlement verifier cannot answer.
//
// pkg/entitlement/adversarial_test.go establishes that the verifier is sound:
// evidence cannot be forged, replayed, spliced, expired, or self-upgraded. But
// every one of those checks is against a principal SUPPLIED BY THE CALLER.
//
// So the gate proves "valid entitlement evidence exists for the claimed
// principal". It does NOT, on its own, prove "the claimed principal is the
// account that actually submitted this intent". Those differ exactly when the
// claim is false.
//
// THREAT MODEL. Only a validator can construct a ValidatorBlock, so this is not
// reachable by an external caller: an unpaid user submitting a writeData to
// Accumulate has no way to set these fields. It requires a modified validator
// binary inside CERTEN's own fleet — an insider or a compromised node, not an
// open bypass. That distinction matters for severity, not for whether it should
// be closed.

// A block whose declared principal disagrees with its own governance proof must
// be refused. Without this the two fields can be set independently: the
// governance proof describes the real, unentitled submitter while the anchor
// reference names an entitled account, and the gate — checking only the latter
// — is satisfied.
func TestPrincipalMustAgreeWithTheGovernanceProof(t *testing.T) {
	blockTime := time.Unix(gateNow, 0).UTC()

	// The real submitter, who is not entitled.
	const realOwner = "acc://unentitled-stranger.acme/data"
	// A genuinely entitled account, whose evidence is public and buildable by
	// anyone — the epoch endpoint is unauthenticated by design.
	const entitledVictim = gatePayer

	// VALID evidence for the entitled account. Anyone can build this: the epoch
	// endpoint is public and unauthenticated by design.
	cfg, ev, _, _ := gateFixture(t, activeLeaf(entitledVictim))
	if ev == nil {
		t.Fatal("fixture produced no evidence")
	}
	tx := principalMismatchBlockJSON(t, "bundle-substitution", realOwner, entitledVictim, ev)

	app := newGateTestApp(EntitlementConfig{Mode: EntitlementEnforce, Keys: cfg.Keys}, nil, blockTime)

	_, results := runBlock(app, 1, tx)
	if results[0].Code == 0 {
		t.Fatal("a block claiming an entitled principal while its governance proof names " +
			"a different, unentitled account was ACCEPTED — the principal is unbound")
	}
	t.Logf("refused as expected: code=%d log=%s", results[0].Code, results[0].Log)
}

// The honest case must keep working: when the two agree, the block proceeds to
// the entitlement check on its merits.
func TestConsistentPrincipalStillReachesTheGate(t *testing.T) {
	blockTime := time.Unix(gateNow, 0).UTC()
	const owner = gatePayer

	cfg, ev, _, _ := gateFixture(t, activeLeaf(owner))
	tx := principalMismatchBlockJSON(t, "bundle-consistent", owner, owner, ev)
	// Observe, so the outcome reflects block shape rather than entitlement.
	app := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)

	_, results := runBlock(app, 1, tx)
	if results[0].Code != 0 {
		t.Fatalf("a self-consistent block was refused: code=%d log=%s", results[0].Code, results[0].Log)
	}
}

// principalMismatchBlockJSON builds an otherwise invariant-valid block whose
// governance proof names govADI while the anchor reference names anchorADI.
func principalMismatchBlockJSON(t *testing.T, bundleID, govADI, anchorADI string, ev *entitlement.Evidence) []byte {
	t.Helper()
	vb := ValidatorBlock{
		ValidatorID:         "validator-1",
		BundleID:            bundleID,
		OperationCommitment: "op-1",
		Timestamp:           time.Unix(gateNow, 0).UTC().Format(time.RFC3339),
		BlockHeight:         1,
		GovernanceProof: GovernanceProof{
			OrganizationADI: govADI,
			AuthorizationLeaves: []AuthorizationLeaf{{
				KeyPage: govADI + "/book/1", KeyHash: "0xkh",
				Role: "DEFAULT_SIGNER", Signature: "0xleafsig",
			}},
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
			AccountURL:  anchorADI, // the CLAIM the entitlement gate keys on
			TxHash:      "0xtx",
			BlockHeight: 1,
		},
		EntitlementEvidence: ev,
	}

	leaves := make([]interface{}, len(vb.GovernanceProof.AuthorizationLeaves))
	for i, l := range vb.GovernanceProof.AuthorizationLeaves {
		leaves[i] = l
	}
	root, err := commitment.ComputeGovernanceMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	vb.GovernanceProof.MerkleRoot = root
	id, err := commitment.ComputeBundleID(vb.GovernanceProof, vb.CrossChainProof)
	if err != nil {
		t.Fatal(err)
	}
	vb.BundleID = id

	b, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// THE REAL PRODUCTION SHAPE. An honest block carries the bare ADI in its
// governance proof and the DATA ACCOUNT in its anchor reference. Taken verbatim
// from intent b54cbc1f on 2026-07-27:
//
//	organizationAdi: acc://carp-seller-91503.acme
//	accountURL:      acc://carp-seller-91503.acme/data
//
// An invariant demanding string equality would refuse every legitimate block —
// a fleet-wide outage dressed up as a security fix.
func TestProductionShapeIsAccepted(t *testing.T) {
	blockTime := time.Unix(gateNow, 0).UTC()
	const bareADI = "acc://carp-seller-91503.acme"
	const dataAccount = "acc://carp-seller-91503.acme/data"

	cfg, _, _, _ := gateFixture(t, activeLeaf(dataAccount))
	tx := principalMismatchBlockJSON(t, "bundle-prod", bareADI, dataAccount, nil)

	app := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)
	_, results := runBlock(app, 1, tx)
	if results[0].Code != 0 {
		t.Fatalf("the real production block shape was REFUSED: code=%d log=%s",
			results[0].Code, results[0].Log)
	}
}

// A stranger's identity must still be refused, whatever sub-account is named.
func TestDifferentIdentityIsStillRefused(t *testing.T) {
	blockTime := time.Unix(gateNow, 0).UTC()
	cfg, _, _, _ := gateFixture(t, activeLeaf(gatePayer))

	for _, tc := range []struct{ name, gov, anchor string }{
		{"stranger identity, data account", "acc://stranger.acme", "acc://payer.acme/data"},
		{"stranger identity, bare", "acc://stranger.acme", "acc://payer.acme"},
		{"lookalike suffix", "acc://payer.acme.evil.acme", "acc://payer.acme/data"},
		{"lookalike prefix", "acc://evil-payer.acme", "acc://payer.acme/data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := principalMismatchBlockJSON(t, "bundle-"+tc.name, tc.gov, tc.anchor, nil)
			app := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)
			_, results := runBlock(app, 1, tx)
			if results[0].Code == 0 {
				t.Fatalf("%s was accepted; the identity roots differ", tc.name)
			}
		})
	}
}

// Case and trailing slashes must not be a way through, and must not cause a
// false refusal either.
func TestIdentityComparisonNormalises(t *testing.T) {
	blockTime := time.Unix(gateNow, 0).UTC()
	cfg, _, _, _ := gateFixture(t, activeLeaf(gatePayer))

	for _, tc := range []struct{ name, gov, anchor string }{
		{"uppercase governance", "ACC://PAYER.ACME", "acc://payer.acme/data"},
		{"trailing slash", "acc://payer.acme/", "acc://payer.acme/data"},
		{"mixed case anchor", "acc://payer.acme", "acc://Payer.Acme/Data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := principalMismatchBlockJSON(t, "bundle-"+tc.name, tc.gov, tc.anchor, nil)
			app := newGateTestApp(EntitlementConfig{Mode: EntitlementObserve, Keys: cfg.Keys}, nil, blockTime)
			_, results := runBlock(app, 1, tx)
			if results[0].Code != 0 {
				t.Fatalf("%s was refused as a mismatch: %s", tc.name, results[0].Log)
			}
		})
	}
}
