package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/strategy"
)

// attestWithRealQuorum gives a test cycle what Phase 8 gives a real one (RB5-F14): `signers` of seven real BLS
// validators sign the cycle's attestation message, the fold is theirs, the registry snapshot is the one Phase 8 builds,
// and the orchestrator's strategy registry holds the scheme that signed it. A Phase 9 fixture used to state
// ThresholdMet with nothing behind it - the very shape of the write-back defect this replaces.
func attestWithRealQuorum(t *testing.T, o *UnifiedOrchestrator, c *activeCycle, signers int) {
	t.Helper()
	msg := &attestation.AttestationMessage{IntentID: c.Request.IntentID, TargetChain: c.Request.TargetChain, ResultHash: [32]byte{1}}
	if len(c.Result.ObservationResults) > 0 && c.Result.ObservationResults[0] != nil {
		msg.ResultHash = c.Result.ObservationResults[0].ResultHash
		msg.BlockNumber = c.Result.ObservationResults[0].BlockNumber
	}
	registry := map[string]consensus.ValidatorRegistryEntry{}
	var atts []*attestation.Attestation
	var lead *attestation.BLSStrategy
	for i := 0; i < 7; i++ {
		s, err := attestation.NewBLSStrategyWithNewKey(fmt.Sprintf("validator-%d", i+1), uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: hex.EncodeToString(s.PublicKey()), VotingPower: big.NewInt(100)}
		if i < signers {
			a, err := s.Sign(context.Background(), msg)
			if err != nil {
				t.Fatal(err)
			}
			atts = append(atts, a)
			if lead == nil {
				lead = s
			}
		}
	}
	threshold := attestation.DefaultThresholdConfig()
	// The fold Phase 8 makes: registered keys at registered power.
	folded, _, err := foldResultAttestations(context.Background(), lead, msg, atts, registry, threshold)
	if err != nil {
		t.Fatal(err)
	}
	// Verified as Phase 8 verifies it: the aggregate under the counted signers' keys.
	ok, err := lead.VerifyAggregated(context.Background(), folded)
	if err != nil || !ok {
		t.Fatalf("the fixture's aggregate does not verify: %v", err)
	}
	folded.Verified = true
	set, err := registryAttestationSet(registry, threshold.CalculateThresholdWeight, msg.BlockNumber)
	if err != nil {
		t.Fatal(err)
	}
	c.Result.AggregatedAttestation = folded
	c.Result.ThresholdMet = folded.ThresholdMet
	c.QuorumSet = set
	if o.config.Registry == nil {
		o.config.Registry = strategy.NewRegistry()
	}
	if _, err := o.config.Registry.GetAttestationStrategy(attestation.AttestationSchemeBLS12381); err != nil {
		if err := o.config.Registry.RegisterAttestationStrategy(lead); err != nil {
			t.Fatal(err)
		}
	}
}
