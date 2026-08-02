package execution

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

// =============================================================================
// Registry identity resolution
// =============================================================================

func regEntry(addr, pub string, power int64) consensus.ValidatorRegistryEntry {
	return consensus.ValidatorRegistryEntry{
		EVMAddress:   addr,
		PublicKeyHex: pub,
		VotingPower:  big.NewInt(power),
	}
}

// The whole point of key-matched identity: no configuration, exactly one answer.
func TestMatchRegistryByPubkey_FindsTheEntryForThisKey(t *testing.T) {
	reg := map[string]consensus.ValidatorRegistryEntry{
		"0xaaa": regEntry("0xaaa", "aabb", 100),
		"0xbbb": regEntry("0xbbb", "ccdd", 100),
	}
	got, err := matchRegistryByPubkey(reg, "0xCCDD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "0xbbb" {
		t.Fatalf("matched %q, want 0xbbb — the 0x prefix and case must not affect matching", got)
	}
}

// A node whose key is not registered must REFUSE to claim an identity. Publishing one anyway
// would make it answer attestation requests with a signature the aggregator discards as
// unregistered, so the quorum would run short with nothing pointing at the cause.
func TestMatchRegistryByPubkey_UnregisteredKeyIsRefused(t *testing.T) {
	reg := map[string]consensus.ValidatorRegistryEntry{
		"0xaaa": regEntry("0xaaa", "aabb", 100),
	}
	if _, err := matchRegistryByPubkey(reg, "deadbeef"); err == nil {
		t.Fatal("an unregistered BLS key must not resolve to any address")
	} else if !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("error should name the cause, got: %v", err)
	}
}

// Two addresses sharing one key makes voting power ambiguous — the same signature could be
// counted under either. Refuse rather than pick.
func TestMatchRegistryByPubkey_AmbiguousKeyIsRefused(t *testing.T) {
	reg := map[string]consensus.ValidatorRegistryEntry{
		"0xaaa": regEntry("0xaaa", "aabb", 100),
		"0xbbb": regEntry("0xbbb", "aabb", 100),
	}
	if _, err := matchRegistryByPubkey(reg, "aabb"); err == nil {
		t.Fatal("a key registered under two addresses must be refused, not resolved arbitrarily")
	}
}

// =============================================================================
// Submission guards — the CRYPTO-007 tripwires
// =============================================================================

// SubmitBatchQuorumProof must refuse before it can spend gas, so these run against a submitter
// with no chain resolver at all: if a guard failed to fire, the test would panic rather than
// pass quietly.
func submitterWithNoChain() *BatchProofSubmitterImpl {
	return NewBatchProofSubmitter(nil, nil)
}

func TestSubmitBatchQuorumProof_RefusesNilAggregate(t *testing.T) {
	s := submitterWithNoChain()
	err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, nil, [32]byte{})
	if err == nil {
		t.Fatal("a nil aggregate means no quorum attested this root; submitting it must be refused")
	}
}

func TestSubmitBatchQuorumProof_RefusesZeroSignedPower(t *testing.T) {
	s := submitterWithNoChain()
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: "aa",
		SignedVotingPower:     big.NewInt(0),
		TotalVotingPower:      big.NewInt(700),
		Signers:               []string{"0xa", "0xb", "0xc", "0xd", "0xe"},
	}
	if err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{}); err == nil {
		t.Fatal("zero signed voting power must be refused")
	}
}

// THE forgery guard at the submission boundary. AggregateBatchAttestations already refuses a
// single-signer fold, but this is the last gate before gas is spent and a valid-looking ZK
// proof asserting full quorum from one key would be minted. The anchor's 29 authorized pubkey
// commitments cover subsets of size 5, 6 and 7 only.
func TestSubmitBatchQuorumProof_RefusesSingleSignerAggregate(t *testing.T) {
	s := submitterWithNoChain()
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: "aa",
		SignedVotingPower:     big.NewInt(700), // claims full quorum...
		TotalVotingPower:      big.NewInt(700),
		Signers:               []string{"0xaaa"}, // ...from one key
	}
	err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{})
	if err == nil {
		t.Fatal("a single-signer aggregate claiming full voting power is the CRYPTO-007 forgery " +
			"and must never reach the chain")
	}
	if !strings.Contains(err.Error(), "1-signer") {
		t.Fatalf("the refusal should name the signer count, got: %v", err)
	}
}

// buildValidatorSetForBatch must no longer return a signed power at all. It used to return the
// total, which is what made every batch declare 7-of-7 regardless of who signed.
func TestBuildValidatorSetForBatch_ReturnsNoSignedPower(t *testing.T) {
	t.Setenv("V6_1_VALIDATOR_SET_ADDRS",
		"0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d,0x5555afa8ff8048bddaac1554afd790c9bf7ec6e0")
	addrs, powers, total, err := buildValidatorSetForBatch()
	if err != nil {
		t.Skipf("validator set not resolvable in this environment: %v", err)
	}
	if len(addrs) != len(powers) {
		t.Fatalf("roster/power length mismatch: %d vs %d", len(addrs), len(powers))
	}
	if total == nil || total.Sign() <= 0 {
		t.Fatal("total voting power must be positive")
	}
	// The signature has exactly four results. A fifth returning signed power would mean the
	// forgery shape had been reintroduced; this test fails to compile in that case, which is
	// the intent.
}
