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
	_, err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, nil, [32]byte{})
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
	if _, err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{}); err == nil {
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
	_, err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{})
	if err == nil {
		t.Fatal("a single-signer aggregate claiming full voting power is the CRYPTO-007 forgery " +
			"and must never reach the chain")
	}
	if !strings.Contains(err.Error(), "1-signer") {
		t.Fatalf("the refusal should name the signer count, got: %v", err)
	}
}

// The anchor recomputes signed power from the addresses it is given, so a submission whose
// declared signedVotingPower disagrees with the sum of its signers' powers is rejected on
// chain -- after the batch anchor has been paid for. Catch it locally instead.
func TestSubmitBatchQuorumProof_RefusesSignerPowerMismatch(t *testing.T) {
	s := submitterWithNoChain()
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: "aa",
		SignedVotingPower:     big.NewInt(600),
		TotalVotingPower:      big.NewInt(700),
		Signers: []string{
			"0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d",
			"0x5555afa8ff8048bddaac1554afd790c9bf7ec6e0",
			"0x6acaa68417f5ad5d4a02d9d3d72e291effcdf30a",
			"0x16ab06f3634218a8f1f3b01dcdd32ddfbdc8a69d",
			"0xf150ff923e29f797b4598b89bd7d02002d00db3a",
		},
		// Five signers at 100 each sums to 500, but 600 is declared.
		SignerPowers: []*big.Int{
			big.NewInt(100), big.NewInt(100), big.NewInt(100), big.NewInt(100), big.NewInt(100),
		},
	}
	_, err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{})
	if err == nil {
		t.Fatal("a declared signed power that does not equal the sum of the signers' powers " +
			"must be refused before it can burn anchor gas")
	}
	if !strings.Contains(err.Error(), "does not equal the sum") {
		t.Fatalf("the refusal should name the cause, got: %v", err)
	}
}

// Signers and SignerPowers are consumed index-for-index; a length mismatch would silently
// mis-attribute voting power.
func TestSubmitBatchQuorumProof_RefusesRaggedSignerSet(t *testing.T) {
	s := submitterWithNoChain()
	agg := &consensus.QuorumAggregate{
		AggregateSignatureHex: "aa",
		SignedVotingPower:     big.NewInt(500),
		TotalVotingPower:      big.NewInt(700),
		Signers:               []string{"0xd4a3dbbae0c04d4307c5e00a5e05b66acc289f5d", "0x5555afa8ff8048bddaac1554afd790c9bf7ec6e0"},
		SignerPowers:          []*big.Int{big.NewInt(100)},
	}
	if _, err := s.SubmitBatchQuorumProof(context.Background(), 1, [32]byte{}, [32]byte{}, [32]byte{}, agg, [32]byte{}); err == nil {
		t.Fatal("a ragged signer set must be refused")
	}
}
