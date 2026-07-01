package execution

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// RB-3: quorum-confirmed header attestation tests.
//
// These assert that the attestation collector only finalizes a result when a BFT
// supermajority (>= 2/3 voting power) independently signed the IDENTICAL ResultHash
// (which binds block_hash + receipts_root + status), and that a divergent-RPC minority
// can never join the quorum — with the aggregate BLS signature independently verified.

func rb3MakeValidatorSet(n int) (*ValidatorSet, []*bls.PrivateKey) {
	vs := &ValidatorSet{TotalVotingPower: big.NewInt(int64(n)), ValidatorCount: n}
	keys := make([]*bls.PrivateKey, n)
	for i := 0; i < n; i++ {
		sk, pk, err := bls.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		keys[i] = sk
		vs.Validators = append(vs.Validators, ValidatorInfo{
			ID:           fmt.Sprintf("val-%d", i),
			Address:      common.BigToAddress(big.NewInt(int64(i + 1))),
			Index:        uint32(i),
			VotingPower:  big.NewInt(1),
			BLSPublicKey: pk.Bytes(),
			Active:       true,
		})
	}
	return vs, keys
}

func rb3MakeAttestation(vs *ValidatorSet, keys []*bls.PrivateKey, i int, resultHash, bundleID [32]byte, block *big.Int) *ResultAttestation {
	msg := ComputeAttestationMessageHash(resultHash, bundleID, block)
	sig := keys[i].SignWithDomain(msg[:], bls.DomainResult)
	return &ResultAttestation{
		ResultHash:       resultHash,
		BundleID:         bundleID,
		ValidatorID:      vs.Validators[i].ID,
		ValidatorAddress: vs.Validators[i].Address,
		ValidatorIndex:   vs.Validators[i].Index,
		BLSSignature:     sig.Bytes(),
		MessageHash:      msg,
		BlockNumber:      block,
	}
}

func rb3PubKeys(vs *ValidatorSet, idxs ...int) [][]byte {
	out := make([][]byte, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, vs.Validators[i].BLSPublicKey)
	}
	return out
}

// TestRB3_QuorumFinalizesOnAgreement: >=2/3 validators signing the same ResultHash
// finalizes, and the aggregate BLS signature verifies against the agreed messageHash.
func TestRB3_QuorumFinalizesOnAgreement(t *testing.T) {
	vs, keys := rb3MakeValidatorSet(4)
	collector := NewAttestationCollector(vs, 2, 3)

	rh := [32]byte{0xAA}
	bundle := [32]byte{0x01}
	block := big.NewInt(100)

	// 2 of 4 = threshold met (CheckThreshold) but NOT supermajority (2*3<8) ⇒ no finalize.
	for _, i := range []int{0, 1} {
		if err := collector.AddAttestation(rb3MakeAttestation(vs, keys, i, rh, bundle, block)); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if agg := collector.aggregated[rh]; agg == nil || agg.Finalized {
		t.Fatalf("must NOT finalize at 2/4 (below 2/3 supermajority)")
	}

	// 3 of 4 ⇒ supermajority ⇒ finalize.
	if err := collector.AddAttestation(rb3MakeAttestation(vs, keys, 2, rh, bundle, block)); err != nil {
		t.Fatalf("add 2: %v", err)
	}
	agg := collector.aggregated[rh]
	if agg == nil || !agg.Finalized {
		t.Fatalf("must finalize at 3/4 (>=2/3 supermajority)")
	}
	if !agg.MeetsSupermajority() {
		t.Error("MeetsSupermajority should be true at 3/4")
	}
	// The embedded aggregate MUST carry the validator root + bitfield for re-verification.
	if len(agg.ValidatorBitfield) == 0 {
		t.Error("aggregate missing validator bitfield")
	}
	// Independently verify the aggregate BLS signature over the agreed messageHash.
	ok, err := VerifyAggregatedBLSSignature(agg.AggregateSignature, agg.MessageHash, rb3PubKeys(vs, 0, 1, 2))
	if err != nil || !ok {
		t.Errorf("aggregate BLS signature must verify: ok=%v err=%v", ok, err)
	}
}

// TestRB3_DivergentRPCCannotJoinQuorum: a validator observing a different result
// (different ResultHash — e.g. a forked RPC) lands in a separate bucket and cannot
// help the honest result reach quorum; with a 2/2 split neither finalizes.
func TestRB3_DivergentRPCCannotJoinQuorum(t *testing.T) {
	vs, keys := rb3MakeValidatorSet(4)
	collector := NewAttestationCollector(vs, 2, 3)

	rhHonest := [32]byte{0xAA}
	rhForked := [32]byte{0xBB} // different block_hash/receipts_root ⇒ different ResultHash
	bundle := [32]byte{0x01}
	block := big.NewInt(100)

	collector.AddAttestation(rb3MakeAttestation(vs, keys, 0, rhHonest, bundle, block))
	collector.AddAttestation(rb3MakeAttestation(vs, keys, 1, rhHonest, bundle, block))
	collector.AddAttestation(rb3MakeAttestation(vs, keys, 2, rhForked, bundle, block))
	collector.AddAttestation(rb3MakeAttestation(vs, keys, 3, rhForked, bundle, block))

	if agg := collector.aggregated[rhHonest]; agg != nil && agg.Finalized {
		t.Error("honest bucket must not finalize with only 2/4 (forked validators cannot join)")
	}
	if agg := collector.aggregated[rhForked]; agg != nil && agg.Finalized {
		t.Error("forked bucket must not finalize with only 2/4")
	}
	// Divergence must be observable.
	if got := collector.DivergentResultHashes(bundle); len(got) != 2 {
		t.Errorf("expected 2 divergent result hashes, got %d", len(got))
	}
}

// TestRB3_HonestSupermajorityWinsDespiteFork: 3 honest + 1 forked ⇒ honest result
// finalizes; the forked RPC cannot prevent quorum, and its bucket never finalizes.
func TestRB3_HonestSupermajorityWinsDespiteFork(t *testing.T) {
	vs, keys := rb3MakeValidatorSet(4)
	collector := NewAttestationCollector(vs, 2, 3)

	rhHonest := [32]byte{0xAA}
	rhForked := [32]byte{0xBB}
	bundle := [32]byte{0x01}
	block := big.NewInt(100)

	for _, i := range []int{0, 1, 2} {
		collector.AddAttestation(rb3MakeAttestation(vs, keys, i, rhHonest, bundle, block))
	}
	collector.AddAttestation(rb3MakeAttestation(vs, keys, 3, rhForked, bundle, block))

	if agg := collector.aggregated[rhHonest]; agg == nil || !agg.Finalized {
		t.Fatal("honest 3/4 supermajority must finalize despite a forked validator")
	}
	if agg := collector.aggregated[rhForked]; agg != nil && agg.Finalized {
		t.Error("forked bucket (1/4) must never finalize")
	}
}

// TestRB3_ConflictingAttestationRejected: a validator cannot attest two different
// results for the same bundle within a bucket (double-sign guard).
func TestRB3_MessageHashMismatchRejected(t *testing.T) {
	vs, keys := rb3MakeValidatorSet(4)
	collector := NewAttestationCollector(vs, 2, 3)

	rh := [32]byte{0xAA}
	bundle := [32]byte{0x01}
	att := rb3MakeAttestation(vs, keys, 0, rh, bundle, big.NewInt(100))
	// Corrupt the message hash so it no longer matches compute(resultHash,bundle,block).
	att.MessageHash = [32]byte{0xDE, 0xAD}
	if err := collector.AddAttestation(att); err == nil {
		t.Error("collector must reject an attestation whose MessageHash doesn't bind its ResultHash")
	}
}
