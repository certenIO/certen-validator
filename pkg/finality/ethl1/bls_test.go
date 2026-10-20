// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// offSubgroupG1 returns a point on E(Fp) that is not in the prime-order subgroup.
func offSubgroupG1(t *testing.T) bls12381.G1Affine {
	t.Helper()
	for x := uint64(2); x < 200; x++ {
		var X, rhs, Y, four fp.Element
		X.SetUint64(x)
		rhs.Square(&X)
		rhs.Mul(&rhs, &X)
		four.SetUint64(4)
		rhs.Add(&rhs, &four)
		if Y.Sqrt(&rhs) == nil {
			continue
		}
		p := bls12381.G1Affine{X: X, Y: Y}
		if p.IsOnCurve() && !p.IsInSubGroup() {
			return p
		}
	}
	t.Fatal("no off-subgroup G1 point found")
	return bls12381.G1Affine{}
}

// offSubgroupG2 returns a point on the twist E'(Fp2) that is not in the prime-order subgroup.
func offSubgroupG2(t *testing.T) bls12381.G2Affine {
	t.Helper()
	for x := uint64(1); x < 200; x++ {
		var X, rhs, Y, b bls12381.E2
		X.A0.SetUint64(x)
		rhs.Square(&X)
		rhs.Mul(&rhs, &X)
		b.A0.SetUint64(4)
		b.A1.SetUint64(4)
		rhs.Add(&rhs, &b)
		if Y.Sqrt(&rhs) == nil {
			continue
		}
		p := bls12381.G2Affine{X: X, Y: Y}
		if p.IsOnCurve() && !p.IsInSubGroup() {
			return p
		}
	}
	t.Fatal("no off-subgroup G2 point found")
	return bls12381.G2Affine{}
}

func committeeOf(pk [48]byte) *committee {
	raw := make([]byte, SyncCommitteeBytes)
	for i := 0; i < SyncCommitteeSize; i++ {
		copy(raw[i*48:], pk[:])
	}
	copy(raw[SyncCommitteeSize*48:], pk[:])
	return newCommittee(raw)
}

// signAll returns sk * H(msg) as a compressed signature, the aggregate signature of seats whose keys are all sk*G1.
func signAll(t *testing.T, sk int64, msg [32]byte, seats int) [96]byte {
	t.Helper()
	h, err := bls12381.HashToG2(msg[:], []byte(blsDST))
	if err != nil {
		t.Fatal(err)
	}
	var s bls12381.G2Affine
	s.ScalarMultiplication(&h, big.NewInt(sk*int64(seats)))
	return s.Bytes()
}

// TestOffSubgroupAndIdentityPointsAreRefused: a public key or signature that is on the curve but outside the prime-order
// subgroup, and the identity in either group, never verify (spec 5.2 step 3: subgroup-checked and non-identity).
func TestOffSubgroupAndIdentityPointsAreRefused(t *testing.T) {
	_, _, g1, _ := bls12381.Generators()
	good := g1.Bytes()
	var msg [32]byte
	var all syncAggregate
	for i := range all.Bits {
		all.Bits[i] = 0xff
	}

	bad1 := offSubgroupG1(t)
	b1 := bad1.Bytes()
	var chk1 bls12381.G1Affine
	if _, err := chk1.SetBytes(b1[:]); err == nil {
		t.Fatal("gnark SetBytes accepted a G1 point outside the subgroup")
	}
	if _, err := committeeOf(b1).key(0); err == nil {
		t.Error("a committee holding an off-subgroup public key decoded the participating seat")
	}
	var inf1 bls12381.G1Affine
	inf1.SetInfinity()
	ib1 := inf1.Bytes()
	if _, err := committeeOf(ib1).key(0); err == nil {
		t.Error("a committee holding the identity public key decoded the participating seat")
	}

	// V-C1A gap A: the refusal of an off-subgroup SIGNATURE must come from the subgroup check and from nothing else. The same
	// bytes decode without the subgroup check (they are a valid point of the curve), G2Affine.SetBytes refuses them, and
	// fastAggregateVerify returns exactly that error.
	bad2 := offSubgroupG2(t)
	b2 := bad2.Bytes()
	var viaSetBytes bls12381.G2Affine
	_, setErr := viaSetBytes.SetBytes(b2[:])
	if setErr == nil {
		t.Fatal("G2Affine.SetBytes accepted a point outside the subgroup")
	}
	var unchecked bls12381.G2Affine
	if err := bls12381.NewDecoder(bytes.NewReader(b2[:]), bls12381.NoSubgroupChecks()).Decode(&unchecked); err != nil {
		t.Fatalf("the off-subgroup signature does not even decode without the subgroup check (%v): the test would not isolate the check", err)
	}
	if !unchecked.IsOnCurve() || unchecked.IsInSubGroup() || unchecked.IsInfinity() {
		t.Fatal("the test point must be on the curve, outside the subgroup, and not the identity")
	}
	copy(all.Signature[:], b2[:])
	if err := fastAggregateVerify(committeeOf(good), all, msg); err == nil || err.Error() != setErr.Error() {
		t.Errorf("an off-subgroup signature: got %v, want exactly the subgroup-check error %v", err, setErr)
	}
	var inf2 bls12381.G2Affine
	inf2.SetInfinity()
	ib2 := inf2.Bytes()
	copy(all.Signature[:], ib2[:])
	if err := fastAggregateVerify(committeeOf(good), all, msg); err == nil {
		t.Error("the identity signature verified")
	}
}

// TestOnlyParticipatingKeysAreDecoded: FastAggregateVerify(participant_pubkeys, ...) of the consensus specification looks only at
// the keys whose bit is set. A committee whose non-participating seat holds bytes that are not a valid key still verifies
// (the committee is authenticated by hash_tree_root against the pin, not by decoding every key); the same bytes at a
// participating seat refuse the update.
func TestOnlyParticipatingKeysAreDecoded(t *testing.T) {
	_, _, g1, _ := bls12381.Generators()
	pk := g1.Bytes() // secret key 1
	raw := make([]byte, SyncCommitteeBytes)
	for i := 0; i < SyncCommitteeSize; i++ {
		copy(raw[i*48:], pk[:])
	}
	copy(raw[SyncCommitteeSize*48:], pk[:])
	for i := 0; i < 48; i++ {
		raw[5*48+i] = 0xff // seat 5: not a valid compressed key
	}
	c := newCommittee(raw)
	var msg [32]byte
	msg[0] = 7
	var agg syncAggregate
	agg.Bits[0] = 0b00001111 // seats 0-3
	agg.Signature = signAll(t, 1, msg, 4)
	if err := fastAggregateVerify(c, agg, msg); err != nil {
		t.Fatalf("a non-participating invalid key refused the committee: %v", err)
	}
	agg.Bits[0] = 0b00101111 // seats 0-3 and the invalid seat 5
	agg.Signature = signAll(t, 1, msg, 5)
	if err := fastAggregateVerify(c, agg, msg); err == nil {
		t.Fatal("an invalid participating key verified")
	}
}
