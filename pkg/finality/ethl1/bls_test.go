// Copyright 2026 Certen Protocol

package ethl1

import (
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
	if err := committeeOf(b1).decode(); err == nil {
		t.Error("a committee holding an off-subgroup public key decoded")
	}
	var inf1 bls12381.G1Affine
	inf1.SetInfinity()
	ib1 := inf1.Bytes()
	if err := committeeOf(ib1).decode(); err == nil {
		t.Error("a committee holding the identity public key decoded")
	}

	bad2 := offSubgroupG2(t)
	b2 := bad2.Bytes()
	copy(all.Signature[:], b2[:])
	if err := fastAggregateVerify(committeeOf(good), all, msg); err == nil {
		t.Error("an off-subgroup signature verified")
	}
	var inf2 bls12381.G2Affine
	inf2.SetInfinity()
	ib2 := inf2.Bytes()
	copy(all.Signature[:], ib2[:])
	if err := fastAggregateVerify(committeeOf(good), all, msg); err == nil {
		t.Error("the identity signature verified")
	}
}
