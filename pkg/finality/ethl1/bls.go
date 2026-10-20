// Copyright 2026 Certen Protocol

package ethl1

import (
	"crypto/sha256"
	"errors"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Ethereum's BLS suite: public keys in G1 (48-byte compressed), signatures in G2 (96-byte compressed), proof-of-possession
// ciphersuite. This is the inverse orientation of pkg/crypto/bls, which therefore must not be used here.
const blsDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

// domainSyncCommittee is DOMAIN_SYNC_COMMITTEE = 0x07000000.
var domainSyncCommittee = [4]byte{0x07, 0, 0, 0}

// committee is a sync committee with its root and lazily decompressed keys.
type committee struct {
	raw  []byte // 24,624 bytes
	root [32]byte
	keys []bls12381.G1Affine
	err  error
	done bool
}

func newCommittee(raw []byte) *committee {
	return &committee{raw: raw, root: hashTreeRootSyncCommittee(raw)}
}

// decode decompresses the 512 keys once. G1Affine.SetBytes performs the on-curve and subgroup checks; the identity is
// refused here. A key the committee holds twice is decoded twice and summed once per set bit.
func (c *committee) decode() error {
	if c.done {
		return c.err
	}
	c.done = true
	c.keys = make([]bls12381.G1Affine, SyncCommitteeSize)
	for i := 0; i < SyncCommitteeSize; i++ {
		if _, err := c.keys[i].SetBytes(c.raw[i*48 : i*48+48]); err != nil {
			c.err = err
			return err
		}
		if c.keys[i].IsInfinity() {
			c.err = errors.New("identity public key")
			return c.err
		}
	}
	return nil
}

// computeDomain is compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root).
func computeDomain(version [4]byte, gvr [32]byte) [32]byte {
	var fv [32]byte
	copy(fv[:4], version[:])
	forkDataRoot := sha2(fv[:], gvr[:]) // hash_tree_root(ForkData{current_version, genesis_validators_root})
	var d [32]byte
	copy(d[:4], domainSyncCommittee[:])
	copy(d[4:], forkDataRoot[:28])
	return d
}

// signingRoot is compute_signing_root(object_root, domain) = hash_tree_root(SigningData{object_root, domain}).
func signingRoot(objectRoot, domain [32]byte) [32]byte {
	return sha256.Sum256(append(append(make([]byte, 0, 64), objectRoot[:]...), domain[:]...))
}

// fastAggregateVerify is bls.FastAggregateVerify over the committee keys whose bit is set: the keys are summed once per
// set bit, the aggregate must not be the identity, the signature must be a subgroup-checked non-identity G2 point.
func fastAggregateVerify(c *committee, agg syncAggregate, msg [32]byte) error {
	var sig bls12381.G2Affine
	if _, err := sig.SetBytes(agg.Signature[:]); err != nil {
		return err
	}
	if sig.IsInfinity() {
		return errors.New("identity signature")
	}
	if err := c.decode(); err != nil {
		return err
	}
	var sum bls12381.G1Jac
	n := 0
	for i := 0; i < SyncCommitteeSize; i++ {
		if !agg.bit(i) {
			continue
		}
		var j bls12381.G1Jac
		j.FromAffine(&c.keys[i])
		sum.AddAssign(&j)
		n++
	}
	if n == 0 {
		return errors.New("no participants")
	}
	var pk bls12381.G1Affine
	pk.FromJacobian(&sum)
	if pk.IsInfinity() {
		return errors.New("identity aggregate public key")
	}
	h, err := bls12381.HashToG2(msg[:], []byte(blsDST))
	if err != nil {
		return err
	}
	_, _, g1, _ := bls12381.Generators()
	var negG1 bls12381.G1Affine
	negG1.Neg(&g1)
	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{pk, negG1}, []bls12381.G2Affine{h, sig})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aggregate signature does not verify")
	}
	return nil
}
