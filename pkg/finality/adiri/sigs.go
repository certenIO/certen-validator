// Copyright 2026 Certen Protocol

package adiri

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// Signature verification (V2_SPEC_S7 5.8 O3). Adiri's BLS is min-sig (signatures in G1, keys in G2, DST
// BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_): pkg/crypto/bls is that orientation and is used UNMODIFIED (annex M14:
// 643/643 live certificates). It is NOT the beacon BLS of the Sepolia kind (min-pk), which is a different package.
//
// Two modes return identical verdicts on every input (the vectors prove it):
//   - ModeOneByOne verifies each record with pkg/crypto/bls.VerifyAggregateSignature;
//   - ModeBatched checks one random linear combination, e(sum r_i sigma_i, g2) = prod_A e(sum_{i: A_i = A} r_i H(m_i), A),
//     and on failure re-verifies one by one only to name the failing epoch, never to accept.
//
// In both, each signature is decoded with the G1 on-curve, non-identity and subgroup checks BEFORE it is verified or enters the
// combination; a failing decode is reported with its reason.

// Mode selects the signature verification strategy.
type Mode int

const (
	ModeOneByOne Mode = iota
	ModeBatched
)

// The reasons of committee_chain_broken{check:"signature_invalid"}.
const (
	ReasonEncoding = "encoding"
	ReasonIdentity = "identity"
	ReasonSubgroup = "subgroup"
	ReasonPairing  = "pairing"
)

// decodeSignature decodes a compressed G1 signature with the encoding, non-identity and subgroup checks, each reported by its
// own reason. The decoder is built WITHOUT its own subgroup check so that ours is the one that decides.
func decodeSignature(b []byte) (bls12381.G1Affine, string) {
	var p bls12381.G1Affine
	d := bls12381.NewDecoder(bytes.NewReader(b), bls12381.NoSubgroupChecks())
	if err := d.Decode(&p); err != nil || len(b) != SigBytes {
		return p, ReasonEncoding
	}
	if !p.IsOnCurve() {
		return p, ReasonEncoding
	}
	if p.IsInfinity() {
		return p, ReasonIdentity
	}
	if !p.IsInSubGroup() {
		return p, ReasonSubgroup
	}
	return p, ""
}

// keyEntry is a validated committee key.
type keyEntry struct {
	g2  bls12381.G2Affine
	pub *bls.PublicKey
}

// keyCache decodes and subgroup-checks each distinct key once.
type keyCache struct{ m map[string]*keyEntry }

func newKeyCache() *keyCache { return &keyCache{m: map[string]*keyEntry{}} }

// get returns the validated key, or nil when it is not a valid, non-identity G2 subgroup point.
func (c *keyCache) get(k []byte) *keyEntry {
	if e, ok := c.m[string(k)]; ok {
		return e
	}
	var e *keyEntry
	if bls.ValidateBLSPublicKeySubgroup(k) == nil {
		var p bls12381.G2Affine
		if _, err := p.SetBytes(k); err == nil {
			if pub, err := bls.PublicKeyFromBytes(k); err == nil {
				e = &keyEntry{g2: p, pub: pub}
			}
		}
	}
	c.m[string(k)] = e
	return e
}

// sigItem is one record's signature statement.
type sigItem struct {
	epoch  int
	sig    []byte
	signer []*keyEntry
	msg    []byte
}

// verifyOne judges one item with pkg/crypto/bls: "" = valid, else the reason.
func verifyOne(it sigItem) string {
	if _, reason := decodeSignature(it.sig); reason != "" {
		return reason
	}
	if bls.ValidateBLSSignatureSubgroup(it.sig) != nil {
		return ReasonPairing
	}
	sig, err := bls.SignatureFromBytes(it.sig)
	if err != nil {
		return ReasonPairing
	}
	pks := make([]*bls.PublicKey, len(it.signer))
	for i, k := range it.signer {
		pks[i] = k.pub
	}
	if !bls.VerifyAggregateSignature(sig, pks, it.msg) {
		return ReasonPairing
	}
	return ""
}

// firstOneByOne verifies every item in ascending epoch order and returns the first failing (index in items, reason), or -1.
func firstOneByOne(items []sigItem) (int, string) {
	for i, it := range items {
		if r := verifyOne(it); r != "" {
			return i, r
		}
	}
	return -1, ""
}

// batchRand returns a 128-bit scalar >= 1.
func batchScalar(rnd io.Reader) (*big.Int, error) {
	var b [16]byte
	for {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return nil, err
		}
		s := new(big.Int).SetBytes(b[:])
		if s.Sign() > 0 {
			return s, nil
		}
	}
}

// batchedAccepts reports whether the random linear combination holds. Every item's signature must already have decoded.
func batchedAccepts(items []sigItem, rnd io.Reader) (bool, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	type group struct {
		a    bls12381.G2Affine
		hsum bls12381.G1Jac
	}
	groups := map[string]*group{}
	var order []string
	var lhs bls12381.G1Jac
	for _, it := range items {
		sig, reason := decodeSignature(it.sig)
		if reason != "" {
			return false, nil
		}
		r, err := batchScalar(rnd)
		if err != nil {
			return false, err
		}
		var rs bls12381.G1Jac
		rs.FromAffine(&sig)
		rs.ScalarMultiplication(&rs, r)
		lhs.AddAssign(&rs)

		var aj bls12381.G2Jac
		for i, k := range it.signer {
			var kj bls12381.G2Jac
			kj.FromAffine(&k.g2)
			if i == 0 {
				aj = kj
			} else {
				aj.AddAssign(&kj)
			}
		}
		var a bls12381.G2Affine
		a.FromJacobian(&aj)
		h, err := bls12381.HashToG1(it.msg, []byte(bls.SignatureDST))
		if err != nil {
			return false, err
		}
		var hj bls12381.G1Jac
		hj.FromAffine(&h)
		hj.ScalarMultiplication(&hj, r)
		key := string(a.Marshal())
		g, ok := groups[key]
		if !ok {
			g = &group{a: a}
			groups[key] = g
			order = append(order, key)
		}
		g.hsum.AddAssign(&hj)
	}
	var l bls12381.G1Affine
	l.FromJacobian(&lhs)
	_, _, _, g2 := bls12381.Generators()
	var negG2 bls12381.G2Affine
	negG2.Neg(&g2)
	ps := []bls12381.G1Affine{l}
	qs := []bls12381.G2Affine{negG2}
	for _, key := range order {
		g := groups[key]
		var p bls12381.G1Affine
		p.FromJacobian(&g.hsum)
		ps = append(ps, p)
		qs = append(qs, g.a)
	}
	ok, err := bls12381.PairingCheck(ps, qs)
	return ok && err == nil, err
}

// firstFailure returns the lowest failing item and its reason under the mode, or -1. In batched mode the combination decides
// acceptance, and a failure is only localised one by one (never accepted by the localisation).
func firstFailure(items []sigItem, mode Mode, rnd io.Reader) (int, string, error) {
	if len(items) == 0 {
		return -1, "", nil
	}
	if mode == ModeBatched {
		// every signature is decoded and checked before it enters the combination
		decodeFailed := false
		for _, it := range items {
			if _, reason := decodeSignature(it.sig); reason != "" {
				decodeFailed = true
				break
			}
		}
		if !decodeFailed {
			ok, err := batchedAccepts(items, rnd)
			if err != nil {
				return -1, "", err
			}
			if ok {
				return -1, "", nil
			}
		}
	}
	i, reason := firstOneByOne(items)
	if i < 0 && mode == ModeBatched {
		// the combination rejected what each signature accepts: a negligible-probability event, never an acceptance
		return 0, ReasonPairing, nil
	}
	return i, reason, nil
}
