// Copyright 2026 Certen Protocol

package adiri_test

import (
	"errors"
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, signatures: every way a record's signature can be refused is named identically in both modes, the batch scalar is
// never zero, and a failing random source is a named verifier failure. The chain is the small synthetic rotation vector.

// gateNonSubgroupSignature is a compressed G1 point that is on the curve and not in the prime-order subgroup.
func gateNonSubgroupSignature(t *testing.T) [adiri.SigBytes]byte {
	t.Helper()
	var four fp.Element
	four.SetUint64(4)
	for x := uint64(1); x < 2000; x++ {
		var X, y2, y fp.Element
		X.SetUint64(x)
		y2.Square(&X)
		y2.Mul(&y2, &X)
		y2.Add(&y2, &four)
		if y.Sqrt(&y2) == nil {
			continue
		}
		p := bls12381.G1Affine{X: X, Y: y}
		if p.IsOnCurve() && !p.IsInSubGroup() {
			return p.Bytes()
		}
	}
	t.Fatal("no on-curve point outside the subgroup found")
	return [adiri.SigBytes]byte{}
}

func gateVerify(t *testing.T, mode adiri.Mode, cf *adiri.CFA1, rnd interface{ Read([]byte) (int, error) }) error {
	t.Helper()
	_, _, _, _, pins := liveParts(t, "syn-rotation")
	par, err := adiri.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	if rnd == nil {
		_, err = adiri.VerifyCommitteeChain(par, cf, mode, nil)
		return err
	}
	_, err = adiri.VerifyCommitteeChain(par, cf, mode, rnd)
	return err
}

func gateCopy(cf *adiri.CFA1) *adiri.CFA1 {
	c := *cf
	c.Records = append([]adiri.Record(nil), cf.Records...)
	return &c
}

func TestEverySignatureRefusalIsNamedIdenticallyInBothModes(t *testing.T) {
	_, _, cf, _, _ := liveParts(t, "syn-rotation")
	if len(cf.Records) < 3 {
		t.Fatalf("%d records", len(cf.Records))
	}
	last := len(cf.Records) - 1
	for _, mode := range []adiri.Mode{adiri.ModeOneByOne, adiri.ModeBatched} {
		if err := gateVerify(t, mode, gateCopy(cf), nil); err != nil {
			t.Fatalf("mode %d refuses the untouched chain: %v", mode, err)
		}
		for _, c := range []struct {
			name   string
			sig    [adiri.SigBytes]byte
			reason adiri.SignatureReason
		}{
			{"identity", [adiri.SigBytes]byte{0xc0}, adiri.ReasonIdentity},
			{"not an encoding", [adiri.SigBytes]byte{}, adiri.ReasonEncoding},
			{"outside the subgroup", gateNonSubgroupSignature(t), adiri.ReasonSubgroup},
		} {
			for _, k := range []int{0, 1, last} {
				cf2 := gateCopy(cf)
				cf2.Records[k].Signature = c.sig
				err := gateVerify(t, mode, cf2, nil)
				st, ok := finality.AsNamed(err)
				if !ok || st.Code != adiri.CodeCommitteeBroken || st.Fields["check"] != adiri.CheckSignatureInvalid ||
					st.Fields["epoch"] != uint64(k) || st.Fields["reason"] != c.reason {
					t.Errorf("mode %d %s at record %d: %v", mode, c.name, k, err)
				}
			}
		}
		// two valid signatures exchanged: pairing failure at the lowest exchanged epoch
		cf2 := gateCopy(cf)
		cf2.Records[1].Signature, cf2.Records[2].Signature = cf.Records[2].Signature, cf.Records[1].Signature
		err := gateVerify(t, mode, cf2, nil)
		st, ok := finality.AsNamed(err)
		if !ok || st.Fields["epoch"] != uint64(1) || st.Fields["reason"] != adiri.ReasonPairing {
			t.Errorf("mode %d exchanged signatures: %v", mode, err)
		}
	}
}

// zeroThenOne yields zero 128-bit scalars for its first three draws and distinct non-zero ones after. A verifier that accepted a zero
// scalar would use blocks 0, 1, 2 for records 0, 1, 2 and drop them from the combination, accepting exchanged signatures; one that
// redraws uses a non-zero block for each record.
type zeroThenOne struct{ n int }

func (r *zeroThenOne) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	if r.n >= 3 {
		p[len(p)-1] = byte(r.n) // distinct non-zero scalars, so that exchanged signatures are detected
	}
	r.n++
	return len(p), nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

func TestBatchScalarIsNeverZeroAndARandomSourceFailureIsNamed(t *testing.T) {
	_, _, cf, _, _ := liveParts(t, "syn-rotation")
	bad := gateCopy(cf)
	bad.Records[1].Signature, bad.Records[2].Signature = cf.Records[2].Signature, cf.Records[1].Signature
	err := gateVerify(t, adiri.ModeBatched, bad, &zeroThenOne{})
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != adiri.CodeCommitteeBroken || st.Fields["epoch"] != uint64(1) || st.Fields["reason"] != adiri.ReasonPairing {
		t.Fatalf("a zero batch scalar must be redrawn, never used: %v", err)
	}
	if err := gateVerify(t, adiri.ModeBatched, gateCopy(cf), &zeroThenOne{}); err != nil {
		t.Fatalf("the untouched chain under redrawn scalars: %v", err)
	}
	err = gateVerify(t, adiri.ModeBatched, gateCopy(cf), failingReader{})
	st, ok = finality.AsNamed(err)
	if !ok || st.Code != finality.CodeVerifierFailed || fmt.Sprint(st.Fields["cause"]) != "entropy source failed" {
		t.Fatalf("a failing random source is a named verifier failure: %v", err)
	}
	// the one-by-one mode never draws a scalar
	if err := gateVerify(t, adiri.ModeOneByOne, gateCopy(cf), failingReader{}); err != nil {
		t.Fatalf("one-by-one needs no randomness: %v", err)
	}
}

func TestAOneRecordChainHasItsSignatureVerifiedInBothModes(t *testing.T) {
	_, _, cf, _, _ := liveParts(t, "syn-rotation")
	one := gateCopy(cf)
	one.Records = one.Records[:1]
	for _, mode := range []adiri.Mode{adiri.ModeOneByOne, adiri.ModeBatched} {
		if err := gateVerify(t, mode, one, nil); err != nil {
			t.Fatalf("mode %d: a valid one record chain: %v", mode, err)
		}
		bad := gateCopy(one)
		bad.Records[0].Signature = cf.Records[1].Signature
		err := gateVerify(t, mode, bad, nil)
		st, ok := finality.AsNamed(err)
		if !ok || st.Fields["epoch"] != uint64(0) || st.Fields["reason"] != adiri.ReasonPairing {
			t.Errorf("mode %d: a one record chain with a foreign signature: %v", mode, err)
		}
	}
}

func TestAChainWithNoRecordsAndAGenesisSetThatIsOnlyASubsetAreRefusedByName(t *testing.T) {
	_, _, cf, _, pins := liveParts(t, "syn-rotation")
	par, err := adiri.ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	empty := gateCopy(cf)
	empty.Records = nil
	_, err = adiri.VerifyCommitteeChain(par, empty, adiri.ModeOneByOne, nil)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.n_records", "reason", finality.ReasonCFA1NoRecords)
	// the pinned genesis committee holds every key of committee(0) and one more: not the same set
	bigger := *par
	bigger.GenesisCommittee = append(append([][]byte(nil), par.GenesisCommittee...), cf.Tables[0][0])
	bigger.GenesisCommittee = append(bigger.GenesisCommittee[:len(par.GenesisCommittee)], gateKey(0x77))
	_, err = adiri.VerifyCommitteeChain(&bigger, gateCopy(cf), adiri.ModeOneByOne, nil)
	gateNamed(t, err, adiri.CodePinMismatch, "pin", "genesis_committee")
}
