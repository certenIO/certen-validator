// Copyright 2026 Certen Protocol

package proofv2

import (
	"fmt"
	"runtime/debug"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"

	"github.com/certen/independant-validator/pkg/ledger"
)

// A major header record is chosen by whoever submits it - a spine extension in CERTEN's consensus. Walking one that is
// malformed must return an error, never panic: in FinalizeBlock a panic stops every node on one transaction. Every
// single-bit flip of real Kermit records that Accumulate's decoder accepts is walked from the spine before it.
func TestAMalformedMajorRecordIsAnErrorNotAPanic(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	gen, set, err := AcceptSpineGenesis(ir.Inputs, fx.pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	base := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	walked, decoderPanics, refused := 0, 0, 0
	for _, idx := range []int{0, 2, 9} { // major blocks 1, 3 and 10
		l := base
		if idx > 0 {
			cps, sets, err := ExtendSpine(base, fx.ar.Majors[:idx], 1)
			if err != nil {
				t.Fatal(err)
			}
			l = &ledger.AccumulateSpineLog{Genesis: gen, Sets: append(append([]ledger.AccumulateSpineSet(nil), base.Sets...), sets...), Checkpoints: cps}
		}
		b, err := fx.ar.Majors[idx].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		for i := range b {
			for bit := 0; bit < 8; bit++ {
				c := append([]byte(nil), b...)
				c[i] ^= 1 << bit
				r := new(api.MajorHeaderRecord)
				if p := recovered(func() { err = r.UnmarshalBinary(c) }); p != nil {
					decoderPanics++ // Accumulate's decoder: guarded by the consensus caller (refusePanic)
					continue
				}
				if err != nil {
					continue
				}
				walked++
				var werr error
				if p := recovered(func() { _, _, werr = ExtendSpine(l, []*api.MajorHeaderRecord{r}, 1) }); p != nil {
					t.Fatalf("major block %d, byte %d bit %d: the walk panicked: %v", idx+1, i, bit, p)
				}
				if werr != nil {
					refused++
				}
			}
		}
	}
	t.Logf("walked %d decodable one-bit flips without a panic (%d refused); the decoder panicked on %d", walked, refused, decoderPanics)
}

// Records whose fields the walk reads are missing: each is a named error. Byte 27 of major block 1 flipped is the
// "nil anchor body" case as the decoder produces it; the walk read the body's type to word its error.
func TestAMajorRecordMissingFieldsIsAnError(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	g, err := genesisValues(ir.Inputs.NetworkRecord, ir.Inputs.GlobalsRecord)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(r *api.MajorHeaderRecord){
		"no record":          nil,
		"nil anchor message": func(r *api.MajorHeaderRecord) { r.Anchor.Message = nil },
		"nil signature":      func(r *api.MajorHeaderRecord) { r.Signatures = append(r.Signatures, nil) },
		"nil update":         func(r *api.MajorHeaderRecord) { r.Updates = append(r.Updates, nil) },
		"nil anchor source":  func(r *api.MajorHeaderRecord) { r.Anchor.Source = nil },
		"nil anchor dest":    func(r *api.MajorHeaderRecord) { r.Anchor.Destination = nil },
		"nil anchor body": func(r *api.MajorHeaderRecord) {
			r.Anchor.Message.(*messaging.TransactionMessage).Transaction.Body = nil
		},
		"nil anchor transaction": func(r *api.MajorHeaderRecord) {
			r.Anchor.Message.(*messaging.TransactionMessage).Transaction = nil
		},
		"nil anchor": func(r *api.MajorHeaderRecord) { r.Anchor = nil },
	} {
		var r *api.MajorHeaderRecord
		if mutate != nil {
			r = fx.ar.Majors[0].Copy()
			mutate(r)
		}
		sp, err := NewSpine(g, 1)
		if err != nil {
			t.Fatal(err)
		}
		var aerr error
		if p := recovered(func() { aerr = sp.Advance(r) }); p != nil {
			t.Errorf("%s: panicked: %v", name, p)
			continue
		}
		if aerr == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func recovered(f func()) (p any) {
	defer func() {
		if r := recover(); r != nil {
			p = fmt.Sprint(r) + "\n" + string(debug.Stack())
		}
	}()
	f()
	return nil
}
