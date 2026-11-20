// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"errors"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// A capture that stops keeps the pages it read, marked partial, and no evidence is assembled from it: it recorded no anchor binding, so
// assembling would read each foreign partition's anchor 0 (block 1) and fail with a g1_chain_moved that hides why the capture stopped.
func TestAPartialCaptureIsMarkedAndNeverAssembled(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/2")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2020} // after BVN2's latest admissible block: the capture stops
	c, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival {
		t.Fatalf("the capture did not stop as set up: %v", err)
	}
	if c == nil || !c.Partial || !c.IsPartial() {
		t.Fatalf("the pages kept from a stopped capture are not marked partial: %+v", c)
	}
	if _, err := c.Assembly(context.Background(), fakeLog{f}, nil); !errors.Is(err, ErrPartialCapture) {
		t.Fatalf("a partial capture was assembled: %v", err)
	}

	// A complete capture is neither.
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2019}
	c, err = f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if c.Partial || c.IsPartial() {
		t.Fatalf("a complete capture reads as partial: %+v", c.Partitions)
	}
}

// A partial capture stored before the mark existed: the real row of intent 84216735 (AGT-0 scene 4b), whose foreign partition BVN3 carries
// no anchor binding. It reads as partial.
func TestALegacyPartialCaptureRowReadsAsPartial(t *testing.T) {
	raw := []byte(`{"version":"` + CaptureVersion + `","principal":"acc://fict-agent-08015.acme/data","partition":"BVN2","block":17418864,` +
		`"partitions":{"BVN2":{"block":17418864,"partition":"BVN2","stateRoot":"846f1175ba82ce8c68d21648aa41006f5fa3a2913ae97e502e28e9de5096a81b"},` +
		`"BVN3":{"block":17409286,"partition":"BVN3","stateRoot":"6500aa70209ff9048c0284145a4d19d8784c6002626f218dac5041e78848ea5d"}},"pages":[]}`)
	cp, err := DecodeCapture(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cp.IsPartial() {
		t.Fatalf("the stored partial row of intent 84216735 does not read as partial")
	}
	if _, err := cp.Assembly(context.Background(), nil, nil); !errors.Is(err, ErrPartialCapture) {
		t.Fatalf("the stored partial row was assembled: %v", err)
	}
}
