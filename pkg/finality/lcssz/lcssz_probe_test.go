// Copyright 2026 Certen Protocol

package lcssz

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// electraFU is an Electra-layout finality update of n bytes whose two offsets are attOff (always 400) and finOff; the rest is zero.
func electraFU(n, finOff int) []byte {
	fu := make([]byte, n)
	binary.LittleEndian.PutUint32(fu, electraFinalityUpdateFixed)
	binary.LittleEndian.PutUint32(fu[4:], uint32(finOff))
	return fu
}

func mustNotPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// The reviewer's probe (V-C2-A1 D3): FinalityUpdateSlots accepts a 2,056-byte Electra finality update whose finalized offset is 2,048,
// and FinalizedExec then sliced fu[2048+244:] ("slice bounds out of range [2292:2056]").
func TestFinalizedExecOnAnElectraFinalityUpdateWhoseFinalizedHeaderIsTruncatedReturnsAnError(t *testing.T) {
	fu := electraFU(2056, 2048)
	if _, _, _, err := FinalityUpdateSlots(Electra, fu); err != nil {
		t.Fatalf("the shape must be one FinalityUpdateSlots accepts: %v", err)
	}
	mustNotPanic(t, "FinalizedExec", func() {
		if _, _, _, err := FinalizedExec(Electra, fu); err == nil {
			t.Fatal("a finalized header of 8 bytes gave an execution block")
		}
	})
}

// Structured sweep: no exported function panics for any finality update length around the fixed parts and any offset pair around
// them, for every layout byte.
func TestNoExportedFunctionPanicsForAnyShape(t *testing.T) {
	lens := map[int]bool{0: true, 1: true, 7: true, 8: true, 9: true}
	for _, base := range []int{electraFinalityUpdateFixed, electraFinalityUpdateFixed + 2*(electraHeaderFixed+electraExecFixed), electraUpdateFixed, electraBootstrapFixed, GloasFinalityUpdateSize, GloasUpdateSize, GloasBootstrapSize} {
		for d := -3; d <= 3; d++ {
			lens[base+d] = true
		}
	}
	for d := 0; d <= 40; d++ {
		lens[2056+d*8] = true
	}
	offs := map[int]bool{0: true, 1: true, 4: true, 8: true}
	for _, base := range []int{electraFinalityUpdateFixed, electraUpdateFixed, 2056, 2048, 2052, 2056 - 244, 2056 - 244 - 584, 1228, 1229, 1227, 1000000, 1<<31 - 1} {
		for d := -3; d <= 3; d++ {
			offs[base+d] = true
		}
	}
	n := 0
	for ln := range lens {
		if ln < 0 {
			continue
		}
		for off := range offs {
			for l := Layout(0); l <= 3; l++ {
				fu := make([]byte, ln)
				if ln >= 8 {
					binary.LittleEndian.PutUint32(fu, electraFinalityUpdateFixed)
					binary.LittleEndian.PutUint32(fu[4:], uint32(off))
				}
				if ln >= electraUpdateFixed {
					binary.LittleEndian.PutUint32(fu, electraUpdateFixed)
					binary.LittleEndian.PutUint32(fu[4+CommitteeBytes+6*32:], uint32(off))
				}
				n++
				what := fmt.Sprintf("len %d offset %d layout %d", ln, off, l)
				mustNotPanic(t, what, func() {
					_, _, _, _ = FinalityUpdateSlots(l, fu)
					_, _, _, _ = FinalizedExec(l, fu)
					_, _ = FinalityUpdateParticipants(l, fu)
					_, _, _, _ = UpdateSlots(l, fu)
					_, _ = UpdateToFinalityUpdate(l, fu)
					_, _ = NextCommittee(l, fu)
					_, _ = BootstrapCommittee(l, fu)
					_, _, _ = SplitFramedUpdates(fu)
				})
			}
		}
	}
	if n < 1000 {
		t.Fatalf("the sweep covered %d shapes", n)
	}
}
