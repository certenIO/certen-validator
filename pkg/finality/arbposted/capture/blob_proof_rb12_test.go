// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2 item 2 (ledger CG-2): the capture records a batch's blobs as unavailable only on PROOF: GoneObservations asks in a row (here 2),
// spread over at least GoneSpan (here one minute), each answered "gone" by every beacon host and by at least MinGoneHosts (2) distinct ones.
// A transient answer resets the run. Without proof the batch is asked again at a bounded back-off and never given up.

func goneHosts(statuses ...int) []BeaconHost {
	out := make([]BeaconHost, len(statuses))
	for i, st := range statuses {
		out[i] = BeaconHost{Host: string(rune('a'+i)) + ".example", Status: st, Gone: st == 404 || st == 410 || st == 200}
	}
	return out
}

func unavailableRows(t *testing.T, store CaptureStore) int {
	t.Helper()
	ks, err := store.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "blobunavailable/")
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

func TestBlobsAreRecordedUnavailableOnlyOnProofFromEnoughHostsOverEnoughTime(t *testing.T) {
	for _, c := range []struct {
		name  string
		hosts []BeaconHost
		proof bool
	}{
		{"two hosts gone, over the span", goneHosts(404, 404), true},
		{"a block served without the blobs counts as gone", goneHosts(404, 200), true},
		{"one host only is not enough hosts", goneHosts(404), false},
		{"one host answered a 503", goneHosts(404, 503), false},
		{"no host answered", goneHosts(0, 0), false},
		{"no host asked", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			testNow = time.Unix(1_800_000_000, 0)
			store := NewMemStore()
			sc := newScenario(t, LocBlob, 1)
			sc.beacon.err = &BeaconError{Slot: 9, Status: 404, Err: "gone", Hosts: c.hosts}
			cp := newCapturer(sc, store)
			tick := func() {
				if _, err := cp.Tick(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			tick()
			testNow = testNow.Add(10 * time.Second) // the second observation, before the span has passed
			tick()
			if n := unavailableRows(t, store); n != 0 {
				t.Fatalf("%d rows before the span has passed", n)
			}
			testNow = testNow.Add(2 * time.Minute)
			tick()
			tick()
			if n, want := unavailableRows(t, store), map[bool]int{true: 1, false: 0}[c.proof]; n != want {
				t.Fatalf("%d rows, want %d", n, want)
			}
		})
	}
}

func TestATransientAnswerResetsTheRunOfGoneObservations(t *testing.T) {
	testNow = time.Unix(1_800_000_000, 0)
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	cp := newCapturer(sc, store)
	tick := func(hosts []BeaconHost) {
		sc.beacon.err = &BeaconError{Slot: 9, Status: 404, Err: "x", Hosts: hosts}
		if _, err := cp.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tick(goneHosts(404, 404))
	testNow = testNow.Add(2 * time.Minute)
	tick(goneHosts(404, 503)) // the run starts again
	tick(goneHosts(404, 404))
	if n := unavailableRows(t, store); n != 0 {
		t.Fatalf("%d rows: a transient answer in between must reset the run", n)
	}
	testNow = testNow.Add(2 * time.Minute)
	tick(goneHosts(404, 404))
	tick(goneHosts(404, 404))
	if n := unavailableRows(t, store); n != 1 {
		t.Fatalf("%d rows after a fresh run over the span, want 1", n)
	}
}

func TestAnUnprovenBatchIsAskedAgainAtABoundedBackOffAndCounted(t *testing.T) {
	testNow = time.Unix(1_800_000_000, 0)
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.beacon.err = &BeaconError{Slot: 9, Status: 503, Err: "down", Hosts: goneHosts(503, 503)}
	cp := NewCapturer(store, sc.l1, sc.beacon, Config{StartBack: 20, UnavailableEvery: 2, BlobBackoffMaxTicks: 4, Now: func() time.Time { return testNow }})
	asks := func() int { return sc.beacon.calls }
	var ticksAsked []int
	for i := 1; i <= 40; i++ {
		before := asks()
		if _, err := cp.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if asks() > before {
			ticksAsked = append(ticksAsked, i)
		}
	}
	if len(ticksAsked) < 8 {
		t.Fatalf("asked on ticks %v: the batch must keep being asked again", ticksAsked)
	}
	last := ticksAsked[len(ticksAsked)-1] - ticksAsked[len(ticksAsked)-2]
	if last > 4 {
		t.Fatalf("ticks %v: the gap between asks grew past the bound of 4 ticks", ticksAsked)
	}
	if unavailableRows(t, store) != 0 {
		t.Fatal("an unproven batch was recorded as unavailable")
	}
}
