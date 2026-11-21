// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/metrics"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

type floorRet map[string][2]uint64

func (f floorRet) Retained(_ context.Context, p string) (uint64, uint64, error) {
	r, ok := f[p]
	if !ok {
		return 0, 0, errors.New("unreachable")
	}
	return r[0], r[1], nil
}

var floorClock = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func floorDeps(ret floorRet, partsErr error) historyFloorDeps {
	return historyFloorDeps{
		partitions: func(context.Context) ([]string, error) {
			if partsErr != nil {
				return nil, partsErr
			}
			return []string{"BVN1", "BVN2", "BVN3", "Directory"}, nil
		},
		retention: ret,
		now:       func() time.Time { return floorClock },
	}
}

const agtFloor = "Directory=13440000,BVN1=17570000,BVN2=17565000,BVN3=17540539"

var (
	// the public Kermit node as measured 2026-11-20: about 700 retained blocks per partition
	publicNode = floorRet{"Directory": {13445201, 13445749}, "BVN1": {17574589, 17575293}, "BVN2": {17570888, 17571592}, "BVN3": {17561366, 17562071}}
	fullNode   = floorRet{"Directory": {13440000, 13445749}, "BVN1": {17569000, 17575293}, "BVN2": {17565000, 17571592}, "BVN3": {17540000, 17562071}}
)

type logLines []string

func (l *logLines) logf(format string, args ...any) { *l = append(*l, fmt.Sprintf(format, args...)) }

// AGT-F104: a node that prunes below the floor is REPORTED - the ❌ log naming the partition, the gauge at 0 and the health
// block - and the validator is not stopped (reportHistoryFloor returns a verdict, never an error to abort on).
func TestAPruningNodeIsReportedAndDoesNotStopTheValidator(t *testing.T) {
	var l logLines
	v := reportHistoryFloor(context.Background(), agtFloor, "https://kermit.example", floorDeps(publicNode, nil), "", l.logf)
	if v != "unmet" {
		t.Fatalf("verdict %q", v)
	}
	if len(l) != 1 || !strings.Contains(l[0], "❌ [PROOF-V2-HISTORY]") || !strings.Contains(l[0], "proof_v2_history_floor_unmet{") || !strings.Contains(l[0], "the validator runs on") {
		t.Fatalf("log %q", l)
	}
	h := metrics.ProofV2HistoryHealth()
	if h["verdict"] != "unmet" || h["met"] != false || h["partition"] == nil || h["floor"] != mustFloor(t).String() || h["checked_at"] != "2026-11-21T12:00:00Z" {
		t.Fatalf("health %v", h)
	}
}

// Every failure is named, never collapsed into "met": no floor configured, a malformed floor, and a node that cannot be read.
func TestEveryFailedJudgementIsNamed(t *testing.T) {
	cases := []struct {
		raw     string
		deps    historyFloorDeps
		verdict string
	}{
		{"", floorDeps(publicNode, nil), "unset"},
		{"BVN1=abc", floorDeps(publicNode, nil), "malformed"},
		{agtFloor, floorDeps(floorRet{}, errors.New("network-status: connection refused")), "unreadable"},
		{agtFloor, floorDeps(floorRet{}, nil), "unreadable"},
	}
	for _, c := range cases {
		var l logLines
		if v := reportHistoryFloor(context.Background(), c.raw, "u", c.deps, "met", l.logf); v != c.verdict {
			t.Errorf("%q: verdict %q, want %q", c.raw, v, c.verdict)
		}
		if len(l) != 1 || !strings.Contains(l[0], "❌") {
			t.Errorf("%q: log %q", c.raw, l)
		}
		if metrics.ProofV2HistoryHealth()["met"] != false {
			t.Errorf("%q: reported as met", c.raw)
		}
	}
}

// A node that keeps the floor is met: logged once on the change to met, then quiet while it stays met; a later failure is
// logged again.
func TestAFullHistoryNodeIsMetAndLoggedOnChange(t *testing.T) {
	var l logLines
	d := floorDeps(fullNode, nil)
	if v := reportHistoryFloor(context.Background(), agtFloor, "u", d, "unmet", l.logf); v != "met" {
		t.Fatalf("verdict %q", v)
	}
	if metrics.ProofV2HistoryHealth()["met"] != true {
		t.Fatal("met not reported")
	}
	reportHistoryFloor(context.Background(), agtFloor, "u", d, "met", l.logf)
	if len(l) != 1 || !strings.Contains(l[0], "📚") {
		t.Fatalf("log %q", l)
	}
	reportHistoryFloor(context.Background(), agtFloor, "u", floorDeps(publicNode, nil), "met", l.logf)
	if len(l) != 2 || !strings.Contains(l[1], "❌") {
		t.Fatalf("log %q", l)
	}
}

// The watcher judges at once (startup is never blocked on the node) and stops with its context.
func TestTheWatcherJudgesAtOnceAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var l logLines
	done := make(chan struct{})
	go func() { watchHistoryFloor(ctx, agtFloor, "u", floorDeps(publicNode, nil), l.logf); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for metrics.ProofV2HistoryHealth()["checked_at"] == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(l) == 0 || !strings.Contains(l[0], "❌") {
		t.Fatalf("log %q", l)
	}
}

// main.go never aborts start on the floor: the old start gate is gone and the watcher is what runs.
func TestMainDoesNotGateStartOnTheFloor(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	m := string(src)
	if strings.Contains(m, "startupHistoryFloor") || !strings.Contains(m, "go watchHistoryFloor(") || !strings.Contains(m, "metrics.ProofV2HistoryHealth()") {
		t.Fatal("main.go must run the floor watcher and serve its verdict, and must not gate start on it")
	}
}

func mustFloor(t *testing.T) proofv2.HistoryFloor {
	f, err := proofv2.ParseHistoryFloor(agtFloor)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestProofV2HistoryCheckUsage(t *testing.T) {
	var out, errw bytes.Buffer
	if code := runProofV2HistoryCheck(nil, &out, &errw); code != 2 || !strings.Contains(errw.String(), "usage") {
		t.Fatalf("code %d, %q", code, errw.String())
	}
}
