package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The validator serves /health only after all initialisation. A normal boot measured 130-143 s on
// 2026-10-05 (BLS-ZK key load about 80 s) and a boot after an execution-rules change also replays the
// committed history (about 270 s), so a shorter start period reports a healthy node as unhealthy.
const minHealthcheckStartPeriodSeconds = 300

func TestImageHealthcheckStartPeriodOutlastsABoot(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("reading Dockerfile: %v", err)
	}
	m := regexp.MustCompile(`(?m)^HEALTHCHECK[^\n]*--start-period=(\d+)s`).FindSubmatch(b)
	if m == nil {
		t.Fatal("Dockerfile has no HEALTHCHECK with --start-period=<seconds>s")
	}
	got, _ := strconv.Atoi(string(m[1]))
	if got < minHealthcheckStartPeriodSeconds {
		t.Fatalf("HEALTHCHECK --start-period=%ds is shorter than a rules-change boot; need at least %ds", got, minHealthcheckStartPeriodSeconds)
	}
}
