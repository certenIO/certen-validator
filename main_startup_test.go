// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A validator without its database used to start anyway, "in DEGRADED mode", with the batch system, the
// proof store, lifecycle tracking and the evidence writers switched off, unless DATABASE_REQUIRED=true was
// set - and production does not set it. Such a validator takes part in consensus and executes intents it
// can record nothing about. It now refuses to start.
//
// The test runs the real main() in a child process against a database that cannot be reached.
func TestValidatorRefusesToStartWithoutItsDatabase(t *testing.T) {
	if os.Getenv("CERTEN_STARTUP_UNDER_TEST") == "1" {
		os.Args = []string{"validator"}
		main()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestValidatorRefusesToStartWithoutItsDatabase$")
	cmd.Env = append(os.Environ(),
		"CERTEN_STARTUP_UNDER_TEST=1",
		"VALIDATOR_ID=validator-startup-test",
		"DATABASE_URL=postgres://certen@127.0.0.1:1/none?sslmode=disable&connect_timeout=2",
		"DATABASE_REQUIRED=",
	)
	out, err := cmd.CombinedOutput()
	log := string(out)
	if ctx.Err() != nil {
		t.Fatalf("the validator was still running 60s after its database refused the connection:\n%s", tail(log))
	}
	if strings.Contains(log, "DEGRADED") {
		t.Fatalf("the validator started without its database (degraded mode):\n%s", tail(log))
	}
	if err == nil {
		t.Fatalf("the validator exited 0 without its database:\n%s", tail(log))
	}
	if !strings.Contains(log, "cannot start without its database") {
		t.Fatalf("the refusal does not say why:\n%s", tail(log))
	}
}

// An explicit DATABASE_REQUIRED=false asked for the degraded mode; it is refused by name rather than
// silently ignored.
func TestValidatorRefusesTheDatabaseOptionalSetting(t *testing.T) {
	if os.Getenv("CERTEN_STARTUP_UNDER_TEST") == "2" {
		os.Args = []string{"validator"}
		main()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestValidatorRefusesTheDatabaseOptionalSetting$")
	cmd.Env = append(os.Environ(),
		"CERTEN_STARTUP_UNDER_TEST=2",
		"VALIDATOR_ID=validator-startup-test",
		"DATABASE_URL=postgres://certen@127.0.0.1:1/none?sslmode=disable&connect_timeout=2",
		"DATABASE_REQUIRED=false",
	)
	out, err := cmd.CombinedOutput()
	log := string(out)
	if ctx.Err() != nil || err == nil || !strings.Contains(log, "DATABASE_REQUIRED=false is not supported") {
		t.Fatalf("DATABASE_REQUIRED=false must be refused by name (err=%v):\n%s", err, tail(log))
	}
}

func tail(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 25 {
		lines = lines[len(lines)-25:]
	}
	return strings.Join(lines, "\n")
}
