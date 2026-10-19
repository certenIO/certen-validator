// Copyright 2026 Certen Protocol

package config

import (
	"strings"
	"testing"
)

// The seven validators share one PostgreSQL with max_connections=100. Each defaulted DATABASE_MAX_CONNS to 25, so the
// fleet could ask for 7 x 25 = 175 connections: a latent exhaustion ("too many clients already") the day every
// validator is busy at once (found in RB8-F, host checked 2026-10-18). The code default now fits one server for the
// fleet; an explicit DATABASE_MAX_CONNS still wins; and a pool that does not fit is said so, loudly, with both numbers.

func TestTheDatabasePoolDefaultFitsSevenValidatorsInOneServer(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	t.Setenv("DATABASE_MAX_CONNS", "")
	t.Setenv("DB_MAX_OPEN_CONNS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	const fleet, serverMax = 7, 100
	if cfg.DatabaseMaxConns <= 0 || cfg.DatabaseMaxConns > DefaultDatabaseMaxConns {
		t.Fatalf("DatabaseMaxConns defaults to %d; want 1..%d", cfg.DatabaseMaxConns, DefaultDatabaseMaxConns)
	}
	if DefaultDatabaseMaxConns > 12 {
		t.Fatalf("DefaultDatabaseMaxConns is %d; the seven validators of one server may hold at most 12 each", DefaultDatabaseMaxConns)
	}
	if got := fleet * cfg.DatabaseMaxConns; got > serverMax {
		t.Fatalf("%d validators x %d connections = %d, over a server's max_connections of %d", fleet, cfg.DatabaseMaxConns, got, serverMax)
	}
	if cfg.DBMaxOpenConns != DefaultDatabaseMaxConns {
		t.Fatalf("DBMaxOpenConns defaults to %d, not the pool default %d: a second default that disagrees is the defect again",
			cfg.DBMaxOpenConns, DefaultDatabaseMaxConns)
	}

	// The YAML-less anchor configuration reads the same variable and must agree.
	anchor, err := loadAnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Database.MaxConnections != cfg.DatabaseMaxConns {
		t.Fatalf("the anchor configuration defaults the pool to %d, the validator configuration to %d",
			anchor.Database.MaxConnections, cfg.DatabaseMaxConns)
	}
}

func TestAnExplicitDatabaseMaxConnsStillWins(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	t.Setenv("DATABASE_MAX_CONNS", "25")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseMaxConns != 25 {
		t.Fatalf("DATABASE_MAX_CONNS=25 was read as %d: an operator's explicit value is theirs to set", cfg.DatabaseMaxConns)
	}
	anchor, err := loadAnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Database.MaxConnections != 25 {
		t.Fatalf("the anchor configuration read DATABASE_MAX_CONNS=25 as %d", anchor.Database.MaxConnections)
	}
}

func TestThePoolBudgetWarnsOnlyWhenTheFleetOutgrowsTheServer(t *testing.T) {
	cases := []struct {
		name       string
		perCluster PoolBudget
		warns      bool
		mentions   []string
	}{
		{"seven validators at the new default fit a stock server", PoolBudget{PerValidator: 12, Validators: 7, ServerMax: 100}, false, nil},
		{"exactly the server's limit still fits", PoolBudget{PerValidator: 20, Validators: 5, ServerMax: 100}, false, nil},
		{"the old default overran it", PoolBudget{PerValidator: 25, Validators: 7, ServerMax: 100}, true, []string{"175", "100", "25", "7"}},
		{"one over the limit warns", PoolBudget{PerValidator: 21, Validators: 5, ServerMax: 100}, true, []string{"105", "100"}},
		{"a lone validator with a pool above the server's limit warns", PoolBudget{PerValidator: 150, Validators: 1, ServerMax: 100}, true, []string{"150", "100"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := c.perCluster.Warning()
			if (w != "") != c.warns {
				t.Fatalf("Warning() = %q; warns=%v", w, c.warns)
			}
			if c.warns && strings.Count(w, "\n") != 0 {
				t.Fatalf("the warning must be one line: %q", w)
			}
			for _, m := range c.mentions {
				if !strings.Contains(w, m) {
					t.Errorf("the warning does not name %q: %q", m, w)
				}
			}
		})
	}
}

func TestThePoolBudgetNamesAPoolThatWouldFitAndNeverFailsAStart(t *testing.T) {
	w := PoolBudget{PerValidator: 25, Validators: 7, ServerMax: 100}.Warning()
	if !strings.Contains(w, "DATABASE_MAX_CONNS") || !strings.Contains(w, "max_connections") {
		t.Fatalf("the warning does not name the two settings to change: %q", w)
	}
	// floor(100 / 7) = 14: the largest pool the fleet fits with.
	if !strings.Contains(w, "14") {
		t.Fatalf("the warning does not name the largest pool the fleet fits with (14): %q", w)
	}
	// A server whose limit cannot be read, or a budget with no fleet, produces no warning and no panic.
	for _, b := range []PoolBudget{{PerValidator: 12, Validators: 7, ServerMax: 0}, {PerValidator: 12, Validators: 0, ServerMax: 100}} {
		if w := b.Warning(); w != "" {
			t.Fatalf("%+v warned without both numbers: %q", b, w)
		}
	}
}

func TestTheConfiguredFleetIsTheAttestationPeersPlusThisValidator(t *testing.T) {
	if got := ConfiguredValidatorCount(nil); got != 1 {
		t.Fatalf("no peers: %d validators; want 1 (this one)", got)
	}
	peers := parseAttestationPeers("http://v2:8080, http://v3:8080,http://v4:8080,http://v5:8080,http://v6:8080,http://v7:8080")
	if got := ConfiguredValidatorCount(peers); got != 7 {
		t.Fatalf("six peers: %d validators; want 7", got)
	}
}
