// Copyright 2026 Certen Protocol

package config

import (
	"strings"
	"testing"
)

// RB3-F71 (the env part) / RB3-F89: a variable that is set but does not parse is refused by name, never
// replaced by the default; and no validator runs as "validator-default".

func TestLoadRefusesEverySetValueThatDoesNotParse(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	bad := map[string]string{
		"DATABASE_MAX_CONNS":   "25x",    // int
		"TLS_ENABLED":          "yes",    // bool
		"DB_CONN_MAX_LIFETIME": "1 hour", // duration
	}
	for k, v := range bad {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err == nil {
		t.Fatalf("Load accepted values that do not parse, running on %+v", cfg)
	}
	for k, v := range bad {
		if !strings.Contains(err.Error(), k+"="+`"`+v+`"`) {
			t.Errorf("the refusal does not name %s=%q: %v", k, v, err)
		}
	}
}

func TestLoadAcceptsWellFormedValues(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ValidatorID != "validator-3" {
		t.Fatalf("VALIDATOR_ID read as %q", cfg.ValidatorID)
	}
}

func TestAnchorConfigRefusesAValueThatDoesNotParse(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	t.Setenv("REQUIRE_QUORUM", "flase")
	if _, err := LoadAnchorConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "REQUIRE_QUORUM=") {
		t.Fatalf("an unparseable anchor setting was not refused by name: %v", err)
	}
}

func TestNoValidatorRunsAsNobodyInParticular(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ValidatorID != "" {
		t.Fatalf("an unset VALIDATOR_ID became %q", cfg.ValidatorID)
	}
	if cfg.RequireValidatorID() == nil {
		t.Fatal("a configuration naming no validator was accepted")
	}
	a, err := LoadAnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if a.Validator.ID != "" {
		t.Fatalf("the anchor config invented validator ID %q", a.Validator.ID)
	}
}
