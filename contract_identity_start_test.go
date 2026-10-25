// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"database/sql"
	"testing"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/metrics"
)

func ciLogf(t *testing.T) func(string, ...any) {
	return func(f string, a ...any) { t.Logf(f, a...) }
}

func ciReset(t *testing.T) {
	t.Cleanup(func() {
		if rt := contractIdentityRuntime.Swap(nil); rt != nil {
			rt.Stop()
		}
	})
}

func TestContractIdentityCaptureIsOffByDefault(t *testing.T) {
	ciReset(t)
	t.Setenv(capture.EnvSwitch, "")
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if contractIdentityRuntime.Load() != nil {
		t.Fatal("the capture started without its switch")
	}
	if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != false || h["capture_disabled_reason"] != "switch_off" {
		t.Fatalf("health = %v", h)
	}
	contractIdentityAttested(1, [32]byte{}, [32]byte{1}, 0) // no runtime: a no-op, not a panic
}

func TestContractIdentityBadSettingsAreNamedStatesAndNeverFatal(t *testing.T) {
	ciReset(t)
	t.Setenv(capture.EnvSwitch, "perhaps")
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if contractIdentityRuntime.Load() != nil {
		t.Fatal("started with a bad switch")
	}
	if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != false || h["capture_disabled_reason"] != "switch_invalid" || h["capture_disabled_setting"] != capture.EnvSwitch {
		t.Fatalf("health = %v", h)
	}
	t.Setenv(capture.EnvSwitch, "on")
	t.Setenv(capture.EnvParallel, "99")
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if h := metrics.ContractIdentityHealth(); h["capture_disabled_reason"] != "setting_invalid" || h["capture_disabled_setting"] != capture.EnvParallel {
		t.Fatalf("health = %v", h)
	}
	t.Setenv(capture.EnvParallel, "")
	// switched on, no durable store yet (WP-S8-5): the named state, not a failure
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if contractIdentityRuntime.Load() != nil {
		t.Fatal("started without a durable store")
	}
	if h := metrics.ContractIdentityHealth(); h["capture_disabled_reason"] != "no_durable_store" {
		t.Fatalf("health = %v", h)
	}
	// a store provider that panics: recovered and announced
	old := contractIdentityStore
	t.Cleanup(func() { contractIdentityStore = old })
	contractIdentityStore = func() (capture.Store, error) { panic("hostile store provider") }
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if h := metrics.ContractIdentityHealth(); h["capture_disabled_reason"] != "start_panicked" {
		t.Fatalf("health = %v", h)
	}
}

func TestContractIdentityCaptureStartsWhenSwitchedOnWithAStoreAndForwardsTriggers(t *testing.T) {
	ciReset(t)
	old := contractIdentityStore
	t.Cleanup(func() { contractIdentityStore = old })
	contractIdentityStore = func() (capture.Store, error) { return capture.NewMemStore(), nil }
	t.Setenv(capture.EnvSwitch, "1")
	startContractIdentityCapture(context.Background(), ciLogf(t))
	if contractIdentityRuntime.Load() == nil {
		t.Fatal("the capture did not start")
	}
	if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != true {
		t.Fatalf("health = %v", h)
	}
	// no agreed reader exists for this chain in the test: the trigger is refused by name inside the capture, the process lives on
	contractIdentityAttested(909, [32]byte{3}, [32]byte{4}, 0)
}

// WP-S8-7: with the validator's database client the default store is the Postgres insert-only store (it no longer stays no_durable_store), and
// without one it is the named absence.
func TestContractIdentityDefaultStoreIsThePostgresStoreWhenTheValidatorHasADatabase(t *testing.T) {
	old := contractIdentityDB
	t.Cleanup(func() { contractIdentityDB = old })
	contractIdentityDB = nil
	if s, err := contractIdentityStore(); err == nil || s != nil {
		t.Fatalf("without a database client there is no store: %v %v", s, err)
	}
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable") // sql.Open does not connect
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	contractIdentityDB = database.NewClientFromDB(db)
	s, err := contractIdentityStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*database.IdentityCaptureStore); !ok {
		t.Fatalf("the default store is %T, want *database.IdentityCaptureStore", s)
	}
}
