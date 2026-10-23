// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
)

// startFinality starts the staged-finality upgrader (RB11, PROOF_V2 S7, certen:finality:v1). For every settled leg the upgrader
// appends the strongest finality level now buildable (l1_posted, finalized; included is derived and never stored) to the leg's
// append-only, hash-linked addendum chain, beside the stored proof, and re-schedules until the chain's top level. It runs on its own
// goroutine under its own deadlines and shares nothing with settlement, attestation or write-back, none of which waits on it; nothing
// it writes is an input of any attestation message, outcome root or govRoot. CERTEN_FINALITY_UPGRADER_ENABLED (default on) turns it
// off, and an off switch is a named, logged state (finality_upgrader_disabled) and a metric, never a silent skip.
//
// The finality runtime (pkg/finality/runtime) builds, from the validator's provider configuration plus the CERTEN_FINALITY_*
// variables, the provers and capture loops of every live chain and the light-client source. The pins are the embedded, hash-checked
// file unless CERTEN_FINALITY_PINS_FILE names an override, whose source it reports. A chain whose providers are missing is announced
// as the named state finality_upgrader_disabled, never skipped silently.
//
// A provider-list entry the runtime refuses (a *finruntime.ConfigError: not an http(s) URL with a host, or rejected by url.Parse) does
// NOT stop the validator. The provider variables are shared by all validators, so a refusal that ended the process would take them
// all down at the same roll, and finality is not an input of consensus. It is announced as the named state
// finality_upgrader_disabled{reason: config_invalid, variable, entry, class} (log, metric certen_finality_upgrader_disabled_total
// {chain="0",env=<variable>}, gauge certen_finality_upgrader_enabled 0 and the health block's upgrader_disabled_reason), every
// refused entry is logged by position, and nothing of the value is printed. Any other failure of the start (a malformed number or
// switch, a wiring or pins error) still refuses the start by name, as before.
func startFinality(ctx context.Context, dbClient *database.Client, logf func(string, ...any)) error {
	on, err := finality.Enabled()
	if err != nil {
		return fmt.Errorf("finality upgrader: %w", err)
	}
	cfg, err := finruntime.ConfigFromEnv()
	if err != nil {
		var refused *finruntime.ConfigError
		if !errors.As(err, &refused) {
			return fmt.Errorf("finality configuration: %w", err)
		}
		for _, r := range finruntime.CheckProviderEnvironment() {
			logf("[FINALITY] config_invalid: %s entry %d (%s)", r.Variable, r.Entry, r.Class)
		}
		finality.AnnounceUpgraderDisabled(logf, finality.ConfigInvalidState(refused.Variable, refused.Entry, refused.Class))
		return nil
	}
	repo := database.NewFinalityAddendaRepository(dbClient)
	wire, err := finruntime.Wire(cfg, finruntime.Deps{
		Registry: finality.Default, Store: database.NewFinalityCaptureStore(dbClient),
		Status: database.NewFinalityStatusRepository(dbClient), Logf: logf,
	})
	if err != nil {
		return fmt.Errorf("finality wiring: %w", err)
	}
	// The Adiri genesis link is embedded and hash-pinned by the pins the runtime built under; it is checked once here, at startup,
	// never per proof.
	if err := adiri.CheckEmbeddedGenesisLink(wire.Pins); err != nil {
		return fmt.Errorf("finality pins: %w", err)
	}
	if _, err := finality.Launch(ctx, on, repo, repo, wire.Registry, wire.Pins, wire.Upgrader); err != nil {
		return fmt.Errorf("finality upgrader: %w", err)
	}
	return nil
}
