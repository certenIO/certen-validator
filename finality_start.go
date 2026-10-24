// Copyright 2026 Certen Protocol

package main

import (
	"context"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
)

// genesisLinkCheck is the load-time check of the embedded Adiri genesis link (a variable so a test can make it fail).
var genesisLinkCheck = adiri.CheckEmbeddedGenesisLink

// launchFinality is finality.Launch (a variable so a test can make it fail or observe what it is given).
var launchFinality = finality.Launch

// finalityRegistry is the registry the finality kinds are registered into: the process-wide one (a variable so each test can use its own,
// since a kind can be registered once).
var finalityRegistry = finality.Default

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
// NO failure of this start ends the validator (RB12-GO-INT F14). The settings come from one environment shared by every validator of the
// fleet, and finality is not an input of consensus, so a start that returned an error - which main turns into log.Fatal and a restart of
// all seven at the same roll - would let a typo in a setting nobody attests with stop the fleet. Every failure is announced as the named
// state finality_upgrader_disabled{reason,...} (log, metric certen_finality_upgrader_disabled_total{chain="0",env=<setting or stage>},
// gauge certen_finality_upgrader_enabled 0 and the health block's upgrader_disabled_reason) and the function returns nil:
//
//	config_invalid   a provider-list entry (a provider URL, the archive list) is refused: variable, entry position, class
//	switch_invalid   the upgrader switch or a per-chain switch is not a switch: variable
//	setting_invalid  a number or duration is malformed or out of its bounds: the first variable, how many were refused
//	pins_invalid     the pins file cannot be read or parsed, the embedded pins fail their hash, or the genesis link fails: stage
//	wiring_failed    a verifier kind cannot be registered: stage
//	launch_failed    finality.Launch refused: stage
//	start_panicked   the start panicked and the panic was recovered: stage
//
// The value of a setting is never printed or stored: it may hold a credential. Every refused setting and provider entry is logged by
// name and position so one restart can correct them all. The error result is kept for the caller's signature; no failure of the start
// is returned through it.
func startFinality(ctx context.Context, dbClient *database.Client, logf func(string, ...any)) error {
	defer func() {
		if r := recover(); r != nil {
			finality.AnnounceUpgraderDisabled(logf, finruntime.StartPanic(r))
		}
	}()
	on, err := finality.Enabled()
	if err != nil {
		finality.AnnounceUpgraderDisabled(logf, finruntime.StartFailure(logf, err))
		return nil
	}
	cfg, err := finruntime.ConfigFromEnv()
	if err != nil {
		finality.AnnounceUpgraderDisabled(logf, finruntime.StartFailure(logf, err))
		return nil
	}
	// The header of a legacy leg (a bundle whose execution proof was written before block_header_rlp was captured) is read from the capture
	// store the legacy-header loop (pkg/finality/legacyhdr, RB12-LEGACY-191) fills; the store is not trusted, the stored proofs are verified
	// against the header like any other. Without this wiring the 191 legs stay no_block_header: TestTheProcessWiresTheLegacyHeaderLoopAndItsHeaderStore.
	capture := database.NewFinalityCaptureStore(dbClient)
	repo := database.NewFinalityAddendaRepository(dbClient).WithLegacyHeaders(capture)
	wire, err := finruntime.Wire(cfg, finruntime.Deps{
		Registry: finalityRegistry, Store: capture, Legacy: repo,
		Status: database.NewFinalityStatusRepository(dbClient), Logf: logf,
	})
	if err != nil {
		finality.AnnounceUpgraderDisabled(logf, finruntime.StartFailure(logf, err))
		return nil
	}
	// The Adiri genesis link is embedded and hash-pinned by the pins the runtime built under; it is checked once here, at startup,
	// never per proof.
	if err := genesisLinkCheck(wire.Pins); err != nil {
		finality.AnnounceUpgraderDisabled(logf, finruntime.StartFailure(logf, finruntime.GenesisLinkFailed(err)))
		return nil
	}
	if _, err := launchFinality(ctx, on, repo, repo, wire.Registry, wire.Pins, wire.Upgrader); err != nil {
		finality.AnnounceUpgraderDisabled(logf, finruntime.StartFailure(logf, finruntime.LaunchFailed(err)))
		return nil
	}
	return nil
}
