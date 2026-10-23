// Copyright 2026 Certen Protocol

package runtime

import (
	"errors"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-GO-INT F14: no failure of the finality start ends the validator. The classification of a failure into the closed set of reasons of
// finality_upgrader_disabled lives HERE, beside the code that raises the failures, so the process's startFinality (finality_start.go) only
// asks for the state and announces it.

// GenesisLinkFailed marks the failure of the load-time check of the embedded Adiri genesis link (pins are not usable).
func GenesisLinkFailed(err error) error {
	return &WireError{Stage: finality.StartStageGenesisLink, Err: err}
}

// LaunchFailed marks the refusal of finality.Launch.
func LaunchFailed(err error) error {
	return &WireError{Stage: finality.StartStageLaunch, Err: err}
}

// StartPanic is the named state of a start that panicked and was recovered. Only the message of a runtime error and the type of any
// other panic value are carried (finality.PanicCause).
func StartPanic(r any) *finality.StateError {
	return finality.StartFailedState(finality.DisabledStartPanicked, finality.StartStageStart, "", finality.PanicCause(r))
}

// StartFailure returns the named finality_upgrader_disabled state of a start that failed with err, and logs, by name and position and
// never by value, EVERY refused provider entry and setting of the environment (so one restart corrects them all):
//
//	a *ConfigError (a provider-list entry)            config_invalid{variable, entry, class}
//	an *envvar.Refusal that is a switch               switch_invalid{variable}
//	any other *envvar.Refusal (a number, a duration)  setting_invalid{variable, refused}
//	a *WireError at a pins stage                      pins_invalid{stage}
//	a *WireError at the kinds or arguments stage      wiring_failed{stage}
//	a *WireError at the launch stage                  launch_failed{stage}
//	any other error                                   wiring_failed{stage: start}
//
// The last row is an error that carries no classification of its own: it is still a named state, with its text as the cause.
func StartFailure(logf func(string, ...any), err error) *finality.StateError {
	var ce *ConfigError
	var we *WireError
	rs := envvar.Refusals(err)
	switch {
	case errors.As(err, &ce):
		logRefusals(logf, nil)
		return finality.ConfigInvalidState(ce.Variable, ce.Entry, ce.Class)
	case len(rs) > 0:
		logged := logRefusals(logf, rs)
		first := rs[0]
		for _, r := range rs {
			if r.Switch {
				first = r
				break
			}
		}
		if first.Switch {
			return finality.SwitchInvalidState(first.Key)
		}
		return finality.SettingInvalidState(first.Key, logged)
	case errors.As(err, &we):
		logf("[FINALITY] start failed at %s: %s", we.Stage, ethrpc.RedactText(we.Error()))
		switch we.Stage {
		case finality.StartStagePinsFile:
			return finality.StartFailedState(finality.DisabledPinsInvalid, we.Stage, EnvPinsFile, we.Error())
		case finality.StartStagePinsEmbedded, finality.StartStageGenesisLink:
			return finality.StartFailedState(finality.DisabledPinsInvalid, we.Stage, "", we.Error())
		case finality.StartStageLaunch:
			return finality.StartFailedState(finality.DisabledLaunchFailed, we.Stage, "", we.Error())
		}
		return finality.StartFailedState(finality.DisabledWiringFailed, we.Stage, "", we.Error())
	}
	logf("[FINALITY] start failed at %s: %s", finality.StartStageStart, ethrpc.RedactText(err.Error()))
	return finality.StartFailedState(finality.DisabledWiringFailed, finality.StartStageStart, "", err.Error())
}

// logRefusals logs the given refusals, then every other refused setting and provider entry of the environment, by name; it returns how
// many distinct settings were refused (the refused field of setting_invalid).
func logRefusals(logf func(string, ...any), first []*envvar.Refusal) int {
	logged := map[string]bool{}
	log := func(r *envvar.Refusal) {
		if logged[r.Key] {
			return
		}
		logged[r.Key] = true
		logf("[FINALITY] setting refused: %s (it must be %s; the value is not printed)", r.Key, r.Want)
	}
	for _, r := range first {
		log(r)
	}
	for _, r := range RefusedSettings() {
		log(r)
	}
	for _, r := range CheckProviderEnvironment() {
		logf("[FINALITY] config_invalid: %s entry %d (%s)", r.Variable, r.Entry, r.Class)
	}
	return len(logged)
}
