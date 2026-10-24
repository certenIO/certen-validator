// Copyright 2026 Certen Protocol

package finality

import (
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB12-GO-INT F14. The finality runtime is no input of consensus, attestation or settlement, and its settings come from ONE environment
// shared by every validator of the fleet. A start that failed - for whatever reason - therefore never ends the process: it is announced
// as the named state finality_upgrader_disabled{reason,...} (AnnounceUpgraderDisabled: the log, certen_finality_upgrader_enabled 0,
// certen_finality_upgrader_disabled_total{chain="0",env} and the health block's upgrader_disabled_reason) and the validator keeps
// running. The reasons are a closed set, registered in testdata/finality/states.json.
const (
	// DisabledConfigInvalid: a provider-list entry (a provider URL, the archive list) is refused. See ConfigInvalidState.
	DisabledConfigInvalid = "config_invalid"
	// DisabledSwitchInvalid: CERTEN_FINALITY_UPGRADER_ENABLED or a per-chain switch holds a value that is not a switch. The switch is not
	// guessed on or off.
	DisabledSwitchInvalid = "switch_invalid"
	// DisabledSettingInvalid: a number or a duration is malformed or out of its bounds (the readers of pkg/envvar refuse it by name).
	DisabledSettingInvalid = "setting_invalid"
	// DisabledPinsInvalid: the pins cannot be used (an override file that cannot be read or parsed, an embedded file that fails its hash,
	// a genesis link that does not verify).
	DisabledPinsInvalid = "pins_invalid"
	// DisabledWiringFailed: the runtime could not register its provers and kinds.
	DisabledWiringFailed = "wiring_failed"
	// DisabledLaunchFailed: the upgrader could not be launched.
	DisabledLaunchFailed = "launch_failed"
	// DisabledStartPanicked: the start panicked; the panic was recovered at the boundary of the start.
	DisabledStartPanicked = "start_panicked"
)

// UpgraderDisabledReasons is the closed set of reasons a whole-upgrader finality_upgrader_disabled state carries (the operator's own
// switch being off is the state without a reason).
func UpgraderDisabledReasons() []string {
	return []string{DisabledConfigInvalid, DisabledSwitchInvalid, DisabledSettingInvalid, DisabledPinsInvalid, DisabledWiringFailed,
		DisabledLaunchFailed, DisabledStartPanicked}
}

// The stages of a start failure (the `stage` field of the reasons that carry one).
const (
	StartStagePinsFile     = "pins_file"     // CERTEN_FINALITY_PINS_FILE cannot be read or is not a pins file
	StartStagePinsEmbedded = "pins_embedded" // the embedded pins fail their hash
	StartStageGenesisLink  = "genesis_link"  // the embedded Adiri genesis link does not verify under the pins
	StartStageKinds        = "kinds"         // a verifier kind cannot be registered
	StartStageArguments    = "arguments"     // the runtime was given no registry or no capture store
	StartStageLaunch       = "launch"        // finality.Launch refused
	StartStageStart        = "start"         // a panic inside the start
)

// StartStages is the closed set of stages.
func StartStages() []string {
	return []string{StartStagePinsFile, StartStagePinsEmbedded, StartStageGenesisLink, StartStageKinds, StartStageArguments, StartStageLaunch, StartStageStart}
}

const disabledEffect = "the finality runtime was not started: no finality addenda are appended and nothing is captured by this validator until the setting is corrected and the process restarted; proofs stay at the level they were stored at; consensus, attestation and settlement are not affected"

// SwitchInvalidState is the named state of a start refused because a switch (CERTEN_FINALITY_UPGRADER_ENABLED, or a per-chain
// CERTEN_FINALITY_CHAIN_<id>_ENABLED) holds a value that is not a switch. The value is never part of the state: env and variable name
// the setting, value is the word invalid.
func SwitchInvalidState(variable string) *StateError {
	return NewState(CodeUpgraderDisabled, "reason", DisabledSwitchInvalid, "env", variable, "value", "invalid", "variable", variable,
		"effect", "the setting is not a switch and is not guessed on or off: "+disabledEffect)
}

// SettingInvalidState is the named state of a start refused because a number or duration is malformed or out of its bounds. variable is
// the first refused setting in the order they are read, refused how many were refused (every refused name is logged; no value is).
func SettingInvalidState(variable string, refused int) *StateError {
	st := NewState(CodeUpgraderDisabled, "reason", DisabledSettingInvalid, "env", variable, "value", "invalid", "variable", variable,
		"effect", disabledEffect)
	if refused > 0 {
		st.Fields["refused"] = refused
	}
	return st
}

// StartFailedState is the named state of a start that failed for a reason other than a refused setting: reason is one of
// DisabledPinsInvalid, DisabledWiringFailed, DisabledLaunchFailed, DisabledStartPanicked and stage one of StartStages. variable names
// the setting that holds the faulty input when there is one (the pins file). cause is the text of an error of our own code or of the
// file system, redacted by the one sanitiser of provider text and bounded; it is never built from the value of a setting (a refused
// setting has its own states) and a panic's value is reduced by PanicCause before it gets here.
func StartFailedState(reason, stage, variable, cause string) *StateError {
	env := "finality:" + stage
	if variable != "" {
		env = variable
	}
	st := NewState(CodeUpgraderDisabled, "reason", reason, "env", env, "value", "unusable", "stage", stage, "effect", disabledEffect)
	if variable != "" {
		st.Fields["variable"] = variable
	}
	if c := boundedCause(cause); c != "" {
		st.Fields["cause"] = c
	}
	return st
}

// maxCause bounds the cause text of a start failure.
const maxCause = 300

func boundedCause(s string) string {
	s = ethrpc.RedactText(strings.TrimSpace(s))
	if len(s) <= maxCause {
		return s
	}
	cut := maxCause
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// PanicCause reduces the value of a recovered panic to what is safe to print: the message of a runtime error (an index, a nil
// dereference: no value of ours) and otherwise only the type of the panic value, which may be a string built from a setting.
func PanicCause(r any) string {
	if re, ok := r.(runtime.Error); ok {
		return re.Error()
	}
	return fmt.Sprintf("a panic of type %T (its value is not printed)", r)
}
