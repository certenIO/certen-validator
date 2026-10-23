// Copyright 2026 Certen Protocol

package finality

import (
	"sort"
	"strings"
	"testing"
)

// RB12-GO-INT F14: finality_upgrader_disabled{reason} is a CLOSED set, registered in states.json, and every state built for a reason
// conforms to the registry (its required fields, its closed enums) and holds no value of a setting and no credential.

func disabledSpec(t *testing.T) stateSpec {
	t.Helper()
	spec, ok := loadRegistry(t).States[CodeUpgraderDisabled]
	if !ok {
		t.Fatal("finality_upgrader_disabled is not registered")
	}
	return spec
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestRB12F14TheReasonsAndStagesAreTheRegisteredClosedSets(t *testing.T) {
	spec := disabledSpec(t)
	if got, want := sortedCopy(spec.Enums["reason"]), sortedCopy(UpgraderDisabledReasons()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("states.json reasons %v, code %v", got, want)
	}
	if got, want := sortedCopy(spec.Enums["stage"]), sortedCopy(StartStages()); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("states.json stages %v, code %v", got, want)
	}
	want := map[string][]string{
		DisabledConfigInvalid:  {"class", "entry", "variable"},
		DisabledSwitchInvalid:  {"variable"},
		DisabledSettingInvalid: {"variable"},
		DisabledPinsInvalid:    {"stage"},
		DisabledWiringFailed:   {"stage"},
		DisabledLaunchFailed:   {"stage"},
		DisabledStartPanicked:  {"stage"},
	}
	got := map[string][]string{}
	for _, c := range spec.ConditionalRequired {
		got[c.When["reason"]] = sortedCopy(c.Required)
	}
	for reason, req := range want {
		if strings.Join(got[reason], ",") != strings.Join(req, ",") {
			t.Errorf("reason %s: registered conditional fields %v, want %v", reason, got[reason], req)
		}
	}
	if len(got) != len(want) {
		t.Errorf("the registry has conditional fields for %d reasons, the code for %d", len(got), len(want))
	}
}

func TestRB12F14EveryReasonStateConformsAndHoldsNoValue(t *testing.T) {
	reg := loadRegistry(t)
	const secret = "hunter2-fake-credential"
	states := []*StateError{
		ConfigInvalidState("CERTEN_FINALITY_ARCHIVE_URLS", 1, "other_scheme"),
		SwitchInvalidState("CERTEN_FINALITY_UPGRADER_ENABLED"),
		SettingInvalidState("CERTEN_FINALITY_MAX_BATCH", 2),
		StartFailedState(DisabledPinsInvalid, StartStagePinsFile, "CERTEN_FINALITY_PINS_FILE", "open https://u:"+secret+"@host.example/p?apikey="+secret+": no such file"),
		StartFailedState(DisabledPinsInvalid, StartStagePinsEmbedded, "", "finality_pins_corrupt"),
		StartFailedState(DisabledPinsInvalid, StartStageGenesisLink, "", "link broken"),
		StartFailedState(DisabledWiringFailed, StartStageKinds, "", "allkinds: kind 3: already registered"),
		StartFailedState(DisabledWiringFailed, StartStageArguments, "", "a registry and a capture store are required"),
		StartFailedState(DisabledLaunchFailed, StartStageLaunch, "", "finality: an upgrader needs a leg source"),
		StartFailedState(DisabledStartPanicked, StartStageStart, "", "runtime error: nil pointer dereference"),
	}
	seen := map[string]bool{}
	for _, st := range states {
		if msg := conforms(reg, st); msg != "" {
			t.Errorf("%s: %s", st.Error(), msg)
		}
		if st.Code != CodeUpgraderDisabled {
			t.Errorf("code %s", st.Code)
		}
		seen[st.Fields["reason"].(string)] = true
		if strings.Contains(st.Error(), secret) {
			t.Errorf("the state holds a credential: %s", st.Error())
		}
		if env, _ := st.Fields["env"].(string); env == "" {
			t.Errorf("%s: env is the label of the metric and must be set", st.Error())
		}
	}
	for _, r := range UpgraderDisabledReasons() {
		if !seen[r] {
			t.Errorf("no state built for the reason %s", r)
		}
	}
}

// The cause of a start failure is text of our own code or of the file system; it is redacted and bounded, so a hostile path or a long
// error cannot fill a log line, a label or a status document.
func TestRB12F14TheCauseIsBoundedAndRedacted(t *testing.T) {
	long := strings.Repeat("x", 5000)
	st := StartFailedState(DisabledWiringFailed, StartStageKinds, "", long)
	c, _ := st.Fields["cause"].(string)
	if len(c) == 0 || len(c) > 300 {
		t.Fatalf("cause length %d", len(c))
	}
	if st2 := StartFailedState(DisabledWiringFailed, StartStageKinds, "", ""); st2.Fields["cause"] != nil {
		t.Fatalf("an empty cause is absent, not invented: %v", st2.Fields)
	}
}
