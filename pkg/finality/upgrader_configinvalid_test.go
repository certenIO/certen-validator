// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-DBFIX-FIX (verifier V3): a provider setting the runtime refuses switches the finality upgrader off as a NAMED state through the
// same announcement every other whole-upgrader off state uses, and says which variable and which entry, never the value.
func TestConfigInvalidIsANamedUpgraderDisabledStateWithVariableAndEntry(t *testing.T) {
	st := ConfigInvalidState("BASE_SEPOLIA_RPC_URL", 1, "bad_escape")
	if st.Code != CodeUpgraderDisabled || st.Fields["reason"] != "config_invalid" || st.Fields["variable"] != "BASE_SEPOLIA_RPC_URL" || st.Fields["entry"] != 1 || st.Fields["class"] != "bad_escape" {
		t.Fatalf("%v", st)
	}
	if !strings.Contains(st.Error(), "consensus") {
		t.Fatalf("the effect must say the validator itself is unaffected: %s", st.Error())
	}
	logs := &logSink{}
	AnnounceUpgraderDisabled(logs.Logf, st)
	out := logs.Joined()
	for _, want := range []string{CodeUpgraderDisabled, "DISABLED", "config_invalid", "BASE_SEPOLIA_RPC_URL", `entry="1"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("the announcement lacks %q:\n%s", want, out)
		}
	}
	h := metrics.FinalityHealth()
	if h["upgrader_enabled"] != false || !strings.Contains(h["upgrader_disabled_reason"].(string), "config_invalid") {
		t.Fatalf("the health block does not carry the state: %v", h)
	}
}

// The switch's own off state goes through the same announcement and now carries its reason in the health block too.
func TestTheOffSwitchCarriesItsReasonInTheHealthBlock(t *testing.T) {
	logs := &logSink{}
	if u, err := Launch(context.Background(), false, &memSource{}, newMemStore(), NewRegistry(), nil, UpgraderConfig{Logf: logs.Logf}); err != nil || u != nil {
		t.Fatalf("%v %v", u, err)
	}
	h := metrics.FinalityHealth()
	if h["upgrader_enabled"] != false || !strings.Contains(h["upgrader_disabled_reason"].(string), EnvEnabled) {
		t.Fatalf("%v", h)
	}
}
