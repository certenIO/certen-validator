package metrics

import (
	"strings"
	"testing"
)

// RB12-DBFIX-FIX (verifier V3): the health block says WHY the whole upgrader is off, not only that it is, and the reason is cleared
// when the upgrader is reported on. The reason is a named state; it never holds a URL.
func TestFinalityHealthNamesWhyTheUpgraderIsOff(t *testing.T) {
	resetFinalityHealth()
	h := FinalityHealth()
	if _, ok := h["upgrader_disabled_reason"]; ok {
		t.Fatalf("a reason before anything was reported: %v", h)
	}
	SetFinalityUpgraderDisabledReason("finality_upgrader_disabled{reason=config_invalid,variable=BASE_SEPOLIA_RPC_URL,entry=1}")
	SetFinalityUpgraderEnabled(false)
	h = FinalityHealth()
	if h["upgrader_enabled"] != false || !strings.Contains(h["upgrader_disabled_reason"].(string), "config_invalid") {
		t.Fatalf("the health block does not say why the upgrader is off: %v", h)
	}
	SetFinalityUpgraderEnabled(true)
	if _, ok := FinalityHealth()["upgrader_disabled_reason"]; ok {
		t.Fatalf("the reason outlived the switch being on: %v", FinalityHealth())
	}
	resetFinalityHealth()
}
