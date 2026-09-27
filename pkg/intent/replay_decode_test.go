// Copyright 2026 Certen Protocol

package intent

import (
	"strings"
	"testing"
)

// RB3-F100: replay protection that does not decode is refused at intent build, by name. It used to be
// decoded into a discarded value with the error ignored.
func TestReplayProtectionThatDoesNotDecodeIsRefused(t *testing.T) {
	intentBlob := map[string]interface{}{"intent_id": "f100", "proof_class": "on_cadence"}
	gov := map[string]interface{}{"organizationAdi": "acc://harbor.acme"}
	cross := map[string]interface{}{}
	tx := strings.Repeat("a1", 32)

	for name, replay := range map[string]map[string]interface{}{
		"expiry not a number": {"expires_at": "soon"},
		"negative expiry":     {"expires_at": -1},
	} {
		if _, err := BuildCertenIntent(tx, intentBlob, cross, gov, replay); err == nil || !strings.Contains(err.Error(), "replay protection") {
			t.Errorf("%s: built (%v)", name, err)
		}
	}
	for name, replay := range map[string]map[string]interface{}{
		"well formed": {"expires_at": 1790600000},
		"absent":      nil,
	} {
		if _, err := BuildCertenIntent(tx, intentBlob, cross, gov, replay); err != nil && strings.Contains(err.Error(), "replay protection") {
			t.Errorf("%s: refused for its replay protection: %v", name, err)
		}
	}
}
