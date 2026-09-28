package proof

import (
	"errors"
	"testing"
)

// RB4-F13: an intent that declared no key book or page has no signing key page - a fact about the intent,
// typed as such so its failure is classed governance_unsatisfied rather than as an outage.
func TestNoDeclaredBookIsNoSigningKeyPage(t *testing.T) {
	_, err := keyBookFor("", "")
	if !errors.Is(err, ErrNoSigningKeyPage) {
		t.Fatalf("want ErrNoSigningKeyPage, got %v", err)
	}
}
