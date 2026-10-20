// Copyright 2026 Certen Protocol

package allkinds_test

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
	"github.com/certen/independant-validator/pkg/finality/allkinds"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/basefinal"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// Every implemented kind is registered by the one call, each exactly once: a kind registered again is refused with the
// registry's "already has a verifier", which proves it is there, and a second allkinds.Register is refused at the first kind.
func TestRegisterAddsEveryImplementedKindExactlyOnce(t *testing.T) {
	reg := finality.NewRegistry()
	if err := allkinds.Register(reg); err != nil {
		t.Fatal(err)
	}
	for name, register := range map[string]func(*finality.Registry) error{
		adiri.Name: adiri.Register, baseposted.KindName: baseposted.Register, basefinal.KindName: basefinal.Register, arbposted.KindName: arbposted.Register, arbfinal.KindName: arbfinal.Register,
	} {
		if err := register(reg); err == nil || !strings.Contains(err.Error(), "already has a verifier") || !strings.Contains(err.Error(), name) {
			t.Errorf("kind %s is not registered by allkinds.Register: %v", name, err)
		}
	}
	if len(allkinds.Kinds()) != 5 {
		t.Errorf("allkinds registers %d kinds, the five implemented so far are adiri, base l1_posted, base finalized, arbitrum l1_posted and arbitrum finalized", len(allkinds.Kinds()))
	}
	if err := allkinds.Register(reg); err == nil || !strings.Contains(err.Error(), "allkinds: kind 0") {
		t.Errorf("a second Register was not refused at the first kind: %v", err)
	}
}

// Each kind registers into a registry on its own (no kind depends on another having been registered), and the default registry
// is left untouched by this package: registration is explicit, never an init().
func TestEveryKindRegistersAloneAndTheDefaultRegistryIsNotTouchedByImport(t *testing.T) {
	for i, register := range allkinds.Kinds() {
		if err := register(finality.NewRegistry()); err != nil {
			t.Errorf("kind %d: %v", i, err)
		}
	}
	if err := adiri.Register(finality.Default); err != nil {
		t.Fatalf("importing allkinds registered into finality.Default: %v", err)
	}
}
