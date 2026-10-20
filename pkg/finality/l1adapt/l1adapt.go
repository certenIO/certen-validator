// Copyright 2026 Certen Protocol

// Package l1adapt is the one adapter between the finality framework (pkg/finality: the pins file, the named states) and the
// Ethereum L1 head verifier (pkg/finality/ethl1: its own Pins and Fault types, which cannot import the framework). Every kind
// that proves its L1 anchor through ethl1 -- Base l1_posted and finalized, Arbitrum l1_posted and finalized -- converts the
// eth_sepolia pins section and the L1 head faults here, so the conversion has one definition.
package l1adapt

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Pins converts the framework's eth_sepolia section into the L1 head verifier's pins. The conversion itself is
// finality.EthSepoliaPins.L1Pins (it lives in pkg/finality because the ledger judges steps with a custom anchor list and
// pkg/finality cannot import this package); this is the entry point every kind uses, with the section's own anchors. The
// framework has already refused a pins file with any malformed hex field (LoadPins), so a decoding failure cannot arise from the
// embedded pins.
func Pins(e *finality.EthSepoliaPins) ethl1.Pins { return e.L1Pins(e.Anchors) }

// PinsOf is the L1 head verifier's view of the eth_sepolia section of a pins file. A file without the section is
// finality_pin_unknown (from Pins.Sepolia).
func PinsOf(p *finality.Pins) (ethl1.Pins, error) {
	e, err := p.Sepolia()
	if err != nil {
		return ethl1.Pins{}, err
	}
	return Pins(e), nil
}

// FaultState adapts an L1 head fault to the framework's state: the same code and the same field names and values.
func FaultState(f *ethl1.Fault) *finality.StateError {
	s := finality.NewState(f.Code)
	for k, v := range f.Fields {
		s.Fields[k] = v
	}
	return s
}

// State adapts err when it is an L1 head fault and returns every other error (nil included) unchanged.
func State(err error) error {
	if f, ok := err.(*ethl1.Fault); ok {
		return FaultState(f)
	}
	return err
}
