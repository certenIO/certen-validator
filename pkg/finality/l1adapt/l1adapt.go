// Copyright 2026 Certen Protocol

// Package l1adapt is the one adapter between the finality framework (pkg/finality: the pins file, the named states) and the
// Ethereum L1 head verifier (pkg/finality/ethl1: its own Pins and Fault types, which cannot import the framework). Every kind
// that proves its L1 anchor through ethl1 -- Base l1_posted and finalized, Arbitrum l1_posted and finalized -- converts the
// eth_sepolia pins section and the L1 head faults here, so the conversion has one definition.
package l1adapt

import (
	"encoding/hex"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// unhex decodes a 0x-prefixed lower-case hex string of exactly n bytes; anything else yields (nil, false). The framework has
// already refused a pins file with any other shape (LoadPins), so a failure here cannot arise from the embedded pins.
func unhex(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") || s != strings.ToLower(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil && len(b) == n
}

// Pins converts the framework's eth_sepolia section into the L1 head verifier's pins.
func Pins(e *finality.EthSepoliaPins) ethl1.Pins {
	var p ethl1.Pins
	p.Network.ChainID = e.ChainID
	gvr, _ := unhex(e.GenesisValidatorsRoot, 32)
	copy(p.Network.GenesisValidatorsRoot[:], gvr)
	for _, f := range e.Forks {
		fk := ethl1.Fork{Name: f.Name, Epoch: f.Epoch}
		v, _ := unhex(f.Version, 4)
		copy(fk.Version[:], v)
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				fk.Layout = ethl1.LayoutElectra
			case "gloas":
				fk.Layout = ethl1.LayoutGloas
			}
		}
		p.Network.Forks = append(p.Network.Forks, fk)
	}
	for _, a := range e.Anchors {
		an := ethl1.Anchor{Period: a.Period, WSPEpochs: a.WspEpochs}
		cr, _ := unhex(a.CommitteeRoot, 32)
		copy(an.CommitteeRoot[:], cr)
		if a.BlockRoot != "" {
			br, _ := unhex(a.BlockRoot, 32)
			var b32 [32]byte
			copy(b32[:], br)
			an.BlockRoot = &b32
		}
		p.Anchors = append(p.Anchors, an)
	}
	p.MinParticipants, p.MaxLinks, p.MaxSpineHeaders = e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders
	return p
}

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
