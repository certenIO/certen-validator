// Copyright 2026 Certen Protocol

package finality

import (
	"embed"
	"strconv"
	"strings"
)

// pins-links holds the bytes beside the pins file (V2_SPEC_S7 4.3): <period>.ssz is the LightClientUpdate that derived the
// ledger entry of that period (26,424 B for a Gloas period), or, for the root pin, its LightClientBootstrap. They are
// configuration like the pins file itself, never evidence about a block; Pins.Extend and Pins.VerifyLedger re-verify them.
//
//go:embed pins-links/*.ssz
var embeddedLinks embed.FS

// EmbeddedLedgerLinks returns the link files embedded with the pins file, by period.
func EmbeddedLedgerLinks() (map[uint64][]byte, error) {
	ents, err := embeddedLinks.ReadDir("pins-links")
	if err != nil {
		return nil, err
	}
	out := make(map[uint64][]byte, len(ents))
	for _, en := range ents {
		p, err := strconv.ParseUint(strings.TrimSuffix(en.Name(), ".ssz"), 10, 64)
		if err != nil {
			return nil, PinsCorrupt(PinsBadValue, "key", "pins-links/"+en.Name())
		}
		b, err := embeddedLinks.ReadFile("pins-links/" + en.Name())
		if err != nil {
			return nil, err
		}
		out[p] = b
	}
	return out, nil
}
