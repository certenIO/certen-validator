// Copyright 2026 Certen Protocol

package runtime

import (
	"fmt"
	"os"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// LoadPins returns the pins the validator builds and verifies under: the embedded file (hash-checked against
// finality.PinsSHA256; a binary whose embedded bytes do not hash to it refuses to start) unless CERTEN_FINALITY_PINS_FILE names
// an explicit override path, which is parsed without an expected hash and reports pins_source = override:<sha256>. The returned
// source and sha256 are what the startup line and the health endpoint report.
func LoadPins(path string) (pins *finality.Pins, source, sha string, err error) {
	if path == "" {
		pins, err = finality.EmbeddedPins()
	} else {
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, "", "", fmt.Errorf("%s: %s", EnvPinsFile, ethrpc.RedactText(rerr.Error()))
		}
		pins, err = finality.ParsePinsOverride(raw)
	}
	if err != nil {
		return nil, "", "", err
	}
	sha, source = pins.Identity()
	return pins, source, sha, nil
}
