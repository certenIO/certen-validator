// Copyright 2026 Certen Protocol

package world

import (
	"embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The REAL runtime code of the pinned builds. Each file of testdata/code is the runtime bytes a live chain serves (cast code), with every
// immutable reference range zeroed: exactly the bytes whose keccak256 is the manifest maskedKeccak of the build (the manifest maskRule).
// A world fills the immutables of its own chain / account into a copy. testdata/code/README.md lists the source of each file.
//
//go:embed testdata/code/*.hex
var codeFS embed.FS

func readHexFile(name string) ([]byte, error) {
	raw, err := codeFS.ReadFile("testdata/code/" + name)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

func buildFile(buildKey, suffix string) string {
	return strings.Replace(buildKey, "/", ".", 1) + suffix
}

// Template is the masked runtime template of a build ("Contract/variant").
func Template(buildKey string) ([]byte, error) {
	return readHexFile(buildFile(buildKey, ".template.hex"))
}

// CreationCode is the creation code of the account build (the CREATE2 input of step 8).
func CreationCode(buildKey string) ([]byte, error) {
	return readHexFile(buildFile(buildKey, ".creation.hex"))
}

// Mask zeroes every reference range of every immutable of the build in a copy of code.
func Mask(code []byte, b ci.Build) ([]byte, error) {
	out := append([]byte{}, code...)
	for _, imm := range b.Immutables {
		for _, r := range imm.References {
			if r.Start < 0 || r.Length < 0 || r.Start+r.Length > len(out) {
				return nil, fmt.Errorf("immutable %s reference [%d,+%d) is outside the %d byte code", imm.Name, r.Start, r.Length, len(out))
			}
			for i := r.Start; i < r.Start+r.Length; i++ {
				out[i] = 0
			}
		}
	}
	return out, nil
}

// MaskedKeccak is keccak256 of the masked code.
func MaskedKeccak(code []byte, b ci.Build) (common.Hash, error) {
	m, err := Mask(code, b)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(crypto.Keccak256(m)), nil
}

// Fill writes the 32-byte value of each immutable at every one of its references in a copy of template. Every immutable of the build needs a
// value and a value for a name the build does not have is refused.
func Fill(template []byte, b ci.Build, vals map[string]common.Hash) ([]byte, error) {
	out := append([]byte{}, template...)
	used := map[string]bool{}
	for _, imm := range b.Immutables {
		v, ok := vals[imm.Name]
		if !ok {
			return nil, fmt.Errorf("build %s: no value for the immutable %s", b.Key(), imm.Name)
		}
		used[imm.Name] = true
		for _, r := range imm.References {
			if r.Length != 32 || r.Start < 0 || r.Start+32 > len(out) {
				return nil, fmt.Errorf("build %s: immutable %s reference [%d,+%d) is not a 32-byte slot of the code", b.Key(), imm.Name, r.Start, r.Length)
			}
			copy(out[r.Start:r.Start+32], v[:])
		}
	}
	for name := range vals {
		if !used[name] {
			return nil, fmt.Errorf("build %s has no immutable %s", b.Key(), name)
		}
	}
	return out, nil
}
