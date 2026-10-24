// Copyright 2026 Certen Protocol

package world

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// The three generation files are the live code of their rows: sha256 of the file, keccak256 of the bytes against the evidence row and the
// masked keccak256 against the row.
func TestGenerationRuntimeFilesAreTheCodeOfTheirRows(t *testing.T) {
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, sha, role, gen, kind string
		evidenceChain              uint64
		evidenceAddr               string
	}{
		{GenV7Catalogued, "c23953162c0f45744b404b45b29a3f42c40a035469a6b8befa2194421da119b2", "account", "CertenAccountV7", "catalogued", 84532, "0x0497513411524c4109f5cac62cd599002c2d689b"},
		{GenV7Observed, "51a43d1e9704f7e660a9935948eb33d8ca1eab61cd085fa181c534d0311241a4", "account", "CertenAccountV7", "observed", 11155111, "0x0bbfc288b997736365fb22ad46c95044e128ff40"},
		{GenAnchorV8_1, "c26b98508b4ccdd300a222a9d89cbc25bb0e2031534ea666ce39a7de18b4fefa", "anchor", "CertenAnchorV8_1", "catalogued", 11155111, "0xb39b707d50089c9eb92818f9b2870eba6da5c2a0"},
	} {
		raw, err := codeFS.ReadFile("testdata/code/" + c.name + genRuntimeSuffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != c.sha {
			t.Errorf("%s: file sha256 %x, README says %s", c.name, got, c.sha)
		}
		code, err := GenerationRuntime(c.name)
		if err != nil {
			t.Fatal(err)
		}
		var row *ci.Generation
		for _, g := range m.Generations() {
			if g.Role == c.role && g.Generation == c.gen && g.Kind == c.kind {
				gg := g
				row = &gg
			}
		}
		if row == nil || row.Pinned || row.RuntimeBytes != len(code) {
			t.Fatalf("%s: no unpinned %s %s row of %d bytes", c.name, c.gen, c.kind, len(code))
		}
		if masked := crypto.Keccak256Hash(maskRefs(code, row.References)); masked != common.HexToHash(row.MaskedKeccak) {
			t.Errorf("%s: masked keccak %s, row %s", c.name, masked.Hex(), row.MaskedKeccak)
		}
		found := false
		for _, e := range row.Evidence {
			if e.ChainID == c.evidenceChain && strings.EqualFold(e.Address, c.evidenceAddr) {
				found = true
				if crypto.Keccak256Hash(code) != common.HexToHash(e.CodeHash) {
					t.Errorf("%s: keccak256 of the bytes differs from the evidence codeHash %s", c.name, e.CodeHash)
				}
			}
		}
		if !found {
			t.Errorf("%s: no evidence row for %s on %d", c.name, c.evidenceAddr, c.evidenceChain)
		}
	}
}

func maskRefs(code []byte, refs []ci.Ref) []byte {
	out := append([]byte(nil), code...)
	for _, r := range refs {
		for i := r.Start; i < r.Start+r.Length; i++ {
			out[i] = 0
		}
	}
	return out
}
