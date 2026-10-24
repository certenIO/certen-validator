package contractidentity

import (
	"strings"
	"testing"
)

// RB12-CLOSE-5 [r3.6:H13, r3.6:H14]: the retirement rule of manifest item 7 and the canonical spelling of a hex key are exact. A row that
// ends before it starts, and a generations key that is not 0x + 64 lower-case hex digits, are refused by name, never repaired.

func wantManifestCorrupt(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want %s", what, CodeManifestCorrupt)
	}
	st, ok := AsState(err)
	if !ok || st.Code != CodeManifestCorrupt {
		t.Fatalf("%s: got %v, want %s", what, err, CodeManifestCorrupt)
	}
}

func TestR36GenerationKeysMustBeCanonical(t *testing.T) {
	m := embeddedOK(t)
	row := func(role, masked string) map[string]any {
		return map[string]any{"role": role, "generation": "CertenAccountV7", "pinned": false, "kind": "observed", "maskedKeccak": masked, "runtimeBytes": 1, "references": []any{}, "source": "x"}
	}
	ext := func(role, masked string) []byte {
		return marshal(t, map[string]any{"schema": ManifestSchema, "generations": []any{row(role, masked)}})
	}
	canon := "0x" + strings.Repeat("c9", 32)
	if _, err := m.WithExtension(ext("account", canon)); err != nil {
		t.Fatalf("canonical control: %v", err)
	}
	spellings := map[string]string{
		"upper-case digits": "0x" + strings.Repeat("C9", 32),
		"mixed case":        "0x" + strings.Repeat("c9", 16) + strings.Repeat("C9", 16),
		"upper-case prefix": "0X" + strings.Repeat("c9", 32),
		"no prefix":         strings.Repeat("c9", 32),
		"31 bytes":          "0x" + strings.Repeat("c9", 31),
		"33 bytes":          "0x" + strings.Repeat("c9", 33),
		"surrounding space": " " + canon + " ",
		"empty":             "",
	}
	for name, s := range spellings {
		name, s := name, s
		t.Run(name, func(t *testing.T) {
			_, err := m.WithExtension(ext("account", s))
			wantManifestCorrupt(t, err, name)
		})
	}
	// the other spelling of an EXISTING key is not a shadow and not lower-cased into one: it is refused as not canonical
	var g Generation
	for _, c := range m.Generations() {
		if strings.ToUpper(c.MaskedKeccak[2:]) != c.MaskedKeccak[2:] {
			g = c
			break
		}
	}
	if g.MaskedKeccak == "" {
		t.Fatal("no generations row with a letter in its hash")
	}
	up := "0x" + strings.ToUpper(g.MaskedKeccak[2:])
	_, err := m.WithExtension(ext(g.Role, up))
	wantManifestCorrupt(t, err, "upper-case spelling of the existing key "+g.MaskedKeccak)
	// a whole manifest (override form) is held to the same spelling
	raw := readTestdata(t, "manifest/identity-manifest.json")
	if _, err := LoadOverride(raw); err != nil {
		t.Fatalf("override control: %v", err)
	}
	bad := strings.Replace(string(raw), "\""+g.MaskedKeccak+"\"", "\""+up+"\"", 1)
	if bad == string(raw) {
		t.Fatal("setup: the row was not found in the manifest text")
	}
	_, err = LoadOverride([]byte(bad))
	wantManifestCorrupt(t, err, "override with an upper-case generations key")
}

func TestR36ValidToBeforeValidFromIsRefused(t *testing.T) {
	m := embeddedOK(t)
	const chain = 11155111
	lastO, lastS := uint64(0), uint64(0)
	for _, r := range m.OwnerRows(chain, "anchor") {
		if r.ValidFromBlock > lastO {
			lastO = r.ValidFromBlock
		}
	}
	for _, r := range m.SetRootRows(chain) {
		if r.ValidFromBlock > lastS {
			lastS = r.ValidFromBlock
		}
	}
	owner := func(from uint64, to any) []byte {
		row := map[string]any{"role": "anchor", "address": "0x" + strings.Repeat("33", 20), "validFromBlock": from}
		if to != nil {
			row["validToBlock"] = to
		}
		return marshal(t, map[string]any{"schema": ManifestSchema, "policy": map[string]any{"owner": map[string]any{"11155111": []any{row}}}})
	}
	setRoot := func(from uint64, to any) []byte {
		row := map[string]any{"chainId": chain, "root": "0x" + strings.Repeat("d1", 32), "validFromBlock": from, "thresholdNumerator": 2, "thresholdDenominator": 3}
		if to != nil {
			row["validToBlock"] = to
		}
		return marshal(t, map[string]any{"schema": ManifestSchema, "policy": map[string]any{"setRootHistory": []any{row}}})
	}
	fo, fs := lastO+10, lastS+10
	for _, c := range []struct {
		name string
		ext  []byte
		bad  bool
	}{
		{"owner open row", owner(fo, nil), false},
		{"owner one-block row", owner(fo, fo), false},
		{"owner validTo after validFrom", owner(fo, fo+5), false},
		{"owner validTo one before validFrom", owner(fo, fo-1), true},
		{"owner validTo zero", owner(fo, 0), true},
		{"setRoot open row", setRoot(fs, nil), false},
		{"setRoot one-block row", setRoot(fs, fs), false},
		{"setRoot validTo one before validFrom", setRoot(fs, fs-1), true},
		{"setRoot validTo zero", setRoot(fs, 0), true},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			_, err := m.WithExtension(c.ext)
			if c.bad {
				wantManifestCorrupt(t, err, c.name)
			} else if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		})
	}
}

// [r3.6:H13] the last block a row is valid at is the smaller of its stored validToBlock and the next row's validFromBlock - 1: a stored
// validToBlock that already ends earlier wins and is never extended.
func TestR36RetirementEndsAtTheEarlierOfStoredAndNext(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }
	for _, c := range []struct {
		name     string
		from     uint64
		to, next *uint64
		end      uint64
		open     bool
	}{
		{"open row, no successor", 10, nil, nil, 0, true},
		{"successor retires an open row at next-1", 10, nil, u(20), 19, false},
		{"a stored validTo that ends earlier wins", 10, u(15), u(20), 15, false},
		{"a stored validTo after next-1 is cut to next-1", 10, u(25), u(20), 19, false},
		{"stored validTo without successor", 10, u(15), nil, 15, false},
	} {
		end, open := effectiveEnd(c.from, c.to, c.next)
		if end != c.end || open != c.open {
			t.Errorf("%s: effectiveEnd = (%d, %v), want (%d, %v)", c.name, end, open, c.end, c.open)
		}
	}
}
