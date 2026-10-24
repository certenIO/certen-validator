// Copyright 2026 Certen Protocol

package basefinal

import (
	"testing"
)

// RB12-OPS-A1 item 1 (ledger F4/N1 sweep): ParsePins ranges over the maps impl_pins, proxy_pins and game_layout. Every failure inside a
// loop returns the same value for the section (bad("impl_pins") and so on), whichever row is the bad one, and the rows of a good section
// land under distinct keys (a key must be lower-case hex), so the answer does not depend on the order a map is visited in. Several bad rows
// at once, and bad rows in several sections at once, answer the same on every load; the sections are judged in the order impl_pins,
// proxy_pins, game_layout.
func TestSeveralBadRowsAnswerTheSameEveryLoad(t *testing.T) {
	bad := func(m map[string]any, section string) {
		rows := m[section].(map[string]any)
		rows["0xZZ"] = map[string]any{"role": "x"}                  // not a hash
		rows["0x"+string32('0')] = map[string]any{"role": "x"}      // the zero hash
		rows["0x"+string32('a')] = map[string]any{}                 // no role
		rows["0X"+string32('b')] = map[string]any{"role": "x"}      // upper-case prefix
		rows["0x"+string32('C')] = map[string]any{"role": "x"}      // upper-case digits
		rows["0x"+string32('d')+"00"] = map[string]any{"role": "x"} // 33 bytes
		rows["0x"+string32('e')[:62]] = map[string]any{"role": "x"} // 31 bytes
		rows["0x"+string32('f')] = "not an object"                  // not a row
	}
	for _, c := range []struct {
		name     string
		sections []string
		key      string
	}{
		{"impl_pins alone", []string{"impl_pins"}, "impl_pins"},
		{"proxy_pins alone", []string{"proxy_pins"}, "proxy_pins"},
		{"impl_pins and proxy_pins", []string{"impl_pins", "proxy_pins"}, "impl_pins"},
	} {
		m := baseSection(t)
		for _, s := range c.sections {
			bad(m, s)
		}
		p := pinsWith(t, m)
		for run := 0; run < 1000; run++ {
			_, err := ParsePins(p)
			wantPinsCorrupt(t, c.name, err, c.key)
		}
	}
	// several bad layouts, and a bad layout beside a bad proxy row: proxy_pins is judged first
	m := baseSection(t)
	layouts := m["game_layout"].(map[string]any)
	layouts["zz_not_hex"] = map[string]any{"clone_head": "nothex", "clone_mid": "0x", "clone_tail": "0x", "args_base_len": 136, "args_per_root": 32}
	layouts["aa_short_base"] = map[string]any{"clone_head": "0x", "clone_mid": "0x", "clone_tail": "0x", "args_base_len": 1, "args_per_root": 32}
	layouts["mm_short_root"] = map[string]any{"clone_head": "0x", "clone_mid": "0x", "clone_tail": "0x", "args_base_len": 136, "args_per_root": 1}
	p := pinsWith(t, m)
	for run := 0; run < 1000; run++ {
		_, err := ParsePins(p)
		wantPinsCorrupt(t, "several bad layouts", err, "game_layout")
	}
	bad(m, "proxy_pins")
	p = pinsWith(t, m)
	for run := 0; run < 1000; run++ {
		_, err := ParsePins(p)
		wantPinsCorrupt(t, "bad proxy row and bad layouts", err, "proxy_pins")
	}
}

func string32(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
