// Copyright 2026 Certen Protocol

package baseposted

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-OPS-A1 item 1 (ledger F4/N1 sweep): ParsePins ranged over a Go map of the nine numeric pins, so a file with two zero pins named a
// random one of them. The pins are now judged in sorted-name order; each case is loaded 1,000 times and names the same key every time.
func TestSeveralZeroPinsAreNamedInSortedOrder(t *testing.T) {
	order := []string{"channel_timeout", "channel_timeout_granite", "denim_time", "granite_time", "isthmus_time", "l2_block_time", "l2_genesis_time",
		"max_rlp_bytes_per_channel", "seq_window_size"}
	for i, named := range order {
		m := baseSection(t)
		for _, key := range order[i:] {
			m[key] = 0
		}
		p := pinsWith(t, m)
		for run := 0; run < 1000; run++ {
			_, err := ParsePins(p)
			wantCode(t, err, finality.CodePinsCorrupt, map[string]string{"key": "base_sepolia." + named})
		}
	}
}

// The embedded section is untouched: it loads, and the same every time.
func TestTheEmbeddedBaseSectionLoadsTheSameEveryTime(t *testing.T) {
	p := pinsWith(t, baseSection(t))
	first, err := ParsePins(p)
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 200; run++ {
		again, err := ParsePins(p)
		if err != nil || again.ChainID != first.ChainID || len(again.SystemConfigImplHashes) != len(first.SystemConfigImplHashes) || again.SystemConfig != first.SystemConfig {
			t.Fatalf("load %d: %v", run, err)
		}
	}
}
