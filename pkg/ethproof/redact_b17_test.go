// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B17 (V-R10B8 D5): PostgreSQL rejects \u0000 in a jsonb document, so provider text that reaches stored evidence
// holds no NUL byte; and removing the NULs never reveals a key that the NULs had split.
func TestB17_D5_BoundProviderTextHoldsNoNULByte(t *testing.T) {
	defer ethrpc.RegisterProviderURL("https://rpc.example.org/v2/" + b15Key)()
	for _, in := range []string{
		"a\x00b",
		"\x00",
		"\x00\x00\x00 text",
		"Post \"https://h.example.org/v2/" + b15Key[:10] + "\x00" + b15Key[10:] + "\": EOF",
		"echo " + b15Key[:8] + "\x00\x00" + b15Key[8:] + " done",
		"https://h.example.org/v2/" + b15Key[:5] + "\x00" + b15Key[5:],
		"ht\x00tps://h.example.org/v2/secretpathvalue",
		strings.Repeat("\x00", 4<<20),
		strings.Repeat("x\x00", 1<<20),
		strings.Repeat("a", 2000) + "\x00" + strings.Repeat("b", 2000),
	} {
		out := ethproof.BoundProviderText(in)
		if strings.IndexByte(out, 0) >= 0 {
			t.Errorf("%.40q: the bounded text holds a NUL byte", in)
		}
		if len(out) > ethproof.MaxReplayTextBytes || !utf8.ValidString(out) {
			t.Errorf("%.40q: %d bytes, valid=%v", in, len(out), utf8.ValidString(out))
		}
		for _, piece := range []string{b15Key[:16], b15Key[16:]} {
			if w := b15Leak(out, piece, 3); w != "" {
				t.Errorf("%.60q: the fragment %q of the key is in %q", in, w, out)
			}
		}
		if again := ethproof.BoundProviderText(out); again != out {
			t.Errorf("%.40q: not a fixed point: %q then %q", in, out, again)
		}
		// the document the text goes into is writable as jsonb: it holds no \u0000 escape
		doc, err := json.Marshal(struct{ Detail string }{out})
		if err != nil || strings.Contains(string(doc), "\\u0000") {
			t.Errorf("%.40q: the evidence document holds a NUL escape: %s (%v)", in, doc, err)
		}
	}
	if got := ethproof.BoundProviderText("a\x00b"); got != "ab" {
		t.Errorf("a NUL is removed, the rest is kept: %q", got)
	}
}
