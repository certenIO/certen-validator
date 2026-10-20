// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B15 (V-R10B6 D1 D2 D3, jsonb note): the bound on provider text is one rule - cut, redact, end at a token boundary -
// so that no fragment of a key survives the 64 KiB read cut or the 1024 cut, the bound is exact, and a second pass is a fixed point.

const b15Key = "ZkQ9xPLm2Tn7VbR4sWcY8dHgJf1A5eUo"

const b15ReadCut = 64 << 10

func b15bs(s string) string { return strings.ReplaceAll(s, "~", "\x5c") }

func b15Rep(unit string, total int) string { return strings.Repeat(unit, total/len(unit)) }

func b15Pad(n int) string {
	if n <= 0 {
		return ""
	}
	s := b15Rep("lorem ipsum dolor sit amet ", n+len("lorem ipsum dolor sit amet "))
	return s[:n]
}

func b15Leak(out, key string, n int) string {
	for i := 0; i+n <= len(key); i++ {
		if w := key[i : i+n]; strings.Contains(out, w) {
			return w
		}
	}
	return ""
}

var b15Forms = []struct {
	name, before, after string
	register            bool
	parts               int
}{
	{"registered literal", " ", " and more text after the key", true, 1},
	{"path of a URL", " https://rpc.example.org/v2/", " and more text after the key", false, 1},
	{"userinfo password of a URL", " https://user:", "@h.example.org/x and more text after the key", false, 1},
	{"bare userinfo", " user:", "@h.example.org/x and more text after the key", false, 1},
	{"quoted URL wrapped at white space", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, 2},
	{"JSON-escaped URL", b15bs(" https:~/~/rpc.example.org~/v2~/"), " and more text after the key", false, 1},
	{"percent-encoded URL", " https%3A%2F%2Frpc.example.org%2Fv2%2F", " and more text after the key", false, 1},
}

func b15KeyText(parts int) (string, []string) {
	if parts == 1 {
		return b15Key, []string{b15Key}
	}
	p := []string{b15Key[:16], b15Key[16:]}
	return p[0] + " " + p[1], p
}

// The key starts at every offset from 300 bytes before the 64 KiB read cut to just after it, behind a long URL that
// redaction collapses to a few bytes (the redacted prefix is then short, and V-R10B6 D1 showed the partial key whole).
func TestB15_V6D1_NoFragmentOfAKeySurvivesTheReadCut(t *testing.T) {
	for _, f := range b15Forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			if f.register {
				defer ethrpc.RegisterProviderURL("https://rpc.example.org/v2/" + b15Key)()
			}
			keyText, pieces := b15KeyText(f.parts)
			head := "https://h.example.org/"
			for _, kind := range []string{"collapsing", "plain"} {
				for off := -300; off <= 8; off++ {
					start := b15ReadCut + off - len(f.before)
					if start < 80 {
						continue
					}
					front := b15Pad(start)
					if kind == "collapsing" {
						front = head + strings.Repeat("a", start-len(head)-1) + " "
					}
					in := front + f.before + keyText + f.after + b15Pad(3000)
					out := ethproof.BoundProviderText(in)
					if len(out) > ethproof.MaxReplayTextBytes {
						t.Fatalf("%s offset %d: %d bytes", kind, off, len(out))
					}
					for _, piece := range pieces {
						if w := b15Leak(out, piece, 3); w != "" {
							t.Fatalf("%s offset %d: the fragment %q of the key is in the bounded text %q", kind, off, w, out)
						}
					}
					if again := ethproof.BoundProviderText(out); again != out {
						t.Fatalf("%s offset %d: a second pass changed the text:\n%q\n%q", kind, off, out, again)
					}
				}
			}
		})
	}
}

// The same around byte 1024 of the redacted text, behind a collapsed URL and behind a run of tokens that redaction lengthens.
func TestB15_V6D1_NoFragmentOfAKeySurvivesThe1024Cut(t *testing.T) {
	for _, f := range b15Forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			if f.register {
				defer ethrpc.RegisterProviderURL("https://rpc.example.org/v2/" + b15Key)()
			}
			keyText, pieces := b15KeyText(f.parts)
			for _, kind := range []string{"collapsing", "expanding", "plain"} {
				for off := -300; off <= 8; off++ {
					target := ethproof.MaxReplayTextBytes + off - len(f.before) // where the key starts in the redacted text
					if target < 120 {
						continue
					}
					var front string
					switch kind {
					case "collapsing":
						front = "https://h.example.org/" + strings.Repeat("a", 5000) + " " + b15Pad(target-len("https://h.example.org/<redacted>")-1)
					case "expanding":
						grown := len("x://h/<redacted> ")
						reps := (target - 8) / grown
						front = strings.Repeat("x://h/y ", reps) + b15Pad(target-reps*grown)
					default:
						front = b15Pad(target)
					}
					in := front + f.before + keyText + f.after + b15Pad(2000)
					out := ethproof.BoundProviderText(in)
					if len(out) > ethproof.MaxReplayTextBytes {
						t.Fatalf("%s offset %d: %d bytes", kind, off, len(out))
					}
					for _, piece := range pieces {
						if w := b15Leak(out, piece, 3); w != "" {
							t.Fatalf("%s offset %d: the fragment %q of the key is in the bounded text %q", kind, off, w, out)
						}
					}
					if again := ethproof.BoundProviderText(out); again != out {
						t.Fatalf("%s offset %d: a second pass changed the text:\n%q\n%q", kind, off, out, again)
					}
				}
			}
		})
	}
}

// V-R10B6 D2: the bound is exact when redaction lengthens the text (a tiny scheme and path grows under /<redacted>).
func TestB15_V6D2_TheBoundHoldsWhenRedactionLengthensTheText(t *testing.T) {
	unit := "x://h/y "
	for n := 1; n <= 4000; n++ {
		in := b15Rep(unit, n+len(unit))[:n]
		if out := ethproof.BoundProviderText(in); len(out) > ethproof.MaxReplayTextBytes {
			t.Fatalf("a text of %d bytes became %d bytes", n, len(out))
		}
	}
	if out := ethproof.BoundProviderText(b15Rep(unit, 947+len(unit))[:947]); len(out) > 1024 {
		t.Fatalf("the reviewer's input became %d bytes", len(out))
	}
}

var b15Suffix = regexp.MustCompile(`…\(truncated ([0-9]+) bytes\)$`)

// For text with nothing to redact the suffix counts exactly the bytes that are not shown, whatever the digits.
func TestB15_V6D2_TheSuffixCountsTheBytesNotShown(t *testing.T) {
	for _, n := range []int{1025, 1026, 1100, 1500, 3000, 10000, 70000, 200000} {
		for _, word := range []string{"a", "é", "ab cd ef gh "} {
			in := b15Rep(word, n+len(word))[:n]
			for !utf8.ValidString(in) {
				in = in[:len(in)-1]
			}
			if len(in) <= ethproof.MaxReplayTextBytes {
				continue
			}
			out := ethproof.BoundProviderText(in)
			m := b15Suffix.FindStringSubmatch(out)
			if m == nil || len(out) > 1024 {
				t.Fatalf("n=%d %q: no suffix or too long (%d): %q", n, word, len(out), tailOf(out))
			}
			dropped, _ := strconv.Atoi(m[1])
			kept := strings.TrimSuffix(out[:len(out)-len(m[0])], " ")
			if !strings.HasPrefix(in, kept) || dropped != len(in)-len(kept) {
				t.Fatalf("n=%d %q: kept %d bytes and says %d were dropped of %d", n, word, len(kept), dropped, len(in))
			}
		}
	}
}

func tailOf(s string) string {
	if len(s) > 100 {
		return "…" + s[len(s)-100:]
	}
	return s
}

var b15Vocab = []string{"https://", "http://", "ws://", "x://", "h.io/", "h.io", "/v2/", "KEYabc123XYZ", " ", " ", "\n", `"`, "'", "`", "<", ">",
	b15bs("~/"), b15bs("~u002f"), b15bs("~n"), "%2F", "%252F", "é", "日", "😀", "x://h/y ", "@", ":", "?k=", "&", "#",
	"…(truncated 5 bytes)", " …(truncated 5 bytes)", "<redacted>", "a", "0x00ab", "user:pw@", "h.example.org", ".", "[::1]:8545/", "\xff"}

// V-R10B6 D3: 20 000 hostile texts, the bound holds and a second pass is a fixed point (117 of 4000 were not).
func TestB15_V6D3_BoundingIsAFixedPointOver20000Texts(t *testing.T) {
	r := rand.New(rand.NewSource(15))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		long := i%100 == 0
		for n := 1 + r.Intn(60); n > 0 || long && b.Len() <= b15ReadCut+r.Intn(3000); n-- {
			b.WriteString(b15Vocab[r.Intn(len(b15Vocab))])
		}
		if i%3 == 0 { // words in front, so that the cut lands inside the vocabulary text
			s := b.String()
			b.Reset()
			b.WriteString(b15Pad(r.Intn(1100)))
			b.WriteString(s)
		}
		in := b.String()
		out := ethproof.BoundProviderText(in)
		if len(out) > ethproof.MaxReplayTextBytes {
			t.Fatalf("input %d (%d bytes) became %d bytes", i, len(in), len(out))
		}
		if again := ethproof.BoundProviderText(out); again != out {
			t.Fatalf("input %d (%d bytes) is not a fixed point:\n%q\n%q", i, len(in), tailOf(out), tailOf(again))
		}
	}
	// the reviewer's shape: the cut lands inside a URL token
	for pad := 900; pad < 1100; pad++ {
		in := strings.Repeat("x", pad-10) + " ws://h/" + strings.Repeat("p", 400)
		out := ethproof.BoundProviderText(in)
		if again := ethproof.BoundProviderText(out); again != out {
			t.Fatalf("pad %d: %q then %q", pad, tailOf(out), tailOf(again))
		}
	}
}

// jsonbLen is the length of the text form PostgreSQL's jsonb writes for compact JSON: one space is added after every ':'
// and ',' that is outside a string.
func jsonbLen(raw []byte) int {
	n, inString, escaped := len(raw), false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString:
			if c == '\x5c' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
		case c == ':' || c == ',':
			n++
		}
	}
	return n
}

// The guard measures the form a stored layer-6 member is read back in (jsonb), not the compact form it was marshalled in.
func TestB15_Jsonb_TheEmissionGuardMeasuresTheStoredForm(t *testing.T) {
	tx, blk := common.Hash{0x07}, common.Hash{0x08}
	evidence := func(providers int) *ethproof.ReplayGuardEvidence {
		st := &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: 1, TxHash: tx, BlockNumber: 9, BlockHash: blk}
		st.Providers = make([]ethproof.ReplayProviderFailure, providers)
		for i := range st.Providers {
			st.Providers[i] = ethproof.ReplayProviderFailure{Host: "h", Error: "e"}
		}
		return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: st}
	}
	// many tiny fields: the compact size is just under the cap, the stored size is over it
	one, _ := json.Marshal(evidence(1))
	two, _ := json.Marshal(evidence(2))
	per := len(two) - len(one)
	n := (ethproof.MaxReplayEvidenceBytes-len(one))/per + 1
	for ; ; n-- {
		raw, _ := json.Marshal(evidence(n))
		if len(raw) <= ethproof.MaxReplayEvidenceBytes {
			break
		}
	}
	ev := evidence(n)
	compact, _ := json.Marshal(ev)
	stored := jsonbLen(compact)
	if len(compact) > ethproof.MaxReplayEvidenceBytes || len(compact) < ethproof.MaxReplayEvidenceBytes-per || stored <= ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the test evidence is %d bytes compact and %d stored", len(compact), stored)
	}
	got := ethproof.BoundReplayEvidence(ev, 1, tx)
	if got == ev || got.State == nil || got.State.Reason != ethproof.ReasonStateUnavailable || got.State.BlockNumber != 9 || got.State.BlockHash != blk {
		t.Fatalf("evidence that is %d bytes stored was kept: %+v", stored, got)
	}
	if want := fmt.Sprintf("the evidence would be %d bytes", stored); !strings.Contains(got.State.Detail, want) || !strings.Contains(got.State.Detail, "more than the 4194304") {
		t.Fatalf("the reason does not state the stored size %d: %s", stored, got.State.Detail)
	}
	if b, _ := json.Marshal(got); jsonbLen(b) > ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the replacement is itself %d bytes stored", jsonbLen(b))
	}

	// the boundary is exact on the stored form: a document of exactly the cap is kept, one byte more is replaced
	exact := func(extra int) *ethproof.ReplayGuardEvidence {
		ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven,
			Reason: ethproof.ReasonStateUnavailable, ChainID: 1, TxHash: tx, BlockNumber: 9, BlockHash: blk, Detail: "x"}}
		b, _ := json.Marshal(ev)
		ev.State.Detail = strings.Repeat("x", 1+ethproof.MaxReplayEvidenceBytes-jsonbLen(b)+extra)
		return ev
	}
	atCap, pastCap := exact(0), exact(1)
	if b, _ := json.Marshal(atCap); jsonbLen(b) != ethproof.MaxReplayEvidenceBytes {
		t.Fatalf("the boundary evidence is %d bytes stored", jsonbLen(b))
	}
	if ethproof.BoundReplayEvidence(atCap, 1, tx) != atCap {
		t.Fatal("evidence of exactly the cap in its stored form was replaced")
	}
	if b, _ := json.Marshal(pastCap); jsonbLen(b) != ethproof.MaxReplayEvidenceBytes+1 {
		t.Fatalf("the evidence one past the cap is %d bytes stored", jsonbLen(b))
	}
	if r := ethproof.BoundReplayEvidence(pastCap, 1, tx); r == pastCap || r.State == nil || !strings.Contains(r.State.Detail, "the evidence would be 4194305 bytes") {
		t.Fatalf("evidence one byte past the cap in its stored form was kept: %+v", r)
	}
}
