package ethrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/ethclient"
)

// RB10-B17 (V-R10B8 D1 D2): the cut of the 64 KiB read bound is one linear pass, and the redaction is a fixed point also when a
// registered literal stands in the host of a quoted URL.

// b17AltUnits are quoted URLs that close each other: the closing quote of one is the opening quote of the next, so that
// dropping the last open URL leaves the one before it open (3.5 s for 70 KiB before RB10-B17).
var b17AltUnits = []struct{ name, unit string }{
	{"alt-quotes", `"a://b 'a://b `},
	{"alt-quotes-nospace", `"a://b'a://b`},
	{"alt-quotes-2", `"a://b 'a://c "a://d 'a://e `},
	{"alt-quotes-3", "\"a://b 'a://b `a://b "},
	{"alt-quotes-long", `"a://b/some/long/path/KEY1 'a://b/some/long/path/KEY2 `},
}

// b17Register registers n distinct provider URLs (the 24 000 literals of a large deployment) and returns the undo.
func b17Register(n int) func() {
	undos := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		undos = append(undos, RegisterProviderURL(fmt.Sprintf("https://host%d.example.org/v2/KEY%dabcdefghij?token=TOK%dxyz&b=Zk%dQ9xPLm2Tn7", i, i, i, i)))
	}
	return func() {
		for _, u := range undos {
			u()
		}
	}
}

// Every entry point that redacts a provider's text, each bounded at 250 ms.
func TestB17_D1_TheAlternatingQuoteShapesAreRedactedInBoundedTimeAtEveryEntryPoint(t *testing.T) {
	for _, registered := range []int{0, 3000} {
		for _, size := range []int{70 << 10, 4 << 20} {
			for _, u := range b17AltUnits {
				name := fmt.Sprintf("%s %dKiB %d registered", u.name, size>>10, registered)
				text := b15Rep(u.unit, size)
				t.Run(name, func(t *testing.T) {
					if registered > 0 {
						defer b17Register(registered)()
						_ = RedactText("warm the registry up") // the rebuild is paid once, outside the timed calls
					}
					slow := func(entry string, limit time.Duration, f func()) {
						t0 := time.Now()
						f()
						if d := time.Since(t0); d > limit {
							t.Fatalf("%s took %s for %d bytes", entry, d, len(text))
						}
					}
					var out string
					slow("RedactText", 250*time.Millisecond, func() { out = RedactText(text) })
					if len(out) > b15Cut || !utf8.ValidString(out) || !strings.Contains(out, "(truncated ") {
						t.Fatalf("RedactText returned %d bytes, valid=%v: %q", len(out), utf8.ValidString(out), tailOf(out))
					}
					slow("RedactError and two Error calls", 250*time.Millisecond, func() {
						e := RedactError(errors.New(text))
						_, _ = e.Error(), e.Error()
					})
					slow("TransientError.Error", 250*time.Millisecond, func() {
						_ = (&TransientError{Host: "h", Attempts: 1, Err: errors.New(text)}).Error()
					})
					slow("BoundRedacted at 1024", 250*time.Millisecond, func() { out = BoundRedacted(text, 1024) })
					if len(out) > 1024 || !utf8.ValidString(out) {
						t.Fatalf("BoundRedacted(.., 1024) returned %d bytes, valid=%v", len(out), utf8.ValidString(out))
					}
					if again := BoundRedacted(out, 1024); again != out {
						t.Fatalf("not a fixed point: %q then %q", tailOf(out), tailOf(again))
					}
				})
			}
		}
	}
}

// The real pool: endpoint 0 answers 403 with a 3.9 MB body of the shape, endpoint 1 is healthy. Do answers in under a
// second, and Primary is never blocked while the failure is recorded.
func TestB17_D1_APoolAnswersInUnderASecondWithAnAlternatingQuoteErrorBody(t *testing.T) {
	for _, u := range b17AltUnits {
		u := u
		t.Run(u.name, func(t *testing.T) {
			body := b15Rep(u.unit, 3_900_000)
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				http.Error(w, body, http.StatusForbidden)
			}))
			defer bad.Close()
			good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x1"}`, req.ID)
			}))
			defer good.Close()
			p, err := NewPool([]string{bad.URL + "/v2/" + b15Key, good.URL}, time.Minute, log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			done, finished := make(chan struct{}), make(chan int64)
			go func() {
				var worst int64
				for {
					select {
					case <-done:
						finished <- worst
						return
					default:
					}
					t0 := time.Now()
					_ = p.Primary()
					if d := int64(time.Since(t0)); d > worst {
						worst = d
					}
					time.Sleep(time.Millisecond)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			t0 := time.Now()
			derr := p.Do(ctx, func(c *ethclient.Client) error { _, e := c.BlockNumber(ctx); return e })
			total := time.Since(t0)
			close(done)
			worst := time.Duration(<-finished)
			if derr != nil {
				t.Fatalf("the healthy endpoint did not answer: %v", derr)
			}
			if total > time.Second {
				t.Errorf("Pool.Do took %s with a %d byte error body", total, len(body))
			}
			if worst > 50*time.Millisecond {
				t.Errorf("a concurrent Pool.Primary waited %s", worst)
			}
			for _, s := range p.Status() {
				if strings.Contains(s, b15Key) {
					t.Fatalf("the status holds the key: %s", s)
				}
			}
		})
	}
}

// b17Alphabet has no digit and none of the capital letters the fixed texts use (E O F P), so that a 3-byte window of a key
// in an output is the key and not the text, the digits of the truncation count, or a word.
const b17Alphabet = "ABCDGHIJKLMNQRSTUVWXYZ"

func b17Key(r *rand.Rand) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = b17Alphabet[r.Intn(len(b17Alphabet))]
	}
	return string(b)
}

// b17Leaked is a 3-byte window of key that out holds, or "".
func b17Leaked(out, key string) string { return b15Leak(out, key, 3) }

// b17Forms are the places a key can stand where a text is cut (every form of the reviewer's matrix and the forms of TestB15).
var b17Forms = []struct {
	name, before, after string
	register            bool   // the key is registered as a literal: one piece, or three joined by white space when pieces is 3
	sep                 string // between the pieces of a key written in several (a wrap); "" for one piece
	pieces              int    // how many (2 when sep is set and pieces is not)
}{
	{"registered literal", " ", " and more text after the key", true, "", 0},
	{"registered literal with white space", " ", " and more text after the key", true, " ", 3},
	{"URL path", " https://rpc.example.org/v2/", " and more text after the key", false, "", 0},
	{"userinfo password", " https://user:", "@h.example.org/x and more text after the key", false, "", 0},
	{"bare user:key@", " user:", "@h.example.org/x and more text after the key", false, "", 0},
	{"bare key@", " ", "@h.example.org/x and more text after the key", false, "", 0},
	{"quoted URL wrapped at a space", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, " ", 2},
	{"quoted URL wrapped at a newline", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, "\n", 2},
	{"quoted URL wrapped twice", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, " ", 3},
	{"quoted URL wrapped five times", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, " ", 5},
	{"quoted URL", ` Post "https://h.example.org/v2/`, `" and more text after the key`, false, "", 0},
	{"JSON-escaped URL", b15bs(" https:~/~/rpc.example.org~/v2~/"), " and more text after the key", false, "", 0},
	{"unicode-escaped URL", b15bs(" https:~u002f~u002frpc.example.org~u002fv2~u002f"), " and more text after the key", false, "", 0},
	{"double-escaped URL", b15bs(" https:~~/~~/rpc.example.org~~/v2~~/"), " and more text after the key", false, "", 0},
	{"percent-encoded URL", " https%3A%2F%2Frpc.example.org%2Fv2%2F", " and more text after the key", false, "", 0},
	{"query value", " https://rpc.example.org/api?apikey=", " and more text after the key", false, "", 0},
	{"JSON string with escaped slashes", b15bs(`{"url":"https:~/~/rpc.example.org~/v2~/`), `"} and more text after the key`, false, "", 0},
}

// b17Fronts are texts of exactly n bytes that stand in front of the key form: ordinary words, one delimiter-free run, URLs that
// redaction collapses, tokens that redaction lengthens, and quoted URLs that close each other.
var b17Fronts = []struct {
	name string
	make func(n int) string
}{
	{"words", b15Pad},
	{"run", func(n int) string {
		if n < 2 {
			return b15Pad(n)
		}
		return strings.Repeat("r", n-1) + " "
	}},
	{"collapsing", func(n int) string {
		const head = "https://h/"
		if n < len(head)+2 {
			return b15Pad(n)
		}
		return head + strings.Repeat("p", n-len(head)-1) + " "
	}},
	{"collapsing quoted", func(n int) string {
		const head = `"https://h/`
		if n < len(head)+3 {
			return b15Pad(n)
		}
		return head + strings.Repeat("p", n-len(head)-2) + `" `
	}},
	{"expanding", func(n int) string { return b15Rep("x://h/y ", n+8)[:n] }},
	{"expanding a://", func(n int) string { return b15Rep("a://b/c ", n+8)[:n] }},
	{"alternating quotes", func(n int) string { return b15Rep(b17AltUnits[0].unit, n+14)[:n] }},
}

// The straddle matrix: the key starts at every offset from 300 bytes before the cut to just after it, for both bounds,
// behind every kind of front. No 3-byte window of the key survives, the text is within the bound and valid UTF-8, and a
// second pass changes nothing.
func TestB17_D1_NoFragmentOfAKeySurvivesEitherCutBehindAnyFront(t *testing.T) {
	regKey := b17Key(rand.New(rand.NewSource(1717)))
	t.Cleanup(RegisterProviderURL("https://rpc.example.org/v2/" + regKey))
	// a registered literal that holds white space (a path segment with %20 in it): the cut can fall inside it between words
	spacedKey := b17Key(rand.New(rand.NewSource(1718)))
	spacedParts := []string{spacedKey[:10], spacedKey[10:21], spacedKey[21:]}
	t.Cleanup(RegisterProviderURL("https://rpc.example.org/" + url.PathEscape(strings.Join(spacedParts, " "))))
	var offsets []int
	for off := -300; off < -40; off += 13 {
		offsets = append(offsets, off)
	}
	for off := -40; off <= 8; off++ {
		offsets = append(offsets, off)
	}
	for _, limit := range []int{b15Cut, 1024} {
		limit := limit
		for _, f := range b17Forms {
			f := f
			t.Run(fmt.Sprintf("%d %s", limit, f.name), func(t *testing.T) {
				t.Parallel()
				r := rand.New(rand.NewSource(int64(limit) + int64(len(f.name))))
				for _, fr := range b17Fronts {
					for _, off := range offsets {
						key := regKey
						if !f.register {
							key = b17Key(r)
						}
						keyText, pieces := key, []string{key}
						switch {
						case f.register && f.sep != "":
							keyText, pieces = strings.Join(spacedParts, f.sep), spacedParts
						case f.sep != "":
							n := max(f.pieces, 2)
							pieces = nil
							for k := 0; k < n; k++ {
								pieces = append(pieces, key[k*len(key)/n:(k+1)*len(key)/n])
							}
							keyText = strings.Join(pieces, f.sep)
						}
						pad := limit + off - len(f.before)
						if pad < 0 {
							continue
						}
						in := fr.make(pad) + f.before + keyText + f.after + b15Pad(3000)
						out := BoundRedacted(in, limit)
						if len(out) > limit {
							t.Fatalf("%s offset %d: %d bytes, more than %d", fr.name, off, len(out), limit)
						}
						if !utf8.ValidString(out) {
							t.Fatalf("%s offset %d: not UTF-8", fr.name, off)
						}
						for _, piece := range pieces {
							if w := b17Leaked(out, piece); w != "" {
								t.Fatalf("%s offset %d: the fragment %q of the key survived; the end of the text is %q", fr.name, off, w, tailOf(out))
							}
						}
						if again := BoundRedacted(out, limit); again != out {
							t.Fatalf("%s offset %d: a second pass changed the text:\n%q\n%q", fr.name, off, tailOf(out), tailOf(again))
						}
					}
				}
			})
		}
	}
}

// V-R10B8 D2: a registered literal that stands in the host of a quoted URL. The redaction is a fixed point.
func TestB17_D2_AQuotedURLWhoseHostIsARegisteredLiteralIsAFixedPoint(t *testing.T) {
	const pathKey, pw, user = "Zq3RtL9mNv2Xb7Kc4Hd8WsPy", "pa55w0rd99", "user8chars"
	defer RegisterProviderURL("https://rpc.example.org/v2/" + pathKey)()
	defer RegisterProviderURL("https://" + user + ":" + pw + "@h.example.org/x")()
	for _, in := range []string{
		`"https://` + pathKey + `/v2/"`,
		`"x://` + pw + `/v2/"`,
		`"http://` + user + `/v2/"`,
		b15bs(`~u0022ws://` + pw + `?k=~u0022`),
		`'https://user:pw@` + pathKey + `'`,
		`Post "https://` + pathKey + `/v2/": EOF`,
		`"https://abc.` + pathKey + `.example.org/v2/x"`,
		`https://abc.` + pathKey + `.example.org/v2/x`,
		`"https://` + pathKey + `:8545/v2/" "https://` + user + `/"`,
	} {
		out := RedactText(in)
		for _, lit := range []string{pathKey, pw, user} {
			if strings.Contains(out, lit) {
				t.Errorf("%q: the literal %q survived: %q", in, lit, out)
			}
		}
		if again := RedactText(out); again != out {
			t.Errorf("%q is not a fixed point:\n%q\n%q", in, out, again)
		}
	}
}

var b17FuzzVocab = []string{"https://", "http://", "ws://", "x://", "h.io/", "h.io", "/v2/", " ", " ", "\n", `"`, `"`, "'", "`", "<", ">",
	b15bs("~/"), b15bs("~u002f"), b15bs("~u0022"), b15bs("~n"), "%2F", "%252F", "é", "日", "😀", "x://h/y ", "@", ":", "?k=", "&", "#",
	"…(truncated 5 bytes)", " …(truncated 5 bytes)", "<redacted>", "a", "0x00ab", "user:pw@", "h.example.org", ".", "[::1]:8545/", "\xff",
	// registered literals, whole and in pieces, as hosts, paths, userinfo and values
	"Zq3RtL9mNv2Xb7Kc4Hd8WsPy", "Zq3RtL9m", "Nv2Xb7Kc4", "pa55w0rd99", "pa55w", "user8chars", "user8", "Qm4Tz8Vb2Nx", "Qm4T",
	"my secret key x", "my sec", "https://Zq3RtL9mNv2Xb7Kc4Hd8WsPy/v2/", `"x://pa55w0rd99/v2/"`, "http://user8chars/v2/",
	`"https://abc.Zq3RtL9mNv2Xb7Kc4Hd8WsPy.example.org/x"`, `"a://b 'a://b `, "a://b/c "}

// 50 000 hostile texts with literals registered (some around the 64 KiB bound, some around 1024): within the bound, valid
// UTF-8 when the input was, and a fixed point.
func TestB17_D2_FiftyThousandHostileTextsWithRegisteredLiteralsAreFixedPoints(t *testing.T) {
	defer RegisterProviderURL("https://rpc.example.org/v2/Zq3RtL9mNv2Xb7Kc4Hd8WsPy")()
	defer RegisterProviderURL("https://user8chars:pa55w0rd99@h.example.org/x?k=Qm4Tz8Vb2Nx")()
	defer RegisterProviderURL("https://rpc.example.org/my%20secret%20key%20x/rpc")()
	r := rand.New(rand.NewSource(1717))
	for i := 0; i < 50000; i++ {
		var b strings.Builder
		limit := b15Cut
		switch {
		case i%50 == 0: // past the read bound
			for b.Len() <= b15Cut+r.Intn(3000) {
				b.WriteString(b17FuzzVocab[r.Intn(len(b17FuzzVocab))])
			}
		case i%7 == 0: // around 1024
			limit = 1024
			b.WriteString(b15Pad(r.Intn(1100)))
			fallthrough
		default:
			for n := 1 + r.Intn(40); n > 0; n-- {
				b.WriteString(b17FuzzVocab[r.Intn(len(b17FuzzVocab))])
			}
		}
		in := b.String()
		out := BoundRedacted(in, limit)
		if len(out) > limit {
			t.Fatalf("input %d (%d bytes): %d bytes returned for the bound %d", i, len(in), len(out), limit)
		}
		if utf8.ValidString(in) && !utf8.ValidString(out) {
			t.Fatalf("input %d (%d bytes): the output is not UTF-8: %q", i, len(in), tailOf(out))
		}
		if again := BoundRedacted(out, limit); again != out {
			t.Fatalf("input %d (%d bytes, bound %d) is not a fixed point:\n%s", i, len(in), limit, b17Diff(out, again))
		}
	}
}

// b17Diff shows the first place where a and b differ, with the text around it.
func b17Diff(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	ctx := func(s string) string { return fmt.Sprintf("%q", s[max(0, i-60):min(len(s), i+60)]) }
	return fmt.Sprintf("first difference at byte %d of %d and %d:\n%s\n%s", i, len(a), len(b), ctx(a), ctx(b))
}
