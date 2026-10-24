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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// RB10-B15 (V-R10B7 D1 D2 D4, V-R10B6 D1 D3): the redactor never runs on unbounded text and never under a mutex, a
// dial error names no key, the literal registry cannot rewrite ordinary words and registers in linear time.

const b15Key = "ZkQ9xPLm2Tn7VbR4sWcY8dHgJf1A5eUo"

// b15Cut is the most bytes RedactText returns: the read bound of the redactor.
const b15Cut = 64 << 10

func b15bs(s string) string { return strings.ReplaceAll(s, "~", "\x5c") }

func b15Rep(unit string, total int) string { return strings.Repeat(unit, total/len(unit)) }

// b15Leak is the first window of n bytes of key that out holds, or "".
func b15Leak(out, key string, n int) string {
	for i := 0; i+n <= len(key); i++ {
		if w := key[i : i+n]; strings.Contains(out, w) {
			return w
		}
	}
	return ""
}

// b15Pad is exactly n bytes of ordinary words.
func b15Pad(n int) string {
	if n <= 0 {
		return ""
	}
	s := b15Rep("lorem ipsum dolor sit amet ", n+len("lorem ipsum dolor sit amet "))
	return s[:n]
}

// The shapes V-R10B7 measured at 4 MiB (RedactText alone 0.2 ms to 4.8 s before the bound).
var b15Shapes = []struct{ name, text string }{
	{"bare-pairs", b15Rep("h.io/a h.io/b ", 4<<20)},
	{"quote-wrapped", b15Rep(`Post "https://h.example.org/v2/KEY": EOF `, 4<<20)},
	{"unterminated-quote", b15Rep(`"https://h.example.org/v2/KEY `, 4<<20)},
	{"quote-open-only", b15Rep(`"`, 4<<20)},
	{"scheme-then-labels", "https://" + b15Rep("a.", 4<<20)},
	{"scheme-pairs", b15Rep("x://h/y ", 4<<20)},
	{"userinfo-run", b15Rep("u@", 4<<20) + "h.io/x"},
	{"tokens-wrapped", b15Rep(`"h.io/a" `, 4<<20)},
	{"slashes", b15Rep("/", 4<<20)},
	{"questions", b15Rep("?", 4<<20)},
	{"ipv6-ish", b15Rep("[2001:db8::1]:8545/x ", 4<<20)},
	{"letters", b15Rep("a", 4<<20)},
	{"labels", b15Rep("a.", 4<<20)},
	{"at-signs", b15Rep("a@", 4<<20)},
	{"http-schemes", b15Rep("http://", 4<<20)},
	{"odd-scheme", b15Rep("a://", 4<<20)},
	{"escaped-pairs", b15Rep(b15bs("https:~/~/h.io~/v2~/KEY "), 4<<20)},
	// RB10-B17 (V-R10B8 D1): quoted URLs that close each other, the shapes the iterative cut took seconds on.
	{"alt-quotes", b15Rep(b17AltUnits[0].unit, 4<<20)},
	{"alt-quotes-nospace", b15Rep(b17AltUnits[1].unit, 4<<20)},
	{"alt-quotes-2", b15Rep(b17AltUnits[2].unit, 4<<20)},
	{"alt-quotes-3", b15Rep(b17AltUnits[3].unit, 4<<20)},
	{"alt-quotes-long", b15Rep(b17AltUnits[4].unit, 4<<20)},
}

// RB12-OPS-A1 (ledger F15): these tests used to assert wall-clock bounds (250 ms, 500 ms, 1 s, 50 ms), which a loaded machine breaks without any
// defect in the redactor. The claim they stand for is that the cost of redacting a text does not depend on its length or its shape beyond the
// read bound, and that redaction never runs under a mutex. Both are now asserted on quantities a load cannot change: the bytes a call
// allocates (the cost model, measured as the smallest of three runs so that a goroutine of another test cannot add to it) and a gate that
// holds the redaction at a chosen point while the mutex is probed. No test below reads a clock.

// b15Cost is the bytes f allocates, the smallest of three runs.
func b15Cost(f func()) uint64 {
	best := ^uint64(0)
	for i := 0; i < 3; i++ {
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		f()
		runtime.ReadMemStats(&b)
		if d := b.TotalAlloc - a.TotalAlloc; d < best {
			best = d
		}
	}
	return best
}

// b15CostBound is the most bytes any shape may allocate in one RedactText (twice that for a RedactError and its first read, three times for a
// TransientError text, which redacts two parts): a fixed multiple of the read bound (the worst shape measured at 9.5 MB), so a pass that grew with the text breaks it.
const b15CostBound = 256 * b15Cut

func TestB15_D1_FourMiBOfEveryShapeIsRedactedInABoundedTime(t *testing.T) {
	for _, sh := range b15Shapes {
		out := RedactText(sh.text)
		if len(out) > b15Cut {
			t.Errorf("%s: RedactText returned %d bytes, more than the %d bound", sh.name, len(out), b15Cut)
		}
		if !strings.Contains(out, "(truncated ") {
			t.Errorf("%s: the cut is not visible in the text", sh.name)
		}
		if !utf8.ValidString(out) {
			t.Errorf("%s: the cut text is not UTF-8", sh.name)
		}
		// the cost does not depend on the length of the text past the read bound: a quarter of the shape costs what all of it costs
		big := b15Cost(func() { _ = RedactText(sh.text) })
		quarter := sh.text[:len(sh.text)/4]
		small := b15Cost(func() { _ = RedactText(quarter) })
		t.Logf("%s: %d bytes allocated for %d, %d for %d", sh.name, big, len(sh.text), small, len(quarter))
		if big > small+4096 || small > big+4096 {
			t.Errorf("%s: RedactText of %d bytes allocated %d, of %d bytes %d: the cost depends on the length of the text", sh.name, len(sh.text), big, len(quarter), small)
		}
		if big > b15CostBound {
			t.Errorf("%s: RedactText of %d bytes allocated %d bytes, more than %d", sh.name, len(sh.text), big, b15CostBound)
		}
		// a redacted error redacts once: its first read costs a redaction, every later read costs nothing
		e := RedactError(errors.New(sh.text))
		first := b15Cost(func() { _ = RedactError(errors.New(sh.text)).Error() })
		if first > 2*b15CostBound {
			t.Errorf("%s: RedactError and its first read allocated %d bytes, more than %d", sh.name, first, 2*b15CostBound)
		}
		_ = e.Error()
		if n := testing.AllocsPerRun(30, func() { _ = e.Error() }); n != 0 {
			t.Errorf("%s: a later read of a redacted error allocated %v times", sh.name, n)
		}
		te := &TransientError{Host: "h", Attempts: 1, Err: errors.New(sh.text)}
		if c := b15Cost(func() { _ = te.Error(); _ = summarize(errors.New(sh.text)) }); c > 3*b15CostBound {
			t.Errorf("%s: TransientError.Error and summarize allocated %d bytes, more than %d", sh.name, c, 3*b15CostBound)
		}
		var logged string
		RedactingLogf(func(f string, a ...interface{}) { logged = fmt.Sprintf(f, a...) })("%s", sh.text)
		if len(logged) > b15Cut {
			t.Errorf("%s: a log line of %d bytes", sh.name, len(logged))
		}
		if args := RedactArgs([]interface{}{sh.text}); len(args[0].(string)) > b15Cut {
			t.Errorf("%s: RedactArgs returned %d bytes", sh.name, len(args[0].(string)))
		}
	}
}

// b15Gated is an error whose text is held back until released: the redaction that asked for it is stopped at a point the test chooses.
type b15Gated struct {
	text    string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newB15Gated(text string) *b15Gated {
	return &b15Gated{text: text, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *b15Gated) Error() string {
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return g.text
}

// b15Within waits for ch; a failure to see it is a hang, which the generous bound only reports, it never decides a passing run.
func b15Within(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Minute):
		t.Fatalf("hung: %s", what)
	}
}

// A redacted error redacts its text once, however often it is read.
type b15Counting struct {
	n   *int32
	msg string
}

func (c b15Counting) Error() string { atomic.AddInt32(c.n, 1); return c.msg }

func TestB15_D1_ARedactedErrorRedactsOnce(t *testing.T) {
	var n int32
	e := RedactError(b15Counting{n: &n, msg: `Post "https://h.example.org/v2/` + b15Key + `": EOF`})
	first := e.Error()
	for i := 0; i < 100; i++ {
		if e.Error() != first {
			t.Fatal("the text of one error changed between reads")
		}
	}
	if strings.Contains(first, b15Key) {
		t.Fatalf("the key survived: %s", first)
	}
	if got := atomic.LoadInt32(&n); got > 2 {
		t.Fatalf("the original's Error was called %d times for 101 reads (once to decide, once to redact)", got)
	}
	// a literal registered after the error was made and before its text was first read is applied to it
	late := "LATEKEY-b15-0001-abcdef"
	e2 := RedactError(errors.New(`Post "https://h.example.org/v2/x": EOF; echo /v2/` + late))
	undo := RegisterProviderURL("https://other.example.org/v2/" + late)
	defer undo()
	if strings.Contains(e2.Error(), late) {
		t.Fatalf("a literal registered before the first read was not applied: %s", e2.Error())
	}
}

// One failing provider answering with megabytes must not hold the pool, or the health of its provider, for the length of the redaction.
// The failure is recorded while the redaction of its text is stopped at the gate; the mutex of the pool is then probed and must be free.
// (A redaction under the mutex would hold the probe until the gate opened: the test would hang, which is reported.)
func TestB15_D1_AHostileErrorBodyDoesNotStallThePool(t *testing.T) {
	body := b15Rep("h.io/a h.io/b ", 3_900_000)
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

	// the real failure path: the megabyte body is bounded, the healthy endpoint answers, and nothing the pool reports holds the key
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if derr := p.Do(ctx, func(c *ethclient.Client) error { _, e := c.BlockNumber(ctx); return e }); derr != nil {
		t.Fatalf("the healthy endpoint did not answer: %v", derr)
	}
	for _, s := range p.Status() {
		if strings.Contains(s, b15Key) {
			t.Fatalf("the status holds the key: %s", s)
		}
		if len(s) > 1024 {
			t.Fatalf("a status line of %d bytes", len(s))
		}
	}

	// the lock: markFailure is stopped inside the redaction of the provider's text, and the pool must still be usable
	g := newB15Gated(body)
	ep := &endpoint{url: bad.URL + "/v2/" + b15Key}
	probe := &Pool{endpoints: []*endpoint{ep}, cooldown: time.Minute}
	recorded := make(chan struct{})
	go func() { probe.markFailure(ep, g); close(recorded) }()
	b15Within(t, g.entered, "markFailure never reached the redaction of the error text")
	statusDone := make(chan struct{})
	go func() { _ = probe.Status(); _ = probe.candidates(); close(statusDone) }()
	b15Within(t, statusDone, "Pool.Status and candidates waited on the mutex while a failure was being redacted")
	close(g.release)
	b15Within(t, recorded, "markFailure did not finish after the gate opened")
	if ep.failures != 1 || strings.Contains(ep.lastReason, b15Key) || len(ep.lastReason) > b15Cut {
		t.Fatalf("failures %d, reason of %d bytes", ep.failures, len(ep.lastReason))
	}
}

func TestB15_D1_TheHealthLockIsNotHeldWhileTheReasonIsRedacted(t *testing.T) {
	h := &providerHealth{}
	g := newB15Gated(b15Rep("h.io/a h.io/b ", 3_900_000))
	big := &TransientError{Host: "h", Attempts: 1, Err: g}
	recorded := make(chan struct{})
	go func() { h.record(context.Background(), context.Background(), big); close(recorded) }()
	b15Within(t, g.entered, "record never reached the redaction of the error text")
	admitted := make(chan struct{})
	go func() { _, _, _ = h.admit(time.Now()); close(admitted) }()
	b15Within(t, admitted, "admit waited on the health mutex while the reason was being redacted")
	close(g.release)
	b15Within(t, recorded, "record did not finish after the gate opened")
	if ask, _, resting := h.admit(time.Now()); ask || resting == nil || len(resting.Error()) > 400 {
		t.Fatalf("the provider should rest with a short reason: ask=%v err=%v", ask, resting)
	}
}

// b15Forms are the shapes a provider key can have where a text is cut. The key starts at a chosen offset around the cut.
var b15Forms = []struct {
	name, before, after string
	register            bool
	parts               int // the key is written in this many pieces, split by a space
}{
	{"registered literal", " ", " and more text after the key", true, 1},
	{"path of a URL", " https://rpc.example.org/v2/", " and more text after the key", false, 1},
	{"userinfo password of a URL", " https://user:", "@h.example.org/x and more text after the key", false, 1},
	{"bare userinfo", " user:", "@h.example.org/x and more text after the key", false, 1},
	{"quoted URL wrapped at white space", ` Post "https://h.example.org/v2/`, `": EOF and more text after the key`, false, 2},
	{"JSON-escaped URL", b15bs(" https:~/~/rpc.example.org~/v2~/"), " and more text after the key", false, 1},
	{"percent-encoded URL", " https%3A%2F%2Frpc.example.org%2Fv2%2F", " and more text after the key", false, 1},
	{"query value of a URL", " https://rpc.example.org/api?apikey=", " and more text after the key", false, 1},
}

func b15KeyText(parts int) (text string, pieces []string) {
	if parts == 1 {
		return b15Key, []string{b15Key}
	}
	pieces = []string{b15Key[:16], b15Key[16:]}
	return pieces[0] + " " + pieces[1], pieces
}

// Every offset of the key around the cut: the text keeps no fragment of it, whichever side of the cut its first byte is on.
func TestB15_D1_NoFragmentOfAKeySurvivesTheCut(t *testing.T) {
	for _, f := range b15Forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			if f.register {
				undo := RegisterProviderURL("https://rpc.example.org/v2/" + b15Key)
				defer undo()
			}
			keyText, pieces := b15KeyText(f.parts)
			for off := -300; off <= 8; off++ {
				start := b15Cut + off
				pad := start - len(f.before)
				if pad < 0 {
					continue
				}
				in := b15Pad(pad) + f.before + keyText + f.after + b15Pad(3000)
				if len(in) <= b15Cut {
					t.Fatalf("the input is %d bytes, not past the cut", len(in))
				}
				out := RedactText(in)
				if len(out) > b15Cut {
					t.Fatalf("offset %d: %d bytes returned", off, len(out))
				}
				for _, piece := range pieces {
					if w := b15Leak(out, piece, 3); w != "" {
						tail := out
						if len(tail) > 160 {
							tail = tail[len(tail)-160:]
						}
						t.Fatalf("offset %d: the fragment %q of the key survived the cut; the end of the text is %q", off, w, tail)
					}
				}
				if again := RedactText(out); again != out {
					t.Fatalf("offset %d: a second pass changed the text", off)
				}
			}
		})
	}
}

var b15Vocab = []string{"https://", "http://", "ws://", "x://", "h.io/", "h.io", "/v2/", "KEYabc123XYZ", " ", " ", "\n", `"`, "'", "`", "<", ">",
	b15bs("~/"), b15bs("~u002f"), b15bs("~n"), "%2F", "%252F", "é", "日", "😀", "x://h/y ", "@", ":", "?k=", "&", "#",
	"…(truncated 5 bytes)", "<redacted>", "a", "0x00ab", "user:pw@", "h.example.org", ".", "[::1]:8545/", "\xff"}

// The sweep: 20 000 hostile texts, some past the bound; the text is bounded, valid, and a fixed point of the redaction.
func TestB15_D1_TheBoundedRedactionIsIdempotentOver20000Texts(t *testing.T) {
	r := rand.New(rand.NewSource(15))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		long := i%100 == 0
		for n := 1 + r.Intn(40); n > 0 || long && b.Len() <= b15Cut+r.Intn(3000); n-- {
			b.WriteString(b15Vocab[r.Intn(len(b15Vocab))])
		}
		in := b.String()
		out := RedactText(in)
		if len(out) > b15Cut {
			t.Fatalf("input %d (%d bytes): %d bytes returned", i, len(in), len(out))
		}
		if again := RedactText(out); again != out {
			t.Fatalf("input %d (%d bytes) is not a fixed point:\n%q\n%q", i, len(in), tailOf(out), tailOf(again))
		}
	}
}

func tailOf(s string) string {
	if len(s) > 120 {
		return "…" + s[len(s)-120:]
	}
	return s
}

// The configured URL of a malformed value is the one origin that held the key in a *url.Error.
func TestB15_D2_ADialOfAMalformedURLNamesNoKey(t *testing.T) {
	const base = "https://eth-sepolia.g.alchemy.com"
	inputs := map[string]string{
		"trailing CR":          base + "/v2/" + b15Key + "\r",
		"trailing LF":          base + "/v2/" + b15Key + "\n",
		"bad percent escape":   base + "/v2/" + b15Key + "%zz",
		"bad port":             "https://eth-sepolia.g.alchemy.com:99999x/v2/" + b15Key,
		"control char in host": "https://eth-sepolia.g.alchemy.com\x7f/v2/" + b15Key,
	}
	saved := constructionRetryBudget
	constructionRetryBudget = 100 * time.Millisecond
	defer func() { constructionRetryBudget = saved }()
	for name, raw := range inputs {
		raw := raw
		t.Run(name, func(t *testing.T) {
			check := func(what string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s: a malformed URL was dialed", what)
				}
				for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%q", err)} {
					if strings.Contains(text, b15Key) {
						t.Fatalf("%s: the error holds the key: %s", what, text)
					}
				}
			}
			_, err := DialRPCRetrying(context.Background(), raw)
			check("DialRPCRetrying", err)
			var ue *url.Error
			if !errors.As(err, &ue) {
				t.Errorf("DialRPCRetrying: the *url.Error is no longer reachable with errors.As: %T", err)
			}
			_, err = DialRetrying(context.Background(), raw)
			check("DialRetrying", err)
			var logged strings.Builder
			_, err = NewPool([]string{raw}, time.Minute, log.New(&logged, "", 0))
			check("NewPool", err)
			if strings.Contains(logged.String(), b15Key) {
				t.Fatalf("NewPool logged the key: %s", logged.String())
			}
			_, err = NewAgreeingReader(context.Background(), 11155111, []string{raw, raw}, 50*time.Millisecond)
			check("NewAgreeingReader", err)
		})
	}
}

func b15Registered(raw, lit string) bool {
	undo := RegisterProviderURL(raw)
	defer undo()
	return RedactText("x "+lit+" y") != "x "+lit+" y"
}

// The literal thresholds (V-R10B7 D4.1, D4.3).
func TestB15_D4a_TheLiteralThresholds(t *testing.T) {
	for _, c := range []struct {
		name, url, lit string
		want           bool
	}{
		{"path segment of 12 letters", "https://rpc.example.org/qwertyuiopas", "qwertyuiopas", true},
		{"path segment of 11 letters", "https://rpc.example.org/qwertyuiopa", "qwertyuiopa", false},
		{"path segment of 11 with a letter and a digit", "https://rpc.example.org/Ab3dE9fG1hJ", "Ab3dE9fG1hJ", true},
		{"path segment of 8 with a letter and a digit", "https://rpc.example.org/Ab3dE9fG", "Ab3dE9fG", true},
		{"path segment of 8 letters", "https://rpc.example.org/Abcdefgh", "Abcdefgh", false},
		{"path segment of 8 digits", "https://rpc.example.org/48151623", "48151623", false},
		{"path segment of 8 hex digits (a block or chain number)", "https://rpc.example.org/ab12cd34", "ab12cd34", false},
		{"path segment of 7 with a letter and a digit", "https://rpc.example.org/Ab3dE9f", "Ab3dE9f", false},
		{"path segment of 12 digits", "https://rpc.example.org/481516234200", "481516234200", false},
		{"path segment of 15 digits", "https://rpc.example.org/481516234200123", "481516234200123", false},
		{"path segment of 16 digits", "https://rpc.example.org/4815162342001234", "4815162342001234", true},
		{"path segment of 32 hex digits", "https://rpc.example.org/v3/0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef", true},
		{"query value of 8 letters", "https://rpc.example.org/p?token=Qwertyui", "Qwertyui", true},
		{"query value of 7 letters", "https://rpc.example.org/p?token=Qwertyu", "Qwertyu", false},
		{"query value of 6 with a letter and a digit", "https://rpc.example.org/p?dkey=Ab3dE9", "Ab3dE9", true},
		{"query value of 5 with a letter and a digit", "https://rpc.example.org/p?dkey=Ab3dE", "Ab3dE", false},
		{"query value of 6 digits", "https://rpc.example.org/p?n=123456", "123456", false},
		{"fragment of 8", "https://rpc.example.org/p#Ab3dE9fG", "Ab3dE9fG", true},
		{"fragment of 7 letters", "https://rpc.example.org/p#Qwertyu", "Qwertyu", false},
		{"userinfo user of 8", "https://operator:x@rpc.example.org/", "operator", true},
		{"userinfo user of 7", "https://operato:x@rpc.example.org/", "operato", false},
		{"userinfo password of 8", "https://u:Sup3rSec@rpc.example.org/", "Sup3rSec", true},
		{"userinfo password of 7", "https://u:Sup3rSe@rpc.example.org/", "Sup3rSe", false},
		{"userinfo admin", "https://admin:beef@rpc.example.org/", "admin", false},
		{"userinfo beef", "https://admin:beef@rpc.example.org/", "beef", false},
		{"userinfo root", "https://root:toor@rpc.example.org/", "root", false},
	} {
		if got := b15Registered(c.url, c.lit); got != c.want {
			t.Errorf("%s: %q registered = %v, want %v", c.name, c.lit, got, c.want)
		}
	}
	// a short userinfo secret is still removed wherever it stands inside a URL
	undo := RegisterProviderURL("https://admin:beef@rpc.example.org/v2/")
	defer undo()
	if got := RedactText("saw https://admin:beef@rpc.example.org/v2/ here"); strings.Contains(got, "beef") || strings.Contains(got, "admin") {
		t.Errorf("a short userinfo secret survived inside a URL: %s", got)
	}
}

// No registered literal can rewrite a hash, a chain name or an ordinary word.
func TestB15_D4a_NoRegisteredLiteralRewritesAHashAChainNameOrAWord(t *testing.T) {
	for _, raw := range []string{
		"https://admin:beef@rpc.example.org/arbitrum/sepolia/v2/Ab3dE9fG?network=sepolia&chain=arbitrum&dkey=Ab3dE9",
		"https://root:cafe@ethereum-sepolia-rpc.publicnode.com/",
		"https://rpc.example.org/ethereum-sepolia/base-sepolia/arbitrum-sepolia/telcoin-adiri?network=arbitrum-sepolia&chain=base-sepolia",
		"https://user:1234@rpc.example.org/api/v1/rpc/QwErTy1234567890/eth?apikey=Qwertyui",
	} {
		defer RegisterProviderURL(raw)()
	}
	hash := "0x00beef11adminrootcafe22ab12cd34deadbeefcafe0123456789abcdef0123456789abcdefab12cd34ef56"
	texts := []string{
		"block hash " + hash + " is final", "user admin, password beef", "the root of the tree", "state root mismatch", "sepolia", "arbitrum",
		"the chain sepolia on host ethereum-sepolia-rpc.publicnode.com", "network=arbitrum-sepolia", "the cafe is open", "dead beef 1234",
	}
	for _, id := range supportedchains.IDs() {
		c, _ := supportedchains.Lookup(id)
		texts = append(texts, c.Name, c.Network, c.Family, c.DisplayName, "chain "+c.Name+" ("+c.Network+")")
		texts = append(texts, c.Aliases...)
	}
	for _, in := range texts {
		if got := RedactText(in); got != in {
			t.Errorf("%q was rewritten to %q", in, got)
		}
	}
}

// Registering N URLs costs N, and the first redaction after them costs N.
func TestB15_D4b_RegisteringThreeThousandURLsIsFast(t *testing.T) {
	const n = 3000
	undos := make([]func(), 0, n)
	defer func() {
		for _, u := range undos {
			u()
		}
	}()
	t0 := time.Now()
	for i := 0; i < n; i++ {
		undos = append(undos, RegisterProviderURL(fmt.Sprintf("https://host%d.example.org/v2/KEY%dabcdefghij?token=TOK%dxyz", i, i, i)))
		if d := time.Since(t0); d > time.Second {
			t.Fatalf("%d registrations took %s and were not done", i+1, d)
		}
	}
	if got := RedactText("a KEY1234abcdefghij b"); strings.Contains(got, "KEY1234abcdefghij") {
		t.Fatalf("a registered literal is not applied: %s", got)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("%d registrations and the first redaction took %s", n, d)
	}
	t0 = time.Now()
	for _, u := range undos {
		u()
	}
	undos = nil
	if got := RedactText("a KEY1234abcdefghij b"); strings.Contains(got, RedactedMarker) {
		t.Fatalf("undone registrations still apply: %s", got)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("undoing %d registrations took %s", n, d)
	}
}
