// Copyright 2026 Certen Protocol

package ethrpc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// =============================================================================
// One redactor for provider text (RB10-B14a)
// =============================================================================
//
// Go's HTTP errors embed the full request URL (Post "https://eth-sepolia.g.alchemy.com/v2/<KEY>": ...), a provider's body
// may echo it, and the production pools hold Alchemy and Infura URLs whose PATH is the API key. RedactText is the one
// sanitiser of such text, in two passes:
//
//  1. The PATTERN pass rewrites every URL-looking token to scheme://host/<redacted> (the userinfo, the path, the query and
//     the fragment are dropped; the host stays, so the provider is still named). It reads a URL as the characters it
//     stands for: a JSON-escaped slash, a unicode-escaped character (single or double escaped), a percent-encoded
//     character, a JSON-escaped newline or tab are all decoded for the purpose of finding the token (the text that is
//     kept is the original, byte for byte, outside the token), and a URL inside a quote may be wrapped at white space.
//  2. The LITERAL pass replaces every registered secret literal wherever it occurs. A pattern cannot know a key; the
//     configured provider URLs are known, so their userinfo, long path segments, query values and fragment are registered
//     (RegisterProviderURL) when a client or pool is constructed, in raw, URL-encoded and JSON-escaped spellings. This
//     catches the echoes that are not URLs (a path-only echo, a bare user:key@host, a header).
//
// It is idempotent, linear in the length of the text (RE2, no backtracking), and text with no URL and no registered literal
// is returned byte for byte. What it does not claim: a secret that is neither inside a URL token nor a registered literal
// (a bare key in prose from a provider that was never configured here), a key used as a host label (the host is kept by
// design so the provider is named), a fragment-only echo (host#KEY) of a URL that was not registered, and look-alike
// characters (a fullwidth solidus) that no HTTP stack produces.

// RedactedMarker replaces what is hidden.
const RedactedMarker = "<redacted>"

// redactedPath replaces everything of a URL after its host.
const redactedPath = "/" + RedactedMarker

// bs is a backslash. It is a constant so that no source text has to spell an escape sequence.
const bs = '\x5c'

// trailingPunctuation is what ends a sentence or a clause after a URL, not the URL.
const trailingPunctuation = ".,;:!?)]}"

// maxQuotedURL is the most bytes a quoted URL may span (a URL wrapped at white space inside its quotes).
const maxQuotedURL = 2048

// minSecretLiteral is the shortest literal registered: anything shorter is a word, and replacing it everywhere would
// destroy the text. A shorter secret is still removed by the pattern pass wherever it stands in a URL.
const minSecretLiteral = 4

// urlBody is the rest of an unquoted URL token: it ends at white space, a quote, a backquote, an angle bracket or a
// backslash that is not an escape (escapes are decoded before the token is read). x5c is the backslash, x60 the backquote.
const urlBody = `[^\s"'\x60<>\x5c]*`

var schemeStart = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://`)

// host[:port] followed by /path or ?name=value, with an optional user:password@ before it. The host is a dotted name (a
// trailing dot allowed), an IPv4 address, localhost, a bracketed IPv6 address, or a single label that carries a port.
var bareURL = regexp.MustCompile(`(?i)(?:[^\s"'\x60<>\x5c/]+@)?` +
	`(?:(?:(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*\.?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|localhost|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?)|[a-z][a-z0-9-]*:[0-9]{1,5})` +
	`(?:/` + urlBody + `|\?[a-z0-9_.%-]+=` + urlBody + `)`)

// RedactText is the one sanitiser of text that came from a provider, a transport or a provider URL before it is stored,
// returned in an error or logged. See the package comment above.
func RedactText(s string) string {
	if s == "" {
		return s
	}
	// Applied until nothing changes (at most four times): what one pass leaves (a userinfo glued in front of a host that a
	// replacement then exposed as a URL) the next removes, so the result is a fixed point and a second call changes nothing.
	for i := 0; i < maxRedactPasses; i++ {
		t := redactBareURLs(redactSchemeURLs(s))
		if t == s {
			break
		}
		s = t
	}
	return redactLiterals(s)
}

// maxRedactPasses bounds the pattern passes.
const maxRedactPasses = 4

// RedactError is err with its text redacted: Error() is RedactText of the original's, and Unwrap returns the original, so
// errors.Is, errors.As and every classification by type or code see the original error. An error whose text has nothing to
// redact is returned itself (a sentinel is still the sentinel). The text is redacted when Error is called, so a literal
// registered after the error was made is covered too.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	if m := err.Error(); RedactText(m) == m {
		return err
	}
	return &redactedError{err: err}
}

type redactedError struct{ err error }

func (e *redactedError) Error() string { return RedactText(e.err.Error()) }
func (e *redactedError) Unwrap() error { return e.err }

// RedactArgs is args with every string and error redacted, for a log call whose format is the caller's.
func RedactArgs(args []interface{}) []interface{} {
	out := make([]interface{}, len(args))
	for i, a := range args {
		switch x := a.(type) {
		case string:
			out[i] = RedactText(x)
		case error:
			out[i] = RedactError(x)
		default:
			out[i] = a
		}
	}
	return out
}

// RedactingLogf wraps a printf-style logger so that nothing it is given carries a credential: the formatted line is
// redacted as a whole, which also covers a URL the format itself holds.
func RedactingLogf(logf func(string, ...interface{})) func(string, ...interface{}) {
	if logf == nil {
		return nil
	}
	return func(format string, args ...interface{}) {
		logf("%s", RedactText(fmt.Sprintf(format, args...)))
	}
}

// =============================================================================
// The pattern pass
// =============================================================================

// decodeURLEscapes returns s with the escapes a URL can be written in turned into the characters they stand for, and the
// byte offset in s of every byte of the result (nil when nothing was decoded, then the result is s itself): the JSON
// escapes of a slash, a quote, a newline, a tab, a carriage return and of any BMP character by four hex digits, each
// under one to four backslashes (a JSON document nested in a JSON string), and a percent escape of a printable ASCII
// character that is not a quote, an angle bracket, a backquote, a backslash or a percent sign, under up to two further
// levels of percent encoding. A decoded character is a real one: a decoded quote ends a token, a decoded slash starts a
// path.
func decodeURLEscapes(s string) (string, []int32) {
	if strings.IndexByte(s, bs) < 0 && strings.IndexByte(s, '%') < 0 {
		return s, nil
	}
	var out []byte
	var off []int32
	flush := func(upTo int, from *int) {
		if out == nil {
			return
		}
		for ; *from < upTo; *from++ {
			out = append(out, s[*from])
			off = append(off, int32(*from))
		}
	}
	copied := 0
	for i := 0; i < len(s); {
		var dec []byte
		width := 0
		switch s[i] {
		case bs:
			dec, width = decodeBackslash(s, i)
		case '%':
			dec, width = decodePercent(s, i)
		}
		if width == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(s))
			off = make([]int32, 0, len(s)+1)
		}
		flush(i, &copied)
		for range dec {
			off = append(off, int32(i))
		}
		out = append(out, dec...)
		i += width
		copied = i
	}
	if out == nil {
		return s, nil
	}
	flush(len(s), &copied)
	off = append(off, int32(len(s)))
	return string(out), off
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var r rune
	for i := 0; i < 4; i++ {
		v := hexVal(s[i])
		if v < 0 {
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

// decodeBackslash decodes the escape that starts at s[i] (one to four backslashes, then a slash, a quote, n, t, r, or u and
// four hex digits). width 0: not an escape.
func decodeBackslash(s string, i int) ([]byte, int) {
	k := 0
	for i+k < len(s) && s[i+k] == bs && k < 4 {
		k++
	}
	j := i + k
	if j >= len(s) {
		return nil, 0
	}
	switch s[j] {
	case '/':
		return []byte{'/'}, k + 1
	case '"':
		return []byte{'"'}, k + 1
	case 'n':
		return []byte{'\n'}, k + 1
	case 't':
		return []byte{'\t'}, k + 1
	case 'r':
		return []byte{'\r'}, k + 1
	case 'u':
		r, ok := hex4(s[j+1:])
		if !ok || r >= 0xD800 && r <= 0xDFFF || r == 0 {
			return nil, 0
		}
		return []byte(string(r)), k + 5
	}
	return nil, 0
}

// decodePercent decodes %XX, %25XX and %2525XX (a percent-encoded URL inside a percent-encoded URL). width 0: not a
// decodable escape.
func decodePercent(s string, i int) ([]byte, int) {
	p := i + 1
	for extra := 0; extra < 2 && p+4 <= len(s) && s[p] == '2' && s[p+1] == '5' && hexVal(s[p+2]) >= 0 && hexVal(s[p+3]) >= 0; extra++ {
		p += 2
	}
	if p+2 > len(s) {
		return nil, 0
	}
	hi, lo := hexVal(s[p]), hexVal(s[p+1])
	if hi < 0 || lo < 0 {
		return nil, 0
	}
	b := byte(hi<<4 | lo)
	if b < 0x21 || b > 0x7e || b == '"' || b == 0x27 || b == '<' || b == '>' || b == '`' || b == bs || b == '%' {
		return nil, 0
	}
	return []byte{b}, p + 2 - i
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// endsToken: the bytes that end an unquoted URL token.
func endsToken(c byte) bool {
	return isSpace(c) || isQuote(c) || c == '<' || c == '>' || c == bs
}

func stripSpace(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < utf8.RuneSelf && isSpace(byte(r)) }) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf && isSpace(byte(r)) {
			return -1
		}
		return r
	}, s)
}

// span is a piece of the original text to replace.
type span struct {
	from, to int
	with     string
}

func applySpans(s string, spans []span) string {
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.from])
		b.WriteString(sp.with)
		last = sp.to
	}
	b.WriteString(s[last:])
	return b.String()
}

func original(off []int32, i int) int {
	if off == nil {
		return i
	}
	return int(off[i])
}

func redactSchemeURLs(s string) string {
	norm, off := decodeURLEscapes(s)
	if !strings.Contains(norm, "://") {
		return s
	}
	var spans []span
	for pos := 0; pos < len(norm); {
		loc := schemeStart.FindStringIndex(norm[pos:])
		if loc == nil {
			break
		}
		start, bodyStart := pos+loc[0], pos+loc[1]
		end, quoted := bodyStart, false
		if start > 0 && isQuote(norm[start-1]) {
			window := norm[bodyStart:min(len(norm), bodyStart+maxQuotedURL+1)]
			if i := strings.IndexByte(window, norm[start-1]); i >= 0 {
				end, quoted = bodyStart+i, true
			}
		}
		if !quoted {
			for end < len(norm) && !endsToken(norm[end]) {
				end++
			}
		}
		tok := norm[start:end]
		if quoted {
			tok = stripSpace(tok)
		} else {
			tok = strings.TrimRight(tok, trailingPunctuation)
			end = start + len(tok)
		}
		if rep, ok := redactSchemeToken(tok); ok {
			spans = append(spans, span{from: original(off, start), to: original(off, end), with: rep})
		}
		pos = max(end, bodyStart)
	}
	return applySpans(s, spans)
}

// redactSchemeToken is scheme://host/<redacted> for a token with something after its host; ok is false for a token that
// hides nothing (a host with nothing after it, or a bare slash).
func redactSchemeToken(core string) (string, bool) {
	i := strings.Index(core, "://")
	scheme, rest := core[:i+3], core[i+3:]
	authority, remainder := rest, ""
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		authority, remainder = rest[:j], rest[j:]
	}
	host, userinfo := authority, false
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		host, userinfo = authority[at+1:], true
	}
	if !userinfo && (remainder == "" || remainder == "/") {
		return "", false // nothing after the host
	}
	// A host never holds a character that ends or changes a token (a quoted token can hold any): what follows one is dropped,
	// so that the result reads the same when it is redacted again.
	if i := strings.IndexFunc(host, func(r rune) bool { return r < utf8.RuneSelf && (endsToken(byte(r))) }); i >= 0 {
		host = host[:i]
	}
	return scheme + host + redactedPath, true
}

func redactBareURLs(s string) string {
	norm, off := decodeURLEscapes(s)
	if !strings.ContainsAny(norm, "/?") {
		return s
	}
	var spans []span
	for _, loc := range bareURL.FindAllStringIndex(norm, -1) {
		tok := norm[loc[0]:loc[1]]
		core := strings.TrimRight(tok, trailingPunctuation)
		if rep, ok := redactBareToken(core); ok {
			spans = append(spans, span{from: original(off, loc[0]), to: original(off, loc[0]+len(core)), with: rep})
		}
	}
	return applySpans(s, spans)
}

func redactBareToken(core string) (string, bool) {
	rest := core
	if at := strings.LastIndex(core, "@"); at >= 0 {
		rest = core[at+1:]
	}
	j := strings.IndexAny(rest, "/?")
	host, remainder := rest, ""
	if j >= 0 {
		host, remainder = rest[:j], rest[j:]
	}
	if (remainder == "" || remainder == "/") && len(rest) == len(core) {
		return "", false // a host and a bare slash: nothing is hidden in it
	}
	return host + redactedPath, true
}

// =============================================================================
// The literal pass
// =============================================================================

// secretSet is the registered literals, longest first, and the replacer built from them.
type secretSet struct {
	lits []string
	rep  *strings.Replacer
}

var secrets struct {
	mu      sync.Mutex
	lits    map[string]int // literal -> registrations holding it
	hosts   map[string]int // lower-case host -> registrations holding it
	current atomic.Pointer[secretSet]
}

// RegisterProviderURL registers the secrets a provider URL carries - the userinfo user and password, every path segment of
// at least 12 bytes, every query value of at least 6, the fragment (each at least minSecretLiteral long) - together with
// their URL-encoded and JSON-escaped spellings, so that RedactText removes them wherever they occur. It is called where a
// provider URL is configured (every client, pool and reader constructor); public segments like rpc, v2 and v3 are shorter
// and stay. The returned function undoes exactly this registration (tests); production ignores it. A literal that is a
// part of any registered host name is not applied (it would rewrite the host, which is kept so the provider is named).
func RegisterProviderURL(raw string) (unregister func()) {
	lits, host := providerSecrets(raw)
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	if secrets.lits == nil {
		secrets.lits, secrets.hosts = map[string]int{}, map[string]int{}
	}
	for _, l := range lits {
		secrets.lits[l]++
	}
	if host != "" {
		secrets.hosts[host]++
	}
	rebuildSecretsLocked()
	var once sync.Once
	return func() {
		once.Do(func() {
			secrets.mu.Lock()
			defer secrets.mu.Unlock()
			for _, l := range lits {
				if secrets.lits[l]--; secrets.lits[l] <= 0 {
					delete(secrets.lits, l)
				}
			}
			if host != "" {
				if secrets.hosts[host]--; secrets.hosts[host] <= 0 {
					delete(secrets.hosts, host)
				}
			}
			rebuildSecretsLocked()
		})
	}
}

// RegisterProviderURLs registers each URL.
func RegisterProviderURLs(raws ...string) {
	for _, r := range raws {
		RegisterProviderURL(r)
	}
}

func rebuildSecretsLocked() {
	var lits []string
	for l := range secrets.lits {
		lower := strings.ToLower(l)
		if strings.Contains(RedactedMarker, lower) || strings.Contains(lower, strings.ToLower(RedactedMarker)) {
			continue
		}
		inHost := false
		for h := range secrets.hosts {
			if strings.Contains(h, lower) {
				inHost = true
				break
			}
		}
		if !inHost {
			lits = append(lits, l)
		}
	}
	if len(lits) == 0 {
		secrets.current.Store(nil)
		return
	}
	sort.Slice(lits, func(i, j int) bool {
		if len(lits[i]) != len(lits[j]) {
			return len(lits[i]) > len(lits[j])
		}
		return lits[i] < lits[j]
	})
	pairs := make([]string, 0, 2*len(lits))
	for _, l := range lits {
		pairs = append(pairs, l, RedactedMarker)
	}
	secrets.current.Store(&secretSet{lits: lits, rep: strings.NewReplacer(pairs...)})
}

func redactLiterals(s string) string {
	set := secrets.current.Load()
	if set == nil {
		return s
	}
	return set.rep.Replace(s)
}

// providerSecrets are the literals a provider URL carries (in every spelling) and its lower-case host.
func providerSecrets(raw string) (lits []string, host string) {
	raw = strings.TrimSpace(raw)
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	authority, tail := rest, ""
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		authority, tail = rest[:j], rest[j:]
	}
	seen := map[string]bool{}
	add := func(l string, min int) {
		if len(l) < min {
			return
		}
		for _, v := range spellings(l) {
			if len(v) >= minSecretLiteral && !seen[v] {
				seen[v] = true
				lits = append(lits, v)
			}
		}
	}
	host = authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		host = authority[at+1:]
		user, pass, hasPass := strings.Cut(authority[:at], ":")
		add(user, minSecretLiteral)
		if hasPass {
			add(pass, minSecretLiteral)
		}
	}
	host = strings.ToLower(host)
	fragment := ""
	if k := strings.Index(tail, "#"); k >= 0 {
		fragment, tail = tail[k+1:], tail[:k]
	}
	path, query := tail, ""
	if k := strings.Index(tail, "?"); k >= 0 {
		path, query = tail[:k], tail[k+1:]
	}
	for _, seg := range strings.Split(path, "/") {
		add(seg, 12)
	}
	for _, kv := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		_, val, has := strings.Cut(kv, "=")
		if !has {
			val = kv
		}
		add(val, 6)
	}
	add(fragment, minSecretLiteral)
	return lits, host
}

// spellings are the ways a literal can appear in text: itself, URL-encoded for a query and for a path (upper and lower case
// hex), and JSON-escaped (with the HTML escapes encoding/json writes, and an escaped slash).
func spellings(l string) []string {
	out := []string{l}
	if low := lowerPercentHex(l); low != l {
		out = append(out, low)
	}
	if d, err := url.PathUnescape(l); err == nil && d != l {
		out = append(out, d)
	}
	if d, err := url.QueryUnescape(l); err == nil && d != l {
		out = append(out, d)
	}
	base := append([]string(nil), out...)
	for _, v := range base {
		for _, e := range []string{url.QueryEscape(v), url.PathEscape(v)} {
			out = append(out, e, lowerPercentHex(e))
		}
		if b, err := json.Marshal(v); err == nil && len(b) >= 2 {
			j := string(b[1 : len(b)-1])
			out = append(out, j, strings.ReplaceAll(j, "/", string(rune(bs))+"/"))
		}
	}
	return out
}

func lowerPercentHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' {
			for k := 1; k <= 2; k++ {
				if b[i+k] >= 'A' && b[i+k] <= 'F' {
					b[i+k] += 'a' - 'A'
				}
			}
		}
	}
	return string(b)
}
