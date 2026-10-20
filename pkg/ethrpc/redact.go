// Copyright 2026 Certen Protocol

package ethrpc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// One redactor for provider text (RB10-B14a, bounded in RB10-B15)
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
//     configured provider URLs are known, so their userinfo, path segments, query values and fragment are registered
//     (RegisterProviderURL) when a client or pool is constructed, in raw, URL-encoded and JSON-escaped spellings. This
//     catches the echoes that are not URLs (a path-only echo, a header).
//
// It is linear in the length of the text (RE2, no backtracking; the cut of the read bound is one pass; the rounds below are
// bounded), it is stable (FIXED POINT below), and text with no URL and no registered literal is returned byte for byte.
//
// THE BOUND (RB10-B15). A provider's text is not bounded by anything but the provider: go-ethereum reads a whole non-2xx
// body into an error. RedactText therefore never works on more than the first MaxRedactedText (64 KiB) of its input, and
// never returns more: the input is cut, then redacted, then ended at a token boundary, and a cut text says so with the
// visible suffix "…(truncated N bytes)" (BoundRedacted is the same rule at any limit; ethproof.BoundProviderText is it at
// 1024). The cut text is ended where no secret can straddle it, by ONE linear pass over the prefix (endOfClosed): at a
// delimiter, so that the last token (a user:password in the middle of being read, a URL with no path yet) is not shown; not
// inside a quoted URL whose closing quote is not in the prefix; and not inside, or right after the first bytes of, a
// registered literal. So no fragment of a URL or of a literal survives the cut. The suffix is separated from the text by a
// space, so no URL token runs into it. N counts the bytes of the input not shown, plus the bytes of the redacted prefix
// dropped to fit the limit. No caller may hold a lock while it calls RedactText on text it does not control; the pool and
// the provider health compute the text first and lock after.
//
// FIXED POINT (RB10-B17). The pattern and literal passes are repeated until the text is stable: at most maxRedactRounds (6)
// rounds, each of at most maxRedactPasses (4) pattern passes and one literal pass (a literal replaced by the marker changes
// the host of a URL and the distance between a quote and its closing quote, which the pattern pass reads again; a marker that
// stands as the host of a quoted URL is kept). In every text tried the result is a fixed point (RedactText of it is itself):
// 50 000 hostile texts with literals registered, around both bounds, and 120 000 more through three further applications,
// changed in none. The loop is bounded, so what is guaranteed is the weaker property the callers rely on: redacting an
// already redacted text never reveals anything (a pass only replaces URLs and literals by the marker) and is stable after
// one more pass; a text that had not settled in six rounds (none has been found) would be returned as the sixth left it.
//
// WHAT IT DOES NOT CLAIM (the honest limits; pkg/ethrpc/REDACTION.md has the same list):
//
//   - a bare key that is neither inside a URL nor a registered literal (a provider that was never configured here);
//   - a key used as a host label: the host stays, by design, so that the provider is named;
//   - a fragment-only echo (host#KEY) of a URL that was not registered;
//   - a base64 Basic-authorization header: the encoding hides the user:password from the pattern, and the decoded pair is
//     not registered as such;
//   - an UNQUOTED URL hard-wrapped at a newline inside its key: the token ends at the newline and the second half stays
//     (a quoted URL wrapped at white space is handled);
//   - a secret shorter than the registration thresholds (a path segment under 8, a query value under 6, a userinfo under 8
//     characters, an all-digit path segment under 16) is removed only when it stands inside a URL; as a bare word it stays,
//     because a literal that short would rewrite ordinary words, chain names and pieces of hashes;
//   - a registered literal that is also a catalogued chain name is not applied (it would rewrite the chain name);
//   - an unbalanced quote makes the redaction over-redact (the text after it is read as one wrapped URL), never under-redact;
//   - the registry only grows in a process (production never unregisters), and a literal registered after a wrapper was built
//     with fmt.Errorf("...%w", RedactError(err)) is NOT applied to that wrapper: the wrapper froze the text when it was made;
//   - look-alike characters (a fullwidth solidus) that no HTTP stack produces;
//   - everything past the 64 KiB prefix, and the end of the prefix back to the last place where no secret can straddle the cut
//     (see the bound above): that text is not shown at all. A run with no white space, quote, angle bracket or backslash
//     that reaches the end of the prefix is dropped back to its START, however long it is (a 70 KB body that is one token,
//     or 4 MiB of "a" or "/", shows only the truncation suffix, even at the 1024 bound): information loss, nothing more.

// RedactedMarker replaces what is hidden.
const RedactedMarker = "<redacted>"

// redactedPath replaces everything of a URL after its host.
const redactedPath = "/" + RedactedMarker

// MaxRedactedText is the most bytes of a text RedactText reads and the most it returns (64 KiB). Redaction is regular-
// expression work at about a megabyte a second on URL-dense text, so it is bounded where the text enters.
const MaxRedactedText = 64 << 10

const (
	// TruncatedPrefix and TruncatedSuffix surround the number of bytes not shown: "…(truncated 4096 bytes)".
	TruncatedPrefix = "…(truncated "
	TruncatedSuffix = " bytes)"
)

// bs is a backslash. It is a constant so that no source text has to spell an escape sequence.
const bs = '\x5c'

// trailingPunctuation is what ends a sentence or a clause after a URL, not the URL.
const trailingPunctuation = ".,;:!?)]}"

// maxQuotedURL is the most bytes a quoted URL may span (a URL wrapped at white space inside its quotes).
const maxQuotedURL = 2048

// minSecretLiteral is the shortest spelling of a registered literal: a decoded spelling shorter than this is a word, and
// replacing it everywhere would destroy the text. (Registration has its own, higher, thresholds: see providerSecrets.)
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
// returned in an error or logged: BoundRedacted at MaxRedactedText. See the package comment above, which also lists what it
// does not claim.
func RedactText(s string) string {
	return BoundRedacted(s, MaxRedactedText)
}

// BoundRedacted is s redacted and at most limit bytes long. The first MaxRedactedText bytes of s are read (never more), cut
// where no secret can straddle the cut (see above), redacted by the pattern and literal passes, and, when the result does
// not fit limit, ended at a token boundary of the redacted text and followed by " …(truncated N bytes)". Text within both
// bounds is returned as the redaction returns it. The result is stable under a second application,
// BoundRedacted(BoundRedacted(s, n), n) is itself, within the honest limit of FIXED POINT above. limit must leave room for
// the suffix; a smaller limit gets the suffix alone.
func BoundRedacted(s string, limit int) string {
	if s == "" {
		return s
	}
	read, unread := readPrefix(s)
	r := redactAll(read)
	if unread == 0 && len(r) <= limit {
		return r
	}
	return cutRedacted(r, unread, limit)
}

// redactAll is the two passes on text already within the read bound, repeated until the text no longer changes.
func redactAll(s string) string {
	// The pattern pass is applied until nothing changes (at most four times): what one pass leaves (a userinfo glued in front
	// of a host that a replacement then exposed as a URL) the next removes. The literal pass then follows, and the two are
	// repeated until the text is stable (RB10-B17, V-R10B8 D2): a literal replaced by the marker changes the length of what
	// stands between a quote and its closing quote (the window of a quoted URL is maxQuotedURL bytes) and the host of a URL,
	// which the pattern pass reads again. The rounds are bounded, so a text that has not settled after maxRedactRounds is
	// returned as that round left it: nothing is revealed by another round, but another application may change it once more.
	for round := 0; round < maxRedactRounds; round++ {
		u := s
		for i := 0; i < maxRedactPasses; i++ {
			t := redactBareURLs(redactSchemeURLs(u))
			if t == u {
				break
			}
			u = t
		}
		t := redactLiterals(u)
		if t == s {
			return t
		}
		s = t
	}
	return s
}

// maxRedactPasses bounds the pattern passes of one round, maxRedactRounds the rounds of pattern and literal passes.
const (
	maxRedactPasses = 4
	maxRedactRounds = 6
)

// readPrefix is the part of s that is read and how many bytes of s are not: s itself when it is within MaxRedactedText,
// otherwise a prefix of at most MaxRedactedText bytes that ends where nothing is open (see endOfClosed).
func readPrefix(s string) (read string, unread int) {
	if len(s) <= MaxRedactedText {
		return s, 0
	}
	cut := MaxRedactedText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	end := endOfClosed(s[:cut])
	return s[:end], len(s) - end
}

// endOfClosed is the end, at most len(p), of the longest prefix of the cut text p that no secret straddles (RB10-B17: ONE
// linear pass, nothing is re-evaluated). A cut at j is refused when it
//
//   - falls inside a token: the prefix must end at a delimiter (white space, a quote, an angle bracket, a backslash that is not
//     an escape), because the last run of bytes may be the userinfo of a URL whose @ was cut off;
//   - falls between a quoted URL's opening quote and the closing quote that the full text has within maxQuotedURL bytes of its
//     body (the pattern pass reads a quoted URL as an unquoted one when the closing quote is not in the prefix, and the pieces of
//     a URL wrapped at white space are then not recognised); or
//   - falls inside a registered literal (any spelling), or after the first bytes of one that the prefix ends in.
//
// Each refusal is a range of cut positions computed once for the whole prefix (a difference array, so that the cost is the
// length of the prefix and not the number of ranges), and the answer is the largest position no range refuses. A range depends
// only on the text of the prefix, never on where the cut ends up, so there is nothing to repeat: the end is a fixed point of the
// three rules by construction (the loop this replaced moved the end by one open URL at a time and was quadratic on quoted
// URLs that close each other). A run with no delimiter is dropped back to its start, however long it is. The pass is over the
// whole prefix (at most MaxRedactedText bytes), so a text of any length costs the same.
func endOfClosed(p string) int {
	norm, off := decodeURLEscapes(p)
	quoted := openQuotedCover(norm)
	lits := literalCover(p)
	for j := len(norm); j > 0; j-- {
		if !endsToken(norm[j-1]) || quoted != nil && quoted[j] > 0 {
			continue
		}
		at := original(off, j)
		if lits != nil && lits[at] > 0 {
			continue
		}
		return at
	}
	return 0
}

// coverSums turns a difference array into the number of ranges that cover each position.
func coverSums(diff []int32) []int32 {
	for j := 1; j < len(diff); j++ {
		diff[j] += diff[j-1]
	}
	return diff
}

// openQuotedCover counts, for every cut position j of the decoded prefix norm (the prefix norm[:j]), the quoted URLs that the
// cut would leave open: a scheme directly after a quote q, with no q between its body and j, while the body is not yet
// maxQuotedURL bytes long (a URL whose closing quote is further away is read as an unquoted one in the full text too, and
// the same in the prefix). nil when no scheme stands after a quote. Positions j = start (the cut right before the scheme,
// after its opening quote) and j after the closing quote are not refused.
func openQuotedCover(norm string) []int32 {
	var diff []int32
	for _, loc := range schemeStart.FindAllStringIndex(norm, -1) {
		start, body := loc[0], loc[1]
		if start == 0 || !isQuote(norm[start-1]) {
			continue
		}
		hi := len(norm) // the cuts start+1 .. hi are refused
		if z := strings.IndexByte(norm[body:min(len(norm), body+maxQuotedURL+1)], norm[start-1]); z >= 0 {
			hi = body + z
		} else if body+maxQuotedURL < len(norm) {
			continue // the whole window is in the prefix and holds no closing quote
		}
		if diff == nil {
			diff = make([]int32, len(norm)+2)
		}
		diff[start+1]++
		diff[hi+1]--
	}
	if diff == nil {
		return nil
	}
	return coverSums(diff)
}

// literalCover counts, for every cut position j of p, the registered literals that a cut at j would split or end in: a
// position i of p where a literal (any spelling) starts, or where p[i:] starts one, refuses the cuts i+1 .. i+m, m the bytes
// they share. (A literal that stands whole in p and is cut right after its last byte is refused too: over-cautious by one
// position, never under.) The shared prefix of p[i:] and the registered literals is found by a binary search in the sorted
// literals, at the positions whose first byte starts some literal; so the cost is the length of p, not the length of p times
// the number of literals. nil when nothing is registered or nothing in p starts a literal.
func literalCover(p string) []int32 {
	set := currentSecrets()
	if set == nil {
		return nil
	}
	var diff []int32
	for i := 0; i < len(p); i++ {
		if !set.first[p[i]] {
			continue
		}
		m := set.sharedPrefix(p[i:min(len(p), i+set.maxLen)])
		if m == 0 {
			continue
		}
		if diff == nil {
			diff = make([]int32, len(p)+2)
		}
		diff[i+1]++
		diff[i+m+1]--
	}
	if diff == nil {
		return nil
	}
	return coverSums(diff)
}

// sharedPrefix is the most bytes that w has in common with the start of a registered literal.
func (s *secretSet) sharedPrefix(w string) int {
	lo, hi := 0, len(s.sorted)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if s.sorted[mid] < w {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	best := 0
	if lo < len(s.sorted) {
		best = commonPrefix(w, s.sorted[lo])
	}
	if lo > 0 {
		if c := commonPrefix(w, s.sorted[lo-1]); c > best {
			best = c
		}
	}
	return best
}

func commonPrefix(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// cutRedacted ends the redacted prefix r at a token boundary so that the result, with the suffix, is at most limit bytes.
func cutRedacted(r string, unread, limit int) string {
	overhead := len(TruncatedPrefix) + len(TruncatedSuffix)
	for digits := 1; ; digits++ {
		budget := limit - overhead - 1 - digits // the kept text, the space, the number
		keep := 0
		if budget > 0 {
			keep = tokenBoundary(r, budget)
		}
		n := len(r) - keep + unread
		if len(strconv.Itoa(n)) > digits {
			continue
		}
		suffix := TruncatedPrefix + strconv.Itoa(n) + TruncatedSuffix
		if keep == 0 {
			return suffix
		}
		return r[:keep] + " " + suffix
	}
}

// tokenBoundary is the length of the longest prefix of r, at most max, that ends a token: not inside a UTF-8 character, not
// inside a run with no white space, quote or angle bracket (when such a delimiter is within 256 bytes), and with no trailing
// white space. A run longer than that is cut where it is.
func tokenBoundary(r string, max int) int {
	keep := len(r)
	if max < keep {
		keep = max
		for keep > 0 && !utf8.RuneStart(r[keep]) {
			keep--
		}
		if keep > 0 && !endsToken(r[keep]) && !endsToken(r[keep-1]) {
			for i := keep - 1; i >= 0 && keep-i <= 256; i-- {
				if endsToken(r[i]) {
					keep = i
					break
				}
			}
		}
	}
	for keep > 0 && isSpace(r[keep-1]) {
		keep--
	}
	return keep
}

// RedactError is err with its text redacted: Error() is RedactText of the original's, and Unwrap returns the original, so
// errors.Is, errors.As and every classification by type or code see the original error. An error whose text has nothing to
// redact is returned itself (a sentinel is still the sentinel). The text is redacted once, when Error is first called, and
// kept: a literal registered between RedactError and the first Error is applied, one registered after is not, and a wrapper
// built from the result (fmt.Errorf("...%w", RedactError(err))) holds the text it was made with.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	if m := err.Error(); RedactText(m) == m {
		return err
	}
	return &redactedError{err: err}
}

type redactedError struct {
	err  error
	once sync.Once
	text string
}

func (e *redactedError) Error() string {
	e.once.Do(func() { e.text = RedactText(e.err.Error()) })
	return e.text
}
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
	return scheme + hostPrefix(host) + redactedPath, true
}

// hostPrefix is the part of host that is kept: a host never holds a character that ends or changes a token (a quoted token can
// hold any), and what follows one is dropped, so that the result reads the same when it is redacted again. The marker is
// kept whole (RB10-B17, V-R10B8 D2): a registered literal that stood in a host position was replaced by it, and a host that
// is the marker reads the same when it is redacted again (the angle brackets of the marker are token-ending bytes).
func hostPrefix(host string) string {
	for i := 0; i < len(host); {
		if strings.HasPrefix(host[i:], RedactedMarker) {
			i += len(RedactedMarker)
			continue
		}
		if endsToken(host[i]) {
			return host[:i]
		}
		i++
	}
	return host
}

// bareDelimiter: the bytes no part of a bare URL (its userinfo, host, port, path or query) can hold: RE2 white space (not
// vertical tab), a quote, a backquote, an angle bracket, a backslash. A match lies inside one run between them.
func bareDelimiter(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || isQuote(c) || c == '<' || c == '>' || c == bs
}

// redactBareURLs: the expression is run on the runs of text that hold a '/' or a '?' - a bare URL cannot match without one,
// and a match never spans a delimiter - so that text with few URLs costs little however long it is (RB10-B15).
func redactBareURLs(s string) string {
	norm, off := decodeURLEscapes(s)
	if !strings.ContainsAny(norm, "/?") {
		return s
	}
	var spans []span
	for i := 0; i < len(norm); {
		for i < len(norm) && bareDelimiter(norm[i]) {
			i++
		}
		j, marked := i, false
		for j < len(norm) && !bareDelimiter(norm[j]) {
			marked = marked || norm[j] == '/' || norm[j] == '?'
			j++
		}
		if marked {
			run := norm[i:j]
			for _, loc := range bareURL.FindAllStringIndex(run, -1) {
				core := strings.TrimRight(run[loc[0]:loc[1]], trailingPunctuation)
				if rep, ok := redactBareToken(core); ok {
					spans = append(spans, span{from: original(off, i+loc[0]), to: original(off, i+loc[0]+len(core)), with: rep})
				}
			}
		}
		i = j
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
	lits   []string
	rep    *strings.Replacer
	sorted []string  // the same literals in byte order (the search of the cut, see sharedPrefix)
	first  [256]bool // the first bytes of the literals
	maxLen int       // the length of the longest literal
}

var secrets struct {
	mu    sync.Mutex
	lits  map[string]int // literal -> registrations holding it
	hosts map[string]int // lower-case host -> registrations holding it
	// dirty is set (under mu) by a registration or an undo and cleared by the rebuild that follows the first use: the set
	// is built once per change that is used, never once per registration, so registering N URLs costs N.
	dirty   atomic.Bool
	current atomic.Pointer[secretSet]
}

// currentSecrets is the set of registered literals in force, rebuilt first when a registration changed it.
func currentSecrets() *secretSet {
	if secrets.dirty.Load() {
		secrets.mu.Lock()
		if secrets.dirty.Load() {
			rebuildSecretsLocked()
			secrets.dirty.Store(false)
		}
		secrets.mu.Unlock()
	}
	return secrets.current.Load()
}

// RegisterProviderURL registers the secrets a provider URL carries - the userinfo user and password (each at least 8
// bytes), the path segments (12 bytes, or 8 with a letter and a digit that are not a hex number, or 16 digits), the query
// values and the fragment (8 bytes, or 6 with a letter and a digit) - together with their URL-encoded and JSON-escaped
// spellings, so that RedactText removes them wherever they occur. It is called where a provider URL is configured (every
// client, pool and reader constructor); public segments like rpc, v2 and v3 are shorter and stay, and so does anything that
// is a catalogued chain name. A shorter secret is still removed wherever it stands inside a URL (the pattern pass). The
// thresholds keep a registered literal from rewriting ordinary words ("admin", "root"), chain names ("sepolia",
// "arbitrum") or the pieces of a hash ("beef"). The returned function undoes exactly this registration (tests); production
// ignores it. A literal that is a part of any registered host name is not applied (it would rewrite the host, which is kept
// so the provider is named).
func RegisterProviderURL(raw string) (unregister func()) {
	lits, host := providerSecrets(raw)
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	if secrets.lits == nil {
		secrets.lits, secrets.hosts = map[string]int{}, map[string]int{}
	}
	added := false // a registration of a URL already registered (a client dialed per request) changes nothing
	for _, l := range lits {
		if secrets.lits[l]++; secrets.lits[l] == 1 {
			added = true
		}
	}
	if host != "" {
		if secrets.hosts[host]++; secrets.hosts[host] == 1 {
			added = true
		}
	}
	if added {
		secrets.dirty.Store(true)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			secrets.mu.Lock()
			defer secrets.mu.Unlock()
			removed := false
			for _, l := range lits {
				if secrets.lits[l]--; secrets.lits[l] <= 0 {
					delete(secrets.lits, l)
					removed = true
				}
			}
			if host != "" {
				if secrets.hosts[host]--; secrets.hosts[host] <= 0 {
					delete(secrets.hosts, host)
					removed = true
				}
			}
			if removed {
				secrets.dirty.Store(true)
			}
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
	var blob strings.Builder // every registered host between NULs: a literal inside it is inside one host
	blob.WriteByte(0)
	for h := range secrets.hosts {
		blob.WriteString(h)
		blob.WriteByte(0)
	}
	hostBlob := blob.String()
	marker := strings.ToLower(RedactedMarker)
	var lits []string
	for l := range secrets.lits {
		lower := strings.ToLower(l)
		if strings.Contains(marker, lower) || strings.Contains(lower, marker) {
			continue
		}
		if len(secrets.hosts) > 0 && strings.Contains(hostBlob, lower) {
			continue
		}
		lits = append(lits, l)
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
	set := &secretSet{lits: lits, rep: strings.NewReplacer(pairs...), sorted: append([]string(nil), lits...)}
	sort.Strings(set.sorted)
	for _, l := range lits {
		set.first[l[0]] = true
		set.maxLen = max(set.maxLen, len(l))
	}
	secrets.current.Store(set)
}

func redactLiterals(s string) string {
	set := currentSecrets()
	if set == nil {
		return s
	}
	return set.rep.Replace(s)
}

// A literal is registered by where it stands in the URL; each place has its own floor, because a short word is common in
// text and a long one is not.
type literalPlace int

const (
	placeUserinfo literalPlace = iota
	placePathSegment
	placeQueryOrFragment
)

// Registration thresholds (RB10-B15, V-R10B7 D4.1/D4.3).
const (
	minUserinfoLiteral     = 8  // a user or a password
	minPathLiteral         = 12 // a path segment
	minMixedPathLiteral    = 8  // a path segment holding a letter and a digit and not being a hex number
	minDigitsPathLiteral   = 16 // an all-digit path segment (a chain id, a block number, a timestamp are shorter)
	minQueryLiteral        = 8  // a query value or the fragment
	minMixedQueryLiteral   = 6  // ... holding a letter and a digit
	maxHexNumberLiteralLen = 11 // an all-hex run up to this long is read as a block or chain number
)

// worthRegistering reports whether l, standing in place, is a secret to register.
func worthRegistering(place literalPlace, l string) bool {
	letter, digit := false, false
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letter = true
		}
	}
	mixed := letter && digit
	switch place {
	case placeUserinfo:
		return len(l) >= minUserinfoLiteral
	case placePathSegment:
		if allDigits(l) {
			return len(l) >= minDigitsPathLiteral
		}
		if len(l) >= minPathLiteral {
			return true
		}
		return len(l) >= minMixedPathLiteral && mixed && !(isHexNumber(l) && len(l) <= maxHexNumberLiteralLen)
	default:
		return len(l) >= minQueryLiteral || len(l) >= minMixedQueryLiteral && mixed
	}
}

// isHexNumber: l is hexadecimal digits, with or without a leading 0x.
func isHexNumber(l string) bool {
	s := strings.TrimPrefix(strings.TrimPrefix(l, "0x"), "0X")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if hexVal(s[i]) < 0 {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// chainWords are the words the supported-chain catalogue uses for its chains (names, networks, aliases, families, display
// names and the parts of each): a provider URL often repeats them in a path or a query ("network=arbitrum-sepolia"), and a
// literal that is one of them would rewrite the chain's name wherever the text names it.
var chainWords = func() func() map[string]bool {
	var once sync.Once
	var words map[string]bool
	return func() map[string]bool {
		once.Do(func() {
			words = map[string]bool{}
			add := func(s string) {
				s = strings.ToLower(strings.TrimSpace(s))
				if s == "" {
					return
				}
				words[s] = true
				for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' || r == ' ' }) {
					words[part] = true
				}
			}
			for _, id := range supportedchains.IDs() {
				if c, ok := supportedchains.Lookup(id); ok {
					for _, s := range append([]string{c.Name, c.Network, c.RPCKey, c.Family, c.DisplayName}, c.Aliases...) {
						add(s)
					}
				}
			}
		})
		return words
	}
}()

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
	add := func(l string, place literalPlace) {
		if !worthRegistering(place, l) || chainWords()[strings.ToLower(l)] {
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
		add(user, placeUserinfo)
		if hasPass {
			add(pass, placeUserinfo)
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
		add(seg, placePathSegment)
	}
	for _, kv := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		_, val, has := strings.Cut(kv, "=")
		if !has {
			val = kv
		}
		add(val, placeQueryOrFragment)
	}
	add(fragment, placeQueryOrFragment)
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
