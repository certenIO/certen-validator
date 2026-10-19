// Copyright 2026 Certen Protocol

package ethproof

import (
	"regexp"
	"strings"
)

// RedactEndpoints is the one sanitiser of text that came from a provider's transport before it is stored or logged
// (RB10-B11). Go's HTTP errors embed the full request URL (`Post "https://eth-sepolia.g.alchemy.com/v2/<KEY>": ...`),
// a provider's body may echo it, and the production pools hold Alchemy and Infura URLs whose PATH is the API key: so
// every URL-looking token in s is rewritten to scheme://host/<redacted> (the userinfo, the path, the query and the
// fragment are dropped; the host stays, so the provider is still named). A URL with nothing after its host is kept as it
// is. A host followed by a path or a key query with no scheme (host:port/path) is rewritten the same way, without the
// scheme.
//
// It is idempotent, and it only ever replaces a URL token: text that holds none is returned byte for byte.
func RedactEndpoints(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") {
		s = schemeURL.ReplaceAllStringFunc(s, redactSchemeURL)
	}
	if strings.ContainsAny(s, "/?") {
		s = bareURL.ReplaceAllStringFunc(s, redactBareURL)
	}
	return s
}

// redactedPath replaces everything of a URL after its host.
const redactedPath = "/<redacted>"

// urlBody is the rest of a URL token. It ends at white space, a quote (Go quotes the URL of a url.Error, in text and
// escaped in JSON), a backslash, or an angle bracket; a backslash that starts a JSON unicode escape (an echoed URL in a
// JSON body writes an ampersand that way, x5c is the backslash) stays inside the token. x60 is the backquote.
const urlBody = `(?:\x5cu[0-9a-fA-F]{4}|[^\s"'\x60<>\\])*`

var schemeURL = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://` + urlBody)

// host[:port] followed by /path or ?name=value, with an optional user:password@ before it.
var bareURL = regexp.MustCompile(`(?i)(?:[^\s"'\x60<>\\/@]+@)?` +
	`(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|localhost)` +
	`(?::[0-9]{1,5})?` +
	`(?:/` + urlBody + `|\?[a-z0-9_.%-]+=` + urlBody + `)`)

// trailingPunctuation is what ends a sentence or a clause after a URL, not the URL.
const trailingPunctuation = ".,;:!?)]}"

func redactSchemeURL(tok string) string {
	core := strings.TrimRight(tok, trailingPunctuation)
	tail := tok[len(core):]
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
		return tok // nothing after the host
	}
	return scheme + host + redactedPath + tail
}

func redactBareURL(tok string) string {
	core := strings.TrimRight(tok, trailingPunctuation)
	tail := tok[len(core):]
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
		return tok // a host and a bare slash: nothing is hidden in it
	}
	return host + redactedPath + tail
}
