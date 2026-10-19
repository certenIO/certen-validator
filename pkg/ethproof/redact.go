// Copyright 2026 Certen Protocol

package ethproof

import (
	"strconv"
	"unicode/utf8"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RedactEndpoints is the one sanitiser of text that came from a provider's transport before it is stored or logged
// (RB10-B11). It is ethrpc.RedactText (RB10-B14a), where the redactor lives so that every layer that builds a provider
// error - the agreeing reader, the transient retry, the provider health, the finality log, the observers - uses the same
// one: every URL-looking token, written plainly or JSON-escaped or percent-encoded, is rewritten to scheme://host/<redacted>
// (the userinfo, the path, the query and the fragment are dropped; the host stays, so the provider is still named), and
// every secret literal of a configured provider URL (ethrpc.RegisterProviderURL) is replaced wherever it occurs, which
// catches the echoes that are not URLs. A URL with nothing after its host is kept as it is.
//
// It is idempotent, and it only ever replaces a URL token or a registered literal: text that holds none is returned byte
// for byte.
func RedactEndpoints(s string) string {
	return ethrpc.RedactText(s)
}

// =============================================================================
// One truncation point for provider-served free text (RB10-B13)
// =============================================================================

// MaxReplayTextBytes is the most bytes any free-text field of S6 evidence - a failure's Error, a named state's Detail, the
// Before-unavailable Reason - may hold when it was built from text a provider served. Honest evidence is under 1 MiB
// without such text, and a provider's error page can be many MB: unbounded, it would push evidence over
// MaxReplayEvidenceBytes and turn a disclosed named state into a refusal of the whole document.
const MaxReplayTextBytes = 1024

// MaxReplayProviderFailures is the most providers a named state or a Before-unavailable disclosure lists; the providers
// after them are one last entry, "(N more providers)".
const MaxReplayProviderFailures = 64

// boundReadBytes is how much of a text is read at all: redaction is regular-expression work, and a 10 MB body must not cost
// a second of it each time a provider answers. Only a prefix is kept, so what is cut off is never shown; the bytes not read
// are counted in the suffix like the others.
const boundReadBytes = 64 << 10

const (
	truncatedPrefix = "…(truncated "
	truncatedSuffix = " bytes)"
)

// BoundProviderText is the one sanitiser of text a provider served before it is stored: RedactEndpoints first, then, when
// the result is longer than MaxReplayTextBytes, a cut at a UTF-8 character boundary with the visible suffix
// "…(truncated N bytes)" (N the bytes dropped), the whole of it at most MaxReplayTextBytes long. Text within the bound is
// returned as RedactEndpoints returns it, and bounding is idempotent.
func BoundProviderText(s string) string {
	return boundProviderTextTo(s, MaxReplayTextBytes)
}

func boundProviderTextTo(s string, max int) string {
	if s == "" {
		return s
	}
	total := len(s)
	if len(s) > boundReadBytes {
		cut := boundReadBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	unread := total - len(s)
	r := RedactEndpoints(s)
	if unread == 0 && len(r) <= max {
		return r
	}
	keep := max - len(truncatedPrefix) - len(truncatedSuffix) - len(strconv.Itoa(total))
	if keep < 0 {
		keep = 0
	}
	if keep > len(r) {
		keep = len(r)
	}
	for keep > 0 && keep < len(r) && !utf8.RuneStart(r[keep]) {
		keep--
	}
	return r[:keep] + truncatedPrefix + strconv.Itoa(len(r)-keep+unread) + truncatedSuffix
}
