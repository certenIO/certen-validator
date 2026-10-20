// Copyright 2026 Certen Protocol

package ethproof

import (
	"strings"

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

// BoundProviderText is the one sanitiser of text a provider served before it is stored: ethrpc.BoundRedacted at
// MaxReplayTextBytes (RB10-B15), the rule every bound on provider text shares. Only the first 64 KiB of the text is read
// (redaction is regular-expression work, and a 10 MB body must not cost a second of it each time a provider answers), cut
// where no URL or registered literal straddles the cut; that prefix is redacted; and when the result is longer than
// MaxReplayTextBytes it is ended at a token boundary (a UTF-8 character boundary at the least) and followed by a space and
// the visible suffix "…(truncated N bytes)", N the bytes not shown, the whole of it at most MaxReplayTextBytes long. Text
// within both bounds is returned as RedactEndpoints returns it, and bounding is stable under a second application (see FIXED
// POINT in ethrpc.RedactText for exactly what is guaranteed). The text holds no NUL byte (withoutNUL).
func BoundProviderText(s string) string {
	return boundProviderTextTo(s, MaxReplayTextBytes)
}

func boundProviderTextTo(s string, max int) string {
	return ethrpc.BoundRedacted(withoutNUL(s), max)
}

// withoutNUL is s without its NUL bytes (RB10-B17, V-R10B8 D5): PostgreSQL rejects the escape \u0000 in a jsonb document, so
// evidence that held one could not be stored at all, and a registered key split by NULs would otherwise not be a literal
// to the redactor and would be joined by whatever later removed them. They are removed BEFORE the text is redacted. The N of
// the truncation suffix counts the bytes of the text without them.
func withoutNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}
