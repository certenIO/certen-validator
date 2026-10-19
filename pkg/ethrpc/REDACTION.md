# Provider-text redaction: what it does and what it does not (RB10-B14a, RB10-B15)

`ethrpc.RedactText` is the one sanitiser of text that came from a provider, a transport or a provider URL before it is
stored, returned in an error or logged. `ethproof.BoundProviderText` is the same rule at 1024 bytes. The text is in the
doc comment of `RedactText` too; this file is the list a reviewer or an operator reads.

## What it does

- Every URL-looking token becomes `scheme://host/<redacted>` (userinfo, path, query and fragment are dropped, the host
  stays so the provider is named). URLs are read as the characters they stand for: JSON-escaped slashes and quotes,
  unicode escapes (single or double escaped), percent escapes (up to two further levels), JSON-escaped newlines and tabs;
  a quoted URL may be wrapped at white space.
- Every registered literal (`RegisterProviderURL`, called by every client, pool and reader constructor and by the
  command-line dials) is replaced wherever it occurs, in raw, URL-encoded and JSON-escaped spellings. This catches
  echoes that are not URLs: a path-only echo, a header, a bare `user:key@host`.
- Registered literals: userinfo user and password of at least 8 bytes; a path segment of at least 12 bytes, or at least 8
  holding a letter and a digit that is not a hex number of up to 11 digits, or an all-digit segment of at least 16; a
  query value or the fragment of at least 8 bytes, or at least 6 holding a letter and a digit. A literal that is a part of
  a registered host, of the marker, or a catalogued chain name or one of its words is not applied.
- The text is read to at most 64 KiB (`MaxRedactedText`), never more, and never returned longer. A text longer than that
  is cut where no secret can straddle the cut (the last token, a quoted URL whose closing quote is not in the prefix, a
  prefix of a registered literal), redacted, ended at a token boundary, and followed by a space and the visible suffix
  `…(truncated N bytes)`. Redaction is never run on unbounded text and never under a mutex: the pool and the provider
  health compute the redacted reason first and lock after. The result is a fixed point (a second pass changes nothing).
- A redacted error (`RedactError`) redacts its text once, when `Error` is first called. `errors.Is`, `errors.As` and every
  classification (`ShouldFailover`, `IsTransient`, `Retry-After`) run on the original, raw error.

## What it does not claim (the honest limits)

1. A bare key that is neither inside a URL nor a registered literal (a provider that was never configured here).
2. A key used as a host label: the host stays, by design, so the provider is named.
3. `host#KEY`: a fragment-only echo of a URL that was not registered.
4. A base64 `Authorization: Basic` header: the encoding hides the pair from the pattern, and the decoded pair is not
   registered as such.
5. An unquoted URL hard-wrapped at a newline inside its key: the token ends at the newline and the second half stays (a
   quoted URL wrapped at white space is handled).
6. A secret shorter than the thresholds above is removed only where it stands inside a URL (the pattern pass); as a bare
   word it stays, because so short a literal would rewrite ordinary words (`admin`, `root`), chain names (`sepolia`,
   `arbitrum`) or pieces of hashes (`beef`).
7. An unbalanced quote makes the redaction over-redact (the text after it is read as one wrapped URL); it never
   under-redacts.
8. The registry only grows in a process (production never unregisters). A literal registered after
   `fmt.Errorf("...%w", RedactError(err))` built its wrapper is not applied to the wrapper: the wrapper froze the text
   when it was made. A `redactedError` itself applies a literal registered before its first `Error()` call, not after.
9. The 64 KiB prefix rule: everything past the first 64 KiB, and the last token or open quoted URL of the prefix, is not
   shown at all, and a user:password longer than 4096 bytes at the cut is not recognised as one. A 1024-byte bound shows
   only the first 1024 bytes of the redacted prefix.
10. Look-alike characters (a fullwidth solidus) that no HTTP stack produces.
