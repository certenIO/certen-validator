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
  health compute the redacted reason first and lock after. Pattern and literal passes are repeated until the text is
  stable (at most six rounds), so a quoted URL whose host is a registered literal (`"https://<key>/v2/"`) is a fixed point.
  Tried on 50 000 hostile texts with literals registered and 120 000 more through three further applications: none changed.
  What is guaranteed is weaker than "forever": redacting an already redacted text never reveals anything and is stable after
  one more pass; a text that had not settled in six rounds (none has been found) is returned as the sixth round left it.
- The cut of the 64 KiB bound is one linear pass over the prefix (`endOfClosed`), not a loop: the cost of a text is the same
  whatever its shape (quoted URLs that close each other took seconds before).
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
9. The 64 KiB prefix rule: everything past the first 64 KiB is not shown at all, and the prefix is ended where no secret
   can straddle the cut: a run with no white space, quote, angle bracket or backslash that reaches the end of the prefix is
   dropped back to its start, however long it is (a 70 KB body that is one token, or 4 MiB of `a` or `/`, shows only the
   truncation suffix, even at the 1024 bound), and so is an open quoted URL or the start of a registered literal. Information
   loss only: nothing that is shown is a secret. A 1024-byte bound shows only the first 1024 bytes of the redacted prefix.
10. Look-alike characters (a fullwidth solidus) that no HTTP stack produces.
11. `ethproof.BoundProviderText` removes NUL bytes before it redacts (PostgreSQL refuses the escape for them in a jsonb
    document); the N of its truncation suffix counts the bytes of the text without them. `ethrpc.RedactText` itself keeps
    them, so a registered key split by NUL bytes is not a literal to it: text that is stored goes through
    `BoundProviderText`, text for an error or a log may go through `RedactText`.
