# finality_base_posted2 - published stream conformance vectors for base-sepolia/l1_posted/v1

Spec: V2_SPEC_S7 r2 section 5.4 O4/O5 (the channel's batches). Companion of `finality_base_posted1` (live evidence, never edited). The Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must agree on every case (8 cases).

`manifest.json` lists the SHA-256 of every other file; `MANIFEST.sha256` is the SHA-256 of `manifest.json`.

Each `streams/<id>.json` is one decompressed channel (the RLP strings `type byte || payload` the channel inflates to) with:

- `params`: the chain constants a span batch is read against (L2 genesis time, L2 block time, L2 chain id; the Base Sepolia pins of set 1).
- `stream`: the decompressed channel, `0x` hex. Every span batch is assembled byte by byte by `generator/gen2.py` (Python, standard library only; no Go code and no code under test is involved), so the literals are the specification.
- `decode`: the decode-level expectation of `decodeBatches(stream, params)`: `{result:"stream_error"}` (the stream does not parse: the kind reports `channel_malformed`; an unsupported batch or transaction type would be `batch_format_unsupported`, none of these cases has one) or `{result:"ok", batches:[...]}` with every field a decimal string and every transaction `0x` hex (its consensus encoding). A decoder must never panic, whatever the counts.
- `verifier`: the verifier-level expectation in set 1's canonical form (`{result:"state", code, fields}`): what `verifyChannel` names for a synthetic calldata channel carrying exactly this stream, judged against an L2 block at timestamp 1790000000. The Go suite builds that synthetic world (`synth_test.go`, from fixed labels); an implementation without one compares the `decode` part only.

What the cases pin: the span batch's per-block transaction counts are untrusted 64-bit numbers. A uint64 sum of them wraps (`[1, 2^64-1]` sums to 0, `[2, 2^64-1]` to 1, `[5, 2^64-5]` to 0) and slips under the 2^20 bound; the decoder then allocates by the wrapped total and indexes by the declared counts. The bound is therefore applied to the exact sum (each count is checked against what remains of the bound before it is added). The first published decoder (Go `e0c50c9`) panicked with an index out of range on the first three cases; the TypeScript twin was exact from the start.

Regenerate: `python -I generator/gen2.py <set directory>` (rewrites `streams/` , `manifest.json`, `MANIFEST.sha256`; this README is hand-written and is listed in the manifest, so regenerate after editing it).
