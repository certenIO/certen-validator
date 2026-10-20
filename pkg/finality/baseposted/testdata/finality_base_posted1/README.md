# finality_base_posted1 - published conformance vectors for base-sepolia/l1_posted/v1

Spec: V2_SPEC_S7 r2 section 5.4, 3.3, 7. The Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must return the same canonical bytes on every case (28 cases).

`manifest.json` lists the SHA-256 of every other file; `MANIFEST.sha256` is the SHA-256 of `manifest.json`.

- `evidence/valid_a.bin`, `valid_b.bin`: real evidence (live Base Sepolia channels posted to the batch inbox, real KZG proofs, a real Sepolia light-client finality chain). A case other than these stores only a `splice` over a named evidence file.
- `pins/*.json`: finality pins override files (`--pins`): `main` is the embedded base_sepolia section plus a Sepolia ledger derived from the captured light-client chain; the others alter exactly one pin.
- `legs/*.json`: the L2 block header (Settlement.Header) the evidence is judged against.
- `cases/*.json`: `{pins, leg, evidence, splice?, expect}`; `expect` is `{result:ok, fields}` or `{result:state, code, fields}`; the comparison is on canonical bytes (sorted keys, integers as decimal strings, bytes 0x lower-case hex).

Synthetic cases (calldata-mode batcher transaction, zlib channels, span batches, wrong batcher sender, transaction not to the inbox, channel timeout, malformed channel) need a synthetic L1 and are covered by Go unit tests in `synth_test.go` / `verify_test.go`; they are not part of this set yet.

Regenerate: `finalitybasepostedrecord watch` (live capture), `finalityethl1record record|build` (light-client chain), `finalitybasepostedrecord build`. Build time of evidence A from the capture: 5s.
