# finality_adiri4 (RB11-GATE-A): Adiri pins strictness and the genesis-link load check

New evidence, new set: finality_adiri1/2/3 stay byte-identical (a published vector set is specification and is never edited). This
set adds what finality_adiri3 does not pin, for the Go verifier and the TypeScript port alike.

Files (all hashed by MANIFEST.json, which MANIFEST.json.sha256 hashes):

- vectors.json, format finality_adiri4/1: the SAME vector shape as finality_adiri3 (name, group, note, leg, pins, evidence, expect),
  group pins, 21 vectors. Each judges Verify(pins, leg, evidence) of the small synthetic rotation chain (evidence/syn-rotation.bin, a
  copy of finality_adiri3's) under the inline adiri pins section of finality_adiri3's syn-rotation with exactly one member changed.
  pins-control-valid is the unchanged section (verdict = syn-rotation's); every other vector is a pins refusal:
  finality_pins_corrupt{key, reason:bad_value|unknown_key[, index]}. The rule they pin: a pinned hash, address or key is exact hex,
  with its 0x prefix where it has one: an odd number of digits (63, 39, 191) is NOT padded with a zero, a non-hex digit is NOT
  truncated, a bare 0x or a one-character value is refused, and the committee, bounds, link-hash length and member names are checked
  as listed. Upper case is accepted (the EIP-2935 address is a mixed-case checksum).
- genesis_link.json, format finality_adiri4-genesis-link/1, 12 vectors: the load-time check of the 290-header genesis link
  (V2_SPEC_S7 4.2, annex A7). Each vector has pins (an adiri section), a link file (link: a path in this set, edited by edits
  {offset, delete, insert-hex}; or link_hex, the bytes inline, possibly empty) and expect: the literal text ok, or the canonical
  state. The check: sha256(file) must equal pins.genesis_link_sha256 (else finality_pins_corrupt{key:adiri.genesis_link_sha256,
  reason:bad_value}); then the file must be a concatenation of RLP header lists that runs from block 1 (parentHash =
  pins.genesis_hash) through linked headers to epoch0_final_state (else key adiri.genesis_link). It is checked once at load, never
  per proof. A pins section without an adiri member is finality_pin_unknown (not a vector: it needs a whole pins file).
- evidence/syn-rotation.bin and link/genesis_link_1_290.bin (176,758 B): data.

Expectations are literals composed by pkg/finality/adiri/vectorgen/gen_adiri4.mjs (stdlib only; it does not call the verifier):
{"code":...,"fields":{sorted keys, every value a string}}. Regenerate with node from the repository root; the output is deterministic.
