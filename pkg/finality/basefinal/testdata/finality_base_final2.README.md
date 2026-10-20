# finality_base_final2 - judge vectors for base-sepolia/finalized/v1 (the checks the independent review found absent)

This README is deliberately OUTSIDE the set directory `finality_base_final2/`, whose files are all pinned by its `manifest.json`
(`MANIFEST.sha256` is the SHA-256 of `manifest.json`). The first set, `finality_base_final1`, is published and is never edited.

Each `judge/<id>.json` is a `certen-finality-judge-vectors/1` case, the same format as the judge cases of set 1: the covered L1 block A
(number, hash, state root, timestamp), the evidence parts that are not the light client (game proxy, game code, output-root index, L2
spine, proof nodes), the leg and the pins file `pins/main.json` (a byte-identical copy of set 1's `pins/main.json`). The state root is a
SYNTHETIC world's: the world is built by the Go synthetic builder `BuildSynth` (which knows the contract layouts, not the judge), the
verdict is the canonical string the Go judge writes (sorted keys, integers as decimal strings, bytes `0x` lower-case hex) and a
TypeScript verifier must return the same bytes.

| case | what it pins | expected |
|---|---|---|
| `zero_claim_header_without_withdrawals_root` | the game claims an output root of all zeros and the L2 header at the head of the spine has no withdrawals root: a header without one has no output root, so the claim cannot match (a zero standing for "absent" must not equal a zero claim) | `output_root_mismatch{computed:0x00..00, claimed:0x00..00}` |
| `output_root_header_is_another_block` | the header's output root is the claimed one, but the game's layout puts that output root 1000 blocks higher: the header must be the block the game implies (spec 5.5 O5, annex step 8) | `output_root_mismatch{computed==claimed}` |
| `portal_names_another_asr_than_the_game_build` | the Portal names an ASR proxy (same code and state as the real one) other than the AnchorStateRegistry the pinned game implementation is built for (annex step 5; the `asr` field of the game_impl pin) | `contract_identity_unproven{role:game_impl,...}` |
| `respected_type_switched_old_game_still_valid` | the ASR's current respected game type was switched after the game was created: the game keeps its own `wasRespectedGameTypeWhenCreated` flag (R11 Q5) | accepted verdict |

Fail-before: at `6814d26` the first three cases are ACCEPTED (the judge returns a verdict, not the written refusal); at the fix they are
refused with the strings in the files. The fourth is accepted at both.

## What a TypeScript twin must mirror (exact list)

1. Output root: a header without a withdrawals root is `output_root_mismatch` (computed all zeros, claimed as claimed) whatever the claim.
2. Output root: `header.number == outBlock` (the block the game implies: `l2seq` for the root claim, `start + interval*k` for the k-th
   intermediate root) else `output_root_mismatch` (computed = the header's root, claimed).
3. Game implementation pin: the row's `asr` (required: a row without a readable `asr` is incomplete = absent) must equal the ASR proven
   from `Portal.slot62`, and the row's `dgf` (optional) must equal the DisputeGameFactory proven from `ASR.slot1` when pinned, else
   `contract_identity_unproven{role:game_impl}`.
4. Pins: `impl_pins` / `proxy_pins` keys must not be the zero hash (`finality_pins_corrupt{bad_value, key}`).
5. Finality delay without wrap: `game_within_delay` iff `A.timestamp <= resolvedAt` or `A.timestamp - resolvedAt <= delay`.
6. Pins layout minimum: `game_layout.args_base_len >= 136` and `args_per_root >= 32` (`finality_pins_corrupt{bad_value, key base_sepolia.game_layout}`).
