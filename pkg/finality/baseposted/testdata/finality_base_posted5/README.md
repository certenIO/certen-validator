# finality_base_posted5 - post-Denim vectors for base-sepolia/l1_posted/v1 (RB11-D-POST)

Companion of `finality_base_posted1` to `4` (never edited). Same case format `certen-base-posted-case/1`; the Go verifier is `pkg/finality/baseposted`; a TypeScript verifier consumes a byte-identical copy and must judge every case the same way.

`manifest.json` lists the SHA-256 of every other file (this README included) and `pins_sha256_embedded`, the SHA-256 of the pins file embedded in the verifier that judged the set (`pkg/finality/pins/finality-pins.json`); `MANIFEST.sha256` is the SHA-256 of `manifest.json`. `pins/main.json` is the embedded pins file whose `eth_sepolia` section is the one derived from the captured light-client chain; its `base_sepolia` section, `post_denim` row included, is byte-identical to the embedded one (a Go test asserts it).

14 cases. Real evidence, captured live from Base Sepolia and Ethereum Sepolia on 2026-10-26: the legs below, each in a Brotli channel of EIP-4844 blobs posted by the batcher to the inbox, real KZG proofs, a real light-client finality chain, five L2 blocks per timestamp second (200 ms blocks), a BaseTime deposit as transaction 1.

| leg | Base Sepolia block | timestamp | channel | L1 block(s) |
|---|---|---|---|---|
| `second_block_last_of_its_second` | 50446330 | 1793011134 | `57717b8326d6f3aa1f2ad0a958f21dea` | [11997451] |
| `second_block_first_of_its_second` | 50446331 | 1793011135 | `57717b8326d6f3aa1f2ad0a958f21dea` | [11997451] |
| `second_block_second_of_its_second` | 50446332 | 1793011135 | `57717b8326d6f3aa1f2ad0a958f21dea` | [11997451] |
| `straddle_last_of_first_channel` | 50447096 | 1793011288 | `57717b8326d6f3aa1f2ad0a958f21dea` | [11997451] |
| `straddle_first_of_next_channel` | 50447097 | 1793011288 | `386bfe8c1c850f58db5e77091cce2b92` | [11997464 11997464] |
| `another_channel_fourth_block` | 50459059 | 1793013680 | `5d6332f3392411bdface99f0be47e31f` | [11997666] |

## What the cases pin

- Valid cases: a block is bound to the singular batch of its channel whose timestamp AND full 32-byte parent hash are the block's (`second_block_second_of_its_second` is a block a timestamp-only lookup judges `batch_binding_mismatch{parent_hash}`; the straddled second is found in the right one of two channels).
- `denim_leg_parent_hash_altered`, `denim_leg_names_the_previous_batch_of_its_second`, `denim_straddle_leg_with_the_other_channel`: the batch is selected by parent hash, never by position or by timestamp.
- `denim_basetime_deposit_dropped`, `denim_basetime_deposit_altered`: the BaseTime deposit is bound only through `transactionsRoot` (no BaseTime or schedule predicate: tech debt O6).
- `denim_pins_without_post_denim` (a new binary on old pins fails closed), `denim_time_after_the_block_is_timestamp_keyed` (before the fork the lookup is by timestamp), `denim_pins_post_denim_row_names_span_batches` (the row is corrupt).

Not in this set: a span batch carrying a Denim block (`batch_format_unsupported{type:span_post_denim}`) and a wrong batcher sender (`batcher_sender_mismatch`). Both need a fabricated L1 (the sender is bound by the L1 transaction trie and the SystemConfig state proof, so any byte change of real evidence is refused earlier with another code); they are judged by Go unit tests over the synthetic world (`denim_rb12_test.go`).

Regenerate (live data; the public providers serve state proofs only near the head, so the channels must be captured while they are posted): `finalitybasepostedrecord capture -dir CAP -from <head-100> -for 24m`, then `finalityethl1record record -out RAW` after the last captured block is finalized, then `finalitybasepostedrecord build-denim -cap CAP -raw RAW -out <set directory>`.
