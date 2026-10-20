# finality_ethl1_v2 - published conformance vectors for the Ethereum L1 finalized-head verifier (electra and gloas layouts)

Spec: V2_SPEC_S7 r2 section 5.2 (steps 1-5), 3.2 (LC container, both layouts, the mixed-fork rule), 5.3 (legacy legs), 7 (faults);
annex R11-sepolia. Consensus-specs reference: `v1.7.0-beta.4` (aa16bb4c), Altair `sync-protocol.md`, Electra and Gloas
`light-client/*.md`. The Go verifier is `pkg/finality/ethl1`; the TypeScript verifier consumes a byte-identical copy of this directory and
must return the same canonical verdict bytes on every case. **This is the set the TypeScript port is written against.** v1
(`finality_ethl1_v1`) is frozen and superseded (its `SUPERSEDED.md`); v2 contains every v1 case regenerated under the v2 domain tag
(`finality_ethl1_v2/` in every derived label, so the synthetic key material differs), except `electra_link_real_fulu_update`, whose v1
verdict was the electra stand-in "refused by name": the real Fulu objects are now judged (`valid_k2_fulu_*`, `adv_electra_*`).

Everything is binary-safe (`-text`). `manifest.json` lists the SHA-256 of every other file (raw capture included); `MANIFEST.sha256` is the
SHA-256 of `manifest.json`. A consumer verifies both before running.

## Files

| path | content |
|---|---|
| `raw/` | the live captures: v1's (2026-10-20, Lodestar v1.50.0, publicnode) and the v2 additions of the same day: `bootstrap_fulu.ssz` (the Fulu LightClientBootstrap of the period-1378 checkpoint block `0x5f71d7f6...b20d`, slot 11,288,576), `update_1377.ssz`, `update_1378.ssz` (the Fulu best updates, electra layout), `spine_legacy.bin`, `capture2.json`. Lodestar's bytes were compared field by field with Lighthouse's JSON (publicnode serves Lighthouse light-client objects as Beacon API JSON): `capture2.json` records the result |
| `raw/spine_legacy.bin` | the 4,057 raw execution headers from the finalized execution head of the period-1378 update (block 11,849,735) down to block 11,845,679, framed `u32be count, then u32be length + RLP per header`; every header was rebuilt from the node's JSON and hashes to the hash the node and the parent link state |
| `pins/*.json` | `Pins` per case: `main` (ledger of periods 1378..1390: 1378 from the Fulu bootstrap with its checkpoint `block_root`, 1379..1390 derived from the captured link chain, the last `block_root` the captured Gloas bootstrap checkpoint) and variants that alter one pin; `synth*` for the synthetic cases |
| `lc/<id>.bin` | the LC part of an evidence container, byte-exact per spec 3.2 (`STR profile, u8 anchorKind, u64 anchorPeriod, B32 anchorRoot, LB anchorBody, LIST<LB> links, LB finalUpdate`, `LB = u8 layout, LP ssz`). Several `adv_ledger_period_<q>_altered` cases share `lc/valid_k1_chain_v2.bin` and differ only in their pins |
| `cases/<id>.json` | one case: `kind` `head` (pins + lc, expect a `FinalizedHead` or a fault) or `covers` (`exec_hash`, `max`, optional `block_number`, and the headers either inline `spine` (raw-RLP hex list) or in `spine_file` (a framed file of the set)) |

## Expected verdicts

`expect` is `{"result":"ok","finalized_head":{...}}`, `{"result":"ok","blocks":[...]}`, `{"result":"ok","headers_walked":"N","block":{...}}` or
`{"result":"fault","code":...,"fields":{...}}`. The comparison is on canonical bytes: keys sorted at every level, no whitespace, **every integer
rendered as a decimal string**, every byte string `0x` + lower-case hex, strings JSON-escaped without HTML escaping. A fault is
`{"code":"...","fields":{...}}` in that form. For `head` cases an ok verdict has the six keys `beacon_root, epoch, exec_hash, participants,
periods_crossed, slot`. For `covers` cases with inline `spine` an ok verdict is the array of `{hash, number, state_root, timestamp}` of the
spine, top first; with `spine_file` (the 4,057-header legacy spine) it is `{"block":{hash,number,state_root,timestamp},"headers_walked":"N"}`
for the block named by `block_number` (the spine is walked and `BlockAt` applied; a fault replaces the whole verdict).

## The electra layout (new in v2)

Layout byte 1 (`LB.layout`), Electra and Fulu. SSZ offsets are little-endian u32. Strict decoding: each offset must equal the value the fixed
parts imply (the first container offset is the fixed size), the second offset must leave 828..860 bytes for the first header and the rest of
the blob must be 828..860 bytes, no trailing byte exists.

* `ExecutionPayloadHeader` (Deneb/Electra/Fulu, 17 fields): fixed part 584 bytes (`extra_data` offset at byte 436 must equal 584), then `extra_data` of 0..32 bytes. hash_tree_root: 17 leaves zero-padded to 32; `logs_bloom` as 8 chunks; `extra_data` as one chunk mixed with its length; uint64 fields little-endian zero-padded.
* `LightClientHeader` = `beacon(112) | offset(execution)=244 | execution_branch(4 x 32) | ExecutionPayloadHeader`, 828..860 bytes. Valid iff `is_valid_merkle_branch(hash_tree_root(execution), execution_branch, depth 4, index 9, beacon.body_root)` (gindex 25), judged by the fork of the header's own slot (a fork whose layout is not `electra` is `finality_fork_unsupported`).
* `LightClientBootstrap` = `offset(header)=24820 | current_sync_committee(24,624) | current_sync_committee_branch(6 x 32) | header` (min 25,648). gindex 86.
* `LightClientUpdate` = `offset(attested)=25216 | next_sync_committee | next_sync_committee_branch(6) | offset(finalized) | finality_branch(7) | sync_aggregate(160) | signature_slot(8) | attested | finalized` (min 26,872). gindices next 87, finalized 169.
* `LightClientFinalityUpdate` = `offset(attested)=400 | offset(finalized) | finality_branch(7) | sync_aggregate | signature_slot | attested | finalized` (min 2,056).
* Mixed forks (spec 3.2 c): the container shape follows the attested header's fork (checked against `forks[].layout`); every header is validated by the rule of the fork of its own slot. A Gloas-shaped update with a Fulu finalized header uses gindex 812 over a zero-extended branch (as in v1).
* A wrong layout byte cannot select a parse that succeeds: every electra blob is longer than its Gloas twin (26,872 > 26,424, 25,648 > 25,472, 2,056 > 1,448).

## Conventions (v1's, unchanged unless stated)

* `index` of `finality_link_invalid` / `finality_participation_insufficient` / `finality_signature_invalid` is the position in `links`; the final update has `index = len(links)`. `finality_link_invalid.period` is the signature period.
* `finality_link_invalid.check` values: `attested_header_exec_branch`, `finalized_header_exec_branch`, `slot_order`, `period_skip`, `not_relevant`, `not_finality`, `finality_branch`, `not_sync_committee_update`, `next_committee_mismatch`, `next_committee_branch`, `not_applied`, `finalized_period`. `finality_bootstrap_invalid.check`: `anchor_period`, `header_exec_branch`, `committee_branch`. **New:** a final update whose finalized header has slot 0 is `not_finality` (it establishes no finalized execution head).
* `finality_evidence_malformed.reason` values the electra decoders add: `header_length`, `execution_offset`, `extra_data_offset`, `extra_data_length`, `attested_offset`, `finalized_offset`, `header_offset`, `length`; the `part` is `anchor_body`, `link` (with `index`) or `final_update`.
* A kind-2 anchor whose ledger entry has no `block_root` is `finality_pin_unknown{kind:2}`; `anchorRoot` or a committee/bootstrap root that differs from the ledger is `finality_pin_mismatch{period, want_root = ledger value, got_root}`; every committee a link learns is held to its ledger entry (first learn and rotation alike).
* Window rule (spec 5.2 step 3, r2 F10): `epoch(finalized_i) - 256*signing_period <= wsp_epochs`; `finality_pin_window{anchor_epoch = 256*signing_period, finalized_epoch, wsp_epochs}`.
* **New:** only the PARTICIPATING keys of a committee are decoded and validated (an invalid key at a seat whose bit is clear does not refuse the committee; the committee is authenticated by hash_tree_root against the pin; an invalid key at a signing seat is `finality_signature_invalid`). The identity point is not a valid key or signature; both are subgroup-checked.
* **New:** the pins' `chain_id` must be 11155111 (`finality_network_mismatch{chain_id: 11155111, want_chain_id: <pins value>}`).

## Cases

`valid_*` are accepted; `adv_*` are refused with the code and fields in `expect`; `spine_*` / `adv_spine_*` exercise `Covers`; `synth_*` / `adv_synth_*` are
signed by a four-key test committee (secret scalars derived from labels at generation time, never stored). New in v2:

* `valid_k2_fulu_k0`, `valid_k1_fulu_k0`: the legacy-leg final update (spec 5.3): the period-1378 Fulu update converted to a finality update, electra layout, under a kind-2 anchor of the Fulu bootstrap / a kind-1 anchor of its committee. `spine_legacy_leg`: its 4,057-header spine to block 11,845,679; `adv_spine_legacy_leg_over_bound`, `spine_legacy_block_above_head`.
* `valid_k2_fulu_chain_to_gloas`, `valid_k1_fulu_chain_to_gloas`: the mixed-fork chain: the Fulu update as link 0, eleven Gloas links, the live Gloas finality update; 12 periods crossed.
* `adv_electra_*`, `adv_gloas_layout_byte_electra_on_gloas_bytes`: a forged execution-header field or branch node (attested and finalized), a forged finality / next-committee branch node, a wrong gindex family at a slot (electra-shaped update at a Gloas slot), extra_data / execution / container offsets that lie, an overlong tail, layout byte 2 on electra bytes and 1 on Gloas bytes, the wrong fork version in the pins, forged bootstrap fields, ledger roots that differ, Fulu-link signature / participation / branches.
* `adv_ledger_period_<q>_altered` (q = 1380..1390): `valid_k1_chain` with the ledger entry of one learned period replaced (first-learn and rotation branches both reached).
* `synth_valid_link_then_final`, `adv_synth_next_committee_mismatch`, `adv_synth_final_period_gap_next_known`, `adv_synth_link_period_skip_next_known`, `synth_valid_nonparticipating_invalid_key`, `adv_synth_participating_invalid_key`, `adv_synth_final_finalized_slot_zero`, `adv_pins_network_mismatch`.

## Regenerating

    finalityethl1record record  -out <v1 raw dir>                                  # v1 capture, network (frozen)
    finalityethl1record record2 -raw <v1 raw dir> -out <v2 additions dir>          # network, once
    finalityethl1record build2  -raw <v1 raw dir> -raw2 <v2 additions dir> -out pkg/finality/ethl1/testdata/finality_ethl1_v2

`build2` is offline and deterministic; it refuses to write a case whose verdict differs from the code and selected fields it states by hand.
