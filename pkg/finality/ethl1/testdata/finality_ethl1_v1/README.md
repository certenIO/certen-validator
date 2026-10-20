# finality_ethl1_v1 - published conformance vectors for the Ethereum L1 finalized-head verifier

Spec: V2_SPEC_S7 r2 section 5.2 (steps 1-5), 3.2 (LC container), 7 (faults); annex R11-sepolia. Consensus-specs reference:
`v1.7.0-beta.4` (aa16bb4c), Altair `sync-protocol.md` and Gloas `light-client/*.md`. The Go verifier is `pkg/finality/ethl1`; a TypeScript
verifier consumes a byte-identical copy of this directory and must return the same canonical verdict bytes on every case.

Everything is binary-safe: this directory has `.gitattributes: * -text`. `manifest.json` lists the SHA-256 of every other file
(the raw capture included); `MANIFEST.sha256` is the SHA-256 of `manifest.json`. A consumer verifies both before running.

## Files

| path | content |
|---|---|
| `raw/` | the live capture (2026-10-20, Lodestar v1.50.0 for the beacon objects, publicnode for the execution headers): `finality_update.ssz`, `bootstrap.ssz`, `updates/<period>.ssz` (1378 is the Fulu, electra-layout update; 1379.. are Gloas), `spine.json` (20 raw RLP headers), `capture.json` |
| `pins/*.json` | `Pins` per case: `main` (ledger of every period 1379..1390 derived from the captured link chain; the block root of the last period is the captured bootstrap checkpoint) and variants that alter exactly one pin; `synth` for the synthetic cases |
| `lc/<id>.bin` | the LC part of an evidence container, byte-exact per spec 3.2 (`STR profile, u8 anchorKind, u64 anchorPeriod, B32 anchorRoot, LB anchorBody, LIST<LB> links, LB finalUpdate`, `LB = u8 layout, LP ssz`) |
| `cases/<id>.json` | one case: `kind` `head` (pins + lc, expect a `FinalizedHead` or a fault) or `covers` (`exec_hash`, raw-RLP `spine`, `max`, optional `block_number`) |

## Expected verdicts

`expect` is `{"result":"ok","finalized_head":{...}}`, `{"result":"ok","blocks":[...]}` or `{"result":"fault","code":...,"fields":{...}}`.
The comparison is on canonical bytes: keys sorted at every level, no whitespace, **every integer rendered as a decimal string**, every byte
string `0x` + lower-case hex, strings JSON-escaped without HTML escaping. A fault is `{"code":"...","fields":{...}}` in that form.
For `head` cases an ok verdict has the six keys `beacon_root, epoch, exec_hash, participants, periods_crossed, slot`; for `covers` it is the array
of `{hash, number, state_root, timestamp}` of the spine, top first.

## Conventions this implementation fixes where the spec leaves a choice (each is a candidate for the spec's next revision)

* `index` of `finality_link_invalid` / `finality_participation_insufficient` / `finality_signature_invalid` is the position in `links`; the final update has `index = len(links)`. `finality_link_invalid.period` is the signature period.
* `finality_link_invalid.check` values used: `attested_header_exec_branch`, `finalized_header_exec_branch`, `slot_order`, `period_skip`, `not_relevant`, `not_finality`, `finality_branch`, `not_sync_committee_update`, `next_committee_mismatch`, `next_committee_branch`, `not_applied`, `finalized_period`. `finality_bootstrap_invalid.check`: `anchor_period`, `header_exec_branch`, `committee_branch`.
* A kind-2 anchor whose ledger entry has no `block_root` is `finality_pin_unknown{kind:2}`; `anchorRoot` or a committee/bootstrap root that differs from the ledger is `finality_pin_mismatch{period, want_root = ledger value, got_root}`.
* Window rule (spec 5.2 step 3): `epoch(finalized_i) - 256*signing_period <= wsp_epochs`, the signing period being the committee's ledger label; reported as `finality_pin_window{anchor_epoch = 256*signing_period, finalized_epoch, wsp_epochs}`. See the check-in finding RB11-C1A-F1: the step-to-step reading refuses the live chain.
* A Gloas-shaped update whose finalized header lies in the Electra or Fulu era is validated at gindex 812 over a zero-extended 11-node branch; a finalized header in a fork with no layout is `finality_fork_unsupported`.
* An electra-layout blob (layout byte 1) is recognised by minimum size and first offset, its attested slot is read, and it is refused as `finality_fork_unsupported{slot, epoch, layout:"electra"}` until RB11-C1B.

## Cases

`valid_*` are accepted; `adv_*` are refused with the code and fields in `expect`; `spine_*` / `adv_spine_*` exercise `Covers`; `synth_*` / `adv_synth_*` are
signed by a four-key test committee (secret scalars derived from fixed labels at generation time, never stored) for rules no live object reaches today:
the fork boundary between the attested slot and `signature_slot - 1`, the exact 342 boundary with a valid signature, an Electra-era finalized header
inside a Gloas-shaped update, the identity signature. Every other case is a byte mutation of the captured objects.

## Regenerating

    finalityethl1record record -out pkg/finality/ethl1/testdata/finality_ethl1_v1/raw        # network, once
    finalityethl1record build  -raw pkg/finality/ethl1/testdata/finality_ethl1_v1/raw -out pkg/finality/ethl1/testdata/finality_ethl1_v1

`build` is offline and deterministic; it refuses to write a case whose verdict differs from the code and selected fields it states by hand.
