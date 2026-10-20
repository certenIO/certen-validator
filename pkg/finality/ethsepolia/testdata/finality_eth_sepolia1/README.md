# finality_eth_sepolia1 - published conformance vectors for eth-sepolia/finalized/v1

Spec: V2_SPEC_S7 r2 sections 3.3, 4.3 and 5.3 (Pins.Extend). The Go verifier is pkg/finality/ethsepolia (Verifier.Verify) over
pkg/finality/ethl1; the TypeScript verifier consumes a byte-identical copy of this directory and must return the same canonical
verdict bytes on every case. Same layout as finality_arb_posted1; where it differs it is stated here.

| path | content |
|---|---|
| raw/<leg>/evidence.bin | the REAL CFE1 container built by the production Prover and accepted by the verifier: gloas_latest (block 11,950,125, post-Gloas, served by the latest finality update), gloas_period (block 11,862,203, post-Gloas, served by the best update of its period), legacy (block 11,845,679, pre-Gloas, electra layout, long spine) |
| raw/<leg>/leg.json | the Sepolia block it is about: hash, number, raw RLP header (Settlement.Header) |
| raw/<leg>/capture.json | when, from where and how long the build took |
| raw/links/<period>.ssz | the ledger link files: the root-pin bootstrap (1378) and the update that derived each later entry |
| raw/pending/ | the recorded answers (finality update, head slot, headers by hash) that the offline builder test replays for a leg newer than the finalized head |
| pins/main.json | the pins the cases are judged under: the embedded pins' network section and a 14-entry ledger (periods 1378..1391) derived by VERIFIED LIGHT-CLIENT LINKS from the root pin. IT IS A VECTOR PIN: its entries 1379..1390 were not cross-checked on two beacon clients (no public endpoint serves those historical states, see the check-in); the published ledger in pkg/finality/pins holds the root pin only |
| pins/<name>.json | variants that alter exactly one thing: ledger_ends_1385, ledger_empty, gvr_other |
| cases/<id>.json | one verification case |
| extend/ | Pins.Extend cases: base and extension pins files, link overrides |

## A verification case

{format, id, description, pins, leg{chain, number, hash, header_rlp}, evidence_base, evidence_patches[{at, del, ins}], expect_canonical}.
The evidence is evidence_base with every patch applied; offsets refer to the BASE, patches are applied from the highest at to the
lowest (they never overlap); ins is 0x hex. The call is Kind.Verify(pins, leg, evidence) with the pins parsed as an override file.
expect_canonical is the canonical text of the verdict: {"code":"verified","fields":{...}} (fields: finalized_slot, finalized_exec_number,
participants, periods_crossed, headers_walked, anchor_period, kind, level) or {"code":<state>,"fields":{...}}; keys sorted at every
level, no whitespace, EVERY integer a decimal string, every byte string 0x lower-case hex. The literals are written in
cmd/finalityethsepoliarecord, computed there from the recorded bytes by small independent readers (RLP, SSZ offsets), not by the
verifier; build refuses a case whose verdict differs from its literal.

## An extend case

{format, id, description, base (pins file), extension (pins file), links_dir, links_replace{period: file}, links_drop[period], expect_canonical}.
The call is ParsePinsOverride(base).Extend(extension bytes, links) with links = every <period>.ssz of links_dir, replaced and dropped
as stated. expect_canonical is {"code":"verified","fields":{"anchors":N,"pins_source":"extension:<sha256 of the extension>"}} or the
finality_ledger_extension_invalid state.

## Check order (the first failing check names the state)

container header (magic, kind, chain, level, block number, block hash against the leg); body decode (bounded, strict: lc.links
count, spine count, trailing bytes); every spine header readable; the L1 finalized head from the LC part (profile, anchor kind and
period, ledger, layouts, forks, every link and the final update); the spine (top = finalized execution head, parent chain);
the leg's number on the spine; hash and byte identity; the spine ends at the leg.

## Regenerating

    finalitypins derive-sepolia -min-clients 0 -api-timeout 4s -out-pins <dir>/pins.json -links-dir <dir>/links     # vector pins
    finalityethsepoliarecord record -vecpins <dir> -raw <raw dir>                                                   # network
    finalityethsepoliarecord build  -raw <raw dir> -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia1      # offline
