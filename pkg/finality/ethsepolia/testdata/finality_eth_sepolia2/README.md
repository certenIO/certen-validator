# finality_eth_sepolia2 - eth-sepolia/finalized/v1 anchored at the EMBEDDED root pin

Spec: V2_SPEC_S7 r2 sections 3.2, 4.3, 5.2 and 8.2. Same case shapes and canonical verdict form as finality_eth_sepolia1 (see its README);
that set is never edited.

## Why a second set

finality_eth_sepolia1 is judged under VECTOR pins: a 14-entry ledger (1378..1391) whose entries 1379..1390 were derived by verified
light-client links only (spec 4.3(b), the two-client rule, cannot be met for them: no public beacon client serves those historical
states, RB11-C2-F1). The pins EMBEDDED in the verifiers hold the root pin 1378 only. Evidence anchored at 1380 or 1391 is therefore
refused under the embedded pins as finality_ledger_behind, although nothing in it is wrong. This set is the production shape under the
embedded pins: the evidence is ANCHORED AT THE ROOT PIN and carries the best light-client update of every period from 1378 to the
signature period as in-evidence LINKS (spec 3.2), at most max_links (64) of them. Each case is judged under pins/main.json, which is
byte-identical to pkg/finality/pins/finality-pins.json at generation; the Go test also judges the valid cases under the pins embedded in
the running verifier.

## Contents

| path | content |
|---|---|
| raw/<leg>/evidence.bin | the CFE1 container built by the production Prover (ethsepolia.Prover.BuildLeg) against the embedded pins from the answers recorded for finality_eth_sepolia1 (final update, spine headers, the best update of every period 1378..1390), and accepted by the verifier. gloas_latest: block 11,950,125, 13 links; gloas_period: block 11,862,203; legacy: block 11,845,679 (electra layout, anchored at 1378, 0 links) |
| raw/gloas_latest_kind2/evidence.bin | the same evidence with a kind-2 anchor: the Fulu bootstrap of the pinned checkpoint block root instead of the bare committee (what the runtime light-client source builds for the rollup kinds) |
| raw/<leg>/leg.json, capture.json | the leg block; sizes and times |
| raw/links/<period>.ssz | the ledger link files (1378 = the root bootstrap, q = the best update of period q-1) |
| pins/main.json | the embedded pins file |
| cases/<id>.json | one verification case |

## Cases

valid_gloas_latest, valid_gloas_period, valid_legacy, valid_gloas_latest_kind2 (accepted, verdict fields as in set 1);
adv_link_signature_flipped (one signature byte of link 5: finality_signature_invalid{index 5}), adv_link_removed (link 5 removed:
finality_link_invalid{period_skip}), adv_links_removed_all (no links although the final update is 13 periods past the anchor:
finality_period_gap), adv_links_over_bound (link count 65: finality_evidence_too_large), adv_kind2_anchor_root_altered (kind-2
anchorRoot differs from the pinned block root: finality_pin_mismatch).

## Regenerating

    finalityethsepoliarecord build2 -set1 pkg/finality/ethsepolia/testdata/finality_eth_sepolia1 -out pkg/finality/ethsepolia/testdata/finality_eth_sepolia2    # offline
