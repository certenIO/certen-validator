# finality_eth_sepolia3 - ledger and light-client-parser vectors for review V-C2-A1 (defects D1, D2, D3)

Spec: V2_SPEC_S7 r2 sections 4.3 and 5.2 step 2. Sets finality_eth_sepolia1 and finality_eth_sepolia2 are never edited; this set only
reads bytes copied from set 1 (the 14-entry vector ledger and its link files) and from the pins embedded in the verifier.

## What it pins

D1 - a ledger whose only entry is the root pin (the embedded ledger) was "re-derived" without ever judging the bootstrap: the loop that
calls the light-client verifier starts at the second entry. VerifyLedger now judges the root pin's bootstrap as the kind-2 anchor of
5.2 step 2 (ethl1.VerifyBootstrapAnchor): the pinned block_root is the root of the bootstrap's header, the header's execution branch
and the current-committee branch hold, and the header is in the entry's period. A refusal is finality_ledger_extension_invalid with
reason root_pin_unverifiable at the root pin's period and `inner` = the light-client verifier's code.

D2 - a block_root on an APPENDED entry was never derived or compared (the last appended entry was accepted with any value). An appended
entry is derived by the one link file of its period (4.3: finality-pins-links/<period>.ssz, the update that carries the next committee,
named by link_sha256); there is no bootstrap beside the file to judge a block_root by, so a block_root on an appended entry is refused
with the new reason `block_root_on_appended_entry` (closed set, testdata/finality/states.json) at that entry's period, by Extend and by
VerifyLedger. Only the first entry of a ledger may carry a block_root.

D3 - lcssz.FinalizedExec sliced the finalized header's execution payload header after FinalityUpdateSlots had only checked that the
finalized offset plus 8 bytes lay inside the object (a 2,056-byte Electra update with finalized offset 2,048 panicked). It now returns
lcssz.ErrFinalizedHeaderTooShort (wrapped) for any shape whose finalized header does not hold the 828 fixed bytes.

## Contents

| path | content |
|---|---|
| pins/embedded.json | the pins embedded in the verifiers (sha256 = PinsSHA256) |
| pins/vector_main.json | set 1 pins/main.json: the 14-entry vector ledger 1378..1391 |
| pins/base_1386.json, pins/extend_valid.pins.json | set 1 extension base and the extension that appends 1387..1391 |
| raw/links/<period>.ssz | set 1 link files (1378 = the root bootstrap, 25,679 B; the others are 26,424 B updates) |
| ledger/<id>.json | one ledger case: op (verify_ledger or extend), the file it patches, the patches, the canonical expected verdict |
| lcssz/<id>.json | one FinalizedExec case: a shape (length, attested offset, finalized offset, planted hash and number) and the expected result |

A ledger case patches before judging: `anchor_patch` sets one anchor field (block_root, or period), `link_patch` XORs one byte of a link
file and, with relink, sets that anchor's link_sha256 to the new file's hash (so the byte is not caught by the hash alone), `link_move`
renames a link file. `links_only` restricts the supplied files. Patches are applied to `pins` (verify_ledger) or `extension` (extend).

## Cases

ledger1_embedded_valid, ledger14_valid, extend_valid (controls, accepted); ledger1_bogus_block_root, ledger1_committee_branch_flipped,
ledger1_header_parent_root_flipped, ledger1_header_exec_branch_flipped, ledger1_header_period_is_not_the_entrys,
ledger1_bootstrap_byte_flipped_not_relinked, ledger14_bogus_first_block_root (root_pin_unverifiable at the root pin);
ledger14_block_root_on_1379 / _1385 / _last_1391 and extend_block_root_on_1387 / _1389 / _last_1391 (block_root_on_appended_entry);
lcssz_exact_fit (accepted), lcssz_fin_off_2048_len_2056, lcssz_one_byte_short (finalized_header_too_short), lcssz_below_minimum_length,
lcssz_finalized_offset_not_after_attested (invalid).

## Regenerating

    $env:PV2_SET3_WRITE = '<abs path of this directory>'; pv2gt.ps1 -Worktree <wt> -Pkg ./cmd/finalityethsepolia3record -Run TestSet3Regenerates -NoTrimpath    # offline

The generator refuses to write a case whose production verdict differs from the verdict written by hand in
cmd/finalityethsepolia3record/main.go. Without PV2_SET3_WRITE the same test regenerates into a temporary directory and requires
byte identity with this directory.
