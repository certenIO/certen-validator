# finality_arb_final2 - superseded expectation

The files of this set are unchanged (MANIFEST d66c84963b219122c615fb71e3156765a361e02cdb979ea9c10be8668b5d2ea2). One expectation described the boundary the wallet proof has since
removed, and the README's sentence "the callee's code is NOT proven to be a ValidatorWallet" no longer describes the verifier (the README is
not edited):

| case | recorded expectation | verdict now |
|---|---|---|
| synth_valid_wallet_route_callee_code_is_not_examined | `finalized`, route wallet (the callee 0x...00cc takes the wallet route on its calldata alone) | `confirmation_path_unproven{reason:"indirect", tx:<its tx>, l1_block:<K>}` |

Since RB12-E1RAISE a transaction whose To is not the Rollup takes the wallet route only for a callee proven to be a ValidatorWallet at K
(V2_SPEC_S7 5.7 O4, amendment r3). That case's callee carries no proof, so it is refused as unidentified code. The set's other cases (the
contract-creation cases, the leg's chain, max_node_bytes) are unchanged. The pins file of this set carries no wallet pins; a consumer adds
the four entries named in finality_arb_final1/SUPERSEDED.md before judging. finality_arb_final3 carries a proven wallet at an unrelated
address (`synth_valid_wallet_at_another_address_proven`) and the refused callees.
