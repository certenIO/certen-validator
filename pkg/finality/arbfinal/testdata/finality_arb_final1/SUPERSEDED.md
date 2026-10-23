# finality_arb_final1 - superseded expectations

The files of this set are unchanged (MANIFEST 444aeb1bb9028cdfc37c0db993539a7a86521ca550f4bb1585569a69583b944f). Twelve expectations
describe a verifier that took the ValidatorWallet route on the calldata alone: a transaction whose To is not the Rollup and whose input
decodes as one of the four ValidatorWallet entry points was a "wallet" confirmation, and the decoded call decided the state. That label
claimed more than the verifier knew: ANY contract can be called with the bytes of an executeTransaction. Since RB12-E1RAISE the route is taken
only for a callee proven to be a ValidatorWallet at K (V2_SPEC_S7 5.7 O4, amendment r3: the callee's account proof shows the pinned proxy
code, its EIP-1967 implementation slot holds the pinned template, and the template's account shows the pinned logic code). These twelve worlds
carry no proof of any callee, so each answers `confirmation_path_unproven{reason:"indirect", tx:<its tx>, l1_block:<K>}`, also when the
decoded call is a force, a fast confirm, has no confirm call, or the fast confirmer is set (those outcomes are stated only for a proven
wallet).

| case | recorded expectation | verdict now |
|---|---|---|
| synth_valid_wallet_execute_transaction | `finalized`, route wallet | `confirmation_path_unproven{indirect}` |
| synth_valid_wallet_execute_transactions | `finalized`, route wallet | the same |
| synth_valid_wallet_execute_transaction_with_gas_refunder | `finalized`, route wallet | the same |
| synth_valid_wallet_execute_transactions_with_gas_refunder | `finalized`, route wallet | the same |
| synth_valid_wallet_call_is_the_bare_selector | `finalized`, route wallet | the same |
| adv_conf_wallet_call_targets_other_contract | `confirmation_path_unproven{wallet_no_confirm_call}` | the same code, reason `indirect` |
| adv_conf_wallet_call_other_selector | `confirmation_path_unproven{wallet_no_confirm_call}` | the same code, reason `indirect` |
| adv_conf_wallet_call_data_three_bytes | `confirmation_path_unproven{wallet_no_confirm_call}` | the same code, reason `indirect` |
| adv_conf_wallet_fast_call | `confirmed_by_owner_force{path:fast}` | `confirmation_path_unproven{indirect}` |
| adv_conf_wallet_force_call | `confirmed_by_owner_force{path:force}` | `confirmation_path_unproven{indirect}` |
| adv_conf_wallet_fast_confirmer_nonzero | `confirmation_path_unproven{fast_confirmer_set}` | the same code, reason `indirect` |
| adv_conf_wallet_fast_confirmer_slot_unproven | `l1_state_proof_invalid{which:slot}` | `confirmation_path_unproven{indirect}` |

The `tx` and `l1_block` fields of the verdict now are the ones the recorded literal carries (the same transaction, judged at the same K).

The pins files of this set carry no wallet pins (the verifier requires them since RB12-E1RAISE: `confirm_path.validator_wallet_impl`,
`proxy_slots.wallet_impl`, and `logic_pins` entries with the roles `validator_wallet_proxy` and `validator_wallet_logic`). A consumer judges
this set after adding those four entries to each stored pins file (the Go harness: `synthworld.WithWalletPins`; the values are in
finality_arb_final3/README.md). With them every case not listed above keeps its recorded verdict, including `real_valid` (a direct-route
confirmation by an externally owned account). `adv_conf_wallet_arrays_of_different_lengths`, `adv_conf_wallet_calldata_undecodable` and
`adv_conf_wallet_calldata_noncanonical` also keep their verdicts: undecodable wallet calldata is stated before any identity is read.

finality_arb_final3 carries the twelve worlds again WITH the wallet proof under their recorded expectations (the `*_proven` and
`adv_wallet_*_proven` cases), and every way the proof can fail. A consumer of this set judges the twelve cases by the "verdict now" column.
