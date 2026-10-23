// Copyright 2026 Certen Protocol

package main

// readme3Text is the README of the third published set. It is written by the generator but is NOT listed in the set's MANIFEST
// (it describes the set; the manifest pins the vectors, the evidence and the pins).
const readme3Text = `# finality_arb_final3 - RB12-E1RAISE vectors for arb-sepolia/finalized/v1: the wallet route PROVEN

Supplements finality_arb_final1, finality_arb_final2 and finality_arb_force1 (never edited). Same file layout, vector format and canonical
verdict text as finality_arb_final1 (see its README); the format tag is finality_arb_final3/1. The Go verifier is pkg/finality/arbfinal;
the TypeScript verifier consumes a byte-identical copy of this directory and must return the same canonical verdict bytes on every vector.
Every expected literal is written in pkg/finality/arbfinal/vectorgen/set3.go, which refuses to write a vector whose literal differs from
the verifier. MANIFEST.json lists vectors.json, evidence/ and pins/ (not this README).

Every pins file of this set is a FULL pins file that carries the wallet pins (below) unless the vector is about their absence. The sets 1
and 2 store pins files from before the wallet pins; a consumer of those sets adds the pins named below to each stored pins file before
judging (the Go harness does it with synthworld.WithWalletPins) and judges the twelve plus one superseded cases by their SUPERSEDED.md.

## The rule (V2_SPEC_S7 5.7 O4, amendment r3)

A transaction whose To is not the Rollup takes the wallet route only if its callee is PROVEN to be a ValidatorWallet. The calldata is
no evidence of it: any contract can be called with the bytes of an executeTransaction. With K the L1 block of the confirmation
transaction and R its stateRoot, the callee C is a ValidatorWallet iff

1. the account proof of C under R shows an existing account whose code hash has the logic_pins role validator_wallet_proxy
   (the exact runtime code of the OpenZeppelin 4.7.3 TransparentUpgradeableProxy that ValidatorWalletCreator.createWallet deploys);
2. the storage proof of proxy_slots.wallet_impl (the EIP-1967 implementation slot) in that account resolves to exactly the 32-byte word
   of confirm_path.validator_wallet_impl (the pinned template address, high 12 bytes zero);
3. the account proof of the pinned template address under the same R shows an existing account whose code hash has the logic_pins role
   validator_wallet_logic (the exact runtime code of the template).

Anything not established is confirmation_path_unproven{reason:"indirect"} at K: a statement about code the verifier has not identified,
never the label "wallet" and never a weaker level. The state is judged at K only (a proof under S does not count); a same-block swap and
restore at K is invisible, as it is for the Rollup logic code.

Order inside the confirmation classifier (after the transaction and receipt are MPT-proven under K and the receipt status, the
AssertionConfirmed log and the AssertionForceConfirmed log are read): creation transaction -> indirect; To == Rollup -> the direct
handling; the selector is not a wallet entry point -> indirect; the arguments of a wallet entry point do not decode canonically ->
wallet_calldata_undecodable; the callee is not proven a ValidatorWallet -> indirect (also when the decoded call is a force, a fast confirm,
has no confirm call, or the fast confirmer is set: those outcomes are stated only for a proven wallet); then the decoded calls and the
anyTrustFastConfirmer slot at K as before.

## The wallet pins

arb_sepolia.confirm_path.validator_wallet_impl  = 0x579831De7576B8580A2BEaa5F56b4b32e1292419 (the template() of the Arbitrum Sepolia ValidatorWalletCreator 0x894fC71fA0A666352824EC954B401573C861D664)
arb_sepolia.proxy_slots.wallet_impl             = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
arb_sepolia.logic_pins[0x8736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8] = "validator_wallet_proxy"  (2,147 B, no immutables)
arb_sepolia.logic_pins[0x41aae8a0f910daa7a04450a94f864df487c0226c75e1809298c297d7f9e2f33a] = "validator_wallet_logic"  (6,864 B, embeds its own address)

The two runtime codes are real (Ethereum Sepolia, 2026-10-23); the synthetic worlds of this set use exactly those code hashes. The official
creator has created no wallet on the real chain, so no real wallet-routed confirmation exists and none is claimed: the worlds are
synthetic and the real vector of this set is a direct-route confirmation. A pins file without any of the four keys, with a zero or short
address or slot, or with either role pinned on the zero hash or on the hash of empty code, is pin_mismatch{field} (the four fields are
confirm_path.validator_wallet_impl, proxy_slots.wallet_impl, logic_pins.validator_wallet_proxy, logic_pins.validator_wallet_logic).

## Groups

synthetic: valid worlds. adv_wallet_*: one fact of the wallet proof changed. adv_pins_*: the pins. live: the real direct-route vector
of set 1 under the pins file with the wallet pins (its verdict is the one set 1 records: the direct route is unchanged).

* *_proven: the four entry points of the ValidatorWallet through a proven callee are accepted with confirmation_route "wallet".
* callee_*, proxy_over_*, implementation_*, proof_*_omitted, proofs_*: every way the identity can fail gives indirect.
* *_without_wallet_proofs, *_to_an_eoa, *_to_another_contract: force, fast, no-confirm and fast-confirmer outcomes decoded through a callee
  that is not proven are indirect; the same outcomes through a proven wallet (adv_wallet_*_proven) keep their states
  (confirmed_by_owner_force{force|fast}, wallet_no_confirm_call, fast_confirmer_set, l1_state_proof_invalid{slot}).
* adv_wallet_confirm_with_a_force_log_*: the AssertionForceConfirmed log is a fact about the Rollup, read before the route.
`
