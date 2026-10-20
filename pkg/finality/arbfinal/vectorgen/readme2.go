// Copyright 2026 Certen Protocol

package main

// readme2Text is the README of the second published set. It is written by the generator but is NOT listed in the set's MANIFEST
// (it describes the set; the manifest pins the vectors, the evidence and the pins).
const readme2Text = `# finality_arb_final2 - RB11-E1-FIX vectors for arb-sepolia/finalized/v1

Supplements finality_arb_final1 (never edited) and finality_arb_force1. Same file layout, vector format and canonical verdict text as
finality_arb_final1 (see its README); the format tag is finality_arb_final2/1. The Go verifier is pkg/finality/arbfinal; the TypeScript
verifier consumes a byte-identical copy of this directory and must return the same canonical verdict bytes on every vector. Every
expected literal is written in pkg/finality/arbfinal/vectorgen/set2.go, which refuses to write a vector whose literal differs from the
verifier. MANIFEST.json lists vectors.json, evidence/ and pins/ (not this README).

Origin: the three LOW findings of the completeness review V-E1-A1 (all three ACCEPTED at d4cf095).

## L1 - the wallet route needs a callee (confirm.go)

A contract-creation transaction has no To: its data is init code, not calldata, so its first four bytes name no entry point.
It is confirmation_path_unproven{reason:"indirect"}, whatever its bytes decode to. (adv_conf_contract_creation_*)

What the wallet route proves, and what it does not: a transaction whose To is set, whose calldata decodes (canonically) as an
executeTransaction / executeTransactions entry point of nitro-contracts v3.1.0 ValidatorWallet and carries a call to the Rollup with
confirmAssertion; the receipt (MPT-proven under K) holds the Rollup's AssertionConfirmed for the assertion and no AssertionForceConfirmed;
anyTrustFastConfirmer = 0 is proven at K. The honesty of the confirmation rests on those Rollup-side facts: the pins carry no wallet
address or code hash (a ValidatorWallet is a per-validator clone), so the callee's code is NOT proven to be a ValidatorWallet and the route
label "wallet" records what the calldata said. spec 5.7: indirect is the state for a caller whose code the verifier does not decode.
synth_valid_wallet_route_callee_code_is_not_examined states that boundary as a vector.

## L2 - the leg's chain (verify.go)

Kind.Verify compares BlockRef.Chain with the container's chain, as Registry.JudgeAddendum does: finality_block_mismatch{field:"chain",
want: leg chain, got: 421614}. (adv_leg_chain_is_*)

## L3 - max_node_bytes for nodes off the tx/receipt proof paths (verify.go, codec.go)

Spec 8.2: state and storage trie nodes are at most max_node_bytes (4096); the transaction and receipt trie nodes on the proof paths are
at most max_tx_leaf_bytes (2 MiB, a calldata-mode batcher transaction is far above 4096). The decoder still bounds every NODES element by
max_tx_leaf_bytes (it cannot know the paths before the spine is covered); after K is determined on the covered spine and before any proof
is consumed, every NODES element that is not read by the MPT walk of key rlp(confTxIndex) from K's transactionsRoot or receiptsRoot must
be at most 4096 bytes, else finality_evidence_too_large{part:"nodes", count: its length, limit: 4096, index: its position in the canonical
ascending NODES order}. The bound is inclusive (4096 is carried). (adv_nodes_filler_*, synth_valid_*_over_max_node_bytes)

Order of checks (additions in bold relative to finality_arb_final1): ... S and K on the spine, K <= S -> **NODES bound (max_node_bytes off
the proof paths)** -> logic identity under S then under K -> ...
`
