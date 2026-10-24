// Copyright 2026 Certen Protocol

package main

// readme4Text is the README of the fourth published set. It is written by the generator but is NOT listed in the set's MANIFEST.json
// (it describes the set; the manifest pins the vectors, the evidence and the pins).
const readme4Text = `# finality_arb_final4 - RB12 vectors for arb-sepolia/finalized/v1: which L1 header the framework header reader judges, and which block's storage holds the fast confirmer

Supplements finality_arb_final1, finality_arb_final2, finality_arb_final3 and finality_arb_force1 (never edited; nothing in this set
supersedes a verdict of theirs). Same file layout, vector format and canonical verdict text as finality_arb_final1 (see its README); the
format tag is finality_arb_final4/1. The Go verifier is pkg/finality/arbfinal; the TypeScript verifier consumes a byte-identical copy of this
directory and must return the same canonical verdict bytes on every vector. MANIFEST.json lists vectors.json, evidence/ and pins/ (not this
README). This set was never published before RB12-ARBFINAL-FIX: the verdicts below are its first and only ones (an earlier build of it, on
pv2/rb12-ops-a1, answered finality_block_not_covered for the three odd-header-at-K worlds; that build was never merged and no consumer holds it).

## 1. Which L1 header the framework header reader judges (BETA finding B-ARB-2) - eight worlds from BETA, two boundary worlds

The light-client spine reader of the L1 head verifier reads four items of an L1 header: parent hash, state root, number and timestamp. The
framework's positional header reader (finality.ReadHeader) reads parent, state root, transactions root, receipts root, number, timestamp and,
from 17 items, the withdrawals root, and refuses a header whose items are not what it expects. The verifier reads the header of K (the L1
block that holds the confirmation transaction) with the framework reader, at K's position on the covered spine (K is covered[0].number - K
headers below the finalized head); the framework reader never judges another header. So, in a world whose spine the light-client reader
accepts:

- an odd header ANYWHERE BUT K - the finalized head, S (the block of the state proof), or any other spine header - does not stop the proof: the
  leg is finalized, whatever the odd header's transactions root, receipts root or withdrawals slot holds (five vectors);
- an odd header AT K is finality_block_header_unreadable{block_number: K, finalized_exec_number: F, reason, index}: K is on the covered spine
  and below (or at) the finalized head, and it is its header that cannot be read; reason and index are the framework reader's own refusal
  (header_item_not_32_bytes at item 4 or 5, header_item_is_list at item 16). It is NOT finality_block_not_covered, which names a block that
  is not on the spine (above the finalized head, or below the spine) and which a builder holds as pending. Five vectors: the three
  worlds of BETA, and K = F (S = K = the finalized head) and K = F - 1 (S = K) for the boundaries.

The eight worlds of BETA: a 31-byte transactions-root item, a 33-byte receipts-root item and a list in the withdrawals slot, each at K and in
the headers other than K; and a 31-byte transactions-root item at S alone and at the finalized head alone. They were built by a throwaway Go
program at pv2/rb11-e1-raise cbb6373 in the BETA session and carried by certen-sdk as the TS-held supplement arb_final_x; vectorgen -set4
<out> -from <dir> reads them from the set itself. The two boundary worlds are built by the generator from synthworld (Parts.OddL1).

## 2. Which block's storage holds the fast confirmer (BETA audit, RB12-ARBFINAL-FIX) - two worlds

A confirmation through a ValidatorWallet is honest only while anyTrustFastConfirmer is the zero address at K (annex A3). Until now synthworld
could not give the Rollup different storage at S and at K, so no published vector separated a verifier that reads the confirmer under K's
state root from one that reads it under S's. In the default world S = F - 2 and K = F - 5:

- wallet_fast_confirmer_set_at_k_only_is_refused: the confirmer is set at K and zero at S: confirmation_path_unproven{fast_confirmer_set};
- wallet_fast_confirmer_set_at_s_only_is_finalized: the confirmer is set at S and zero at K: finalized (confirmation_route wallet).

A verifier that reads the confirmer under S's root answers the other way round on both.

Provenance of the generator. vectorgen -set4 <out> -from <dir> judges EVERY vector with the verifier of the checkout, refuses to write a vector
whose expected literal differs from the verdict, and writes the layout and the manifest. Run with -from on this directory it reproduces it
byte for byte (gen4_test.go). The pins file of the worlds (pins/synth.json) is a full pins file that carries the wallet pins.
`
