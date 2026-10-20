# finality_arb_final1 - published conformance vectors for arb-sepolia/finalized/v1

Spec: V2_SPEC_S7 r2 sections 0, 3.3, 5.7 (O1-O4, r2:C1 logic identity under S and K, r2:L6 wallet-mediated confirmations), 7, 8.2;
annex R11-arbitrum-sepolia A2-A5 and R11-controllers Q1/Q3. The Go verifier is pkg/finality/arbfinal; the TypeScript verifier consumes a
byte-identical copy of this directory and must return the same canonical verdict bytes on every vector.

## Files

| path | content |
|---|---|
| vectors.json | the vectors (format finality_arb_final1/1) |
| evidence/<name>.bin | the CFE1 container of a vector (spec 3.1 + 3.3 arb-sepolia/finalized/v1) |
| pins/<name>.json | a FULL pins file (finality-pins.json format) a vector is judged against; the synthetic vectors use pins/synth.json = the repository's embedded pins with eth_sepolia.anchors replaced by the synthetic test committee's entry (the real fork table, genesis validators root and 342 floor apply) |
| MANIFEST.json, MANIFEST.json.sha256 | SHA-256 of every other file; SHA-256 of MANIFEST.json |

## A vector

{name, group, note, leg:{chain, number, hash, header_hex}, pins, evidence | base+edits, expect}

* leg is the Settlement block the evidence is about (BlockRef: chain, number, hash, raw header RLP as hex). The verifier is called as
  Verify(pins, leg, evidence).
* pins is "embedded" or the name of a file under pins/.
* evidence is a file under evidence/, or base (the name of another vector) plus edits: out = base[:offset] + hex(insert) + base[offset+delete:],
  edits applied highest offset first. An empty edit list means the same bytes as the base.
* expect is the canonical text of the verdict: {"code":"finalized","fields":{...}} for an accepted container (the Result of 5.7: assertion,
  m = number of the L2 block the assertion ends at, s_number/s_hash, k_number/k_hash, confirm_period_blocks, confirmation_path "honest",
  confirmation_route "direct"|"wallet", confirmation_tx) or {"code":<state>,"fields":{...}} for a named state. Canonical form: keys sorted at
  every level, no whitespace, every integer of any width as a decimal string, every byte string 0x + lower-case hex, strings JSON-escaped
  without HTML escaping. The expected literals are written in the generator (pkg/finality/arbfinal/vectorgen), which refuses to write a
  vector whose literal differs from the verifier.

## Groups

synthetic: valid worlds built by pkg/finality/arbfinal/synthworld (an L2 header chain, a Rollup state trie with the BoLD assertion node and
the two EIP-1967 logic accounts at the REAL pinned code hashes, a confirmation transaction and receipt in a synthetic L1 block, an L1 spine
and a Gloas-layout light-client finality update signed by a test committee whose secret scalars derive from labels and are never stored).
adversarial: the same worlds with one fact changed, either in the state (a different trie) or in the evidence bytes.
live: vectors of a real capture (added by a later extension or set; see the check-in).

## Verification order (the first failing check names the state)

container header (kind, chain, level, leg) -> pins -> strict body decode (bounds, max_header_chain) -> leg header and pre-BoLD ->
L1 finalized head and spine (l1_finality_unproven{reason, inner}) -> S and K on the spine, K <= S -> logic identity under S then under K
(contract_identity_unproven{role,address,code_hash,judged_at}) -> machineStatus 1 -> node status 2 (assertion_unknown / assertion_not_confirmed)
-> parent config (assertion_preimage_mismatch{part}) -> L2 spine (finality_header_chain_broken{spine:"l2"}, spineLast* mismatches) ->
confirmation path under K (l1_tx_proof_invalid, confirmation_path_unproven{reason}, confirmed_by_owner_force{path}).
