# govRoot v3: the per-intent commitment over the proof v2 levels (RB6 switch)

Status: specification for the RB6 switch (PROOF_V2.md §10-§11, owner decisions 2026-10-05: Base Sepolia only; the
plan's per-level v2 commitments, not an extra slot). govRoot v2 (pkg/execution/contracts/govroot_v2.go,
pkg/intentcert/govroot.go) is unchanged and stays the record of what was signed before activation.

## Where it is used

govRoot is the per-intent commitment every validator signs into the intent certificate (RB5 D3):
- `pkg/consensus/intent_certificate.go` computes it at consensus;
- `pkg/execution/intent_certificate_check.go` re-computes it before execution.

v3 replaces v2 at both sites once the chain requires it, which is consensus state, not configuration
(`consensus.ProofV3Required`). It is required exactly when CERTEN's chain holds a verified Accumulate spine under the
incarnation of the BLS registry in force, with at least one verified major block. Every validator reads the same
committed state, so all of them flip at the same CERTEN block without coordinated restarts. The act that flips it is
the spine's acceptance under execution rules v13 (the next section). Before then, v2 is computed exactly as today, and
a block carrying a v3 certificate is refused (`ErrIntentProofV3NotInForce`). After, a block without one is refused
(`ErrIntentProofV2Missing`). An earlier draft used a per-node `PROOF_V3_ACTIVATION_DN_BLOCK`; that was dropped,
because a node configured differently would fork.

## The consensus-held spine (execution rules v13)

A proof v2 is judged inside FinalizeBlock, where no I/O is allowed, against the validator-set spine CERTEN's chain
holds (`ledger.AccumulateSpineLog`, `proofv2.VerifyFromSpine`). Two consensus transactions build it:
- `certen.accumulate.spine.genesis/v1` carries the incarnation's genesis facts. It is accepted only if they recompute
  the BLS registry's `accumulate_incarnation`, so genesis and incarnation are part of CERTEN's chain rules. A registry
  update to a new incarnation (an Accumulate restart, itself a governed admin act) lets a new genesis replace the spine.
- `certen.accumulate.spine.extend/v1` carries the next major-block records. Every validator verifies them
  deterministically from the last checkpoint (`proofv2.ExtendSpine`), and the chain stores one compact checkpoint per
  major block: last minor block, root and state anchors, set hash and network-update count. A full validator set is
  stored only when it changes.

A proposer builds its evidence on no more major blocks than the chain has verified (`Builder.BuildBounded`), so the
evidence starts at an agreed checkpoint, and its own minor-root runs cover the rest. Offline, the same evidence verifies
from the pinned incarnation's genesis by walking the stored major records (`proofverify --incarnation-evidence`).

## Binding the levels to the proof (`intentcert.BindProofV2`)

govRoot v3 commits the report's facts and the G0-G2 hashes side by side. Consensus and the offline check also require:
- G0's execution entry is the report's transaction, and G0's receipt starts there;
- G0's execution witness and block are the root and block of the partition anchor the transaction's receipt passes
  through. This proves that the anchor block is the execution block (RB6-F14), which the report alone does not;
- the key page G1 validated against is the certified key page, and it is one of the proven pages.

The spine-derived Accumulate set root must also equal the L4 leg's, so one anchor commits one set.

## Determinism

All seven validators must compute the same bytes independently, so every slot is built from facts the chain fixes,
never from a path a server chose:
- **The certified Directory block** is the first Directory self-anchor at or after the Directory block the
  transaction's Directory leg reached (MinorRootRange Until), and its root chain anchor.
- **The partition anchor** is the one the Directory executed for the transaction's block.
- **The pages and their chains** are as of that block.

Receipt paths, run boundaries and server-chosen heights are never committed.

## Domain tags

All new; none of them is used anywhere else. govRoot v2 already uses `certen:g{0,1,2}:v2`, so the levels here are
`:v3`.

## The ten slots

Each slot is `keccak256(tag || ":" || payload)`, where every payload field is fixed-width (bytes32 or uint64 big-endian)
or `sha256` of a canonical encoding.

| slot | tag | payload |
|---|---|---|
| L1 | `certen:l1:v3` | txHash ‖ partitionAnchorTxHash ‖ uint64(anchorBlock) |
| L2 | `certen:l2:v3` | certifiedRootChainAnchor ‖ uint64(certifiedDirectoryBlock) |
| L3 | `certen:l3:v3` | partitionStateTreeAnchor ‖ uint64(anchorBlock) |
| L4 | `certen:l4gov:v3` | accumulateSetRoot (certen:accval:v1, proven equal to the anchor's accRoot) ‖ incarnation ‖ uint64(certifiedDirectoryBlock) |
| G0 | `certen:g0:v3` | sha256(CanonicalG0JSONV2) ‖ txHash ‖ certifiedRootChainAnchor |
| G1 | `certen:g1:v3` | sha256(CanonicalG1JSONV2) ‖ pagesRoot |
| G2 | `certen:g2:v3` | sha256(CanonicalG2JSONV2) ‖ G1 slot |
| key page | as v2 | `HashURLString(canonical key page URL)` |
| key book | as v2 | `HashURLString(canonical key book URL)` |
| operation id | as v2 | operation id |

The root is `keccak256(bytes32("certen:govroot:v3") || the ten slots)`, and every slot is required.

**pagesRoot** commits the proven pages. Sort the pages by canonical URL; for each, take
`sha256(canonicalURL) ‖ sha256(state) ‖ bound(1 byte) ‖ uint64(mainHeight)`. pagesRoot is the merkle hash
(merkle.Hasher) of the sha256 of each such record.
- A page whose chains are unbound (a named state) has bound = 0 and mainHeight = 0, so the commitment states the
  limitation rather than hiding it.
- An intent with no captured pages cannot be certified under v3. That is the one G1 refusal, by name
  (`g1_historical_unavailable`), because a v3 G1 slot without pages would claim what was not proven.

## What fails closed and what is named

- **Fail closed (no certificate, no anchor), the same as v1 today:** no v2 core (S1-S2 does not build or verify), the
  set check fails, or no pages were captured.
- **Named inside the commitment:** a page whose chains are unbound (the bound byte); cross-identity authorities (the
  capture error, recorded with the proof).

## Conformance

The Go and TypeScript verifiers must compute the same govRoot v3 for the conformance fixture. The fixture carries the
G0-G2 canonical JSON hashes and the operation id; the manifest's report gains `govRootV3`.
