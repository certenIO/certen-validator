# govRoot v3: the per-intent commitment over the proof v2 levels (RB6 switch)

Status: specification for the RB6 switch (PROOF_V2.md §10-§11, owner decisions 2026-10-05: Base Sepolia only; the
plan's per-level v2 commitments, not an extra slot). govRoot v2 (pkg/execution/contracts/govroot_v2.go,
pkg/intentcert/govroot.go) is unchanged and stays the record of what was signed before activation.

## Where it is used

govRoot is the per-intent commitment every validator signs into the intent certificate (RB5 D3):
- `pkg/consensus/intent_certificate.go` computes it at consensus;
- `pkg/execution/intent_certificate_check.go` re-computes it before execution.

v3 replaces v2 at both sites from an activation height on: the Accumulate Directory block height
`PROOF_V3_ACTIVATION_DN_BLOCK`, compared with the intent's certified Directory block. Every validator flips at the same
block, so the switch is atomic without coordinated restarts. Before the height, v2 is computed exactly as today.

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
