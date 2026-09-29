# The Accumulate incarnation anchor (v1)

Status: specified and implemented 2026-09-29 (RB5 Phase A; owner decision D1). Code: `pkg/proof/incarnation.go`,
`cmd/incarnation`. Committed in every CertenAnchorV8_2 anchor as `accumulateIncarnation`.

## Why

Accumulate has restarted more than once. Each restart re-created every account and all state at a new genesis, and no
chain commits to the one before it. MainNet's block 1 is 2025-07-13 and Kermit's is 2026-02-01, although both networks
are older than that.

Nothing Accumulate's validators sign names the chain they are on:
- An anchor signature covers a SequencedMessage over a PartitionAnchor. Every URL in it is a protocol constant, the same
  on every network and every incarnation.
- The genesis transaction (`systemGenesis`) is an empty struct, so its hash `e43be90e…16d5` is identical everywhere.

A permanent record that cannot say which chain it is about is ambiguous. The incarnation identity removes that ambiguity.

## Definition

```
incarnation = keccak256(
    "certen:incarnation:v1"                        21 bytes, ASCII, no terminator
 || uint64BE(genesisMinorBlockIndex)               8   must equal protocol.GenesisBlock (1)
 || genesisRootChainAnchor                         32  anchor(directory)-root[0]
 || genesisStateTreeAnchor                         32  anchor(directory)-bpt[0]
 || uint64BE(genesisTimeUnix)                      8   acc://dn.acme/ledger/1 .time, seconds
 || sha256(genesisNetworkRecord)                   32  the NetworkDefinition record of acc://dn.acme/network
 || sha256(genesisGlobalsRecord)                  32  the NetworkGlobals record of acc://dn.acme/globals
)
```

A "record" is the single blob of the data account's entry, exactly as stored (`DataAccount.Entry.GetData()[0]`).

How the inputs correspond to a CometBFT genesis document:

| CometBFT genesis field | Chain-state counterpart used here |
|---|---|
| `app_hash` | genesis BPT root = `anchor(directory)-bpt[0]` |
| `genesis_time` | `acc://dn.acme/ledger/1`.time |
| `chain_id` (`<network>.<partition>`) | NetworkDefinition.networkName, inside the network record |
| initial validators | NetworkDefinition.validators (keys, partitions), inside the network record |
| — | accept threshold, inside the globals record |

The CometBFT genesis document itself is not an input, for two reasons:
- No public Accumulate endpoint serves it. On Kermit, `/genesis` returns 404, the CometBFT ports don't answer, and
  `consensus-status` is node-scoped and carries no chain_id.
- CometBFT is being replaced by DAG-BFT, and the same chain must keep the same identity across that change.

## What a verifier checks (`IncarnationEvidence.Verify`, offline)

1. **Genesis anchor.** `anchor-sequence[0]` on `acc://dn.acme/anchors` must:
   - hash to its chain entry;
   - be a `directoryAnchor` from `acc://dn.acme`;
   - have `minorBlockIndex = 1`.
   It supplies both genesis roots.
2. The Directory's own record of those roots, `anchor(directory)-root[0]` and `-bpt[0]`, is read by index; each receipt
   must recompute, and each entry must equal the anchor's field.
3. **Quorum.** The genesis anchor's delivered copy carries ed25519 signatures from the Directory validators. They are
   verified by the Layer4 code every CERTEN proof uses. The set and threshold they were checked against must equal the
   genesis network and globals records.
4. **Unchanged since genesis.** `/network` and `/globals` must each have a `main` chain of height 1 whose only entry is
   the `systemGenesis` transaction. The height is bound through the account's state hash. So the record in force is the
   genesis record.
5. `/network`, `/globals` and `ledger/1` must be proven into one BPT root by merkle path from the accounts' own bytes,
   with their chain heights bound.
6. The value is recomputed. A restated value in the evidence must match it.

A verifier holding a pinned value compares it with the recomputed one. Any failure is an error: there is no weaker
answer.

## Stated limits

- **A distinguisher, not a proof of distinctness.** An operator who replayed a byte-identical genesis at the same
  second would produce the same value.
- **The BPT root in step 5 is the serving node's current root.** It is not certified by a quorum in v1. Certifying it
  means a continuous receipt from that root to a quorum-signed Directory root, which is RB6 §3. The genesis roots
  themselves (step 3) are quorum-signed.
- **Once `/network` or `/globals` changes,** step 4 needs a historical state proof at genesis, which no node retains
  today. The tool then stops with `genesis_record_not_served` and never substitutes the current record. The published
  value (below) stays valid, because it was derived while the records were still the genesis records.

## Pinned values (derived 2026-09-29; evidence in `pkg/proof/testdata/incarnation/`)

| Network | Endpoint | Incarnation |
|---|---|---|
| Kermit (networkName DevNet, 3 validators, 2/3) | `https://kermit.accumulatenetwork.io/v3` | `0xcac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0` |
| MainNet (networkName MainNet, 1 validator, BVN Cyclops) | `https://mainnet.accumulatenetwork.io/v3` | `0x90721b40a0114a1c6d1a22b95d47e168e8c5d8c4fbc885f7cd36c6fe07fc91c0` |

Kermit inputs:
- genesis root `e3f31192…cf81`
- genesis BPT `5cd146ba…d5ff`
- time 2026-02-01T01:44:46Z
- network record sha256 `03c01368…77a1`
- globals record sha256 `e0c00fb1…ce45`
- genesis anchor signed by 3 of 3 (2 required)

MainNet inputs:
- genesis root `672f89ff…6e17`
- genesis BPT `b166048d…b79b`
- time 2025-07-13T13:49:18Z
- network record sha256 `91ab70c2…498e`
- globals record sha256 `b1e68e0f…a9fc`
- genesis anchor signed by 1 of 1

The MainNet row is labelled by its endpoint. Whether that endpoint is the production MainNet is an open owner question.

Reproduce:

```
go run ./cmd/incarnation                                          # Kermit
go run ./cmd/incarnation -endpoint https://mainnet.accumulatenetwork.io/v3 -bvn Cyclops
go run ./cmd/incarnation -verify pkg/proof/testdata/incarnation/kermit.json   # offline
```

## v2 (future, upstream ask)

A DAG-BFT genesis carries a Committee (with an Epoch), per-validator signed genesis certificates, and the snapshot's
root hash (accumulate-core `dagbft-integration`, `internal/node/dagbft/genesis.go`). When Accumulate serves these
publicly, a `certen:incarnation:v2` adds the signed genesis certificates. That binds the identity to signatures made
at genesis, which is strictly stronger than v1.
