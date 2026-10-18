# The executor-version activation table: a published, pinned input of the proof

Status: written in RB9 verifier round VA (J1). It is text for the PROOF_V2 erratum (RB9-J2 / RB13); `PROOF_V2.md` §1 is not edited here.

## Why it exists

`PROOF_V2.md` §1 names three inputs a verifier trusts: Accumulate's published incarnation plus more than 2/3 honest per set, the target
chain's own consensus, and standard cryptography. The evidence-2.1 verifier and the signature-type gate (RB8) also need to know **which executor
version governed a given block of a given partition**, because the rules they implement depend on it:

| Rule | Needs executor version | Where it is used |
|---|---|---|
| authority-set inheritance (parent's set, not a copy) and the delegation path of an authority signature | at or above v2-baikonur (6) | `pkg/proof/v2` `xexecutor.go`, `intentcert.BindProofV21` |
| `rsaSha256`, `ecdsaSha256`, `typedData` key signatures exist | at or above v2-vandenberg (7) | `liteclient/proof/govsig` gate, `pkg/proof/v2` `xsigverify.go` |
| `eth` verifies by the raw r‖s rule (not DER) | at or above v2-baikonur (6) | `liteclient/proof/govsig` gate |

The version in force at a (partition, block) is **not** in anything the spine proves, and live Kermit serves no historical receipt for
`<partition>/ledger` (finding RB9-C1b-2-B2: "cannot generate a receipt when there are uncommitted changes"). So the verifier derives it from a
table of the block in which each partition received its `activateProtocolVersion` message. That table is therefore a **fourth trust input**,
and it is published here rather than left implicit in the source.

## The table (Kermit, Accumulate commit e1d1db9ebb7c)

Source of truth in the code: `accumulate-lite-client-2/liteclient/proof/govsig/gate.go` (`kermitActivations`). `pkg/proof/v2/xexecutor_table.go` is a
thin view over it (the same rows through the same function, `govsig.ExecutorFloor`); there is no second copy.

| Partition | Version | Activation message received at local block |
|---|---|---|
| Directory | v2-kourou (9) | 9,538,105 |
| BVN1 | v2-kourou (9) | 12,491,272 |
| BVN2 | v2-kourou (9) | 12,492,057 |
| BVN3 | v2-kourou (9) | 12,491,127 |

Each partition has exactly two entries on its partition ADI main chain: `systemGenesis` and one `activateProtocolVersion`. A block **after** a
partition's activation block is established by the pin. A block at or below it (or a partition not in the table)
is **not established**: the verifier does not assume the genesis version (the public API's BPT history retention is about 710 blocks, so it cannot be
read), and says so by name: `g1_executor_version_unsupported` / `g1_executor_version_unproven{partition,block}`.

## What a later activation does

A new `activateProtocolVersion` on any partition needs (1) a new row in `govsig` `kermitActivations`, (2) a build, and (3) a deploy to **all 7
validators at once**: the table is read by the consensus binding, so a validator on an older table decides a block differently. Until then the
tool below fails.

## Re-deriving the table: `cmd/execversionpins`

```
go run ./cmd/execversionpins -endpoint https://kermit.accumulatenetwork.io/v3
```

For each partition it reads the partition ADI's main chain (`acc://dn.acme`, `acc://bvn-BVN1..3.acme`), takes every `activateProtocolVersion`
message, reads that entry again with the chain-entry receipt that places it in the chain at a local block, requires the receipt to start at the entry and
validate to the anchor it names, recomputes the table, and compares it with the compiled one. It prints what it read and **exits 1** when a
partition has no activation, more than one (the compiled table has one row), another version or another block, or when a partition is on only one
side; it exits 2 when the network cannot be read.

Run on 2026-10-18 against Kermit: all four partitions show `version v2-kourou` at the blocks above (chain index 1 each), every receipt validates, exit 0.

Limit, stated rather than hidden: the receipt the network serves for a chain entry ends at the partition's own root chain anchor for that local block.
The tool validates it; it does not additionally prove that anchor into a certified Directory root (the machinery for that is `ProveEntry`, used for page
histories). The table is a pinned input precisely because that last link is not carried by the proof; the tool makes the pin reproducible by anyone with
network access. Raising the tool to prove the anchor into a certified Directory root is recorded as finding RB9-J1-F2.
