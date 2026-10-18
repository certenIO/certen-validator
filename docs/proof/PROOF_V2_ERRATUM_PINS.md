# PROOF_V2 erratum: the executor-activation table is a pinned input (text for section 1)

Status: written in RB9 verifier round VB (RB9-J2) to close finding "PROOF_V2 S1 says nothing else is a trust input, and it is not true". It is the exact replacement text. `PROOF_V2.md` itself is **not** edited
here: RB13-D applies this erratum after the owner's decision OD1 (the same sitting that applies the other text corrections). The table, its source of truth and the tool that re-derives it are described in
`docs/proof/EXECUTOR_VERSION_PINS.md`.

## The defect in the claim

`PROOF_V2.md` section 1 lists three inputs (Accumulate's published incarnation and more than 2/3 honest per validator set; the target chain's own consensus; standard cryptography) and then says
"Nothing else is a trust input" and "These are the irreducible assumptions". The evidence-2.1 verifier (`pkg/proof/v2`, `liteclient/proof/govsig`, `intentcert.BindProofV21`) also needs to know **which
executor version governed a block of a partition**, because the rules it re-evaluates (authority-set inheritance, delegation, the key-signature types `rsaSha256`, `ecdsaSha256`, `typedData`, the `eth`
r||s rule) exist only from a given version. The version in force at a (partition, block) is in nothing the spine proves, and live Kermit serves no historical receipt for `<partition>/ledger`
(RB9-C1b-2-B2). So the code derives it from a table of the block in which each partition received `activateProtocolVersion`, compiled into the verifier. That table is a fourth input, and the sentence that
denies it is false. The claim is not lowered to fit the code: the strongest true statement is stated, and the raise that removes the input is queued with its acceptance test.

## Replacement text for section 1

Replace the sentence "Nothing else is a trust input: not CERTEN, CERTEN's validators or database, the node that served the data, an RPC provider, agreement between providers, a CERTEN-published
checkpoint, or whether any node still retains history." and the sentence "These are the irreducible assumptions; no design can remove them. Stated residual assumptions:" and the list that follows with:

> Nothing else is a trust input - not CERTEN, CERTEN's validators or database, the node that served the data, an RPC provider, agreement between providers, a CERTEN-published checkpoint, or whether any
> node still retains history - **with one named exception, a pinned input**:
>
> 4. **The executor-activation table (a pin, until it is proven into the proof).** For each Accumulate partition, the local block in which it received its `activateProtocolVersion` message
>    (Kermit, Accumulate commit e1d1db9ebb7c: Directory v2-kourou at 9,538,105; BVN1 at 12,491,272; BVN2 at 12,492,057; BVN3 at 12,491,127). It is compiled into the verifier
>    (`accumulate-lite-client-2/liteclient/proof/govsig`, `kermitActivations`; the evidence-2.1 verifier reads it through the same function, there is no second copy) and **published** in
>    `docs/proof/EXECUTOR_VERSION_PINS.md`. It is used for exactly one purpose: to establish that a block of a partition was executed by a version at or above the one that introduced a rule the verifier
>    re-evaluates. A block after a partition's activation block is established as executed by that version or later; a block at or below it, or a partition not in the table, is **not established**
>    and is reported by name with the partition and block (`g1_executor_version_unproven`, `g1_executor_version_unsupported`), never assumed. Only the judgement of S3 (who authorized the intent) reads
>    the table - for the evidence-2.1 re-evaluation (`BindProofV21`, `xexecutor_table.go`) and for the version gate of the key-signature types (`govsig.Verify`); no other statement does (a search of the
>    code for the table's readers, 2026-10-18).
>
>    The pin is **re-derivable by anyone with network access**: `go run ./cmd/execversionpins -endpoint https://kermit.accumulatenetwork.io/v3` re-reads each partition's main chain, takes every
>    `activateProtocolVersion` message with the chain-entry receipt that places it at a local block, requires the receipt to start at the entry and validate to the partition's root chain anchor,
>    recomputes the table and compares it with the compiled one. It exits non-zero on any difference (another block, another version, a second activation, a partition missing), and 2 when the
>    network cannot be read. A later activation on any partition is a new row, a new build and a deploy to every validator at once (the table is read by the consensus binding); until the row exists the
>    blocks after that activation are not wrongly established, they are simply not claimed above the previous row.
>
>    What the pin is not: the re-derivation checks the table against what Accumulate serves and proves the entry into the partition's own root chain anchor; it does **not** prove that anchor into a certified
>    Directory root, so a re-deriver trusts the endpoint that serves the chain entries. A verifier that holds only a proof file therefore trusts this one table in addition to the three inputs above - the
>    strongest true statement of the delivered system.
>
> Stated residual assumptions:
> - Sepolia's beacon validator set is permissioned (testnet); the same machinery on mainnet runs against the open set.
> - A testnet incarnation restart ends that incarnation's chain of trust; a proof reaches its own incarnation's genesis.
> - The executor-activation table above is an input of the verifier, not of the proof, and is not carried in the proof file. It is removed from this list when the raise below is delivered.

## The queued raise that removes the pin

Prove each partition's `activateProtocolVersion` message by receipt into a certified Directory root, in the proof itself, so a verifier derives the table from the evidence and no pin is needed:

- an evidence member (additive to 2.1, versioned by its own domain tag where it enters a hashed input) holding, per partition: the `activateProtocolVersion` message from the partition ADI's main chain, its
  chain-entry receipt to the partition's root chain anchor, and that anchor proven into the certified Directory root with the machinery that already proves a page history (`ProveEntry`, the
  per-partition anchors of evidence 2.1);
- the verifier derives the activation block of each partition from that member, requires the partition's anchor of the judged block to be after it, and refuses (named state) a document that does not
  carry it for a rule that needs it;
- acceptance: a vector set in which the member is missing, points at a different message, a different partition or a block at or below the judged block gives the named states above; Go and
  TypeScript verdicts are identical (`certen-sdk/packages/verify`); `cmd/execversionpins` is kept as the cross-check of the compiled table until the table is removed from the consensus binding;
- when delivered, section 1 reverts to "Nothing else is a trust input", the pinned-input paragraph and the third residual assumption are deleted, and this erratum is superseded with a reason (never
  removed).

Tracked as finding RB9-J1-F2 (`cmd/execversionpins` validates the chain-entry receipt but does not prove the anchor into a certified Directory root) and queued as a work package of its own; it is not part
of RB9.

## Where this is applied

RB13-D, after OD1: the text above replaces the named sentences of section 1; section 3's S3 row gains "(evidence 2.1 and the key-signature types of RB8: also the executor-activation table of section 1)";
`docs/proof/G1_CROSS_PARTITION.md` D6 and `docs/proof/EXECUTOR_VERSION_PINS.md` already state the table as a pinned input.
