# Validator Trust Root — Research and AIP Runbook

**Companion prompt:** `VALIDATOR_TRUST_ROOT_CLAUDE_PROMPT.md`
**Predecessor:** `PHASE8_RUNBOOK.md` (closed — all gates green, fleet deployed)
**Date:** 2026-08-28
**Target repo for research:** `C:\Accumulate_Stuff\accumulate-core` — **READ ONLY**
**Deliverable:** two draft Accumulate Improvement Proposals — one for the
network running **today** (CometBFT), one for DAG-BFT

> ⚠️ **Read §2A before §2.** §2 describes machinery on `dagbft-integration`,
> which Kermit and mainnet DO NOT RUN and which is months away. §2A is what
> exists on `main` today, and it is where the near-term answer lives.

> This runbook produces a **design and an AIP**, not a code change to
> accumulate-core. Nothing in `accumulate-core` is modified. CERTEN-side code
> may be written only where the runbook says so, and only after the design is
> settled.

---

## 1. The gap, stated precisely

CERTEN's L4 proves that a quorum of Accumulate validators signed the Directory
state that contains a transaction. Measured on the live fleet 2026-08-28, that
verification is real and complete in every respect but one:

```
layer4_verify.go   ed25519.Verify over the derived digest        ✅ real
                   signer ∈ ValidatorSet                          ✅ real
                   signer active on the signing partition         ✅ real
                   threshold = AcceptThreshold(active count)      ✅ recomputed
                   quorum counted over DISTINCT signers           ✅ real
```

and then:

```
layer4.go:255      ValidatorSet: ni.Validators
layer4.go:421      networkInfo() ← JSON-RPC "network-status" at BUILD TIME
```

**The validator set is read from the network at build time and embedded in the
proof.** Offline verification therefore proves the signatures are internally
consistent *with the set the proof carries*. Nothing binds that set to the real
Accumulate network.

### Why this is the load-bearing gap

A forged proof carrying a fabricated validator set and signatures made by that
set's keys **verifies offline and passes every check above**. The proof is
self-consistent and worthless. Everything CERTEN sells — that a governance
decision is cryptographically provable to a third party who trusts nobody —
rests on closing this.

The codebase is honest about it today; it is not hidden. `pkg/execution/layer5.go`
ships the caveat inside the artifact:

```go
"This attests to whatever was signed, NOT to whether the Accumulate validator
 set that signed L4 was the legitimate one."
```

That is the sentence this work exists to delete.

### The requirement, in one line

> For any transaction and any block **within a network incarnation**, determine
> what the validator set was, prove it cryptographically back to **that
> incarnation's** genesis, and commit enough of that proof to the external
> anchor that an offline third party can check it — while stating explicitly
> that the incarnation boundary is a trust event.

**This supersedes the unqualified "back to network genesis" this section
originally carried.** §2B explains why that phrasing was false: the network has
restarted, and no chain contains a commitment to the one before it. §2B.4c
explains the "commit to the anchor" clause: the on-chain record today binds
CERTEN's validator set and never Accumulate's.

---

## 2. What already exists in accumulate-core — DO NOT REDISCOVER

Research performed 2026-08-28 against `C:\Accumulate_Stuff\accumulate-core`,
branch `dagbft-integration` (HEAD `c01b026e`, a merge of
`issue-3910-remove-cometbft`). **Every path below was read, not inferred.**
Confirm each still exists before relying on it, then move on.

### 2.1 Where the validator set lives

| Thing | Location | Type |
|---|---|---|
| Validator set + partitions | `acc://dn.acme/network` (data account) | `protocol.NetworkDefinition` |
| Accept threshold | `acc://dn.acme/globals` (data account) | `protocol.NetworkGlobals` |
| Path constants | `protocol/protocol.go:61` (`Network`), `:66` (`Globals`) | |
| Genesis block index | `protocol.GenesisBlock = 1` | |

```go
// protocol/types_gen.go:608
type NetworkDefinition struct {
    NetworkName string
    Version     uint64
    Partitions  []*PartitionInfo
    Validators  []*ValidatorInfo
}
```

The validator set is therefore **ordinary account state**, mutated by ordinary
transactions on an ordinary main chain. That is the whole reason this is
tractable: every change to it already has a receipt.

### 2.2 The spine — Accumulate has already built this (#4058)

This is the central finding. `internal/api/private/api.go:36-60` defines two
optional Sequencer extensions:

```go
// MajorHeaderRanger ... serves the major-block spine (#4058): for each major
// block in the range, the major-block index chain entry plus the partition's
// self-anchor for the minor block that closed it, with the archived
// validator-quorum signatures. A fast-syncing node walks these records from
// its trust anchor to the present, verifying each quorum against the validator
// set tracked by induction. Only the directory partition serves this.
type MajorHeaderRanger interface { MajorHeaderRange(...) }

// MinorRootRanger ... binds minor blocks past the spine to it (#4058).
type MinorRootRanger interface { MinorRootRange(...) }
```

Record shapes (`internal/api/private/types_gen.go:28-70`):

```go
type MajorHeaderRecord struct {
    Index      uint64                        // major block index
    Entry      *protocol.IndexEntry
    Anchor     *messaging.SequencedMessage   // DN self-anchor for the closing minor block
    Signatures []protocol.KeySignature       // ARCHIVED validator quorum over that anchor
    Updates    []*NetworkUpdateProof         // network-account txns of this window
}

type NetworkUpdateProof struct {
    Transaction *protocol.Transaction
    Receipt     *merkle.Receipt               // proven INTO the anchor
}
```

Server side: `internal/api/v3/major_header.go`. `getNetworkUpdatesInWindow`
(:133) collects `dn.acme/network` and `dn.acme/globals` transactions in each
major-block window, **each with a receipt binding it to the anchor's root chain
anchor**, and comments:

> "These carry the validator-set timeline: a spine walker applies them without
> per-anchor quorum checks because the receipts bind them to a quorum-verified
> root."

### 2.3 The induction walk

`internal/fastsync/spine.go`:

```go
func NewSpine(genesis *network.GlobalValues, next uint64) (*Spine, error)
```

- The trust anchor is a **pinned genesis snapshot** — `snapshot.go:85` calls it
  "the walk's only out-of-band" input.
- `spine.go:122` refuses a walk whose root proof "does not start at genesis".
- `spine.go:197` rejects a signature whose signer "is not an active directory
  validator" **in the set tracked so far**.
- Each window's `Updates` mutate the tracked globals before the next quorum
  check. That is the induction.

**This is a complete light-client validator-set induction chain, and it already
works.** The design problem is largely solved inside Accumulate.

### 2.4 Why CERTEN cannot use it today

1. **It is `internal/api/private`.** Node-to-node only. `pkg/api/v3/message/private.go`
   carries the client, `internal/api/routing/message.go:276` routes
   `PrivateMajorHeaderRangeRequest`. No public v3 service exposes it — the public
   `ServiceType` list is `Node, Network, Metrics, Query, Event, Submit, Validate,
   Faucet, Snapshot, Consensus`. There is no proof/spine service.
2. **It is on `dagbft-integration`.** CometBFT is being removed (#3910). Any AIP
   must state which executor/consensus regime it targets and whether the artifact
   survives the DAG-BFT transition.
3. **It is a whole-chain sync primitive, not a point query.** It answers "walk me
   from genesis to now"; CERTEN needs "prove the validator set at block N for one
   historical transaction", ideally without replaying the entire spine per proof.
4. **The genesis trust anchor has no published distribution.** A pinned genesis
   snapshot is out-of-band by design. For a third-party verifier of a CERTEN
   proof, "out-of-band" has to mean something concrete and checkable.

---

## 2A. What is available NOW — the CometBFT track (READ THIS BEFORE §2)

**Section 2 describes `dagbft-integration`. Kermit and mainnet do not run it, and
DAG-BFT is months away.** Everything below was measured on 2026-08-28 against
`origin/main` and against the live networks. This is the track that matters
first.

### 2A.1 The spine does NOT exist on main

```
internal/fastsync/spine.go          ABSENT on origin/main
internal/api/v3/major_header.go     ABSENT on origin/main
internal/api/private/api.go         present, but WITHOUT the two rangers
```

So none of §2's machinery is reachable on the network CERTEN actually proves
against. Any design that depends on it is a DAG-BFT-era design.

### 2A.2 But the validator set is already ordinary, provable account state

`internal/core/execute/v2/block/network_accounts.go` on **main**,
`processNetworkAccountUpdates`:

```go
case *protocol.WriteData:
    switch targetName {
    case protocol.Network:
        err = x.globals.Pending.ParseNetwork(body.Entry)   // the validator set
    ...
    }
    // Force WriteToState for variable accounts
    if !body.WriteToState {
        return errors.BadRequest.WithFormat("updates to %v must write to state", ...)
    }
```

Three things follow, and they are the foundation of the near-term design:

1. A validator-set change is a **`WriteData` transaction on
   `acc://dn.acme/network`** — an ordinary transaction on an ordinary data
   account's main chain.
2. `WriteToState` is **mandatory** — the account state can never drift from the
   entry history.
3. Therefore **every change already has a receipt**, provable by the exact
   L1–L3 machinery CERTEN already runs on `certen-kermit-12.acme/data`.

No new protocol is needed to prove the *timeline*. That is a much smaller ask
than §2 implies.

### 2A.3 Measured: the timeline is currently EMPTY

```
acc://dn.acme/network  main chain entries:
    mainnet.accumulatenetwork.io/v3   ->  1
    kermit.accumulatenetwork.io/v3    ->  1
```

That single entry is a **`systemGenesis`** transaction (principal `acc://ACME`).
**The validator set has never been changed on either network.** The induction
chain from genesis to today has length zero: the current set *is* the genesis
set.

This is a gift and a trap. The gift: a genesis-rooted proof today needs to walk
nothing. The trap: the code path that would prove a change has **never run**,
which is precisely the condition Phase 8 showed produces five defects the moment
it does. Any design must be exercised against a *simulated* change, not against
the empty case.

### 2A.4 The real base-case gap, measured

> ⛔ **CORRECTED BY PHASE 0 — this section's conclusion is FALSE.** The genesis
> entry *is* receipt-provable; querying it **by index** returns a receipt that
> validates offline on both networks. The failure below is a by-**hash** lookup
> through a database-local `ElementIndex` map, not a missing capability, and it
> is not genesis-specific. See §9 Phase 0, §0.2. Do not design around this gap.

Ordinary `writeData` entries are receipt-provable today — CERTEN does it on
every proof. The genesis entry is **not**:

```
query acc://dn.acme/network chain main entry=e43be90e3492...  includeReceipt
  -> get entry index: Account.acc://dn.acme/network.MainChain.ElementIndex.
     e43be90e3492... not found
```

So the gap on CometBFT is **not** the update timeline and **not** the signature
verification. It is the **base case**: the genesis network definition cannot be
proven through the normal chain-entry path, so induction has nothing to stand on.

Confirm this before designing around it — it may be a query-shape problem rather
than a missing capability, and that would change the proposal entirely.

### 2A.5 Candidate that already exists publicly

> ⛔ **CORRECTED BY PHASE 1 (§9.1.5): no live network runs it.** `SnapshotService`
> is defined in the public API but is not advertised by mainnet or Kermit, and
> `list-snapshots` fails with `acc-svc/snapshot:directory: notFound`. It may be
> *asked for*; it cannot be *used*.

`pkg/api/v3/api.go:82` on main defines a public `SnapshotService` with
`ListSnapshots`. If genesis snapshots are listable and fetchable, that is a
plausible published trust anchor without new protocol. Determine what it
actually serves.

### 2A.6 What this means for the deliverable

The ask **splits in two**, and they must be written as separate AIPs:

| | Target | Ask | Depends on |
|---|---|---|---|
| **A — now** | CometBFT / `main` / Kermit | make the **genesis** network definition verifiable, and guarantee historical anchor signatures are retained so induction is possible once the set does change | nothing unmerged |
| **B — later** | DAG-BFT / `dagbft-integration` | promote the #4058 spine (`MajorHeaderRange` / `MinorRootRange`) to the public API so induction scales without walking every update | #4058 landing |

**A is the one that unblocks CERTEN.** Write it first, and write it so it does
not depend on B. If A alone closes the gap for the current network, say so
plainly rather than bundling B to look thorough.

---

## 2B. THE NETWORK RESTARTS — this invalidates "prove back to genesis"

**Read this before designing anything.** It was contributed by the maintainer
2026-08-28 and then confirmed against both live networks. It is the single most
important fact in this document, and §1's one-line requirement is *wrong* as
written because of it.

### 2B.1 Genesis is not where §2A looked

`acc://dn.acme/network`'s main-chain entries are **hashes**, not the definition.
The genesis actions are visible by parsing a **partition's block 0/1**, and
every partition has its own network account. Measured on Kermit, BVN1 block 1:

```
main  acc://bvn-BVN1.acme             systemGenesis
main  acc://bvn-BVN1.acme/anchors     systemGenesis
main  acc://bvn-BVN1.acme/globals     systemGenesis
main  acc://bvn-BVN1.acme/network     systemGenesis   <-- per-partition
main  acc://bvn-BVN1.acme/operators   systemGenesis
main  acc://bvn-BVN1.acme/routing     systemGenesis
main  acc://bvn-BVN1.acme/votes       systemWriteData
      (11 entries, every system account created in one block)
```

So §2A.4's "the genesis entry is not receipt-provable" may be an artefact of
looking at the DN's hash-only entry rather than at the partition genesis block.
**Re-derive that finding from partition block 1 before treating it as a gap.**

### 2B.2 The network has forked and restarted, more than once

Each restart **re-created every account and all state at a new genesis**. The
prior transaction history is not cryptographically continued into the new
chain — it is re-established by the operators.

Measured 2026-08-28:

| Network | Block 1 timestamp | Current DN height |
|---|---|---|
| Kermit (`networkName: DevNet`, `v2-jiuquan`) | **2026-02-01** | 7,937,941 |
| **MainNet** (`v2-vandenberg`) | **2025-07-13** | 34,641,646 |

Accumulate mainnet has existed publicly since 2022. A block-1 timestamp of
2025-07-13 means **the numbering and the chain itself restarted**, with prior
state re-created at genesis.

### 2B.3 What this does to the trust model

1. **"Prove back to genesis" is ambiguous and, unqualified, false.** The most a
   verifier can establish is a chain back to the genesis of the **current
   incarnation**. That genesis is an operator-established state, not a
   cryptographic continuation of the previous chain.
2. **Every restart is a trust discontinuity.** At the boundary, state exists
   because operators asserted it. No amount of downstream cryptography converts
   that into a proof. It must be *named*, not smoothed over.
3. **CERTEN proofs may have a shelf life.** A proof anchored to incarnation N
   references a validator set and anchors that may be unprovable — or absent —
   from incarnation N+1's chain. **Nobody has established what happens to a
   stored CERTEN proof across a network restart.** This is a live product risk,
   not a theoretical one: 402 proofs are already marked `summary_only` for a
   less severe reason. (Measured again in Phase 0: **392** distinct proofs —
   see §9, §0.5.)
4. **L5 changes meaning, upward.** `pkg/execution/layer5.go` currently
   under-sells itself as "COORDINATES, not an offline proof". But an anchor
   published to an external chain at time T is the **only artefact that survives
   a re-genesis** — it is independent of Accumulate's incarnation. Across a
   restart, L5 may be the strongest link CERTEN holds, not the weakest.

### 2B.4a Cross-restart continuity is IMPOSSIBLE from the chain — measured

`protocol/types_gen.go:995` on `origin/main`:

```go
type SystemGenesis struct {
    fieldsSet []bool
    extraData []byte
}
```

**An empty struct.** The genesis transaction carries no prior-state root, no
previous-chain commitment, no linkage of any kind to the incarnation before it.

So this is settled, and it does not need researching:

> **A validator set in incarnation N-1 cannot be proven from incarnation N's
> chain. Not with a better API, not with more receipts. The chain contains no
> commitment to what preceded it.**

What remains researchable is the *consequence*: what a verifier should do when a
proof references an incarnation that is no longer the live one, and what weaker
claim can still be honoured (see §2B.4b).

### 2B.4b L5 is the only cross-incarnation bridge — and its cadence supports it

Measured against the production proof database 2026-08-28:

```
proof_class:   on_demand 403   |   on_cadence 26
anchors by network (top):  ethereum-sepolia 157, sepolia 70, base-sepolia 54,
                           arbitrum-sepolia 28, near-testnet 23   (21 networks)
anchors per day:           2, 8, 2, 1, 5, 7, 1, 16  — tracks TRAFFIC, not a clock
```

⚠️ That 21-network spread is **historical**. Only **ethereum-sepolia,
base-sepolia and arbitrum-sepolia are active** — everything else in that list
(near-testnet, solana-devnet, ton-testnet, cardano-preview, polygon-amoy,
moonbase-alpha, bsc-testnet, tron-shasta, hedera, aptos, sui) is legacy and
unsupported. See §4A.4. Read the counts as evidence of *cadence*, not as a list
of chains to design for.

**External anchoring is PER-INTENT, not per-major-block.** It is not the
12-hourly major-block cadence — an on-demand intent is anchored within minutes
(measured this session: submit → anchored on base-sepolia in ~5 min). The L5
merkle path proves *this intent's leaf* into the batch root that was published.
So L5 already operates at exactly the granularity CERTEN's model needs.

That matters because the anchor is on a chain that **did not restart**. It is
the only artefact that survives a re-genesis.

**But be precise about what it proves.** An external anchor establishes:

> this proof, with exactly this content, existed no later than block B on chain
> C at time T

It does **not** retroactively establish that the Accumulate validator set which
signed L4 was legitimate. Across a restart, that legitimacy is unrecoverable.
The honest post-restart claim is a **non-repudiable existence and time
witness**, not a governance proof — and it must be labelled as a different,
weaker claim, in the same way `summary_only` marks the 402 proofs that predate
L4 persistence. Do not let a cross-incarnation proof report the same verdict as
a within-incarnation one.

### 2B.4c THE ANCHOR COMMITS TO CERTEN'S VALIDATORS, NOT ACCUMULATE'S

Measured 2026-08-28 against the **deployed** contracts, not the source tree's
legacy names. **The live anchor is `CertenAnchorV8_1`**, not V6_1:

```
base-sepolia V8.1 anchor  0xEA9eeeE42a7971792B11Fd2f682C9c1172490272  (22,431 bytes deployed)
production CertenAccount  0x3850C52C22Eb5ac1d727784DeFdCa7C5DB050389
  anchorContract()     -> 0xEA9eee…   (V8.1 — CONFIRMED on chain)
```

`CertenAccountV7.sol:85` declares the field as `CertenAnchorV6_1 public
anchorContract`, which is a stale TYPE NAME — the deployed target is V8.1. Do
not read the source's V6_1 references as the live version; verify on chain.

In V8_1, `currentValidatorSetRoot` is **on-chain contract state**
(`CertenAnchorV8_1.sol:541`), recomputed by `_recomputeValidatorSetRoot()` on any
change to membership, voting power or threshold, and any signature whose claimed
root does not match is rejected. That is a genuinely strong binding — for
CERTEN's validators.

The pre-exec message (contract header, `CertenAnchorV8_1.sol:14`) is:

```solidity
keccak256(abi.encode(
    bytes32("certen:bls:v1:pre"), chainId, anchorId,
    anchor.executionCommitment,   // = batchRoot
    anchor.operationID,
    validatorSetRoot))            // <-- CERTEN's 7 operators
```

**That is CERTEN's validator set.** Grepping `CertenAnchorV8_1.sol` for any
Accumulate-validator concept returns **nothing**. The Accumulate validator set is
not in the current anchor contract at all.

What DOES reach the chain about Accumulate is inside govRoot, via
`L4LegSummary` (`healing_proof.go:160`): `Partition`, `SignedHash`,
`StateTreeAnchor`, `RootChainAnchor`, `MinorBlockIndex`, `Threshold`, and
`Signers` — the sorted public keys that signed.

So the anchor commits to **who signed** and **how many were required**, but never
to **who was eligible**. The denominator is missing. A fabricated proof listing
three arbitrary keys as `Signers` with `Threshold: 2` produces an internally
consistent govRoot, and no on-chain check can distinguish it.

**Consequence, stated plainly:** an on-chain verifier can establish *"CERTEN's
quorum attested to this"*. It cannot establish *"Accumulate's real validators
signed it."* The Accumulate half of the chain terminates in CERTEN's own
attestation rather than in cryptography — which is the §1 gap, surfacing one
layer out, on chains where the record is permanent.

**So YES, the anchor needs an extension**, and it is in scope for this work:

- commit an **Accumulate validator-set root** (the membership + threshold the
  quorum was drawn from) beside the existing CERTEN `validatorSetRoot`
- commit the **incarnation identity** (§2B), so a permanent on-chain record says
  which chain it is about
- decide whether this rides in the anchor message (changes the signed preimage
  and the contract) or in govRoot (changes the preimage only) — the second is
  cheaper and may suffice; **evaluate both, do not assume**

Note the ordering constraint: whatever is added must be something an *offline*
verifier can check, or it is decoration. Committing a root nobody can expand is
worse than committing nothing, because it looks like coverage.

### 2B.4d L5 status, measured correctly

A raw count misleads here. The trajectory is what matters:

```
proofs total                     429
already carry an anchor_tx_hash  421   (98%)
already have an anchor_reference 401   (93%)
carry an L5 row                   10

L5 coverage by day:
  2026-08-21   0 / 7
  2026-08-22   0 / 5
  2026-08-24   0 / 1
  2026-08-25   0 / 2
  2026-08-26   8 / 8     <- Phase 8 fleet upgrade
  2026-08-28   2 / 2
```

**L5 is not "barely deployed" — it is 100% for every proof produced since it
shipped.** The 419 without it are historical, and predate the implementation.

The more important number is the first one: **98% of proofs already have an
external anchor.** The gas was already spent. What was missing was never the
anchor — it was the *merkle path binding this proof's leaf into that anchor*,
persisted so it can be checked offline. Not recording it was an unforced loss of
a property already paid for.

That reframes the "should L5 be mandatory" question entirely: it is not a cost
decision, and it is largely already done. What remains is (a) backfill for the
historical 419, honestly marked where the batch tree cannot be reconstructed, and
(b) deciding what a MISSING L5 means — see §2B.4e.

### 2B.4e Mandatory to RECORD, never mandatory to VERIFY

If a proof were invalid without L5, then an anchoring failure — chain outage,
gas exhaustion, RPC timeout — becomes a **governance-proof failure**. That is
precisely the defect class removed twice in this session: a capability limit
reported as a governance rejection.

So the rule is:

- **Record L5 on every proof.** It is nearly free; the anchor already exists.
- **A missing L5 is a distinct, named state** — not a silent pass, not a
  rejection. Model it on `summary_only`.
- **L5 alone does not close the §1 gap.** It proves *existence and time*, not
  validator-set legitimacy. Necessary, not sufficient. Any claim built on it
  must say which of the two it is making.

### 2B.4 The requirement, restated honestly

Replace §1's one-liner with:

> For any transaction and any block **within a network incarnation**, determine
> what the validator set was and prove it cryptographically back to that
> incarnation's genesis — **and state explicitly that the incarnation boundary
> is a trust event, identifying which incarnation the proof belongs to.**

A design that does not carry the incarnation identity inside the artifact cannot
tell a verifier which chain its proof is even about.

---

## 3. The open questions the research must answer

These are the questions. Do not answer them from this document — answer them
from the code, and cite file:line for every answer.

**Q1 — Genesis identity.** What exactly identifies Accumulate genesis? Is there a
canonical hash of the genesis snapshot / initial `NetworkDefinition`? Where is it
computed, and is it queryable? If two parties independently pin "genesis", can
they verify they pinned the same thing?

**Q2 — Completeness of the update timeline.** Does `getNetworkUpdatesInWindow`
capture *every* mutation of the validator set, or only those written to
`dn.acme/network` and `dn.acme/globals`? Can a validator set change by any other
path (executor-internal, genesis-only, DAG-BFT epoch change)? A single unproven
mutation breaks induction.

**Q3 — Archived signature retention.** `MajorHeaderRecord.Signatures` are
described as *archived*. Are historical anchor signatures retained indefinitely,
or pruned? If pruned, a proof about an old transaction cannot be built later, and
the AIP must say so or ask for retention.

**Q4 — Point query feasibility.** Given a DN block N, can a server produce a
bounded proof of the validator set at N — e.g. nearest major-block checkpoint
plus the update deltas and receipts to N — without the client walking from
genesis? What is the size of that artifact?

**Q5 — Cost of induction.** How many major blocks exist on mainnet today, and how
large is one `MajorHeaderRecord`? This decides whether a verifier can walk the
spine once and cache, or needs checkpointing.

**Q6 — DAG-BFT survival.** ✅ **ANSWERED IN PHASE 2 (§9.2.3): the primitive
survives untouched**, and `DAGBFT_MIGRATION_ANALYSIS.md`'s L3/L4 rows are stale.
The original question text follows.

**Q6 — DAG-BFT survival.** Under DAG-BFT, does the "quorum signature over a DN
self-anchor" primitive survive? `docs/proof/DAGBFT_MIGRATION_ANALYSIS.md` in the
CERTEN repo already flags that **StateHash is excluded from the certificate
quorum** — determine whether that breaks the spine's quorum check.

**Q7 — Minimal public surface, ON MAIN.** What is the smallest public API that
closes the gap **for the network running today**? Candidates, to be evaluated not
assumed:
  - (a) ~~make the genesis network-definition entry receipt-provable~~ — **DEAD,
        see §9.1.1/§9.1.4**: it already is (by index), and it proves nothing,
        because `systemGenesis` has an empty body
  - (b) publish a canonical, checkable genesis anchor (hash or signed checkpoint),
        possibly via the existing public `SnapshotService`
  - (c) a point query: "validator set at height H, with proof to genesis"
  - (d) guarantee retention of historical anchor quorum signatures, so induction
        remains possible after the set changes
  - (e) DAG-BFT ERA ONLY: promote `MajorHeaderRange` + `MinorRootRange` to public v3

**Q9 — Is the genesis entry actually unprovable?** §2A.4 measured
`ElementIndex ... not found` for the genesis entry while ordinary writeData
entries prove fine. Establish whether that is a missing capability or the wrong
query shape. **This single answer decides whether AIP A is a one-line API fix or
a protocol change.**

**Q11 — Incarnation identity.** How does a verifier tell which incarnation a
proof belongs to, from the artifact alone? Is there a network/chain identifier
that changes on restart (`networkName`, a genesis hash, an executor version)?
If not, two incarnations are indistinguishable inside a stored proof, and that
must be fixed before anything else in this document matters.

**Q12a — What is the correct post-restart verdict?** Given §2B.4a (continuity is
impossible) and §2B.4b (L5 survives), define the outcome a verifier must produce
for a proof from a previous incarnation. It must be a distinct, named state -
neither "verified" nor "failed" - carrying what IS still established (existence,
content, external timestamp) and what is not (validator-set legitimacy). Model
it on `summary_only`. Then say where that marker lives, given govRoot must not
move.

**Q12 — Proof survival across a restart.** Take a CERTEN proof anchored to the
previous incarnation. Against the current chain: does it still verify, fail
loudly, or — the dangerous case — appear to verify against re-created state?
Determine this empirically if any pre-restart artefact still exists. Whatever
the answer, the artifact must fail closed and say "different incarnation"
rather than produce a confident verdict.

**Q13 — Re-derive the base case correctly.** §2A.4 concluded the genesis entry
is unprovable from the DN's hash-only entry. Redo it against **partition block
0/1** (§2B.1), which is where genesis actually is. The conclusion may change
completely.

**Q14 — ✅ IMPLEMENTED IN PHASE 4b (§9.4b).** Eight-slot message under
`certen:bls:v2:pre`, cross-language agreement proven by shared test vectors,
govRoot unmoved. NOT deployed and NOT wired in - see §9.4b.8.

**Q14 — DECIDED, NOT OPEN: the commitment goes in the ANCHOR PRE-EXEC MESSAGE.**

Decision taken 2026-08-28 by the maintainer. Do not re-litigate it; implement
it. The remaining work is *how*, not *whether*. See §4A for the full rationale,
the honest limits, and the scope.

**Q15 — ✅ ANSWERED IN PHASE 4c (§9.4c).** (ii) backfill measured IMPOSSIBLE for
all 419; (i) already shipped on the verify side, two build-side gaps remain;
(iii) specified and must ship with Phase 4b. Original question text follows.

**Q15 — The L5 workstream.** §2B.4d/e measured: 98% of proofs already carry an
anchor (the gas is spent), L5 is 100% for proofs produced since it shipped, and
419 historical proofs lack it. Three separate deliverables, do not conflate:
  - (i) **Error handling.** A proof that fails to achieve L5 must land in a
        distinct named state modelled on `summary_only` — never a silent pass,
        never a governance rejection. An anchoring outage is a capability limit.
  - (ii) **Backfill.** Can the batch tree be reconstructed for the historical
        419 from `batch_transactions`? Where it cannot, mark — never fabricate.
  - (iii) **Extension.** Carry the Accumulate validator-set root, the induction
        path, and the incarnation identity (§4A decided where the commitment
        lives). L5 today proves existence and time only.

**Q10 — ✅ RUN IN PHASE 3 (§9.3.1).** A validator-set change was executed end
to end on `origin/main`'s executor; the previous set became unprovable, exactly
as Phase 1 predicted. Original question text follows.

**Q10 — Exercise the path that has never run.** The validator set has never
changed on mainnet or Kermit (§2A.3), so the update-proof path has zero
production history. Simulate a change (devnet, simulator, or
`internal/core/execute` tests) and prove it end to end before claiming the
timeline is provable. Phase 8's record: five defects, all found only by running.

**Q8 — ✅ ANSWERED IN PHASE 4 (§9.4).** The contract is written as steps 10-16
of `VerifyOffline`, with three named weaker states, govRoot unmoved, and the
artifact growth measured at +9.8%/+13.1%. Original question text follows.

**Q8 — What CERTEN must build regardless.** Whatever the API, the verifier side
is CERTEN's. What does `layer4_verify.go` need so that `ValidatorSet` is
*derived* rather than *asserted*?

---

## 4A. DECISION — the Accumulate validator-set commitment goes in the anchor message

### 4A.1 What was decided

The Accumulate validator-set root, and the incarnation identity, are added as
**named fields of the anchor pre-exec message** — the message CERTEN's validator
quorum signs and the anchor contract verifies. Not govRoot alone, not the L5
artifact alone.

### 4A.2 Why, honestly

Be accurate about this, because an overclaim here would be the same defect this
project keeps deleting: **govRoot (option b) would also be cryptographically
sufficient for an offline verifier.** govRoot is itself committed on chain, so a
field added to its preimage is bound just as tightly, one hash deeper. Anyone
claiming (a) is the *only* sound option is wrong.

(a) is nonetheless the right choice, for four reasons that are about legibility
and timing rather than raw soundness:

1. **Explicit quorum attestation.** CERTEN's validators sign the pre-exec
   message. Putting the Accumulate set root *there* makes the quorum explicitly
   attest to **which Accumulate validator set it saw** — a named commitment,
   not one buried inside a hash preimage that happens to contain it.
2. **Both validator states, side by side, in one signed message.** That is
   precisely the end-to-end binding the system is missing:
   `currentValidatorSetRoot` (CERTEN, already on-chain state) and
   `accumulateValidatorSetRoot` (the set that signed L4) in the same attestation.
3. **Symmetry with an existing, proven mechanism.** V8_1 already rejects any
   signature whose claimed CERTEN set root is stale
   (`CertenAnchorV8_1.sol:541`). The same shape extends naturally.
4. **The window is now.** CERTEN is **pre-mainnet and pre-real-users**. Changing
   a signed preimage means a contract redeploy plus re-pinning every
   `CertenAccount` (they are immutable and pinned via `initializeAnchor`). That
   is cheap today and effectively impossible once real value and real users
   depend on the deployed set. This is the last clean moment.

### 4A.3 What this does NOT buy — state it in the AIP and the spec

**The contract still cannot validate the Accumulate validator set.** It cannot
run the induction walk, and it cannot verify Accumulate's ed25519 quorum. (a)
makes the set **committed and non-substitutable**; the *validation* stays
offline, in the verifier that expands the artifact.

So the honest claim after this lands is:

> The anchor binds which Accumulate validator set the CERTEN quorum attested to.
> An offline verifier can expand that root and check the induction to the
> incarnation's genesis. The contract does not, and cannot, check it on chain.

Anyone reading this as "the chain now verifies Accumulate governance" has been
misled, and the documents must prevent that reading.

### 4A.4 Scope — ONE chain family, THREE networks

**Corrected 2026-08-28 by the maintainer.** An earlier draft of this section
said "8 chain families". That was wrong: it counted every binding file in the
tree, including deployments that are **legacy, obsolete and inactive, on
contracts that are no longer supported.**

**The only active deployments are three EVM testnets, all running the same
`CertenAnchorV8_1` bytecode.** Verified on chain 2026-08-28:

```
sepolia            0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0   22,431 bytes
base-sepolia       0xEA9eeeE42a7971792B11Fd2f682C9c1172490272   22,431 bytes
arbitrum-sepolia   0x4b9eA187772E115641Fd40F35BF7a84925e7A035   22,431 bytes
```

~~Identical bytecode on all three~~ — **corrected in §9 Phase 0, §0.4**: same
compiled source, but the deployed code differs in 24 bytes (8 sites holding the
`DEPLOYMENT_CHAIN_ID` immutable). One contract, three chain-bound deployments.

**IN SCOPE**

```
NEW, derived from the deployed originals - do not edit the live V8_1/V7 files:
  certen-contracts/evm/src/core/CertenAnchorV8_2.sol      from CertenAnchorV8_1.sol
  certen-contracts/evm/src/account/CertenAccountV7_2.sol  from CertenAccountV7.sol
  pkg/execution/contracts/v8_2_binding.go                 from v6_1_binding.go
  pkg/consensus/  signV8_2PreExecBLS                      from signV6_1PreExecBLS
                                                          (the EVM one only)
```

**OUT OF SCOPE — legacy, inactive, unsupported. DO NOT UPDATE THESE.**

```
v6_1_binding_near.go     v6_1_binding_solana.go   v6_1_binding_aptos.go
v6_1_binding_sui.go      v6_1_binding_ton.go      v6_1_binding_cardano.go
signV6_1PreExecBLS{Near,Solana,Aptos,Sui,Ton,Cardano}
certen-contracts/{aptos-cli,cardano,cosmwasm}/ and the non-EVM programs
other EVM testnets: polygon-amoy, optimism-sepolia, moonbase-alpha,
                    bsc-testnet, tron-shasta, hedera(296)
```

Touching them adds risk and reviewer confusion for zero benefit. If a change
appears to require editing one, stop and say why — it is a signal the design
has drifted, not a task.

**What this does to the decision.** It makes §4A *more* clearly right, not less.
The migration is three redeploys of one contract plus re-pinning the accounts on
those three chains — not a heterogeneous eight-ecosystem rollout. Combined with
pre-mainnet timing, the cost objection to putting the commitment in the signed
message essentially disappears.

### 4A.4a A new account contract MOVES EVERY ACCOUNT ADDRESS

`CertenAccountV7_2` is not a cosmetic rename. A `CertenAccount` address is
derived by CREATE2, and CREATE2 commits to the **init code hash** — so changing
the account contract changes every derived address. Consequences the executor
must plan for, not discover:

- The **factory must be redeployed** and pinned to the V8_2 anchor.
- Every ADI gets a **new account address**. The production account
  `0x3850C52C…050389` (V8_1-pinned) does not become V8_2; it is superseded.
- `initializeAnchor` is one-shot and the account is immutable — there is no
  in-place upgrade path. This is by design.
- Anything holding a balance or an allowlist entry at an old address must be
  migrated deliberately, or explicitly abandoned and recorded as such.

This exact class of failure is already on record: the Sepolia anchor
version-drift episode, where an account pinned to a stale anchor could not be
re-pointed and needed a new factory and a new ADI. **Pre-mainnet is precisely
why this is acceptable now** — and precisely why it must be done now rather
than later.

**The atomicity rule still holds, and is now easy to satisfy.** All three
deployments must move together under one bumped domain tag
(`certen:bls:v2:pre`), so an old signature can never replay against the new
message. Three identical EVM deployments make that a single coordinated change
rather than the mixed-fleet hazard an eight-family rollout would have been.

### 4A.5 Required properties of the commitment

1. **Offline-expandable.** The artifact must carry the full validator set (and
   the induction path) so a verifier can recompute the root. A committed root
   nobody can expand is decoration that looks like coverage.
2. **Canonically encoded.** Sorted, length-prefixed, domain-separated. Rule 12:
   two validators reading identical chain data must produce identical bytes.
3. **Carries the incarnation identity** (§2B) — a permanent on-chain record must
   say which chain incarnation it is about.
4. **Commits the threshold and the membership**, not only the signers. The
   missing denominator (§2B.4c) is the whole point.
5. **Versioned deliberately.** A new domain tag (e.g. `certen:bls:v2:pre`), so a
   signature for the old message can never be replayed against the new one.

---

## 4. Non-negotiable rules

1. **accumulate-core is READ ONLY.** No edits, no branches, no commits in that
   repo. The deliverable is a proposal.
2. **Cite file:line for every claim about how Accumulate behaves.** A design
   built on a guess about someone else's protocol is worse than no design.
3. **Verdicts come from the code, never from this runbook.** Section 2 is a
   research head start and may be stale or wrong. Confirm before relying.
4. **Distinguish "exists on `dagbft-integration`" from "exists on `main`".**
   Check both. An AIP that proposes promoting something that only exists on an
   unmerged branch must say so.
5. **Do not invent protocol.** If Accumulate has a mechanism, propose exposing or
   extending it. Propose something new only after showing nothing existing fits,
   and say what you ruled out.
6. **Name what the proposal does NOT solve.** An AIP that overclaims is the same
   defect class this project spent Phase 8 removing from its own spec.
7. **Size the artifact.** Any proposal that makes a verifier download data must
   state how much, at today's chain height, with the measurement shown.
8. **A trust root is out-of-band or it is not a trust root.** Be explicit about
   what the verifier must obtain independently, and how they check they got the
   right thing. Do not disguise a bootstrapping assumption as a proof.

---

## 5. Order of work

| Phase | Work | Gate |
|---|---|---|
| 0 | Confirm §2 against both branches; record what moved | Every §2 claim re-verified with file:line, or corrected |
| 1 | Answer Q1–Q3 (genesis identity, timeline completeness, retention) | Each answered with citations; gaps named |
| 2 | Answer Q4–Q6 (point query, cost, DAG-BFT) | Measured numbers, not estimates |
| 3 | Evaluate Q7 options (a)–(d) against the answers | A recommendation with the rejected options and why |
| 4 | Answer Q8 — the CERTEN-side verifier design | Written as a change to `layer4_verify.go`'s contract |
| 4b | Implement §4A — the anchor-message commitment, EVM only, 3 networks | Message shape defined, canonical encoding pinned, all 3 deployments moved together under one bumped tag |
| 4c | Answer Q15 — the L5 workstream | Three deliverables separated: error handling, backfill, extension |
| 5 | Draft AIP A (CometBFT, now) then AIP B (DAG-BFT) | Matches §6; every claim cited; A does not depend on B |
| 6 | Adversarial review of the draft | A named attack the proposal does NOT stop, or an argument none exists |

Gates are blocking. Phase 5 cannot start before Phase 3 has a recommendation.

---

## 6. Deliverable format

Write AIPs to `C:\Accumulate_Stuff\AIPs\AIP-X\` following the house style — see
`AIP-50/docs/050-user-transaction-fees.md`. Header table, then:

```
| AIP | Title | Status | Category | Author | Created |

# Summary          one paragraph, what changes
# Motivation       why, in terms of what is impossible today
# Specification    data structures (yaml, as AIP-50 does), API methods, wire shapes
# Rationale        options considered and rejected, with reasons
# Security         what it proves, what it does NOT prove, the residual trust
# Compatibility    executor version, DAG-BFT, existing clients
# Implementation   ordered steps, each independently reviewable
# References       file:line into accumulate-core for every behavioural claim
```

The GitLab issue form the Accumulate governance project uses is:

```
### Summary
### What is the need?
### What is the desired behavior?
### How will this be implemented?
```

Produce **both**: the long-form AIP markdown, and a short issue body that fits
that form.

If the research shows the gap needs more than one change, write more than one
AIP. Do not force unrelated changes into a single proposal.

---

## 7. Definition of done

- [ ] Every §2 **and §2A** claim re-verified or corrected, on **both** `main`
      and `dagbft-integration`, with file:line.
- [ ] Q13 and Q11 answered FIRST — the base case must be re-derived from
      partition genesis, and a proof must be able to name its incarnation.
- [ ] Q9 answered — it determines the size of the near-term ask.
- [ ] Q12 answered: what happens to an existing CERTEN proof across a restart.
- [ ] A validator-set change actually simulated and proven end to end (Q10),
      not reasoned about.
- [ ] Q1–Q8 each answered with citations, or explicitly recorded as unanswerable
      and why.
- [ ] A recommended solution, with the alternatives and the reason each lost.
- [ ] Measured sizes and counts wherever the proposal costs a verifier bandwidth.
- [ ] **AIP A** (CometBFT / today) saved under `C:\Accumulate_Stuff\AIPs\`,
      standing on its own without AIP B.
- [ ] **AIP B** (DAG-BFT / spine) saved separately, marked as depending on #4058.
- [ ] A matching short issue body per AIP.
- [ ] A written statement of what the proposal does not solve, and the residual
      trust assumption that remains after it ships.
- [ ] The CERTEN-side change described concretely enough to implement:
      what `layer4_verify.go` accepts, what it refuses, and how the artifact grows.
- [ ] A named adversary the design defeats, and one it does not.

---

## 8. Working notes

- CERTEN-side files that will change: `layer4.go` (build), `layer4_verify.go`
  (verify), `layer4_types.go` (shape), and `pkg/execution/layer5.go`'s
  `ExternalClaim()` — whose caveat sentence should shrink when this lands.
- `docs/proof/DAGBFT_MIGRATION_ANALYSIS.md` (CERTEN repo) already analyses the
  CometBFT→Bullshark primitive map. Read it before answering Q6.
- The Phase 6/7/8 pattern applies to any new evidence: anything added to a proof
  travels **beside** the hashed struct unless a govRoot version bump is
  deliberate. `pkg/proof/timing_evidence.go` documents the pattern.
- Do not assume the answer is "expose MajorHeaderRange publicly". It is the
  leading candidate, not the conclusion.

---

# 9. PHASE FINDINGS

Appended by each session. One heading per phase. This is the shared state
between sessions — nothing here may live only in a transcript.

---

## Phase 0 — re-verification of §2 / §2A / §2B on both branches

**Run 2026-08-28.** `accumulate-core` at `origin/main` = `56f5ae9b`,
`origin/dagbft-integration` = `c01b026e` (the HEAD §2 was researched against).
Nothing in `accumulate-core` was modified; every citation is `git show <ref>:<path>`
against those two refs. Live queries hit `mainnet.accumulatenetwork.io/v3`,
`kermit.accumulatenetwork.io/v3`, three EVM testnet RPCs, and the production
proof database on the fleet. Re-runnable: `docs/l4/phase0_verify.sh`.

**Gate 0 verdict: PASSED.** Every §2-series claim was re-verified or corrected.
Five corrections, one of which invalidates §2A.4's central conclusion.

### 0.1 Confirmed, with line numbers pinned to a branch

| Claim | Status | Citation |
|---|---|---|
| §2.1 `Network` / `Globals` path constants | ✅ both branches | `protocol/protocol.go:61`, `:67` |
| §2.1 `GenesisBlock = 1` | ✅ both branches | `protocol/protocol.go:73` |
| §2.1 `NetworkDefinition` shape | ✅ both, **different lines** | dagbft `protocol/types_gen.go:608`; **main `:596`** |
| §2.2 `MajorHeaderRanger` | ✅ dagbft only | `internal/api/private/api.go:36-47` (iface `:44`, method `:46`) |
| §2.2 `MinorRootRanger` | ✅ dagbft only | `internal/api/private/api.go:49-59` (iface `:56`, method `:58`) |
| §2.2 `MajorHeaderRecord` / `NetworkUpdateProof` | ✅ dagbft only | `internal/api/private/types_gen.go:28-40`, `:56-61` |
| §2.2 `getNetworkUpdatesInWindow` + its comment | ✅ dagbft only | `internal/api/v3/major_header.go:129-133` |
| §2.3 `NewSpine`, genesis refusal, active-validator refusal | ✅ dagbft only | `internal/fastsync/spine.go:48`, `:122`, `:197`; quorum at `:201-203` |
| §2.3 "the walk's only out-of-band trust input" | ✅ dagbft only | `internal/fastsync/snapshot.go:85-87` |
| §2.4 spine is `internal/api/private`, no public service | ✅ **on both branches** | `pkg/api/v3/enums_gen.go:463` (identical text on main and dagbft) |
| §2.4 private routing | ✅ dagbft | `internal/api/routing/message.go:276` (and `:234` for MinorRoot) |
| §2A.1 spine absent on main | ✅ **stronger than stated** | `internal/fastsync/` does not exist on main at all (`git ls-tree` empty); no ranger in `internal/api/private/api.go` |
| §2A.2 validator-set change is `WriteData`, `WriteToState` mandatory | ✅ main, **qualified below** | `internal/core/execute/v2/block/network_accounts.go:78`, `:91`, `:109-111` |
| §2A.3 exactly one main-chain entry | ✅ live, both networks, **and also for `/globals`** | measured |
| §2A.5 public `SnapshotService` | ✅ both branches | `pkg/api/v3/api.go:82-84`; `ServiceTypeSnapshot = 10` at `enums_gen.go:138` |
| §2B.1 partition genesis block holds `systemGenesis` for every system account | ✅ live | Kermit `bvn-BVN1.acme` block 1, 11 entries |
| §2B.2 block-1 timestamps | ✅ live | MainNet `2025-07-13T13:49:18Z`; Kermit `2026-02-01T01:44:46Z` |
| §2B.4a `SystemGenesis` is an empty struct | ✅ **both branches, and in the schema source** | main `protocol/types_gen.go:995`; dagbft `:959`; `protocol/system.yml:98-99` on both (union, zero fields) |
| §2B.4c `currentValidatorSetRoot` is on-chain state, recomputed | ✅ | `CertenAnchorV8_1.sol:541`, `:1590`, `:1620` |
| §2B.4c the 6-field pre-exec message | ✅ exact | `CertenAnchorV8_1.sol:1999-2005` |
| §2B.4c `CertenAccountV7.sol:85` names the stale type | ✅ | `CertenAnchorV6_1 public anchorContract;` |
| §2B.4c live anchor is V8.1 | ✅ on chain | `0x3850C52C…050389.anchorContract()` → `0xea9eee…490272` |
| §1 `ValidatorSet: ni.Validators` from build-time RPC | ✅ | `layer4.go:255`, `layer4.go:421-427` |
| §1 the caveat sentence | ✅ | `pkg/execution/layer5.go:225` |

Current heights, re-measured (both grew since §2B.2, as expected):
MainNet DN `34,653,971`, Kermit DN `7,958,618` (`acc://dn.acme/ledger`.`index`).

Fleet proof database, re-measured — **§2B.4b and §2B.4d reproduce exactly**:

```
proof_artifacts total                429
  anchor_tx_hash present             421   (98%)
  anchor_references rows             401   (93%)
  merkle_path present  (= "L5 row")   10
proof_class  on_demand 403  |  on_cadence 26
L5 by day: 08-21 0/7 · 08-22 0/5 · 08-24 0/1 · 08-25 0/2 · 08-26 8/8 · 08-28 2/2
```

Precision note: what §2B.4d calls "an L5 row" is the column
`proof_artifacts.merkle_path`, not a separate table.

### 0.2 CORRECTION 1 — §2A.4 is WRONG. The genesis entry IS receipt-provable.

This is the finding that matters most, and it changes the size of AIP A.

§2A.4 concluded the genesis network definition "cannot be proven through the
normal chain-entry path". That conclusion came from a query **by entry hash**.
The same entry queried **by index** returns a complete merkle receipt, on both
networks:

```
query acc://dn.acme/network chain=main entry=e43be90e…16d5 includeReceipt
  -> ERROR  "get entry index: Account.acc://dn.acme/network.MainChain
             .ElementIndex.e43be90e…16d5 not found"

query acc://dn.acme/network chain=main index=0    includeReceipt
  -> receipt { start e43be90e…16d5, anchor …, entries[…], localBlock 1, majorBlock 1 }
```

The receipt was recomputed offline (sha256, `right` flag = concat order) and
**validates on both networks**:

```
MainNet  path len 5   anchor 672f89ffc3cc87cff9a7fea1529ec893ec775e49e0cf4da1ab9c927979176e17  VALID
Kermit   path len 4   anchor e3f3119213a1ead44647659d67e47f4269a2affb13f150aa87b20baacf93cf81  VALID
```

**Why the by-hash form fails, in code.** `internal/api/v3/querier.go:455-460`
(`queryChainEntryByValue`) resolves the hash through `record.IndexOf(value)` →
`pkg/database/merkle/chain.go:108-116` → `ElementIndex(hash).Get()`, a
**database-local hash→index map**. `querier.go:447-453`
(`queryChainEntryByIndex`) never touches it. The receipt itself is built
identically in both paths, by `queryChainEntry` (`querier.go:462`).

**It is not genesis-specific.** Measured on Kermit `acc://dn.acme/votes`
(10 entries): indices **0 and 1 both fail by hash**, indices 2, 5 and 9 all
succeed. Both failing entries are the ones written in the genesis blocks. An
ordinary account written after that boundary — `acc://certen-kermit-12.acme/data`
index 0 — resolves by hash and returns a receipt.

So this is a **per-node database-index artifact affecting entries that entered
the store other than through `merkle.Chain.AddEntry`**
(`pkg/database/merkle/chain.go:64-75`, the only writer of `ElementIndex` outside
snapshot restore; restore rebuilds it at
`internal/database/snapshot/merkle_snapshot.go:117-145`, driven from
`restore.go:165` and `:184`). It is **not** a missing proof capability.

**Consequence.** §2A.4's framing — "THE BASE CASE IS THE GAP" — does not
survive. The base case is provable today against an unmodified public v3 node,
by index. Phase 1 must still answer Q9/Q13 properly (why the index entry is
missing on these nodes, and whether that is guaranteed or incidental), but it
should start from "this works" rather than "this is impossible". The prompt's
own note applies: **this single answer decides whether AIP A is a one-line API
fix or a protocol change**, and the evidence points hard at the former.

Also correct §2B.1's implication: you do **not** have to go to a BVN. The DN's
**own block 1** lists `main acc://dn.acme/network systemGenesis` directly —
30 entries on MainNet, 12 on Kermit. §2B.1 is right that the DN main-chain
*entry* is a bare hash; it is wrong that the DN block is the wrong place to look.

### 0.3 CORRECTION 2 — the genesis transaction hash carries NO network identity

The genesis chain entry is **byte-identical on two different networks and two
different incarnations**:

```
MainNet  acc://dn.acme/network  entry[0] = e43be90e349210456662d8b8bdc9cc9e5e46ccb07f2129e7b57a8195e5e916d5
Kermit   acc://dn.acme/network  entry[0] = e43be90e349210456662d8b8bdc9cc9e5e46ccb07f2129e7b57a8195e5e916d5
```

The same hash also appears at index 0 of `acc://dn.acme`, `dn.acme/globals`,
`dn.acme/votes`, `bvn-BVN1.acme/network` and `bvn-BVN2.acme/network`. That
follows directly from §2B.4a: `SystemGenesis` has zero fields, and its header
principal is the constant `acc://ACME`, so the transaction hashes to the same
value everywhere.

**This pre-empts one candidate answer to Q11 and must be recorded before Phase 1
wastes time on it: the genesis txid cannot identify an incarnation.**

What *does* differ is the **genesis-block root anchor** returned in that same
receipt — `672f89ff…6e17` (MainNet) vs `e3f31192…cf81` (Kermit), both at
`localBlock 1` / `majorBlock 1`. It is queryable today from an unmodified public
node and it is a genuine candidate incarnation identifier. Phase 1 should
evaluate it against Q1 and Q11 — including whether two honest parties derive it
identically, and whether it is stable across a node's own re-sync.

### 0.4 CORRECTION 3 — §4A.4's "identical bytecode on all three" is FALSE

All three active deployments are 22,431 bytes, as §4A.4 says. They are **not
identical**. Measured 2026-08-28 via `eth_getCode`:

```
sepolia           0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0   22,431 B
base-sepolia      0xEA9eeeE42a7971792B11Fd2f682C9c1172490272   22,431 B
arbitrum-sepolia  0x4b9eA187772E115641Fd40F35BF7a84925e7A035   22,431 B

pairwise diff: exactly 24 differing bytes, at 8 three-byte sites
  offsets 4685, 5258, 5547, 8955, 10315, 13051, 14788, 21599
  sepolia  aa36a7 = 11155111    base 014a34 = 84532    arbitrum 066eee = 421614
```

Every differing byte is the inlined `DEPLOYMENT_CHAIN_ID` immutable. **Same
compiled source, three chain-bound deployments.** The conclusion §4A.4 draws
survives intact — this is one contract to change, not eight — but the sentence
"Identical bytecode on all three" must not be repeated in an AIP or a spec.
Phase 4b must also expect three *different* deployed-code hashes when verifying
a V8_2 rollout, and must not use bytecode equality as its cutover check.

Path note for Phase 4b: `certen-contracts/` is a sibling of
`independant_validator` under `C:\Accumulate_Stuff\certen\`, not a
subdirectory of it. §4A.4's paths are relative to `certen\`.

### 0.5 CORRECTION 4 — WITHDRAWN. §2B.3's "402" was right.

> ⛔ **This correction was itself wrong and is withdrawn in §9.4c.1.**
> `proof_artifacts.verification_status = 'summary_only'` is exactly **402**,
> which is what §2B.3 meant. The 392 below counts a different column
> (`governance_proof_levels.level_json`). Both numbers are correct; only this
> section's conclusion was not. Original text follows.


§2B.3 cites "402 proofs are already marked `summary_only`". Measured today:
**392 distinct proofs** (1,106 `governance_proof_levels` rows). The argument is
unaffected; the number is not 402.

### 0.6 CORRECTION 5 — §2B.4c's grep claim, narrowed

§2B.4c says "Grepping `CertenAnchorV8_1.sol` for any Accumulate-validator
concept returns **nothing**." The claim is true **about validators** and false
as a grep instruction: the contract does carry Accumulate concepts —
`adiURLHash` (`:291`), `accumulateBlockHeight` (`:205`, an event field), and
`operationID`. What is absent is any notion of an Accumulate *validator*,
*quorum*, *ed25519 key* or *threshold*. State it that way; the loose version
will be contradicted by the first reviewer who runs the grep.

`accumulateBlockHeight` at `:205` is worth Phase 4b's attention: an
Accumulate-block field already reaches the chain in an event, which is a useful
precedent for the incarnation identity — though an event is not part of the
signed preimage and is therefore not a substitute for §4A.1.

### 0.7 QUALIFICATION — §2A.2's "every change already has a receipt"

`processNetworkAccountUpdates` returns early for system transactions
(`network_accounts.go:38-40`, `Body.Type().IsSystem()`) **before** reaching the
`WriteData` case that enforces `WriteToState` (`:109-111`). So the mandate binds
ordinary governance writes, not system transactions — and genesis is exactly a
system transaction. §2A.2's conclusion is sound for the *update timeline*; do
not extend it to the base case.

Two further details Phase 1 will need, both from this session's reading:

- `getNetworkUpdatesInWindow` (`major_header.go:133-136`) walks
  `s.partition.JoinPath(protocol.Network)` and `…JoinPath(protocol.Globals)` —
  the **serving partition's own** accounts, not a hard-coded `dn.acme`. Every
  partition has its own `/network` (verified live: `bvn-BVN1.acme/network` and
  `bvn-BVN2.acme/network` each have exactly 1 entry).
- `network_accounts.go:115-125` shows BVN `/network` accounts are updated only
  by internally-produced transactions pushed from the DN, never directly. That
  is what makes the per-partition copies a consistent mirror rather than an
  independent timeline — relevant to Q2's completeness argument.

### 0.8 UNRESOLVED — is `mainnet.accumulatenetwork.io` the public MainNet?

`network-status` on that endpoint reports:

```
networkName  MainNet        executorVersion  v2-vandenberg
partitions   [Cyclops, Directory]            validators  1
```

One validator, and a single BVN named `Cyclops` — not the Apollo / Yutu /
Chandrayaan topology of the Accumulate mainnet as publicly documented. Either
the topology was replaced at the 2025-07-13 re-genesis, or this endpoint is not
the production mainnet.

**Tried:** `network-status` (Directory), `consensus-status` (rejected —
`node ID is missing`, which needs a node id this session does not have),
`acc://dn.acme/ledger`, and DN blocks 1 and 2. Not resolved from the API alone.

This is blocking for any AIP that quotes a "mainnet" number, and it interacts
directly with §2B.2 — a topology change across the boundary would be further
evidence for the re-genesis, but it must be established, not assumed. **Ask the
maintainer.** Do not let a Phase 2 cost measurement cite this endpoint as
"mainnet" until it is settled.

### 0.9 Not attempted in Phase 0, by design

Q1–Q15 remain open; Phase 0 verifies §2, it does not answer them. Specifically
**not** done here, and still owed: the simulated validator-set change (Q10),
the `MajorHeaderRecord` size measurement (Q5), and any test of a stored proof
against a restarted chain (Q12). Nothing in this section should be read as
progress on those.

---

## Phase 1 — Q13, Q11, Q12, Q9, Q1–Q3

**Run 2026-08-28.** Same refs as Phase 0 (`origin/main` = `56f5ae9b`,
`origin/dagbft-integration` = `c01b026e`). `accumulate-core` was **not
modified** — the simulator work ran against a `git archive` copy extracted to a
scratch directory, and `git status --porcelain` on the repo is empty. Probes and
run instructions: `docs/l4/phase1_probe/`.

**Gate 1 verdict: PASSED.** Q13, Q11, Q12, Q9, Q1, Q2 and Q3 are each answered
with citations or measurements. Q10 remains open by design (Phase 2+). One
Phase 0 hypothesis is corrected — by me, against my own guess.

### 1.0 The one-paragraph result

The near-term gap is **not** where §2A.4 put it and **not** where Phase 0 left
it. Proving the genesis *chain entry* is worthless, because `systemGenesis` has
an empty body and commits to nothing. What has to be proven is the genesis
*account state*, which lives in the BPT — and that **is** provable offline
today, but **only while it is still the current state**. `BPT.GetReceipt`
constructs a receipt "for the current state" only, and there is no height
parameter anywhere in the public API. The validator set has never changed on
either network, so current == genesis, and the gap is invisible. **The first
validator-set change makes the genesis set permanently unprovable through the
public API.** That is the ask for AIP A.

### 1.1 Q13 — the base case, re-derived correctly. ANSWERED.

**Step 1: the genesis entry proves nothing.** `SystemGenesis` is an empty struct
(§9.0.1; `protocol/system.yml:98-99`). A receipt over it establishes that a
contentless transaction was anchored. It says nothing about the validator set.
Phase 0 was right that the entry is provable and right that §2A.4's conclusion
was false — but "the base case is provable" was the wrong lesson to draw from it.

**Step 2: the validator set is in the account state, and that IS provable
offline today.** Measured with `docs/l4/phase1_probe/main.go`, which queries
`acc://dn.acme/network` with `includeReceipt`, re-derives the receipt's start
from the returned state, and validates the path:

```
=== kermit : acc://dn.acme/network state proof ===
  account type            : dataAccount
  receipt.start           : 733250b14876c25fb2a89c050c1793b45e12386a9d1fd5c41ab65c3ed15f0c88
  sha256(marshalled state): 733250b14876c25fb2a89c050c1793b45e12386a9d1fd5c41ab65c3ed15f0c88
  LEAF DERIVABLE OFFLINE  : true
  path length             : 5
  MERKLE PATH VALID       : true
  networkName             : DevNet
  validators              : 3
  partitions              : 4
```

The leaf is derivable because `hasher[0]` is a plain hash of the marshalled main
state (`internal/database/observer_prod.go:31`, `hashState(&err, &hasher, true,
a.Main().Get)`), and `Account.StateReceipt` combines that state hasher's receipt
with the BPT receipt (`internal/database/bpt_account.go:66-88`). So a verifier
holding the account bytes can recompute the leaf and walk to the BPT root
without trusting the server. **This is a real, working, offline-checkable proof
of the current validator set, and it needs no protocol change.**

**Step 3: and it is current-state only. This is the gap.**

```go
// pkg/database/bpt/bpt_receipt.go:17
// GetReceipt constructs a receipt for the current state for the given key.
func (b *BPT) GetReceipt(key *record.Key) (*merkle.Receipt, error)
```

`Account.BptReceipt` (`bpt_account.go:53-64`) calls exactly that, and
`indexing.ReceiptForAccountState` (`internal/database/indexing/receipts.go:124-142`)
calls `account.StateReceipt()` and then attaches *the latest* root index entry
purely for its block number. The API has no height parameter for account state:
`ReceiptOptions` carries only `ForAny` and `ForHeight` (`pkg/api/v3/options.yml:119-124`),
and `ForHeight` is consumed only on the **chain-entry** path
(`internal/api/v3/querier.go:517-519`), never on the account path
(`querier.go:339-346`). The BPT is stored under a single `Root`
(`pkg/database/merkle/model.yml`, `pkg/database/bpt/model.yml:16`) and mutated
in place — there is no versioned or historical tree to query.

**Step 4: historical BPT *roots* are retained; historical *membership* is not.**
This asymmetry is the precise shape of the ask. Measured on Kermit:

```
acc://dn.acme/anchors  chain anchor(directory)-bpt  ->  173,373 entries
  index 0      5cd146ba4ba40712ab002936d29ef213a7e2ff4ebc0b5ec4183b1ae8af00d5ff
  index 173372 79cd33f73adc0bba662f4c1de8b4bb664244ec269e38fd77d30883f283003868
mainnet: 13,732 entries, index 0 = b166048d9c3c89417ea3aec01afa0e671332391e08660f9d8c1ee6605bacb79b
```

Every historical BPT root is on an indexed, receipt-provable chain — this is the
same `anchor(<partition>)-bpt` chain CERTEN's L2/L3 already use
(`layer2.go:164-165`, `layer3.go:35-38`). What is missing is the *membership
path* from an account leaf to one of those historical roots.

**So the AIP A ask is one bounded thing:** a way to obtain a BPT membership
receipt for an account against a *historical* BPT root, not only the current
one. Everything else — the roots, the anchoring, the quorum signatures over
them, the offline leaf derivation — already exists and already works.

**Also re-derived, per §2B.1's instruction:** the per-partition copies behave
identically. `bvn-BVN1.acme/network` and `bvn-BVN2.acme/network` each have
exactly one main-chain entry, the same `systemGenesis` hash. Kermit BVN1 block 1
carries all 11 system accounts (§9.0.1). Nothing about the partition view
changes the answer — the base case is a *state* question, not a *block* question.

### 1.2 Q11 — incarnation identity. ANSWERED, and the news is bad.

**A stored CERTEN proof contains nothing that names its network or its
incarnation.** Inspected `testdata/proof_bvn1.json`, every field of both L4 legs:

```
layer4Bvn: partition BVN1  source acc://bvn-BVN1.acme  destination acc://dn.acme
           anchorPool acc://dn.acme/anchors   networkVersion 0
layer4Dn:  partition Directory  source acc://dn.acme   destination acc://bvn-BVN1.acme
           signer[0] acc://dn.acme/network    networkVersion 0
top-level keys: input, layer1, layer2, layer3, layer4Bvn, layer4Dn
```

Every one of those URLs is a protocol constant. `acc://dn.acme` is the Directory
on MainNet, on Kermit, and on every incarnation of both. `networkVersion` is
`NetworkDefinition.Version`, measured as **0** on both live networks — it is not
a discriminator either.

**Nor is it in the signed preimage, which is the load-bearing part.** The L4
digest is `sha256( ED25519Signature.Metadata().Hash() || signedHash )`
(`layer4_verify.go:29-60`; `protocol/signature.go:385-390`, where `Metadata()`
clears the signature and the transaction hash, leaving public key, signer URL,
signer version and timestamp). `signedHash` is the hash of a `SequencedMessage`,
whose fields are `Message`, `Source`, `Destination`, `Number`
(`pkg/types/messaging/types_gen.go:111-121`), wrapping a `PartitionAnchor`
whose fields are `Source`, `MajorBlockIndex`, `MinorBlockIndex`,
`RootChainIndex`, `RootChainAnchor`, `StateTreeAnchor`
(`protocol/types_gen.go:654-669`).

**Not one field in that preimage identifies a network or an incarnation.** The
Accumulate validators are not signing anything that says which chain they are
on. This is not a CERTEN omission — it is a property of the protocol's anchor
signatures, and it means the incarnation identity **must** be added by CERTEN,
alongside the hash, exactly as §4A.1 decided.

**Candidates evaluated:**

| Candidate | Verdict |
|---|---|
| genesis transaction hash | **DEAD.** `e43be90e…16d5` is byte-identical on MainNet, on Kermit, and on a genesis built from scratch in the simulator (§9.0.3, §9.1.4). It is a constant, not an identifier. |
| `networkName` (`MainNet` / `DevNet`) | **Weak.** Asserted account state, and stable across a restart of the same network — it names the network, not the incarnation. |
| `NetworkDefinition.Version` | **Dead.** Measured 0 on both networks. |
| CometBFT `GenesisDoc.ChainID` = `NetworkID + "." + PartitionId` (`internal/node/genesis/bootstrap.go:147`) | **Names the network, not the incarnation** — the composition contains nothing that changes on a restart. Not exposed by any public API. |
| **genesis root anchor** — `anchor(directory)-root[0]` | **BEST AVAILABLE.** See below. |

The genesis root anchor is queryable today, differs between chains, and is
itself receipt-provable into a later quorum-signed root:

```
mainnet  anchor(directory)-root[0] = 672f89ff…6e17   receipt VALID into block 86, majorBlock 1
kermit   anchor(directory)-root[0] = e3f31192…cf81   receipt VALID into block 3,  majorBlock 1
```

(Both equal the anchor of the genesis chain-entry receipt measured in §9.0.2 —
two independent queries agreeing.) Because it proves into a later root anchor,
and root anchors are what the validator quorum signs, an incarnation identifier
built on it can be **bound to the same quorum signature the rest of L4 uses**.
That is the property no other candidate has.

**State the limit plainly, per rule 6a.** This is a *distinguisher*, not a
*proof of distinctness*. It differs across incarnations because genesis content
and timestamps differ. An operator who deliberately replayed a byte-identical
genesis would produce a colliding identifier. It is strong enough to stop a
verifier silently accepting a proof from a dead chain; it is not a cryptographic
guarantee that two incarnations are different, and the AIP must not say it is.

### 1.3 Q12 / Q12a — proof survival across a restart. ANSWERED. The dangerous case is the real one.

**Empirical part.** CERTEN holds **41 proofs created before Kermit's current
genesis** (oldest `2026-01-25 15:57:27+00`; Kermit block 1 is `2026-02-01`).
These are genuine pre-restart artefacts. Their Accumulate transactions are gone
from the current chain:

```
kermit txid 85756bbafb4ca5ca… -> NOT FOUND
kermit txid d81a379086efc63e… -> NOT FOUND
kermit txid 3f160290ff827bbc… -> NOT FOUND
```

**Limit of that experiment, stated honestly:** all 41 predate L4 persistence.
Every one of their `governance_proof_levels` rows is already `summary_only`, and
their `artifact_json` uses the old schema (`cycle_id`, `attestation`,
`anchor_block`, …) with no L1–L5 legs. **So I could not run a modern L4 offline
verification against a real pre-restart proof — none exists.** That is a gap in
the evidence, not a gap in the answer.

**Structural part, which settles it.** `layer4_verify.go` imports
`crypto/ed25519`, `crypto/sha256`, `encoding/hex`, `fmt`, `strings`,
`messaging`, `url`, `protocol` — **no `net/http`, no client, no context**.
`VerifyOffline()` performs no network access, by construction; the existing
`TestOffline_StoredProofsVerifyWithNetworkDisabled` asserts it, and the full
offline suite passes (10/10 tampering cases correctly rejected, run this
session).

Combine that with Q11: the artifact carries no incarnation identity, and the
verifier never asks the chain anything. Therefore:

> **A stored L4 proof from incarnation N returns a confident PASS after a
> restart, unchanged, forever.** Not "fails". Not "warns". The verdict is
> *necessarily* identical before and after, because nothing the verifier reads
> can differ.

This is precisely the outcome §2B.3 named as the dangerous one, and it is not a
risk — it is the current behaviour, and it is structural.

**Q12a — the verdict a verifier must produce.** The three-way discipline (rule
8) maps cleanly, and the marker must live **beside** govRoot, per the
`pkg/proof/timing_evidence.go` pattern, so govRoot does not move:

| Situation | Verdict | What is established |
|---|---|---|
| Proof's incarnation == the live incarnation | `verified` | everything L1–L4 claims |
| Proof names an incarnation ≠ the live one | **`foreign_incarnation`** (new, modelled on `summary_only`) | content, internal consistency, and — if L5 is present — external existence and time. **Not** validator-set legitimacy. |
| Proof carries no incarnation identity at all (every proof issued to date) | **`incarnation_unknown`** | the same, minus the ability to say *which* chain. This is a *could-not-read*, not a refusal, and must not be reported as a governance rejection. |

Note the third row is not hypothetical: it is the state of all 429 stored
proofs. Backfilling an incarnation identity onto historical proofs is possible
only where the referenced chain is still live — mark, never fabricate.

### 1.4 Q9 — is the missing hash→index map guaranteed or incidental? ANSWERED: GUARANTEED. (This corrects my own Phase 0 hypothesis.)

§9.0.2 speculated the missing `ElementIndex` was "a per-node database-index
artifact" of snapshot provisioning. **That was wrong, and I am correcting it
against my own guess.** Built a genesis from scratch in the simulator — no
snapshot restore anywhere in the path — and asked the same question
(`docs/l4/phase1_probe/q9_genesis_index_test.go`, against a `git archive` copy
of `origin/main`):

```
--- acc://dn.acme/network : main chain height 1 ---
    entry[0]        = e43be90e349210456662d8b8bdc9cc9e5e46ccb07f2129e7b57a8195e5e916d5
    IndexOf(entry0) -> ERROR: Account.acc://dn.acme/network.MainChain.ElementIndex.e43be90e… not found
    VERDICT: hash->index map ABSENT on a freshly built genesis
--- acc://dn.acme/globals : main chain height 1 ---
    (identical)
```

Reproduced exactly the live behaviour, on a chain that has never been
snapshotted. So the by-hash lookup failure is **guaranteed for genesis entries**,
not a provisioning accident. Two consequences:

- Any AIP-A text must say the genesis entry is reachable **by index**, and must
  not propose "fix the node's index" as the remedy — there is nothing to fix.
- The same run independently reproduced the cross-network genesis hash constant
  `e43be90e…16d5` for a **third** time, from a locally constructed genesis. §9.0.3
  is now confirmed by construction, not just by observation.

**Mechanism, offered as explanation and labelled as such.** `ElementIndex` and
`Element` are declared `type: index` in `pkg/database/merkle/model.yml:28-39`
("Not indexed directly") — locally-derived index records rather than state.
Genesis is built in a temporary database and delivered as a snapshot
(`internal/node/genesis/bootstrap.go:142-143`), and the restore path rebuilds
the index only from mark points and the head hash list
(`internal/database/snapshot/merkle_snapshot.go:117-145`, driven from
`restore.go:165,184`). **I verified the *behaviour* by running it; I did not
isolate which of those steps drops the entry.** Do not cite the mechanism as
measured — cite the empirical result.

### 1.5 Q1 — genesis identity. ANSWERED, with a hard limit.

**Is there a canonical genesis artifact?** Yes, and it is richer than expected.
`internal/node/genesis/bootstrap.go:143-184` writes a CometBFT `GenesisDoc` into
the genesis snapshot's `SectionTypeConsensus`, carrying:

- `doc.ChainID = opts.NetworkID + "." + opts.PartitionId` (`:147`)
- `doc.Params` — the consensus parameters
- `doc.Validators` — **every genesis validator active on the partition, with
  public key, address and power** (`:150-169`)

So the genesis validator set is committed inside a well-defined, hashable
document. That is the natural trust root.

**Is it queryable? NO.** `SnapshotService`/`ListSnapshots` exists in the public
API on both branches (`pkg/api/v3/api.go:82-84`, `ServiceTypeSnapshot = 10` at
`enums_gen.go:138`) but **neither live network runs it**:

```
mainnet services: [f001, consensus, event, metrics, network, node, query, submit, validate]
kermit  services: [f001, consensus, event, faucet, metrics, network, node, query, submit, validate]
snapshot offered: False on both
list-snapshots -> "dial /p2p/12D3KooWNDFRs…/acc-svc/snapshot:directory: notFound"
```

**This kills §2A.5 / Q7 option (b) as written.** The service is defined but not
deployed; proposing "use the existing SnapshotService" would be proposing
something that has never run in production. An AIP may still ask for it to be
enabled — but it must say that it is currently absent, not that it is available.

**Can two parties verify they pinned the same genesis? Yes, with a caveat that
matters.** Both can query `anchor(directory)-root[0]`, compare, and each obtain
a receipt proving it into a later quorum-signed root. That is a genuine
consistency check. But both parties obtained it **from the network whose
legitimacy is the question** — so it is not, by itself, a trust root (rule 6). A
trust root requires that the value be fixed out-of-band. This is exactly what
§4A buys: writing the incarnation identity into the anchor pre-exec message
publishes it to a chain that did not restart, at a time nobody can backdate.
**That is the argument for §4A that Phase 1 supplies and §4A.2 does not yet
make.**

### 1.6 Q2 — completeness of the update timeline. ANSWERED: complete, with two named exceptions.

The consensus validator set is not stored — it is **derived** from the account
state, every block:

```go
// internal/core/execute/v2/block/block_end.go:261-263
var valUp []*execute.ValidatorUpdate
if !m.isGenesis && !m.globals.Active.Equal(&m.globals.Pending) {
    valUp = execute.DiffValidators(&m.globals.Active, &m.globals.Pending, m.Describe.PartitionId)
```

`DiffValidators` (`internal/core/validators.go:18-55`) computes adds and removes
purely from `GlobalValues.Network.Validators`. `globals.Pending` is mutated in
exactly one production place — `processNetworkAccountUpdates`
(`network_accounts.go:78-111`), on a `WriteData` to `dn.acme/network`, with
`WriteToState` mandatory. Every other caller of the protocol-level mutators
(`AddValidator`, `RemoveValidator`, `UpdateValidatorKey`,
`protocol/network_def.go:63,82,93`) is **initialization only**:
`internal/node/daemon/init.go:217-218,226` and `cmd/accumulated/run/devnet.go:377-378`.

> **The CometBFT validator set cannot diverge from `acc://dn.acme/network`,
> because it is computed from it.** The account's chain history therefore *is*
> the complete timeline. There is no side channel to miss.

BVN copies are consistent by construction: BVN `/network` accounts reject direct
updates and are written only by internally-produced transactions pushed from the
DN (`network_accounts.go:115-125`), which are stored as real transactions
(`msg_network_update.go:120-160`) and so are equally provable. And a DN anchor
carries `Updates []NetworkAccountUpdate` inside the **quorum-signed**
`DirectoryAnchor` (`protocol/types_gen.go:322-334`) — a validator-set change is
therefore already inside a signed message today, on `main`, with no spine.

**The two exceptions, named:**

1. `!m.isGenesis` (`block_end.go:262`) — genesis establishes the set without
   producing an update. The timeline's *base case* is outside the timeline. This
   is §1.1 again, arriving from a second direction.
2. `Executor.Init(validators)` (`internal/core/execute/v2/block/executor.go:216-243`)
   takes the validator set from the consensus layer at startup.

Both are boundary conditions, not runtime paths. Neither breaks induction *after*
genesis; both are why induction needs a base case it cannot get from the chain.

### 1.7 Q3 — archived signature retention. ANSWERED: retained, but not guaranteed.

Measured on Kermit, whose `acc://dn.acme/anchors` main chain has **355,574
entries** across 173k+ blocks:

```
anchors main[1]      blockValidatorAnchor   1 blockAnchor signature   (genesis era, 2026-02-01)
anchors main[1000]   directoryAnchor        3 blockAnchor signatures  (= all 3 validators)
anchors main[100000] blockValidatorAnchor   1 blockAnchor signature
```

Index 1 still carries its signature 355,000 entries later. Supporting this at the
code level: **no pruning function exists** — `grep -rn "func.*[Pp]rune"` over
`internal/database/` and `internal/core/execute/v2/` returns nothing.

**But absence of pruning is not a retention guarantee.** What was measured is one
node's behaviour on one network with no pruning implemented. An operator running
a pruned or state-synced node, or a future release that adds pruning, breaks
proof construction for old transactions silently. **AIP A should ask for
retention to be a stated commitment**, which is Q7 option (d) — and Q7(d) is
therefore *not* redundant just because nothing prunes today.

### 1.8 What Phase 1 changes about the deliverable

- **AIP A's ask is now concrete and small:** a BPT membership receipt against a
  *historical* root. Not a new proof system; a height parameter on a proof that
  already exists and already verifies offline.
- **Q7 option (a) is dead as stated** — the genesis entry is provable by index
  and proves nothing anyway (§1.1, §1.4).
- **Q7 option (b) is dead as stated** — no live network runs `SnapshotService`
  (§1.5). It can be *asked for*; it cannot be *used*.
- **Q7 option (c)** — "validator set at height H with proof" — is the surviving
  candidate, and §1.1 shows it decomposes into one missing primitive.
- **Q7 option (d)** survives and is independently necessary (§1.7).
- **§4A gains its strongest argument** (§1.5): the incarnation identity is
  obtainable from Accumulate but cannot be a *trust root* while it is only ever
  fetched from Accumulate. Publishing it to a chain that did not restart is what
  converts a consistency check into a trust root.
- **A new CERTEN-side defect is now on the record** (§1.3): every stored proof
  will verify confidently against a chain that no longer exists. That is not a
  Phase 5 design note — it is a live product risk, and it is the same
  overclaiming-verdict class this project has removed twice.

### 1.9 Still open after Phase 1

- **Q10 — the simulated validator-set change has NOT been run.** Phase 1 built
  the harness that makes it possible (an out-of-tree simulator copy that builds
  and runs, `GOWORK=off`), but did not exercise a change. This remains the
  single most important unrun experiment, and §2A.3's warning stands: the update
  path has zero production history.
- **Q4–Q6** (point query shape, induction cost, DAG-BFT survival) — Phase 2.
- **§9.0.8** — whether `mainnet.accumulatenetwork.io` is the public MainNet is
  still unresolved and still blocking for any "mainnet" number in an AIP.
- The mechanism behind Q9's missing index is explained but not isolated (§1.4).

---

## Phase 2 — Q4, Q5, Q6

**Run 2026-08-28.** Same refs as Phases 0–1. `accumulate-core` **not modified**
(`git status --porcelain` empty); the sizing ran against a `git archive` copy of
`origin/dagbft-integration`. Probes: `docs/l4/phase2_probe/`.

**Gate 2 verdict: PASSED.** Q4, Q5 and Q6 are answered with measured bytes and
counts taken from live production data, not estimates. One unrelated finding
surfaced that is **more urgent than DAG-BFT** and is recorded in §9.2.4.

### 2.1 Q5 — cost of induction. ANSWERED. The whole spine is 1–3 MB.

**Major blocks in existence, measured 2026-08-28:**

```
MainNet   822 major blocks   (genesis 2025-07-13 -> 411 days x 2/day = 822)  ✅ 12-hourly
Kermit    417 major blocks   (genesis 2026-02-01 -> 208 days x 2/day = 416)  ✅
both networks opened major block N at 2026-08-28T12:00:00Z
```

Cross-checked two ways: the block query's `majorRange` total and the
`major-block` index chain on `<partition>/anchors` agree exactly (822 / 417).

**One `MajorHeaderRecord`, built from real Kermit data and marshalled**
(`TestQ5_MajorHeaderRecordSize`) — a real major-block `IndexEntry` (index 416),
a real `DirectoryAnchor` in a real `SequencedMessage`, and the real 3-signature
validator quorum from `dn.acme/anchors` main[1000]:

```
IndexEntry                    17 B   (source 355261, block 417, rootIndexIndex 389720)
DirectoryAnchor body         996 B   (1 receipt, 0 updates)
SequencedMessage (anchor)   1043 B
KeySignature                 165 B   each, x3 signers = 495 B
---------------------------------------------------
MajorHeaderRecord TOTAL     1572 B   (0 updates in window)
```

**Variance.** Sampled ten anchors across the whole chain
(`TestQ5b_AnchorSizeDistribution`): body min **89 B**, median **996 B**, max
**1,856 B**, mean 973 B. The driver is the receipt count (0–3 seen), i.e. how
many partitions anchored into that DN block. **Updates seen: 0 everywhere** —
consistent with §2A.3, the set has never changed.

**The whole spine, at today's height:**

| Validators | Bytes/record | MainNet (822) | Kermit (417) |
|---|---|---|---|
| 1 (mainnet today) | 1,242 | **997 KB** | 506 KB |
| 3 (kermit today) | 1,572 | 1.26 MB | **640 KB** |
| 8 | 2,397 | 1.92 MB | 976 KB |
| 16 | 3,717 | **2.98 MB** | 1.51 MB |
| 32 | 6,357 | 5.10 MB | 2.59 MB |
| 64 | 11,637 | 9.34 MB | 4.74 MB |

Record size is `~1,077 B + 165 B x validators`, plus the update deltas (zero so
far).

> **Verdict: a verifier can walk the entire spine once and cache it. No
> checkpointing scheme is needed.** Even at 64 validators — far beyond anything
> Accumulate has run — the full induction from genesis to today is under 10 MB,
> and it grows at ~2 records/day (≈1.1 MB/year at 16 validators). This removes
> the concern §2.4(3) raised about the spine being "a whole-chain sync
> primitive, not a point query": at these sizes the distinction is an
> optimisation, not a blocker.

### 2.2 Q4 — point query feasibility. ANSWERED. ~2.4 KB, and it needs no spine.

Two shapes were sized. The second is the one that matters.

**(a) The spine shape** — nearest major-block checkpoint plus deltas — is not
actually a point query in the implementation. `spine.go:118-123` refuses any
walk that does not start at genesis:

```go
if s.LastMinorBlock == 0 && s.RootChainAnchor == [32]byte{} {
    if proof.MerkleState.Count != 0 {
        return errors.Unauthenticated.With("root proof does not start at genesis")
    }
}
```

So the spine offers "walk me from genesis", not "prove me block N". Binding a
*minor* block past the spine needs a second record, `MinorRootRecord`
(`internal/api/private/types_gen.go:43-54`: anchor, signatures, updates, plus a
`RootProof *merkle.ReceiptList` extending the last verified root). CERTEN's
proofs are per-intent at minor-block granularity, so it would need both. Given
§2.1's measurements this is affordable, but it is a walk, not a query.

**(b) The CERTEN shape**, which Phase 1 §1.1 showed is the real ask — "the
validator set at block N, provable to a signed anchor". Measured from live
Kermit data (`TestQ4_PointQueryArtifactSize`):

```
NetworkDefinition (the payload)          335 B
full dataAccount state (leaf preimage)   397 B      <- what the leaf hashes
BPT membership path                      165 B      (5 steps x 33 B)
root-chain receipt for the BPT root    ~ 264 B      (8 steps, per §9.1.2)
signed anchor + quorum (3 validators)   1538 B
--------------------------------------------------
POINT QUERY ARTIFACT TOTAL              2364 B
```

At mainnet scale the BPT is deeper — measured **17 steps (561 B)** for
`dn.acme/network` on MainNet versus 5 on Kermit, since path length grows with
account count:

| Validators | Artifact (mainnet-depth BPT) |
|---|---|
| 1 | 2,430 B |
| 8 | 3,585 B |
| 16 | **4,905 B** |
| 32 | 7,545 B |

> **Verdict: the point query is feasible and costs ~2.4–7.5 KB — roughly 300x
> smaller than walking the spine, and small enough to embed in every CERTEN
> proof artifact.** Every component already exists and is already served, except
> one: the BPT membership path must be against a *historical* root
> (Phase 1 §1.1). That single missing primitive is the whole of AIP A's ask, and
> Q4 now prices it: **~2.4 KB per proof, versus 640 KB–3 MB per verifier for the
> spine alternative.**

This also settles Q7's shape. Option **(c)** — "validator set at height H, with
proof" — is not merely the surviving candidate (Phase 1 §1.8); it is the
*cheaper* one by two orders of magnitude, and it is the only one that fits
inside a per-intent artifact.

### 2.3 Q6 — DAG-BFT survival. ANSWERED: the primitive survives untouched.

**The quorum signature over a DN self-anchor is executor-layer chain state, not
consensus-engine state, and the check is byte-identical on both branches.**

`internal/core/execute/v2/block/msg_block_anchor.go`, same line on both:

```go
// :305 on origin/main AND on origin/dagbft-integration
if uint64(len(sigs)) < ctx.Executor.globals.Active.ValidatorThreshold(partition) {
    return false, nil
}
```

And the spine's own quorum check never touches a certificate:

```go
// internal/fastsync/spine.go:189 (dagbft-integration)
func verifyQuorum(g *network.GlobalValues, anchor *messaging.SequencedMessage, sigs []protocol.KeySignature) error {
    for _, sig := range sigs {
        if !sig.Verify(nil, anchor) { ... }
```

`grep` over `spine.go` for `Certificate` or `StateHash` returns **nothing**. It
verifies `protocol.KeySignature` values over a `messaging.SequencedMessage` —
the *same* primitive CERTEN's L4 verifies (`layer4_verify.go:29-60`).

**So the StateHash-binding gap does not break it.**
`DAGBFT_MIGRATION_ANALYSIS.md` §4.3 is right that `Certificate.StateHash` is a
sibling of the header and is not covered by the DAG vertex quorum. But neither
the spine nor CERTEN's shipped L4 reads the certificate. The flag is real for
anything that would bind to `Certificate.StateHash`; it is not a risk to this
design.

**CORRECTION to `DAGBFT_MIGRATION_ANALYSIS.md`.** Its table row
(`:58`) reads:

> | **L3** | Anchor signed by ≥2/3 validators | **CometBFT** `/commit`, `Header.AppHash`, CanonicalVote precommits | **Full rewrite** → Bullshark certificate + StateHashMessage |

That describes a design **L4 has already moved off**, and `layer4_types.go` says
so in its own header: *"L4 replaces the former CometBFT `bindConsensusAppHash`
assertions… That is chain state, not engine state, so the same evidence exists
on CometBFT and on DAG-BFT."* The "full rewrite" row is stale relative to
shipped code. Q6's honest answer is **no rewrite is needed**, and the migration
doc should be corrected rather than cited.

### 2.4 UNPLANNED FINDING — Kourou lets an anchor be authorized with NO validator signatures

Found while verifying Q6. It is not a DAG-BFT issue, it is on `main`, and it is
a nearer-term threat to L4's premise than anything in §2.3.

`msg_block_anchor.go` on **origin/main**, `txnIsReady`:

```go
// :277-290
// A collection proof under a root of the SOURCE that we already hold
// authorizes the anchor by itself — no signature quorum (#4087).
if ctx.blockAnchor.Proof != nil {
    held, err := x.proofAnchorIsHeld(batch, ctx)
    ...
    if held { return true, nil }
}
```

and `checkSignature` short-circuits entirely (`:243-249`):

```go
// A proof-authorized anchor carries no signature to check.
if ctx.blockAnchor.Signature == nil { return nil }
```

The same mechanism is on `dagbft-integration` under a different issue number
(`:271-276`, "#4056"), keyed off the directory root instead of the source root.
**Both tracks have it.**

**Gated, and not yet live.** It requires `V2KourouEnabled()`
(`msg_block_anchor.go:126`; `protocol/version.go:70-71`,
`v >= ExecutorVersionV2Kourou`). Measured executor versions:

```
ExecutorVersionV2Vandenberg = 7    <- MainNet runs this
ExecutorVersionV2Jiuquan    = 8    <- Kermit runs this
ExecutorVersionV2Kourou     = 9    (10 on dagbft-integration)
protocol/version.go:14  ExecutorVersionLatest = ExecutorVersionV2Kourou
```

**Neither live network has it enabled today — but it is the next activation on
`main`.**

**Why this matters to CERTEN.** `layer4_types.go` states L4's premise as:

> "anchors are threshold-signed at the *executor* layer (see accumulate-core
> `internal/core/execute/v2/block/msg_block_anchor.go`: `txnIsReady` requires
> `len(sigs) >= globals.Active.ValidatorThreshold(partition)`)"

Under Kourou that becomes **conditionally false**. An anchor may be delivered,
executed and become chain history with **zero validator signatures**. For such an
anchor:

- L4 cannot be built — there is no quorum to carry. That is a **capability
  limit**, and must be reported as one, never as a governance rejection. This is
  the exact defect class removed twice already (§2B.4e).
- More seriously, a verifier must stop treating *"the network accepted this
  anchor"* as implying *"a validator quorum signed it."* After Kourou those are
  different statements.

The collection-proof form is intended for recovery — the comment notes a
historical quorum "can be impossible to re-gather after validator churn" — so
normal anchors will still carry signatures. But CERTEN cannot rely on an
intention. **This belongs in AIP A's compatibility section and in the Phase 4
verifier contract**, and it should be raised with the maintainers before Kourou
activates. It is cheap to handle now and expensive to discover in production.

### 2.5 What Phase 2 changes about the deliverable

- **Q7(c) is now the recommendation on cost grounds as well as feasibility**:
  ~2.4 KB per proof against 640 KB–3 MB per verifier (§2.2 vs §2.1).
- **The spine (AIP B) is cheap enough to be a genuine fallback**, not a
  theoretical one — under 10 MB in every scenario measured. AIP B should say so
  with these numbers rather than hedging.
- **Q6 removes a supposed blocker**: no DAG-BFT rewrite is required for the
  anchor-quorum primitive, and `DAGBFT_MIGRATION_ANALYSIS.md` needs correcting.
- **A new compatibility hazard is on the record** (§2.4) that neither the
  runbook nor the prompt anticipated, and that arrives *before* DAG-BFT.

### 2.6 Still open after Phase 2

- **Q10 — the simulated validator-set change is STILL NOT RUN.** Phase 1 built
  the harness; Phase 2 used it for sizing but did not exercise a change. Every
  size in §2.1 has `updates = 0` because the path has never run — the one number
  in this section that is *structurally* unmeasured is the cost of a
  `NetworkUpdateProof`. That is now the single largest hole in the evidence.
- **§9.0.8** — whether `mainnet.accumulatenetwork.io` is the public MainNet
  remains unresolved. Note it bites here: MainNet's "1 validator" is why its
  per-record cost looks cheapest in §2.1, which would be a misleading number to
  publish.
- Q7 (Phase 3), Q8 (Phase 4), §4A implementation (Phase 4b), Q15 (Phase 4c).

---

## Phase 3 — Q10 (run at last) and Q7 (the recommendation)

**Run 2026-08-28.** Same refs. `accumulate-core` **not modified**
(`git status --porcelain` empty); Q10 ran against a `git archive` copy of
`origin/main`. Probe: `docs/l4/phase3_probe/`.

**Gate 3 verdict: PASSED.** A recommendation, with every rejected option and the
reason it lost. And **Q10 has now been run** — it was the largest hole in the
evidence after Phase 2, and it confirms Phase 1's central claim by construction
rather than by code reading.

### 3.1 Q10 — the path that had never run. RUN. Phase 1 was right.

A real validator-set change, executed end to end on `origin/main`'s executor
(`ExecutorVersionV2Vandenberg`, the version MainNet runs), then the decisive
question:

```
BEFORE: 3 validators, NetworkDefinition.Version=0, main chain height=1
BEFORE: state leaf   9f87ee782870e0c9
BEFORE: BPT root     fe23c46e1212d0c1  (receipt VALIDATES)

  -- WriteData to acc://dn.acme/network, signed by the operator page, SUCCEEDS --

AFTER : 4 validators, NetworkDefinition.Version=1, main chain height=2
AFTER : state leaf   5600b391edab5fd7
AFTER : BPT root     a2081164441ff857  (receipt VALIDATES: true)

=== Q10: can the PREVIOUS validator set still be proven? ===
  receipt.start is now  5600b391edab5fd7 (the NEW state)
  the genesis leaf was  9f87ee782870e0c9
  -> StateReceipt() returns a proof of the CURRENT set ONLY.
  -> There is no API taking a height or a historical root.
  -> The genesis validator set is now UNPROVABLE via the public API.

  ASYMMETRY: anchor(directory)-bpt retains 6 historical BPT roots,
             including the one the genesis set was provable against.
             The ROOT survives; the MEMBERSHIP PATH to it does not.
```

**Phase 1 §1.1 predicted exactly this from reading `bpt_receipt.go:17`. It is now
demonstrated.** The moment the set changes, the previous set becomes unprovable
through the public API, while the root it was provable against remains on chain
forever. That asymmetry is the entire content of AIP A.

**Three further results from the same run:**

1. **The update entry IS by-hash resolvable** — `by-hash lookup -> index 1`,
   where the genesis entry at index 0 is not. This confirms §9.1.4's distinction
   empirically: genesis entries never get an `ElementIndex`; runtime entries,
   written through `merkle.Chain.AddEntry`, always do. The update receipt is
   1 step and validates.

2. **`NetworkUpdateProof` measured at last — the number Phase 2 could not get**,
   because on the live networks every window has `updates = 0`:

   ```
   Transaction (WriteData + full NetworkDefinition) :  518 B
   Receipt                                          :  142 B
   -> NetworkUpdateProof ~= 660 B  (4-validator set)
   ```

   Note it carries the **entire** `NetworkDefinition`, not a delta
   (`updateNetworkDefinition` in `test/e2e/validators_test.go:125-136` calls
   `values.FormatNetwork()`), so it scales with validator count, not with the
   size of the change. §9.2.1's spine totals are therefore unchanged for the
   history to date, and grow by ~660 B–2 KB per future change — negligible.

3. **A validator-set change is a real governance action.** On a 3x3 network the
   same transaction stays **pending**, not failed: the operator page threshold
   (`OperatorAcceptThreshold` 1/3 over 9 operators = 3) was not met by one
   signature. Q2's claim that this is an ordinary, authorised, receipted
   transaction is confirmed from the submitting side as well as the executing
   side.

### 3.2 Q7 — the options, evaluated against everything measured

| | Option | Verdict |
|---|---|---|
| (a) | Make the genesis network-definition entry receipt-provable | **REJECTED** |
| (b) | Publish a canonical genesis anchor via `SnapshotService` | **REJECTED as stated** |
| (c) | Point query: "validator set at height H, with proof" | **RECOMMENDED — AIP A** |
| (d) | Guarantee retention of historical anchor quorum signatures | **ACCEPTED as a secondary ask in AIP A** |
| (e) | Promote `MajorHeaderRange` + `MinorRootRange` to public v3 | **DEFERRED — AIP B** |

**(a) REJECTED — it is already true, and it would not help.** The genesis entry
*is* receipt-provable today, by index, and the receipt validates offline on both
live networks (§9.0.2). Proposing it would be proposing something that already
works. Worse, it would not close anything: `SystemGenesis` is an empty struct
(`protocol/system.yml:98-99`), so a receipt over it proves that a **contentless**
transaction was anchored. The by-hash failure that motivated §2A.4 is guaranteed
for genesis entries on any node (§9.1.4, reproduced from a locally built
genesis), so there is no node bug to fix either.

**(b) REJECTED as stated — it has never run in production.** `SnapshotService`
is defined in the public API on both branches (`pkg/api/v3/api.go:82-84`) but
neither live network advertises it, and `list-snapshots` fails with
`dial …/acc-svc/snapshot:directory: notFound` (§9.1.5). Proposing "use the
existing service" would be proposing an unrun code path. Two further problems
even if it were enabled: a snapshot is a whole-state blob, not a per-proof
artifact, so it cannot ride inside a 2.4 KB proof; and it would still need
out-of-band distribution to be a trust root at all (rule 6). **It may be asked
for as a supporting measure — a published, hash-pinned genesis snapshot is a
good thing — but it cannot be the mechanism.**

**(c) RECOMMENDED.** It is the only option that is simultaneously *sufficient*,
*cheap*, and *decomposable to one missing primitive*:

- **Sufficient.** Phase 1 §1.1 measured that the validator set is already
  provable offline: the BPT leaf is derivable from the returned account state
  (`observer_prod.go:31`), the membership path validates, and the state parses
  to the real `NetworkDefinition`. Nothing about the *proof format* is missing.
- **Cheap.** ~2,364 B on Kermit, 2.4–7.5 KB at mainnet BPT depth by validator
  count (§9.2.2) — small enough to embed in every CERTEN proof, against
  640 KB–3 MB per verifier for (e).
- **One primitive.** Everything is already served *except* a membership path
  against a **historical** BPT root. `BPT.GetReceipt` is documented
  "for the current state" (`pkg/database/bpt/bpt_receipt.go:17`), the BPT is
  stored under a single `Root` and mutated in place, and `ReceiptOptions.ForHeight`
  is honoured only on the chain-entry path (`querier.go:517-519`), never on the
  account path (`querier.go:339-346`).

**This is not inventing protocol (rule 4).** Accumulate already has the account
state receipt, the retained historical BPT root chain (`anchor(<part>)-bpt`,
173,378 entries on Kermit), the anchoring, and the quorum signatures over it.
The ask is to make an **existing proof** available against an **existing,
already-retained root**. What that costs the implementer is retention of, or
re-derivation of, historical BPT nodes — an archival-mode question, not a new
proof system. **The AIP must present it that way and must not pretend the
retention cost is free**; Phase 4/5 should ask the maintainers which of the two
(retain vs replay-on-demand) they prefer, because that is their call, not ours.

**(d) ACCEPTED as a secondary ask.** Measured retained today — Kermit's
`dn.acme/anchors` main[1] still carries its `blockAnchor` signature 355,574
entries later, and no pruning function exists in `internal/database/` or the v2
executor (§9.1.7). But *absence of pruning is not a guarantee*. A pruned or
state-synced node, or a future release that adds pruning, silently breaks proof
construction for old transactions. Stating retention as a commitment costs
nothing today and is not redundant.

**(e) DEFERRED to AIP B, and it is a genuine fallback, not a token one.** It
works — `verifyQuorum` is a complete induction (`spine.go:189-204`) and Q6 shows
the primitive survives DAG-BFT untouched (§9.2.3). It is affordable — under
10 MB in every scenario measured, ~1.1 MB/year of growth (§9.2.1). AIP B should
say so with those numbers rather than hedging. But it loses for AIP A on four
counts: it exists only on `dagbft-integration`; it is a *walk*, not a query
(`spine.go:118-123` refuses any walk not starting at genesis); it costs ~300x
more bandwidth; and its base case is a pinned genesis snapshot that
**no live network serves** (§9.1.5) — so it inherits (b)'s problem.

### 3.3 The recommendation, in one line

> **AIP A: (c) + (d).** Make the account-state (BPT membership) proof available
> against a historical BPT root, and commit to retaining the historical anchor
> quorum signatures. **AIP B: (e)**, the #4058 spine promoted to public v3,
> marked as depending on #4058 and on DAG-BFT.

### 3.4 What CERTEN can do TODAY, with no AIP at all — and its limit

This is the most consequential thing Phase 3 found, and it changes what AIP A is
*for*.

**The account state hash commits to the account's own chain contents.**
`observer_prod.go:63-80`, `hashChains`, hashes each chain's
`CurrentState().Anchor()` — the merkle DAG root, which commits to every entry
and to the count. So a verifier who has proven the state of
`acc://dn.acme/network` at BPT root R has *also* proven, at that same root, the
exact contents and height of that account's main chain.

Therefore, **while the main chain height is 1**, a single present-day state proof
establishes:

> the validator set is X, **and** this account has exactly one entry — the
> genesis entry — so the set has never changed, so X *is* the genesis set.

That is the induction base case and the entire timeline, in one 2.4 KB artifact,
**obtainable today, from an unmodified public node, verifiable offline.** It
follows the spec's own "record, don't re-derive" pattern
(`CERTEN_GOVERANCE_PROOF_SPEC.MD` §1.2.2) and the beside-the-hash convention of
`pkg/proof/timing_evidence.go`.

**Mechanically it is checkable offline**: the server returns the account state
and, separately, the chain list with each chain's count and merkle state; the
verifier recomputes the `hashChains` component and checks it against the
corresponding sibling in the state receipt's path. If it matches, the chain
heights are *bound*, not asserted.

**Stated honestly, three limits, none of which the AIP may gloss:**

1. **It is designed and cited, not run.** I verified the mechanism in code and
   measured every component, but I did **not** implement or execute this
   end-to-end. Phase 4 owns the verifier contract; do not report it as working.
2. **It only helps proofs built while the claim is still true.** It captures the
   set *at build time*. For a transaction whose proof was never built then — and
   for all 429 existing proofs — it does nothing. Historical coverage still needs
   (c).
3. **It expires at the first validator-set change.** Q10 shows exactly what
   happens: once height goes to 2, "height is 1, therefore never changed" is
   false, and proving what the set *was* needs the historical membership path.
   After that, CERTEN can still chain forward — prove state at R committing to
   height H, plus receipts for entries 0..H-1 showing each change (~660 B each,
   §3.1) — but the *base case* is gone, because the state at the older roots is
   unprovable.

So the split is clean, and it should shape both documents:

| | Closes | Needs |
|---|---|---|
| **CERTEN-side, today** | the §1 gap for **newly built** proofs, while the set is unchanged | nothing from Accumulate |
| **AIP A (c)+(d)** | historical proofs, and everything after the first set change | Accumulate |

**AIP A is therefore not urgent in the sense of "CERTEN is blocked" — it is
urgent in the sense of "the window closes at the first validator-set change,
and after that the genesis set is unprovable forever."** That is a much stronger
and more honest motivation than "we cannot prove anything today", and it is what
the Motivation section should say.

### 3.5 What this does NOT solve — carried forward to Phase 6

- **The incarnation boundary is untouched.** (c) proves a set within an
  incarnation. It says nothing across a restart (§9.1.2, §9.1.3), and
  `SystemGenesis` being an empty struct means nothing can. Every artifact must
  carry the incarnation identity and a verdict distinct from `verified`.
- **A stored proof still cannot tell it is on a dead chain** (§9.1.3). That is a
  CERTEN defect, fixable by CERTEN, and it is independent of both AIPs.
- **Kourou** (§9.2.4) will let anchors be authorized with no validator
  signatures. Neither AIP addresses it; the verifier contract must.
- **(c) makes the set *derivable*; it does not make it *legitimate*.** A verifier
  can prove "this set was the network's recorded validator set at height H". Who
  was entitled to put it there is the operator-book question, one level further
  out, and neither AIP touches it. Say so.

### 3.6 Still open after Phase 3

- **§9.0.8** — `mainnet.accumulatenetwork.io` identity, still unresolved, still
  blocking any published "mainnet" number.
- Q8 (Phase 4), §4A implementation (Phase 4b), Q15 (Phase 4c), the AIPs
  (Phase 5), adversarial review (Phase 6).
- The retention-versus-replay question inside (c) is deliberately left to the
  maintainers (§3.2).

---

## Phase 4 — Q8, the CERTEN-side verifier contract

**Run 2026-08-28.** Same refs. `accumulate-core` **not modified**. Sizing probe:
`docs/l4/phase4_probe/`, run against both live networks.

**Gate 4 verdict: PASSED.** The change is written as a change to
`layer4_verify.go`'s contract: what it accepts, what it refuses, what it names,
how the artifact grows (measured), and why govRoot does not move.

**Nothing in this phase was implemented.** It is a specification. Where it says
"the verifier checks X", that is the proposed contract, not shipped behaviour.

### 4.1 The one-line statement of the change

> Today `Layer4.ValidatorSet` is **asserted** — `layer4.go:255` copies it from a
> build-time `network-status` RPC. The change makes it **derived**: the leg
> carries a `ValidatorSetProof` that reconstructs the same set from chain state
> and binds it to the same quorum-signed `StateTreeAnchor` the leg already
> proves. `VerifyOffline` then checks that the asserted set **equals** the
> derived one, and refuses the leg if it does not.

That single equality is the §1 gap closing. A forged proof carrying a fabricated
validator set can still make its own signatures verify — but it can no longer
make the fabricated set hash to a leaf inside a BPT root that a real quorum
signed.

### 4.2 What the artifact gains

One new structure, carried **once per proof** — not once per leg. Both the BVN
and DN legs draw their validator set from the same `acc://dn.acme/network`
account, so one proof serves both.

```go
// ValidatorSetProof derives Layer4.ValidatorSet from chain state instead of
// asserting it. Every field is checked; nothing here is trusted on assertion.
type ValidatorSetProof struct {
    // Incarnation is the genesis root anchor of the chain this proof is about
    // (§9.1.2): anchor(directory)-root[0]. Without it a proof cannot say which
    // chain it belongs to, and a restart makes it silently meaningless (§9.1.3).
    Incarnation string `json:"incarnation"` // hex32

    // AccountState is the canonical binary encoding of acc://dn.acme/network's
    // DataAccount, hex. sha256(AccountState) IS the BPT leaf - the "simple hash
    // of the main state" at accumulate-core internal/database/observer_prod.go:31.
    AccountState string `json:"accountState"`

    // StateReceipt proves that leaf into a BPT root
    // (internal/database/bpt_account.go:66-88, Account.StateReceipt).
    StateReceipt Receipt `json:"stateReceipt"`

    // Chains lets the verifier RECOMPUTE the hashChains component
    // (observer_prod.go:63-80) and check it against the corresponding sibling
    // in StateReceipt. That is what BINDS MainChainHeight instead of asserting
    // it - see §9.3.4. Without this the height is just a number in a struct.
    Chains []ChainRoot `json:"chains"`

    // MainChainHeight is acc://dn.acme/network's main chain height at that root.
    // 1 means only the genesis entry exists, so the set has NEVER changed, so
    // this IS the genesis set OF THIS INCARNATION.
    MainChainHeight uint64 `json:"mainChainHeight"`

    // Updates carries one entry per validator-set change when height > 1.
    // Measured at ~660 B each (§9.3.1). Empty today on both live networks.
    Updates []NetworkUpdateEvidence `json:"updates,omitempty"`
}

type ChainRoot struct {
    Name   string `json:"name"`
    Count  uint64 `json:"count"`
    Anchor string `json:"anchor"` // hex32, the chain's merkle DAG root
}
```

`Receipt` is the existing type the other layers already use — no new receipt
format is introduced.

### 4.3 What `VerifyOffline` adds — steps 10 through 16

The existing steps 1–9 are unchanged. Appended, in order, each failing closed:

```
10. If ValidatorSetProof is absent -> the leg is VALIDATOR_SET_ASSERTED.
    NOT an error. See §4.4 - every proof issued to date is in this state.

11. sha256(AccountState) == StateReceipt.Start.
    Refuse on mismatch: the state does not hash to the leaf being proven.

12. StateReceipt validates as a merkle path from Start to Anchor.
    Refuse on mismatch. (Same receipt verifier L1-L3 already use.)

13. Recompute the hashChains component from Chains and check it against the
    corresponding sibling in StateReceipt's path.
    Refuse on mismatch. THIS is what binds MainChainHeight and the chain
    contents; without step 13, step 16's base case is an assertion.

14. AccountState decodes to a DataAccount whose entry decodes to a
    NetworkDefinition; the validator set derived from it EQUALS
    Layer4.ValidatorSet, compared canonically (sorted by public key, with
    ActiveOn sorted).
    Refuse on mismatch. *** This is the step that closes the gap. ***

15. StateReceipt.Anchor == the StateTreeAnchor of a quorum-signed anchor in
    THIS proof - the Directory leg's, since dn.acme/network lives on the DN.
    Refuse on mismatch: an unbound BPT root proves nothing about who signed.

16. Base case / induction:
      MainChainHeight == 1 -> the set has never changed; the derived set is
                              this incarnation's genesis set. Done.
      MainChainHeight  > 1 -> require len(Updates) == MainChainHeight-1, each
                              receipt-proven into the same root, applied in
                              order, and the result must equal the derived set.
                              Refuse if any update is missing or does not apply.
```

Step 15 deserves emphasis because it is where the two halves meet. The DN leg
already proves `StateTreeAnchor` is what a validator quorum signed (steps 1–9).
Step 15 says the BPT root the validator set was proven into **is that same
anchor**. The chain is then: quorum signature → signed anchor → BPT root →
account leaf → `NetworkDefinition` → the validator set the signatures were
checked against. It closes on itself, offline.

### 4.4 What it refuses, what it names, and what it must never do

Rule 8's three-way discipline, applied. **A thing that could not be READ is not
a thing that REFUSED, and neither is a thing that was PROVEN WRONG.**

| Situation | Verdict | Exit | Meaning |
|---|---|---|---|
| All 16 steps pass, incarnation == live | `verified` | 0 | the full claim |
| `ValidatorSetProof` absent | **`validator_set_asserted`** | 3 | could-not-read. The quorum was checked; the *set* it was checked against is asserted. |
| `Incarnation` absent | **`incarnation_unknown`** | 3 | could-not-read. Cannot say which chain. |
| `Incarnation` != the live incarnation | **`foreign_incarnation`** | 3 | proven-different. Content and time may still hold via L5; validator legitimacy does not. |
| Steps 11–16 fail | `failed` | 1 | proven-wrong: tampering or corruption |

The three new names are modelled on `summary_only`
(`pkg/database/proof_artifact_types.go:72`) and reuse `proofverify`'s existing
exit-3 channel (`cmd/proofverify/main.go:53,184`), whose message already says
the right thing: *"Nothing about this proof is known to be wrong… what is
missing is the evidence needed to check it again."*

**Three things this contract must never do**, each of which is a defect this
project has already removed once:

1. **Never fail a proof for lacking a `ValidatorSetProof`.** All 429 stored
   proofs lack one. Turning step 10 into an error converts a capability limit
   into a governance rejection — the exact defect class §2B.4e names and that
   Phase 8 removed twice.
2. **Never let `validator_set_asserted` print as `verified`.** That is
   `timing_evidence.go`'s lesson verbatim: *"`summary_only` exists in this
   codebase precisely so a weaker claim cannot read as the stronger one."*
3. **Never treat "the network accepted this anchor" as "a quorum signed it."**
   After Kourou (§9.2.4) an anchor can be authorized by a collection proof with
   **zero** validator signatures. A leg built from such an anchor has no quorum
   to carry, and must land in a named state — `anchor_proof_authorized` — not
   in `failed`. This is the one contract item driven by a change that has not
   shipped yet, and it is cheap now and expensive later.

### 4.5 govRoot does NOT move — and where the commitment goes instead

**`L4LegSummary` is hashed into govRoot** (`healing_proof.go:160-176`; §2B.4c).
Widening it would move every govRoot ever signed. That is exactly the trap
`timing_evidence.go:31-45` documents:

> *"Struct layout IS the wire format, so widening ValidatedSignature — the
> obvious move — would move every govRoot ever signed. TestP6_CanonicalShapesUnchanged
> blocks it, correctly."*

**So `ValidatorSetProof` rides BESIDE the hashed summary**, on the
`GovernanceProof` wrapper, in a type not reachable from any canonical hash —
the same place and for the same reason as `SignatureTimingBasis` and
`GovReceiptEvidence`. The govRoot preimage is byte-identical with or without it.
`TestP6_CanonicalShapesUnchanged` must keep passing unmodified; if it fails, the
change is in the wrong place.

**The on-chain commitment is a separate matter and lives elsewhere.** §4A
decided the Accumulate validator-set root and the incarnation identity go in the
**anchor pre-exec message** — the signed preimage of the message CERTEN's own
quorum signs and the anchor contract verifies. That is not govRoot, so there is
no conflict. The relationship is:

```
anchor pre-exec message  commits  accumulateValidatorSetRoot + incarnation   (32+32 B on chain)
ValidatorSetProof        carries  the full expansion of that root            (~2 KB, off chain)
```

which satisfies §4A.5.1's requirement that the commitment be **offline-expandable**:
*"A committed root nobody can expand is decoration that looks like coverage."*

The root itself must be canonically encoded (§4A.5.2/4/5) and commit
**membership and threshold**, not just the signers — the missing denominator of
§2B.4c:

```
accumulateValidatorSetRoot =
    keccak256( "certen:accval:v1"                      domain, versioned
             , incarnation                             32 B (§9.1.2)
             , acceptThreshold.num, .denom             the DENOMINATOR
             , uint32(len(validators))                 length-prefixed
             , for each validator SORTED by publicKey:
                   publicKey(32) , uint32(len(activeOn)) , activeOn sorted )
```

Sorting is load-bearing for the same reason `healing_proof.go:168-176` gives for
`Signers`: two validators reading identical chain data must produce identical
bytes, or the result is an intermittent, unreproducible on-chain revert.

### 4.6 How the artifact grows — MEASURED, not estimated

Built as real JSON from live data (`docs/l4/phase4_probe`):

```
=== kermit ===                        === mainnet ===
leaf derivable            : true      leaf derivable            : true
BPT path steps            : 5         BPT path steps            : 17
main chain height         : 1         main chain height         : 1
  -> BASE CASE: set has NEVER changed   -> BASE CASE: set has NEVER changed
ValidatorSetProof compact : 1839 B    ValidatorSetProof compact : 2453 B
current stored proof      : 18784 B   current stored proof      : 18784 B
GROWTH (one per proof)    : +9.8%     GROWTH (one per proof)    : +13.1%
```

**+1.8–2.5 KB on an 18.8 KB proof: under 10% on Kermit, under 14% at mainnet BPT
depth.** Carried once per proof, not once per leg — both legs draw on the same
account, and duplicating it would double the cost for nothing (+19.6% / +26.1%).

Growth after the set starts changing: +~660 B per historical change (§9.3.1,
measured), since each `NetworkUpdateEvidence` carries the full
`NetworkDefinition` plus a receipt rather than a delta.

Note both live networks report `mainChainHeight = 1`, so **today the base case
needs no `Updates` at all** and the artifact is complete at 1.8–2.5 KB.

### 4.7 What the contract does NOT establish

Four things, each of which must be stated in the spec and in the AIP:

1. **It proves the set was *recorded*, not that it was *legitimate*.** Step 14
   proves the network's own `dn.acme/network` account held this set. Who was
   entitled to write it there is the operator-book question, one level further
   out, and this contract does not reach it (§9.3.5).
2. **It stops at the incarnation boundary.** `SystemGenesis` is an empty struct
   (§9.2B.4a), so nothing can carry a proof across a restart. `foreign_incarnation`
   is the honest verdict, and it is weaker than `verified` — never the same one.
3. **It only helps proofs built while the evidence is obtainable.** For the 429
   existing proofs, and for any historical transaction whose proof was not built
   at the time, the state at the old BPT root is unprovable (§9.3.1, run). That
   is what AIP A (c) is for. **Mark, never fabricate** — `proof_artifact_types.go:68-71`
   already says why: *"re-querying Accumulate returns today's validator set, not
   the one that signed."*
4. **L5 is still necessary and still not sufficient.** It proves existence and
   time on a chain that did not restart; it says nothing about validator
   legitimacy (§2B.4e). A `foreign_incarnation` proof with a valid L5 is a
   non-repudiable existence witness — a different, weaker claim, and it must
   report as one.

### 4.8 Implementation order, each step independently reviewable

1. Add `ValidatorSetProof`, `ChainRoot`, `NetworkUpdateEvidence` in a package
   **not reachable from any canonical hash**, beside `pkg/proof/timing_evidence.go`.
2. Add the builder side: fetch the account state + receipt + chain list at
   build time, alongside the existing `networkInfo()` call in `layer4.go:421`.
   `layer4.go:255` keeps setting `ValidatorSet` — the proof does not replace it,
   it *checks* it.
3. Add steps 10–16 to `VerifyOffline`, with step 10 returning the named state
   rather than an error.
4. Add the three named states to `VerificationStatus` and the exit-3 branch of
   `cmd/proofverify/main.go`.
5. Confirm `TestP6_CanonicalShapesUnchanged` still passes **unmodified**, and
   that a stored proof's govRoot is byte-identical before and after.
6. Only then: §4A's anchor-message field (Phase 4b), which commits the root the
   artifact now expands.

Steps 1–5 are CERTEN-only, need nothing from Accumulate, and close the gap for
newly built proofs while `mainChainHeight == 1` (§9.3.4).

### 4.9 Still open after Phase 4

- **§9.0.8** — `mainnet.accumulatenetwork.io` identity, still unresolved.
- Nothing here is implemented or run. Steps 10–16 are a specification; the
  measurements behind §4.6 are real, the verifier is not.
- Phase 4b (§4A implementation), Phase 4c (Q15), Phase 5 (the AIPs), Phase 6
  (adversarial review).

---

## Phase 4b — §4A implemented: the anchor-message commitment

**Run 2026-08-28.** `accumulate-core` **not modified** (`git status --porcelain`
empty). This is the first phase that writes code, and it lands in **two** repos:
`certen-contracts` (Solidity) and `independant_validator` (Go).

**Gate 4b verdict: PASSED for what a session can do.** The message shape is
defined, the canonical encoding is pinned, cross-language agreement is
**proven by test**, and all three active deployments are covered by one bumped
tag. **Nothing was deployed** — see §4b.8.

### 4b.1 The message, as built

Eight slots under a bumped domain tag. `CertenAnchorV8_2.sol::_verifyBLSProof`
and `contracts.ComputeEvmMessageHashV8_2_Pre` produce this identically:

```
keccak256(abi.encode(
    bytes32("certen:bls:v2:pre"),      // BUMPED - no V8.1 signature can replay
    uint256(DEPLOYMENT_CHAIN_ID),
    anchorId,
    anchor.executionCommitment,
    anchor.operationID,
    currentValidatorSetRoot,            // CERTEN's set    (V8.1)
    anchor.accumulateValidatorSetRoot,  // ACCUMULATE's set  (NEW)
    anchor.accumulateIncarnation        // which chain       (NEW)
))
```

Both validator states now sit side by side in one signed object, which is what
§4A.2 asked for and what V8.1 could not express.

**The Accumulate root, canonically encoded** (`certen:accval:v1`):

```
keccak256(
  "certen:accval:v1"                 // 16-byte domain tag
  || incarnation                      // 32 B
  || uint64BE(thresholdNumerator)     //  8 B   <- the missing denominator
  || uint64BE(thresholdDenominator)   //  8 B
  || uint32BE(len(validators))        //  4 B   length prefix
  || for each validator SORTED by publicKey ascending:
         publicKey                    // 32 B
      || uint32BE(len(activeOn))      //  4 B   length prefix
      || for each partition SORTED ascending:
             uint32BE(len(partition)) //  4 B   length prefix
          || partition                //  n B
)
```

Sorted, length-prefixed and domain-separated, per §4A.5.2. Every §4A.5
requirement is met: it is offline-expandable (the artifact carries the set —
Phase 4 §4.2), canonically encoded, carries the incarnation, commits
**threshold and membership** rather than only the signers, and is deliberately
versioned.

This is **not** an `abi.encode`. The contract never recomputes this root — it
cannot, having no access to Accumulate state — it only commits to it. The
encoding is therefore optimised for unambiguous re-derivation from an artifact
by an offline verifier, not for Solidity's decoder. Stated in the code so a
reader does not go looking for the on-chain mirror.

### 4b.2 Cross-language agreement — PROVEN, not asserted

The same fixed vectors are asserted on both sides. If either encoding drifts,
one of the two tests goes red:

```
Go   pkg/execution/contracts/v8_2_binding_test.go  TestV8_2_FixedVectors
Sol  evm/test/CertenAnchorV8_2Binding.t.sol        test_MessageHashMatchesGoBinding

accumulateValidatorSetRoot = 0074e2d6a7b1388c113c4f9f3621b3988d4aae715df060b395a181aaafced0f2
messageHash (v2:pre)       = 85d3623ce19d4453f9df1077e6d7b29c10892db6916289eecca246644f59cb2d
```

The vector's incarnation is Kermit's real genesis root anchor
(`e3f3119213a1…cf81`, measured live in §9.0.2/§9.1.2), so the test data is the
production shape rather than a placeholder.

```
Go   ok  pkg/execution/contracts   9 tests
Sol  Ran 5 tests ... 5 passed; 0 failed
```

Beyond the shared vector, the Go tests prove the properties the encoding claims:
order-independence (shuffled input, identical root), caller inputs not mutated,
**length prefixes actually disambiguate** (`{"BVN1","BVN2"}` vs `{"BVN1BVN2"}`
do not collide), the threshold is committed (2/3 and 1/3 differ), the
incarnation is committed (MainNet's and Kermit's genesis anchors differ), the
bumped tag is not decoration (V8.2 ≠ V6.1 for identical inputs), and every
unusable input is refused rather than silently encoded.

### 4b.3 A hazard §4A did not anticipate, and the real reason V7_2 exists

`CertenAccountV7._verifyAnchorUsable` destructures `anchorContract.anchors()`
**positionally**:

```solidity
(
    , , , , , , , , , , ,
    bool valid,          // position 12
    bool proofExecuted,  // position 13
    ,
) = anchorContract.anchors(proof.anchorId);
```

Had the two new fields been inserted anywhere above position 12 — the natural
place, next to `accumulateBlockHeight`, which is where an author would put them
— `valid` and `proofExecuted` would have shifted by two. The contract would
have kept compiling and started reading `governanceExecuted` and
`governanceLevel` as the verification flags. **An unverified anchor would have
read as verified**, silently, on a permanent record.

They are therefore **APPENDED at the end**, which changes the tuple arity from
15 to 17 and turns the hazard into a compile error. `test_AppendedFieldsDoNotShiftValidOrProofExecuted`
deploys a real V8.2, creates a real anchor and asserts `valid` is still #12,
`proofExecuted` still #13, and the two new fields round-trip at #16 and #17.

**This is the concrete reason `CertenAccountV7_2` is required.** §4A.4 listed it
without saying why, and a reasonable reader would conclude it was a cosmetic fix
for the stale `CertenAnchorV6_1` type name. It is not: V7 **cannot compile**
against V8.2, because the tuple it destructures changed width. The retype is a
consequence, not the motive.

### 4b.4 What was created

**`certen-contracts`** (all new files; no existing contract edited):

```
evm/src/core/CertenAnchorV8_2.sol          from CertenAnchorV8_1.sol
evm/src/account/CertenAccountV7_2.sol      from CertenAccountV7.sol
evm/src/account/CertenAccountFactoryV10.sol  from CertenAccountFactoryV9.sol
evm/test/CertenAnchorV8_2Binding.t.sol     new
```

**`independant_validator`** (commit `52c364d`):

```
pkg/execution/contracts/v8_2_binding.go       442 lines
pkg/execution/contracts/v8_2_binding_test.go  261 lines
pkg/consensus/v8_2_signing.go                 266 lines
```

The factory was **not** in §4A.4's list, and it is needed anyway: a factory
embeds `type(Account).creationCode` in its CREATE2 derivation, so
`CertenAccountFactoryV9` physically cannot deploy a V7_2. §4A.4a's "the factory
must be redeployed" therefore means a *new factory contract*, not a redeploy of
the existing one. Recording it here because §4A.4's scope list is otherwise
exact and a future reader will notice the extra file.

**Measured sizes** (`forge build`, EIP-170 limit 24,576 B):

```
CertenAnchorV8_1    22,431 B   headroom 2,145 B
CertenAnchorV8_2    22,839 B   headroom 1,737 B   (+408)
CertenAccountV7     12,975 B   headroom 11,601 B
CertenAccountV7_2   13,281 B   headroom 11,295 B  (+306)
```

Note V8_1 compiles to **exactly** the 22,431 bytes measured on chain in §9.0.4 —
an independent confirmation that the source tree matches all three deployed
contracts. V8.2's 1,737 B of headroom is real but not generous; a future feature
of any size will need to reckon with it.

### 4b.5 govRoot did NOT move

Required by the definition of done, and verified rather than assumed:

```
TestP6_GovRootInvariant_GoldenSlots   PASS   (unmodified)
TestP6_CanonicalShapesUnchanged       PASS   (unmodified)
TestP7_V1GovRootStillReproduces       PASS
```

`ComputeAccumulateGovRoot` is untouched and the V8.2 builder calls it unchanged.
The Accumulate set root travels in the **anchor message**, not in govRoot's
preimage — §4A.2's point, and §9.4.5's: govRoot would have been
cryptographically sufficient too, but the message is where the CERTEN quorum
explicitly attests to which Accumulate set it saw.

### 4b.6 Scope — no legacy chain was touched

Verified by inspecting both repos' change sets:

```
independant_validator  3 new files, none matching near|solana|aptos|sui|ton|cardano
certen-contracts       4 new files, all under evm/src/{core,account} and evm/test
```

`signV8_2PreExecBLS` **refuses** non-EVM targets rather than silently falling
back to the V6.1 path — a caller arriving with a NEAR or Solana intent has a
routing bug, and quietly signing the old message would hide it. It accepts only
`sepolia`, `base-sepolia` and `arbitrum-sepolia`; the inactive EVM testnets
(polygon-amoy, optimism-sepolia, moonbase-alpha, bsc-testnet, tron-shasta,
hedera) are refused with the rest.

The pre-existing modifications in `certen-contracts` (`tron/hardhat.config.js`,
`evm/package.json`, various untracked scratch files) were already in the working
tree and are **not** part of this work; they were deliberately left uncommitted.

### 4b.7 The honest weak point: where the incarnation comes from

`signV8_2PreExecBLS` reads the incarnation from the `ACCUMULATE_INCARNATION`
environment variable, and **fails closed** when it is unset, non-hex, wrong
length, or all zeroes.

That is not where it belongs. It should come from the L4 evidence — but it
cannot yet, because **nothing in an L4 leg identifies which chain it is about**
(§9.1.2, measured). The signed preimage is a `SequencedMessage` over a
`PartitionAnchor`, and every URL in it is a protocol constant identical across
MainNet, Kermit, and every incarnation of both. Until Phase 4's
`ValidatorSetProof` lands and carries the incarnation inside the artifact, the
value has to come from outside the proof.

Two consequences to carry forward, neither of them hidden:

1. **A misconfigured `ACCUMULATE_INCARNATION` produces a wrong-but-well-formed
   commitment.** The contract cannot detect it (it cannot validate the set), and
   an offline verifier would only catch it by comparing against a known-good
   value. This is a real operational hazard and the strongest argument for
   finishing Phase 4's artifact work before cutover.
2. The validator **set** does come from the proof — `Layer4DN.ValidatorSet` and
   `AcceptThreshold`, the full set rather than only the signers, which is the
   whole point. `BuildV8_2AccumulateSetInputs` is exported precisely so the EVM
   submission path reduces the same evidence the same way; a second independent
   reduction is exactly how two paths drift.

### 4b.8 What was NOT done, and must not be reported as done

- **Nothing was deployed.** No contract was pushed to sepolia, base-sepolia or
  arbitrum-sepolia. The atomicity rule (§4A.4a — all three together, one bumped
  tag) is a **deployment** requirement, and deployment is an irreversible,
  outward-facing action that needs explicit authorisation. It is the next
  operational step, not a completed one.
- **`signV8_2PreExecBLS` is not wired in.** `bft_integration.go:1221` still
  calls `signV6_1PreExecBLS`. The switch-over must happen together with the
  contract cutover, or validators would sign a message no deployed contract
  verifies. Left deliberately, and it is the single change that arms this work.
- **The EVM submission path is not updated.** `pkg/anchor/anchor_manager.go`
  still packs the 8-argument `createAnchorWithLegs`; V8.2's `createAnchor` and
  `createBatchAnchor` take ten. `BuildV8_2AccumulateSetInputs` is exported ready
  for it, but the call sites are unchanged.
- **`createAnchorWithLegs` was not extended.** V8.2 threads the two fields
  through `createAnchor` and `createBatchAnchor` — the paths that write an
  `Anchor` and therefore the paths `_verifyBLSProof` reads. The multi-leg path
  writes an `IntentAnchor` and has its own execution route. Extending it is
  additional work, and claiming it was covered would be false.
- **Phase 4's `ValidatorSetProof` is not implemented.** Without it the artifact
  cannot expand the committed root, and §4A.5.1 warns that "a committed root
  nobody can expand is decoration that looks like coverage." **Phase 4b commits
  the root; Phase 4's artifact work is what makes it mean something.** Neither
  half is useful alone.

### 4b.9 Still open after Phase 4b

- The five items in §4b.8, of which the artifact work and the coordinated
  three-network cutover are the load-bearing ones.
- **§9.0.8** — `mainnet.accumulatenetwork.io` identity, still unresolved.
- Phase 4c (Q15, the L5 workstream), Phase 5 (the AIPs), Phase 6 (adversarial
  review).

---

## Phase 4c — Q15, the L5 workstream as three separate deliverables

**Run 2026-08-28.** `accumulate-core` **not modified**. Measurements against the
production proof database on the fleet.

**Gate 4c verdict: PASSED.** The three deliverables are separated and reported
separately. One is measured as **impossible**, one is **already shipped** and
Q15's framing of it is stale, and one is specified. Phase 0's §0.5 correction is
itself corrected below.

### 4c.1 CORRECTION TO MY OWN PHASE 0 — §2B.3's "402" was right

§9.0.5 claimed the `summary_only` count is "392, not 402" and recorded §2B.3's
number as an error. **That was wrong.** The two numbers measure different
things, and both are correct:

```
proof_artifacts.verification_status = 'summary_only'              402   <- §2B.3's number
distinct proof_id with summary_only in governance_proof_levels    392   <- what §9.0.5 measured
overlap of the two sets                                           378
```

§2B.3 was referring to the artifact-level status, which is exactly 402. §9.0.5
queried a different column and reported the difference as a defect in the
runbook rather than in its own query. **§9.0.5 is withdrawn.**

The 24/14 split either side of the overlap is a real, separate observation — some
proofs carry the artifact status without a level marker and vice versa — but it
is a consistency question about CERTEN's own bookkeeping, not a correction to
§2B.3, and it should not be presented as one.

### 4c.2 Q15(ii) — BACKFILL. Measured: IMPOSSIBLE for all 419.

Q15 asked "can the batch tree be reconstructed for the historical 419 from
`batch_transactions`?" The answer is no, and not for the reason one would guess.
The tree data is abundant; the *linkage* is destroyed.

**The data is there:**

```
batch_transactions rows            70,621   (with merkle_path: 70,621)
anchor_batches rows                68,152   (with merkle_root:  68,152)
```

**The link is not:**

```
proofs missing L5                     419
  ..with batch_id set                   0     <- every one is NULL
  ..with blank accum_tx_hash            1
  ..joinable to batch_transactions
    by accumulate_tx_hash             415     (all 415 have a merkle_path)
  ..joining to an ANCHORED batch        0
```

Every one of the 419 has `proof_artifacts.batch_id IS NULL`, so the direct
reference is gone. The obvious fallback is to re-link by transaction hash. It
does not work:

```
proofs resolving to EXACTLY ONE batch_transactions row        0
proofs mapping to MORE THAN ONE distinct batch              415
maximum distinct batches for a single proof                   35
```

**Not one proof resolves to a unique batch.** The same `accumulate_tx_hash`
appears in up to 35 different batches, so "joinable" does not mean
"identifiable". Adding the proof's own recorded root as a disambiguator does not
rescue it:

```
resolve to exactly one batch via (tx hash + merkle_root)      0
still ambiguous (>1 batch shares that root and that tx)      40
resolve to NO batch at all                                  375
```

375 of the 415 carry a `merkle_root` that matches **no** batch they appear in,
and the remaining 40 are still ambiguous. There is no third key available.

> **Verdict: the backfill cannot be done for any of the 419. Mark them; never
> fabricate one.** Choosing among 35 candidate batches — or among 40 ambiguous
> ones — would manufacture a merkle path that looks exactly like a real one and
> is not. That is strictly worse than an absent one.

This is the same conclusion, for the same reason, that
`pkg/database/proof_artifact_types.go:68-71` already records for L4:

> *"The evidence for these proofs CANNOT be recovered: re-querying Accumulate
> returns today's validator set, not the one that signed. Marking is the only
> honest option — a synthesized quorum would be worse than an absent one."*

**A related data-model observation, offered as a lead not a conclusion.** Only
**10** of 68,152 `anchor_batches` rows carry an `anchor_tx_hash`, while **421**
of 429 `proof_artifacts` rows do. Anchoring is recorded on the proof, not on the
batch. That is why "joining to an anchored batch" returns 0 even though the
proofs plainly were anchored. It does not change the verdict — the ambiguity
above is fatal on its own — but it is the likely reason the linkage was never
maintained, and it is worth fixing before the same gap reopens on new proofs.

### 4c.3 Q15(i) — ERROR HANDLING. Already shipped on the verify side; Q15's framing is stale.

Q15(i) asks for "a distinct named state modelled on `summary_only` — never a
silent pass, never a governance rejection." **`cmd/proofverify/main.go:280-321`
already implements exactly that**, with the three-way discipline intact:

| Outcome | Exit | What it prints |
|---|---|---|
| L1–L5 verified | 0 | plus an explicit note that L5 is *not* verified offline, and that nothing in the proof establishes validator-set legitimacy |
| `ErrNoLayer5` | 3 | `SUMMARY-ONLY (L5)` — *"L1–L4 verified… Nothing about it is known to be wrong."* |
| binding present, leaf does not recompute | 1 | `FAILED (L5)` — *"This proof is not in the batch it claims to be in."* |

The code comment says why, and it is the right reason: *"a DISTINCT message, not
the L1-L4 one: 'L1-L4 verified, L5 absent' is its own state and an operator has
to be able to tell it from a proof whose quorum evidence is missing."*

**So Q15(i) should be re-scoped, not built.** Two real gaps remain, both on the
*build* side rather than the verify side:

1. **The reason is not recorded.** `persistLayer5`
   (`pkg/execution/layer5_rows.go:288-300`) logs and returns on both failure
   paths. Downstream, "no L5 row" conflates three different situations that an
   operator needs to tell apart:
   - the proof **predates** the feature (all 419 historical ones),
   - anchoring was attempted and **could not be observed** (a capability limit —
     chain outage, gas, RPC timeout),
   - `BuildLayer5` **errored** on data it did have.

   The first is permanent and expected; the second is transient and should be
   retried; the third is a bug. Today they are indistinguishable in storage. The
   fix is a recorded reason beside the absent row — not a new verdict, since the
   verdict is already right.

2. **`failed` is used in production but is not a declared constant.**
   `pkg/database/proof_artifact_types.go` declares only
   `VerificationStatusVerified` and `VerificationStatusSummaryOnly`, yet
   production holds:

   ```
   summary_only 402 | verified 12 | failed 9 | NULL 6
   ```

   Nine rows carry a status the type system does not know about, and six carry
   none at all. That is a small defect, but it is in exactly the vocabulary this
   whole workstream depends on being unambiguous.

**And the rule that must not be broken**, restated because it is the one that
bites: a missing L5 must never make a proof invalid. If it did, an anchoring
outage would become a governance-proof failure — the capability-limit-as-
governance-rejection defect this project has removed twice. The current code
gets this right; any change to it must keep getting it right.

### 4c.4 Q15(iii) — THE EXTENSION. Specified.

L5 today proves **existence and time**: *this proof, with this content, existed
no later than block B on chain C at time T*. It says nothing about validator-set
legitimacy, and `layer5.go:225` says so inside the artifact.

The extension carries what Phase 4 and Phase 4b built:

```go
// Beside the hashed summary, never inside it - the timing_evidence.go pattern.
type Layer5AccumulateBinding struct {
    // AccumulateValidatorSetRoot is now COMMITTED ON CHAIN by CertenAnchorV8_2's
    // pre-exec message (§9.4b.1). L5 carries it so a reader of the artifact can
    // see what the anchor transaction committed to without re-deriving it.
    AccumulateValidatorSetRoot string `json:"accumulateValidatorSetRoot"`

    // Incarnation is which Accumulate chain. Without it a permanent on-chain
    // record cannot say what it refers to (§9.1.2), and a stored proof cannot
    // tell it is on a dead chain (§9.1.3).
    Incarnation string `json:"incarnation"`

    // ValidatorSetProof is the EXPANSION of the committed root - the account
    // state, the BPT membership path, the chain roots, the height (§9.4.2).
    // Without it the on-chain commitment is, in §4A.5.1's words, "decoration
    // that looks like coverage".
    ValidatorSetProof *ValidatorSetProof `json:"validatorSetProof,omitempty"`
}
```

Three properties this must have, each inherited from a measured finding:

1. **It rides beside govRoot, not inside it** — `timing_evidence.go:31-45`.
   Phase 4b already proved govRoot does not move; the extension must not
   undo that.
2. **It is mandatory to RECORD, never mandatory to VERIFY** (§2B.4e). A proof
   lacking it lands in `validator_set_asserted` (§9.4.4), not in `failed`.
3. **It does not upgrade L5's claim.** Even with the Accumulate set attached, an
   external anchor still proves existence and time. Across an incarnation
   boundary it becomes the *only* surviving link (§2B.4b) — and that is a
   **non-repudiable existence and time witness**, a different and weaker claim
   than a within-incarnation governance proof. It must never report the same
   verdict.

**And the sequencing matters.** Phase 4b put the commitment on chain; the
expansion lives here. Shipping 4b without this leaves a root nobody can expand.
Shipping this without 4b leaves an expansion nothing commits to. **Neither half
is useful alone**, and the cutover plan has to move both.

### 4c.5 What Phase 4c changes about the deliverable

- **Q15(ii) is closed as impossible**, with numbers. The AIPs and the spec should
  say the 419 are permanently `summary_only` for L5 and say why — not "backfill
  pending".
- **Q15(i) shrinks to two small build-side fixes**, because the verify side is
  already correct. An AIP or plan that describes it as unbuilt would be wrong.
- **Q15(iii) is the load-bearing half of Phase 4b** and must ship with it.

### 4c.6 Still open after Phase 4c

- The five deployment items from §9.4b.8 — nothing is deployed or wired in.
- **§9.0.8** — `mainnet.accumulatenetwork.io` identity, still unresolved.
- Phase 5 (the AIPs), Phase 6 (adversarial review).
