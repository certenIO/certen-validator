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
   less severe reason.
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

**Q6 — DAG-BFT survival.** Under DAG-BFT, does the "quorum signature over a DN
self-anchor" primitive survive? `docs/proof/DAGBFT_MIGRATION_ANALYSIS.md` in the
CERTEN repo already flags that **StateHash is excluded from the certificate
quorum** — determine whether that breaks the spine's quorum check.

**Q7 — Minimal public surface, ON MAIN.** What is the smallest public API that
closes the gap **for the network running today**? Candidates, to be evaluated not
assumed:
  - (a) make the genesis network-definition entry receipt-provable (may be a
        query-shape fix rather than new protocol — see §2A.4)
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

**Q14 — DECIDED, NOT OPEN: the commitment goes in the ANCHOR PRE-EXEC MESSAGE.**

Decision taken 2026-08-28 by the maintainer. Do not re-litigate it; implement
it. The remaining work is *how*, not *whether*. See §4A for the full rationale,
the honest limits, and the scope.

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

**Q10 — Exercise the path that has never run.** The validator set has never
changed on mainnet or Kermit (§2A.3), so the update-proof path has zero
production history. Simulate a change (devnet, simulator, or
`internal/core/execute` tests) and prove it end to end before claiming the
timeline is provable. Phase 8's record: five defects, all found only by running.

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

### 4A.4 Scope — 8 chain families, not one

The pre-exec message is constructed independently per chain family. **Every one
must change together, or a proof signed for one chain will not verify on
another** — and a partial rollout is the mixed-fleet hazard from `PHASE8_RUNBOOK`
rule 15, one layer out:

```
pkg/execution/contracts/     v6_1_binding.go          EVM
                             v6_1_binding_near.go     NEAR
                             v6_1_binding_solana.go   Solana
                             v6_1_binding_aptos.go    Aptos
                             v6_1_binding_sui.go      Sui
                             v6_1_binding_ton.go      TON
                             v6_1_binding_cardano.go  Cardano
pkg/consensus/v6_1_signing.go   signV6_1PreExecBLS{,Near,Solana,Aptos,Sui,Ton,Cardano}
certen-contracts/               evm/src/core/CertenAnchorV8_1.sol, aptos-cli/,
                                cardano/, cosmwasm/, + per-chain programs
```

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
| 4b | Implement §4A — the anchor-message commitment, all 8 chain families | Message shape defined, canonical encoding pinned, every family updated together |
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
