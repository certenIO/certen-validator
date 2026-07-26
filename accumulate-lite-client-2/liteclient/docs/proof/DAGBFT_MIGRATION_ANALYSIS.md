# Proof-System Migration Analysis: CometBFT → DAG-BFT (Bullshark)

**Status:** Analysis / pre-implementation. Investigated 2026-06-05 against the Accumulate
`dagbft-integration` branch (`gitlab.com/accumulatenetwork/accumulate`).

**Scope:** What must change in Certen's two working proof systems —
governance **G0–G2** (`proof/consolidated_governance-proof`) and Merkle **L1–L4**
(`proof/working-proof_do_not_edit`) — to achieve a "perfect" (fully trustless) proof system
when Accumulate replaces CometBFT consensus with its DAG-BFT (Bullshark) engine.

> ✅ **Source-verified 2026-06-06** against a full clone of `dagbft-integration` @ commit `8fc49879`
> (`C:\Accumulate_Stuff\accumulate-clone-DAG_BFR-Exploration`). Every byte layout, the quorum rule, the
> commit rule, and the StateHash binding below were read line-by-line in the checked-out tree. See
> **§10 Source verification** for exact file:line citations and two findings that the earlier web-fetch
> pass could not resolve.

---

## 0. TL;DR

- **5 of the 7 proof layers are consensus-agnostic and need ~zero change**: G0, G1, G2, L1, L2.
  They run on Accumulate's *application layer* (receipts, BPT/anchor Merkle, key-page Ed25519
  governance), which is unaffected by swapping the consensus engine.
- **Only L3–L4 are CometBFT-coupled** and require a real (but bounded) rewrite to Bullshark.
- **In steady state, L3 over Bullshark is *simpler* than CometBFT** (fixed-width SignBytes, explicit
  stake/quorum, recomputable leader) — EXCEPT for one genuine new gap and one new obligation:
  1. 🚩 **StateHash is NOT bound by the certificate quorum** (the post-execution state root is
     excluded from the signed header digest). This is the DAG-BFT analog of today's
     `L4ConsensusProofH=0` gap and is the #1 design decision.
  2. **Finality is a DAG commit rule** (leader/anchor + causal ordering), not a single ≥2/3 vote.

---

## 1. Branch / release context

- Release integration target: **`main`** (8 open MRs target it). Freshest tested code physically lives
  on **`bootstrap-v3-merge-1.4.4`** = `main` + 65 commits. Latest stable tag `v1.4.4.1` (2026-05-20).
- **CometBFT is being actively removed**: `issue-3910-remove-cometbft` → `dagbft-integration`; plus
  `feature/proof-service-implementation` commits "Remove CometBFT snapshot commands for DAG-BFT (#3904)"
  and "Comment out CometBFT consensus service code (#3903)" (2026-04-13).
- Prior proof-API work (reference scaffold only — stale Aug 2025, CometBFT-based, v1.5.0 line):
  **`3658-cryptographic-proof-api`** (ConsensusProof/ValidatorSignature/ValidatorSet record types,
  validator-transition tracking, L3 sig validation, self-rated "90%, L4 pending").
- `feature/proof-service-implementation` is **cross-partition receipt proofs**, NOT consensus exposure —
  not the L3/L4 surface.

---

## 2. Consensus-coupling map (the core finding)

| Layer | Proves | Depends on | DAG-BFT impact |
|---|---|---|---|
| **G0** | Inclusion & finality of a chain entry | Accumulate **receipt** (`start→anchor`, `localBlock`=MBI); finality = anchored into a major block | **None** — app-layer. Confirm receipt RPC + major-block anchoring exist under Bullshark |
| **G1** | Governance correctness (KPSW-EXEC) | **Key-page** state machine (genesis→`updateKeyPage`) + **Ed25519** sigs + M-of-N threshold + timing (`localBlock ≤ EXEC_MBI`) | **None** — Accumulate governance, not consensus validators. **Zero change** |
| **G2** | Outcome binding | Canonical tx-hash recompute + effect/receipt/witness binding | **None** |
| **L1** | Account → BVN BPT root | BPT Merkle receipt, `SHA-256(l‖r)` | **None** — confirm BPT preserved in DAG-BFT executor |
| **L2** | BPT → DN state-tree anchor | BVN→DN anchoring Merkle | **None** — confirm anchoring preserved |
| **L3** | Anchor signed by ≥2/3 validators | **CometBFT** `/commit`, `Header.AppHash`, CanonicalVote precommits | **Full rewrite** → Bullshark certificate + StateHashMessage |
| **L4** | Validator set chains to genesis | **CometBFT** `ValidatorsHash`/`NextValidatorsHash`, ABCI updates | **Full rewrite** → epoch/committee lineage |

**Why G0–G2 / L1–L2 are safe:** none of them ever read CometBFT. G0–G2 verify Accumulate receipts +
key-page Ed25519 governance (application objects). L1–L2 verify the BPT/anchor Merkle structure. As long
as the DAG-BFT executor still produces the same BPT, anchoring, receipts, and major blocks (and exposes
them via the same RPC shapes), these five layers are untouched. **The only validation work for them is a
regression check that the receipt / BPT / anchor RPC responses are byte-identical under the new executor.**

---

## 3. DAG-BFT (Bullshark) primitives — ground truth

From `pkg/consensus/types` and `pkg/consensus/bullshark` on `dagbft-integration`:

### 3.1 `Header` (`types/header.go`)
```go
type Header struct {
    Author    ed25519.PublicKey
    Round     Round
    Epoch     uint64
    Payload   map[BatchDigest]WorkerID
    Parents   []CertificateDigest
    Signature []byte
    // ... digest cache
}
```
`Digest()` = SHA-256 over `marshalForDigest()` = **Author(32) ‖ Round(8) ‖ Epoch(8) ‖ Payload(sorted by
digest) ‖ Parents(sorted by digest)**. 🚩 **No StateHash / state root / app_hash field, and it is NOT in
the digest.**

### 3.2 `Certificate` (`types/certificate.go`)
```go
type Certificate struct {
    Header            Header
    Signatures        [][]byte   // ed25519, from validators
    SignedAuthorities []uint16   // indices of validators who signed
    StateHash         StateHash  // state after executing this cert's txns (SIBLING of Header)
}
```
Signatures verify over **`headerDigest(32) ‖ round(8) ‖ epoch(8)`** (big-endian) — i.e. the certificate
quorum attests **availability/ordering of the DAG vertex, NOT the StateHash.**

### 3.3 `Committee` (`types/committee.go`)
```go
type ValidatorInfo struct { PublicKey ed25519.PublicKey; Stake <weight> }
type Committee struct { /* validators */ Epoch uint64 }
```
- **Stake-weighted** (not equal weight).
- `QuorumThreshold()` = `2*totalStake/3 + 1` (2f+1).
- Epoch transitions: `UpdateValidators()` (increments epoch), `DiffWith()`, `ValidatorUpdate{add|remove|stake}`.
- ⚠️ **No committee hash/digest method present** in the excerpt — a canonical committee digest will likely
  need to be added (the L4 lineage analog of `ValidatorsHash`).

### 3.4 `StateHashMessage` (`types/state_verification.go`)
```go
type StateHashMessage struct { Round; Epoch; BlockIndex; StateHash; Author; Signature }
```
- Signs **`Round(8) ‖ Epoch(8) ‖ BlockIndex(8) ‖ StateHash(32)`** = **56 bytes**, big-endian, ed25519
  (`ed25519.Verify(Author, content, Signature)`). Author pubkey is NOT in the signed bytes.
- Described in-code as **state-hash gossip / divergence detection** — i.e. validators announce their
  computed state root; it is **not** (as found) a quorum-committed consensus certificate.

### 3.5 Signer (`types/signer.go`)
- `Signer` iface; `ADISigner` (validator id = ADI URL root, e.g. `acc://validator-1.acme`) and
  `RawKeySigner` (id = hex pubkey). ed25519, signs raw data (digest constructed by caller).

### 3.6 Commit rule (`bullshark/ordering.go`, `bullshark/leader.go`)
- **Leader/anchor election is deterministic & recomputable**: stake-weighted, seeded by `SHA256(round)`
  (`electLeader(round)`, `ComputeLeaderSeed(round)`). A light client CAN recompute the legitimate leader
  for a round from `Committee + round` alone.
- **Commit threshold:** a leader/anchor certificate commits when referenced (directly/transitively) by
  **f+1 stake** of the next round (Bullshark validity threshold). Safety holds because every supporting
  certificate already carries 2f+1 availability sigs.
- **Ordering:** `commitLeaderChain` → `orderDag` takes the anchor's causal history (ancestors from
  `lastCommitRound+1` to leader round), dedups already-committed, sorts deterministically by **(round asc,
  then author)**, emits a **linear `[]ConsensusOutput`**. Execution of that linear sequence yields the
  `StateHash` at each `BlockIndex`.

---

## 4. L3 rewrite — CometBFT → Bullshark

### 4.1 Primitive mapping
| CometBFT (current L3 spec) | Bullshark |
|---|---|
| `Header.AppHash` | `Certificate.StateHash` (but see §4.3 — not quorum-bound) |
| `/commit` precommits | `Certificate.Signatures` + `SignedAuthorities` (ed25519) |
| `CanonicalVote` SignBytes (protobuf + uvarint len-prefix + PartSetHeader + per-vote BFT-time) | **fixed `headerDigest(32) ‖ round(8) ‖ epoch(8)`**, big-endian. No protobuf, no PartSetHeader, no timestamps |
| validator set + `votingPower` | `Committee.ValidatorInfo{PublicKey, Stake}` |
| `≥2/3 voting power` | `Committee.QuorumThreshold()` = `2*totalStake/3 + 1` |

**This kills the #1 Tendermint-light-client failure mode** (canonical-vote encoding mismatch). Bullshark
SignBytes are a fixed-width concat.

### 4.2 New finality-proof obligation (Bullshark DAG commit)
"User tx is final" is no longer "one block got ≥2/3 precommits." It requires, all recomputable by a light
client from `Committee(epoch)`:
1. The tx's **certificate** (carries 2f+1 availability sigs over `headerDigest‖round‖epoch`).
2. A **committed leader/anchor** certificate whose causal history (via `Parents`) includes the tx cert.
3. **Commit proof** of that anchor: f+1 stake of round+1 certificates referencing it.
4. **Leader legitimacy**: recompute `electLeader(round)` from the committee → equals the anchor's author.
5. **Deterministic `orderDag`** placing the tx cert at its `BlockIndex`.

### 4.3 🚩 The StateHash-binding gap (the key design decision)
The certificate quorum signs the header digest, which **excludes StateHash**. The only artifact signed over
StateHash is the `StateHashMessage`, which appears to be a non-quorum gossip/divergence layer. Therefore L3
cannot simply "verify the certificate quorum signed the app_hash." Options:

- **(A) Aggregate StateHashMessages:** prove ≥2f+1 stake of validators signed a matching
  `(Epoch, BlockIndex, StateHash)`. Repurposes divergence-detection as the consensus proof. Works without
  core changes IF those messages are retained/exposed and reach quorum — **must confirm with core dev.**
- **(B) Bind StateHash into consensus (preferred, needs core change):** include `StateHash` (or a commitment
  to it) in the `Header`/certificate so the existing 2f+1 certificate quorum transitively attests it —
  exactly how CometBFT puts `AppHash` in the header. Cleanest; makes L3 a single quorum check.

This decision gates the entire L3 design. **Raise it with Accumulate core before implementing.**

---

## 5. L4 rewrite — validator lineage → epoch/committee lineage

| CometBFT (current L4 spec) | Bullshark |
|---|---|
| `ValidatorsHash` / `NextValidatorsHash` | committee digest per epoch (⚠️ **digest method to be added**) |
| header-chain lineage | **epoch-transition** lineage: `UpdateValidators` / `DiffWith` / `ValidatorUpdate` |
| ABCI `ValidatorUpdates` + DN governance txns | same Accumulate governance txns drive `ValidatorUpdate`s |
| weak-subjectivity checkpoint + BTC/ETH anchors | unchanged concept; checkpoint = a trusted `Committee(epoch)` |

`ValidatorTransitionQuery` → **`EpochTransitionQuery`**: ordered, contiguous, signed committee deltas from a
trusted checkpoint epoch to the target epoch; each transition's `newCommitteeDigest` chains to the next's
`previousCommitteeDigest` (no-omission invariant, same shape as the CometBFT spec). Because leader election
and quorum are stake-weighted by `Committee`, lineage MUST track stake, not just membership.

---

## 6. API method morphs (the L3/L4 doc rewrite)

| Current spec method | DAG-BFT replacement | Returns |
|---|---|---|
| `BlockHeaderQuery` | `CertificateQuery` | `Header{author,round,epoch,parents,payload}` + `StateHash` + recomputable `headerDigest` |
| `ConsensusProofQuery` | `CertificateProofQuery` | `Signatures` + `SignedAuthorities` + the `headerDigest‖round‖epoch` preimage + (per §4.3) the StateHashMessage set for `(epoch,blockIndex,stateHash)` + anchor-commit evidence (f+1 round+1 refs) |
| `ValidatorSetQuery` | `CommitteeQuery(epoch)` | `ValidatorInfo[]` (pubkey+stake), `totalStake`, `quorumThreshold`, committee digest |
| `ValidatorTransitionQuery` | `EpochTransitionQuery` | signed `ValidatorUpdate` deltas per epoch, contiguity-chained by committee digest |

The **make-or-break canonical-encoding** requirement (old L3 §3) re-targets from CometBFT `CanonicalVote`
to: (a) `Header.marshalForDigest()` byte layout, (b) the `headerDigest‖round‖epoch` vote preimage,
(c) the 56-byte `StateHashMessage` content, and (d) the committee→digest hashing. Pin all four.

---

## 7. Effort assessment

- **G0–G2, L1–L2:** ~free. Regression-test the receipt/BPT/anchor RPCs under the DAG-BFT executor; no proof
  logic rewrite.
- **L3:** bounded rewrite. Steady-state verification is *simpler* than CometBFT (fixed SignBytes, explicit
  stake/quorum, recomputable leader), but adds the DAG commit-rule walk (§4.2) and hinges on the StateHash
  binding decision (§4.3).
- **L4:** comparable to the CometBFT plan, re-expressed over epochs/committees; needs a committee digest
  method added upstream.
- **Reuse:** `3658-cryptographic-proof-api` is useful for **API shape / record types** only; its CometBFT
  verification core does not carry over.

---

## 8. Open questions for Accumulate core dev

1. **StateHash binding (§4.3):** Is `StateHash` committed anywhere the 2f+1 certificate quorum signs? If
   not, will core add it to the `Header`/certificate (option B), or is aggregating ≥2f+1 `StateHashMessage`s
   the sanctioned path (option A)? Are `StateHashMessage`s retained and queryable?
2. **Does `Certificate.StateHash` equal the Accumulate DN BPT / state-tree anchor** that L1–L2 bind to, or a
   different (DAG-execution) digest? If different, an extra binding layer is needed.
3. **Committee digest:** canonical encoding for `Committee → digest` (the `ValidatorsHash` analog)? Validator
   ordering + per-validator serialized form (pubkey + stake) + tree/hash function.
4. **Finality query:** will the API expose committed anchors + their f+1 commit evidence + `BlockIndex`, or
   must the client walk the DAG itself?
5. **Leader election determinism:** confirm `electLeader`/`ComputeLeaderSeed` are stable, recomputable from
   the committed `Committee`, and not dependent on non-deterministic local state.
6. **Epoch retention / pruning:** earliest epoch `EpochTransitionQuery` can answer (drives weak-subjectivity
   checkpoint recency).
7. **External anchors:** does DN BTC/ETH anchoring still anchor the same DN state root under DAG-BFT?

---

## 10. Source verification (2026-06-06, clone @ `8fc49879`)

All byte layouts from the earlier pass **confirmed exact**, plus two previously-open items now **resolved**.

### 10.1 Byte layouts — confirmed
- **Header digest** (`types/header.go:114 marshalForDigest`): `SHA-256(` `Author(32) ‖ Round(8 BE) ‖
  Epoch(8 BE) ‖ NumPayload(4 BE) ‖ [BatchDigest(32) ‖ WorkerID(1)]*sorted ‖ NumParents(4 BE) ‖
  [CertDigest(32)]*sorted` `)`. (Refinement vs earlier: there ARE 4-byte count prefixes; payload/parents
  are sorted by digest bytes for determinism.) **StateHash is not a header field.**
- **Two distinct signatures** (don't conflate):
  - `Header.Signature` = `ed25519.Sign(key, headerDigest[:])` — the *author's* self-signature over the
    32-byte digest (`header.go:187`).
  - `Certificate.Signatures[]` = the *quorum votes*. Each is `ed25519.Sign(key, voteContent)` where
    `voteContent = HeaderDigest(32) ‖ Round(8 BE) ‖ Epoch(8 BE)` = **48 bytes** (`vote.go:44 voteContent`,
    `vote.go:65 Sign`; re-derived identically in `certificate.go:155-158 Verify`).
- **`StateHashMessage` content** (`state_verification.go:46 messageContent`): `Round(8 BE) ‖ Epoch(8 BE) ‖
  BlockIndex(8 BE) ‖ StateHash(32)` = **56 bytes**, ed25519, Author NOT in signed bytes. ✔ exact.
- **Committee/quorum** (`committee.go`): `ValidatorInfo{PublicKey ed25519, Stake uint64}`;
  `QuorumThreshold()` = `(2*total)/3 + 1` (`:79`); `ValidityThreshold()` = `total/3 + 1` (f+1, `:88`);
  stake-weighted `HasQuorum`/`HasValidity`. Epoch transitions `UpdateValidators` increments epoch (`:297`),
  `DiffWith` (`:314`), `ValidatorUpdate{Add|Remove|Stake}`. Validators deterministically sorted by pubkey
  (`sortValidatorsByKey :302`). **Still NO committee digest/hash method → must be ADDED for L4.**
- **Certificate quorum check** (`certificate.go:121 Verify`): epoch match → header sig → author∈committee →
  per-sig `ed25519.Verify(validator.PublicKey, voteContent, sig)` → sum `validator.Stake` →
  `committee.HasQuorum(totalStake)`; dup-signer guarded. (Issue #3880 note `:184`: insecure
  headerDigest-only fallback was removed — they hardened exactly this path.)
- **Commit rule** (`bullshark/leader.go`): leader election deterministic & light-client-recomputable —
  `seed = SHA256(BigEndian(round))` (`:28`, exposed as `ComputeLeaderSeed :117`), `selectByStake` maps
  `seed%totalStake` to a validator (`:50`). Leaders only on **even rounds ≥2** (`:108`). Anchor commits on
  **f+1** support: `hasSupport` sums `StakeOf(cert.Author())` for round+1 certs where `IsAncestor(leader,
  cert)` and requires `>= ValidityThreshold()` (`:86-101`). `commitLeaderChain`→`orderDag` linearizes.

### 10.2 RESOLVED ✅ — `Certificate.StateHash` IS the Accumulate app_hash analog L1–L2 bind to
`adapter/executor_bridge.go ProduceBlock` (`:178`) runs the **Accumulate executor**: `block.Close()` →
`state.Hash()` (`:240-246`) → that hash is returned, stored as `lastBlockHash`, and surfaced as
`StateHash()` ("same as last block hash", `:308-313`); it is what gets written into `Certificate.StateHash`
via `SetStateHash`. This is the **same `state.Hash()` that the CometBFT path put into `Header.AppHash`.**
⇒ **The L1–L2 Merkle chain still resolves to the exact value carried in `Certificate.StateHash`.** The proof
*data* is intact; no extra binding layer is needed at the data level. Bonus: the committee is sourced from
the **same Accumulate on-chain `globals.Network.Validators`** (`executor_bridge.go:100-126`) — so **L4's data
source is unchanged**; only the signature-verification scheme changes. (Note: `Stake` is currently hardcoded
to `1` for globals-sourced validators → effectively equal weight today; `handleValidatorUpdates` uses
`u.Power`.)

### 10.3 HARD-CONFIRMED 🚩 — the state root is NOT consensus-attested anywhere
The value is right, but **nothing signs it under quorum**:
- `certificate.go:56-59` explicitly: StateHash "is **NOT** part of the certificate digest since it's computed
  post-execution." The quorum (`voteContent`, 48 B) covers header only — i.e. **DAG availability/ordering**.
- `state_verification.go` is a **divergence detector, not a quorum**: `StateHashTracker` records local/remote
  hashes and fires `divergenceCallbacks` on mismatch (`:241 RecordRemoteHash`); `CheckConsistency` wants
  all-agree, `ValidatorHashCount` just counts reporters — **no stake, no 2f+1, no threshold anywhere**. It is
  also **pruned** (~`maxTrackedRounds` default 100 rounds, `:344 Prune`) and not shown to be persisted/served.
- A repo-wide grep finds StateHash reaching a quorum/threshold in **zero** places (only snapshot state-sync
  *trusts* a snapshot hash; consensus types never aggregate it by stake).

**Consequence for L3:** on this branch a "≥2/3 of stake signed this state root" proof is **not constructable
from existing consensus artifacts** — those signatures don't exist.

⚠️ **Critical timing constraint (corrects an earlier framing):** in DAG-BFT the header is voted on **before
execution** — certificates order *batch availability*; `StateHash` is computed *after* commit by the executor
(`certificate.go`: "computed post-execution"; `executor_bridge.ProduceBlock` runs the executor on
already-committed certs). So you **cannot** put block N's `StateHash` into block N's own voted header — no
validator knows it at signing time. "Bind it into the header" is therefore NOT a same-block change. The two
architecturally-sound primitives, both **consensus changes that must be core-designed/owned** (safety +
executor-version + migration):
- **Option B′ — delayed binding (CometBFT-style):** block N+1's header carries block N's post-execution
  `StateHash`, and N+1 receives the normal 2f+1 votes. Exactly how CometBFT's `AppHash` works (state after the
  *previous* block). Cost: a consensus-structure change + a one-block lag on state finality.
- **Option A′ — post-execution state certificate:** aggregate the `StateHashMessage`s (today unthresholded
  gossip, pruned ~100 rounds) into a real 2f+1 stake-signed execution certificate — the Sui/Aptos-style
  "signed checkpoint" pattern. Cost: NEW threshold + persistence/serving code.

**This is a genuine protocol-design decision, not a drop-in fix** — raise it as an RFC/design issue with
Accumulate core (with a PoC branch) and let them choose the direction, rather than submitting a finished
consensus MR. Everything downstream (the L3 verifier shape, `ConsensusProofQuery`) depends on which primitive
they pick.

### 10.4 Status of the §8 open questions after verification
- Q1 (StateHash binding): **answered** — not bound; pursue Option B (§10.3).
- Q2 (`StateHash` == DN BPT/state-tree anchor): **answered YES** — it's the executor `state.Hash()` (§10.2).
- Q3 (committee digest): **confirmed needed** — no digest method exists; ordering is canonical (sorted by
  pubkey), so a digest is straightforward to add.
- Q5 (leader determinism): **confirmed** recomputable from committee+round (§10.1).
- Q4, Q6, Q7 (finality/anchor query exposure, epoch retention/pruning, external anchors): still open — depend
  on the v3 API surface, not the consensus types.

---

## 11. v3 API surface (source-verified 2026-06-06, `pkg/api/v3`)

The v3 API is schema-driven (`*.yml` → generated Go). Reviewed `api.go`, `queries.yml`, `responses.yml`,
`records.yml`, `types.yml`.

### 11.1 What EXISTS today — the consensus-agnostic data plane (already powers G0–G2 + L1–L2)
- **`Querier.Query(scope, ChainQuery)`** → `ChainEntryRecord` + **`Receipt`** (Merkle `start→anchor`,
  `localBlock`, `majorBlock`). This is the spine of L1, L2, G0, and G1-timing. Unaffected by DAG-BFT.
- **`BlockQuery`** (`Minor`/`Major`, with ranges) → `MinorBlockRecord{Index, Time, Source, Entries,
  Anchored}` / `MajorBlockRecord{Index, Time, MinorBlocks}`. ⚠️ A "block" here is a **pure index/metadata
  object — NO block hash, NO state root, NO signatures.** The state root only appears as the `anchor` inside
  `Receipt`s.
- **`AnchorSearchQuery`** → queries `{account}#anchor/{hash}` with a `Receipt` (the BVN→DN internal anchor
  mechanism; substrate for L2).
- **`NetworkService.NetworkStatus`** → `Globals`, **`Network` (`protocol.NetworkDefinition` = the validator
  set)**, `MajorBlockHeight`, `DirectoryHeight`. This is the SAME on-chain validator source the executor
  bridge reads (§10.2) — but returned **current-only, trusted, unsigned, no stake, no epoch, no state-proof**.
- **`ConsensusService.ConsensusStatus`** → liveness `Ok`, `LastBlock`, the serving node's OWN
  `ValidatorKeyHash`, `Peers` (`ConsensusPeerInfo`). **No proof material.**
- **`SnapshotService.ListSnapshots`** → `SnapshotInfo`. (Note: `ConsensusInfo` is still `cometbft.GenesisDoc`
  — see §11.3.)

### 11.2 What is MISSING — the entire L3/L4 trustless surface must be ADDED to v3
`ConsensusService` has exactly one method (`ConsensusStatus`). There is **no** way to fetch any of:
1. **A Bullshark `Certificate`** (header + 2f+1 vote sigs + `SignedAuthorities` + `StateHash`) — → new
   **`CertificateQuery`** / **`ConsensusProofQuery`** on `ConsensusService`. Must also return the anchor/leader
   **commit evidence** (the f+1 round+1 certs referencing the anchor) so finality is provable, not just a
   single quorum.
2. **A proven, historical, stake-weighted committee** — `NetworkStatus.Network` is current/trusted/unsigned.
   → new **`CommitteeQuery(epoch|height)`** returning `ValidatorInfo{pubkey, stake}` + a `Receipt` binding it
   to the committed `StateHash` + a committee digest.
3. **Epoch-transition lineage** — nothing exposes signed committee deltas. → new **`EpochTransitionQuery`**
   (the `ValidatorTransitionQuery` analog over `ValidatorUpdate`/`DiffWith`).
4. **A state-root quorum** — cannot be exposed because the artifact does not exist (§10.3); blocked on the
   core-side Option-B change before any API can serve it.

### 11.3 Migration is mid-flight at the API layer (an opportunity, not a blocker)
Only **1** CometBFT reference remains in all of `pkg/api/v3` (`SnapshotInfo.ConsensusInfo =
cometbft.GenesisDoc`). The consensus **engine** was swapped (`pkg/consensus/bullshark`) but **no DAG-BFT
consensus-proof surface has been added to v3 yet.** CometBFT light clients used the CometBFT RPC (`/commit`,
`/validators`) directly — never v3 — so there is **no legacy v3 consensus-proof endpoint to refactor.** The
L3/L4 methods can therefore be designed cleanly into v3 from scratch. The `3658-cryptographic-proof-api`
branch already demonstrates the *pattern* for adding ConsensusProof/ValidatorSet/ValidatorSignature **records**
to v3 (just re-target its CometBFT shapes to Bullshark per §4–§6).

### 11.4 Resolution of the remaining §8 open questions
- **Q4 (finality query):** PARTIAL. Block/anchor **indexing** is exposed (`BlockQuery`, `AnchorSearchQuery`,
  `MinorBlockRecord.Anchored`) — enough for the **G0 finality notion** (tx is in minor block N, anchored into
  major block M). The **consensus finality** (certificate + f+1 commit evidence) is **NOT** exposed → must be
  added (§11.2 #1).
- **Q6 (epoch retention/pruning):** UNDEFINED at the API — there is no epoch/committee query to bound. Data
  points: `StateHashTracker` prunes ~100 rounds (ephemeral); `SnapshotService` exists for state-sync. Weak-
  subjectivity checkpoint recency will be set by how far back the (to-be-added) `CommitteeQuery`/
  `EpochTransitionQuery` can answer — a retention policy to be decided WITH the new endpoints.
- **Q7 (external BTC/ETH anchors):** NOT first-class. `AnchorSearchQuery` covers the **internal** anchor
  mechanism (`{account}#anchor/{hash}`); there is no `ExternalAnchorQuery` and no external-anchor record in the
  v3 schema. External (BTC/ETH) anchoring of DN roots, if needed for the checkpoint, requires either a new
  method or querying the anchor-pool accounts directly — confirm the mechanism with core.

### 11.5 Net API delta
Reuse as-is: `ChainQuery`+`Receipt`, `BlockQuery`, `AnchorSearchQuery`, `NetworkStatus` (for the *current*
set + heights). Add to `ConsensusService`: `CertificateQuery`/`ConsensusProofQuery`, `CommitteeQuery(epoch)`,
`EpochTransitionQuery`, and (once core binds StateHash) a state-root proof. None of the existing query/record
types need to change for G0–G2 / L1–L2 — they are orthogonal to the new consensus surface.

---

## 9. References (read raw before implementing)
- `pkg/consensus/types/{header,certificate,committee,state_verification,signer,vote}.go`
- `pkg/consensus/bullshark/{ordering,leader,bullshark}.go`
- Current systems (do NOT edit): `proof/consolidated_governance-proof/{g0,g1,g2}_layer.go`,
  `proof/working-proof_do_not_edit/{proof_builder,chained_proof,layer1,layer2,layer3}.go`
- Companion specs (CometBFT-era): `docs/proof/L3_CONSENSUS_PROOF_API_REQUIREMENTS.md`,
  `docs/proof/L4_VALIDATOR_API_REQUIREMENTS.md`
- Related Certen memory: `liteclient-consensus-proof-live`, `accumulate-upstream-branches-l4`,
  `dagbft-proof-migration`.
