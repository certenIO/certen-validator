# Validator Trust Root — Research and AIP Runbook

**Companion prompt:** `VALIDATOR_TRUST_ROOT_CLAUDE_PROMPT.md`
**Predecessor:** `PHASE8_RUNBOOK.md` (closed — all gates green, fleet deployed)
**Date:** 2026-08-28
**Target repo for research:** `C:\Accumulate_Stuff\accumulate-core` — **READ ONLY**
**Deliverable:** one or more draft Accumulate Improvement Proposals

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

> For **any** transaction and **any** block, determine what the validator set
> was at that block, and prove that set cryptographically back to network
> genesis.

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

**Q7 — Minimal public surface.** What is the smallest public API that closes the
gap? Candidates, to be evaluated not assumed:
  - (a) promote `MajorHeaderRange` + `MinorRootRange` to public v3
  - (b) a new point query: "validator set at height H, with proof to genesis"
  - (c) publish signed genesis checkpoints so verifiers start recent, not at genesis
  - (d) embed the induction path in the anchor receipt CERTEN already fetches

**Q8 — What CERTEN must build regardless.** Whatever the API, the verifier side
is CERTEN's. What does `layer4_verify.go` need so that `ValidatorSet` is
*derived* rather than *asserted*?

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
| 5 | Draft the AIP(s) | Matches the template in §6; every claim cited |
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

- [ ] Every §2 claim re-verified or corrected, on **both** `main` and
      `dagbft-integration`, with file:line.
- [ ] Q1–Q8 each answered with citations, or explicitly recorded as unanswerable
      and why.
- [ ] A recommended solution, with the alternatives and the reason each lost.
- [ ] Measured sizes and counts wherever the proposal costs a verifier bandwidth.
- [ ] Draft AIP(s) saved under `C:\Accumulate_Stuff\AIPs\`, matching §6.
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
