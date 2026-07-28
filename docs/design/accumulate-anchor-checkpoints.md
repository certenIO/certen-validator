# Anchor checkpoints: binding the principal without validator signatures

**Status:** proposal · **Written:** 2026-07-28.

---

## 1. The problem this solves

CERTEN's entitlement gate decides whether CERTEN spends its own money, keyed on
the principal a ValidatorBlock declares. Two things now constrain that claim:

- the principal must agree with the block's governance proof (`a4f61bb`), and
- a carried lite-client proof must be internally valid, name the same identity,
  and concern the same transaction (`91dae72`).

Neither makes the claim **true**. A validator willing to fabricate a coherent
Merkle chain can still produce a self-consistent block. The receipts prove
structure; nothing proves the anchor they arrive at is one Accumulate actually
produced.

The obvious fix is to verify the anchor against Accumulate's validator
signatures — L3/L4. Everything needed for that already exists inside a CometBFT
node, but it is not exposed in a verifiable form, and getting it exposed depends
on another team's roadmap (see `accumulate-consensus-proof-api-ask.md`).

**This proposal closes the same gap without any of it.**

---

## 2. The idea

We do not need to re-derive trust in an anchor from validator signatures if the
fleet already **agrees** on one.

CERTEN's validators run a BFT chain with committed state. That state can hold a
known-good Accumulate root. A carried proof is then required not merely to be
internally consistent, but to **chain to a root the fleet has committed**.

That converts the question from

> "is this anchor real?" — unanswerable without signatures

to

> "does this receipt reach a root we already agreed on?" — pure hashing.

Deterministic, no network, no clock, and therefore safe inside a consensus rule.

### Why this is not circular

The fleet is not attesting Accumulate's state; it is *remembering* a value an
operator quorum vouched for once, and extending that memory by proof. The trust
assumption is explicit and bounded: **one root, agreed at genesis.** Everything
after is mathematics.

That is exactly how a light client works. It is a weaker assumption than
"trust whichever anchor the current proposer supplies", which is the assumption
today.

---

## 3. How roots advance

A checkpoint that never moves is useless: proofs for recent transactions cannot
chain to an old root without the intervening history.

Accumulate's anchors form a Merkle chain, and `merkle.Receipt` already supports
exactly the operation needed — a receipt whose `Start` is an earlier root and
whose `Anchor` is a later one proves the earlier is contained in the later.
`Receipt.Validate()` checks that by pure hashing, and `Receipt.Combine()`
appends one receipt to another.

So the checkpoint advances the way a light client syncs:

```
seal R0 at genesis
    │
    │  receipt proving R0 → R1   (validated by every node, deterministically)
    ▼
   R1
    │  receipt proving R1 → R2
    ▼
   R2 ...
```

Each advance is a transaction carrying a receipt. Every validator verifies the
receipt against the root it already holds and accepts the new root only if the
hashing works out. **No node has to trust the submitter** — a forged receipt
fails the hash walk.

This is the property that makes the design worth building: after genesis, the
fleet's trust in Accumulate roots is maintained by proof rather than by
authority.

---

## 4. Reusing what already exists

None of the machinery is new. The entitlement policy already demonstrates every
piece:

| Need | Existing mechanism |
|---|---|
| A value in committed state | `EntitlementPolicyState` in the ledger, sealed at genesis |
| Quorum-authorised change | `PolicyUpdateTx`, m-of-n admin signatures |
| Deterministic activation | `ActivePolicyAt(schedule, blockTime)` — derived, never mutated |
| Replay safety | append-only schedule, idempotent by version |
| Version discipline | `ExecutionRulesVersion` + refuse-to-start on mismatch |

A checkpoint is the same shape: sealed at genesis, extended by a quorum-signed
transaction, derived rather than mutated, append-only.

The critical lesson from the entitlement work applies unchanged: **derive
consensus-relevant state from committed history, never accumulate it by
mutation.** The active checkpoint at block H must be a pure function of
`(checkpoint chain, H)`, or replaying block 10 after the chain reaches block 210
will judge it against a root that did not exist yet — the divergence that cost
us the fleet on 2026-07-27, relocated.

---

## 5. Design

### 5.1 State

```go
type AnchorCheckpointState struct {
    // Append-only chain of roots the fleet has agreed on. The active root for a
    // block is the latest entry whose ActivationUnix <= block time — derived,
    // exactly as the entitlement policy is.
    Chain []AnchorCheckpoint

    // Who may extend the chain, and how many must agree. Sealed at genesis.
    AdminKeys      map[string]string
    AdminThreshold int
}

type AnchorCheckpoint struct {
    Root           []byte  // an Accumulate DN root
    Partition      string
    Height         uint64  // the Accumulate block height it came from
    ActivationUnix int64
    Version        uint64
    ProposedAt     int64   // CERTEN height, for audit
}
```

### 5.2 Extending the chain

`AnchorCheckpointTx` carries the new root plus a receipt proving the **current**
root is contained in it, and an admin quorum signature.

Verification, entirely deterministic:

1. Quorum: `AdminThreshold` distinct valid admin signatures over the tx preimage.
2. Monotonic version, as with policy updates — a captured tx cannot be replayed.
3. `receipt.Start == currentRoot` and `receipt.Anchor == newRoot`.
4. `receipt.Validate(nil)` — the hash walk actually connects them.
5. Activation at least `MinActivationDelay` seconds of block time ahead.

Step 3–4 is what makes this trustworthy: an operator cannot insert an arbitrary
root, only one that provably extends the root the fleet already holds. A
compromised admin quorum could still stall the chain by proposing nothing, but
cannot rewrite history.

### 5.3 Using it

`verifyLiteClientBinding` gains one check, and it is the point of the whole
exercise:

```go
// TODAY: the receipt must be internally consistent.
if !dnAnchorProof.Validate(nil) { reject }

// ADDED: and it must arrive somewhere the fleet has agreed on.
if !anchorIsKnown(dnAnchorProof.Anchor, checkpointsAt(blockTime)) { reject }
```

`anchorIsKnown` accepts the anchor if it equals a committed root, or if the
proof chains to one. A fabricated proof now has to produce a receipt reaching a
root the fleet already holds — which requires breaking SHA-256, not editing
JSON.

---

## 6. What this achieves, and what it does not

**Closed.** A malicious validator can no longer bind an entitlement to a
fabricated Accumulate anchor. The anchor must chain to a root the fleet
committed, and that check is pure hashing every node performs identically.

**Not closed.** The fleet's belief in the *genesis* root rests on operator
attestation, not on Accumulate's validator signatures. If the seeded root were
wrong, everything chaining from it would be consistently wrong.

That residual is small and bounded, and it is worth being precise about why:

- It is **one value, once**, verifiable out of band against any Accumulate
  explorer or full node at seal time.
- It is **auditable forever** — the root is in committed state and the whole
  chain of extensions is on the CERTEN chain.
- It **degrades safely**: a wrong root causes refusals, not unauthorised
  spending, because proofs stop chaining.

Compare with today, where every proposer is trusted for every anchor on every
block. This replaces continuous, invisible, per-block trust in whoever proposes
with a single, visible, auditable act of trust at genesis.

L3/L4 verification would remove even that. This gets most of the way there
without waiting on anyone, and the two are complementary: when
`ConsensusProofQuery` and `BlockHeaderQuery` ship, the seed root stops being
operator-attested and becomes *proven* — the checkpoint chain, the transaction,
the quorum and the activation logic are all unchanged.

---

## 7. Sequencing

1. `AnchorCheckpointState` in the ledger; seeded from env at genesis, exactly as
   the entitlement policy is. **No behaviour change** — the value is recorded
   and not yet enforced.
2. `AnchorCheckpointTx` with quorum, monotonic version, receipt verification and
   time-based activation. Reuse `PolicyUpdateTx` wholesale; the shape is
   identical.
3. Add the `anchorIsKnown` check to `verifyLiteClientBinding` in **observe**
   first — log what real traffic would do without refusing it. The lite-client
   binding was validated this way on 2026-07-28 and it is what caught two
   would-be outages.
4. Only then require it, as an execution-rules bump.
5. The cross-boundary replay test from `policy_activation_replay_test.go` is the
   template for step 4's verification: switch at a time, restart across the
   boundary, require identical app hashes. **That test is the deliverable, not
   the code.**

An operator tool mirroring `cmd/policy-update` (`keygen` / `propose` / `sign` /
`submit`) should ship with step 2. A governance mechanism with no way to invoke
it is unreachable — that was discovered the hard way when `CheckTx` silently
refused every policy update.

---

## 8. Open questions

- **Which root?** The DN root is the natural choice: it subsumes BVN state via
  anchoring, so one root covers all partitions. Worth confirming the carried
  `DNAnchorProof` actually terminates there in practice.
- **How often to advance?** Each extension costs a transaction and a quorum
  signature. Advancing per Accumulate major block is likely far more often than
  needed; the requirement is only that recent proofs can still chain.
- **What if the chain falls behind?** Proofs for recent transactions stop
  chaining and are refused — fail-closed, consistent with the rest of the
  design, but it makes checkpoint freshness an availability dependency worth
  monitoring rather than discovering.
