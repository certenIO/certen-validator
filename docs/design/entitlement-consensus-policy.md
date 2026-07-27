# Making the entitlement gate safe to switch on

**Status:** IMPLEMENTED (Layers 1-3) · **Written:** 2026-07-27, after the enforce rollout bricked
the fleet for ~2 hours and cost the CERTEN chain its history.

---

## 1. What actually happened

The entitlement gate was flipped from `observe` to `enforce` via `.env.shared`
and the validators were restarted. Every node then crash-looped on:

```
panic: state.AppHash does not match AppHash after replay.
  Got 9B34726E…342544, expected 8028A10C…C63BA3
```

Recovery required wiping CometBFT's chain state *and* the app ledger on all
seven nodes and restarting from height 1.

Nothing was wrong with the entitlement data. The epoch was valid, the signature
verified, the set was complete, and the entitled principal had passed the whole
pipeline minutes earlier. What broke was the *switch*.

---

## 2. The exact mechanism

Three facts combine into the failure.

**(a) The app hash is a chain over accepted bundle IDs.**

```
appHash(H) = SHA256( appHash(H-1) || sorted(unique bundle-ids in block H) )
```

**(b) A rejected transaction never contributes a bundle ID.**
`processValidatorTransaction` returns `Code 4` at the entitlement check
(`abci_validator.go:319`) and returns before `blockBundles = append(...)`
(`:342`).

**(c) The gate's verdict is parameterised by node-local mutable config.**
`EntitlementConfigFromEnv()` reads `CERTEN_ENTITLEMENT_MODE` and
`CERTEN_ENTITLEMENT_KEYS` from the environment at process start.

Therefore: **changing an environment variable silently changes the app hash of
every block containing an unentitled intent.** On restart CometBFT replays
history; blocks originally committed under `observe` re-execute under `enforce`,
produce a different hash than CometBFT recorded, and the node dies before it can
serve. The app then persists the wrong hash, so subsequent restarts skip the
replay and fail identically. There is no self-recovery.

The same mechanism forks the fleet if two nodes ever hold different values —
which is why the existing code comments correctly insist enforce must be
fleet-wide. The insight that was missed is that **"fleet-wide" is not enough: it
must also be time-wide.** A single node restarting after a config change replays
its own history under new rules and diverges from itself.

---

## 3. The invariant that was violated

> A validator's **accept/reject** decision must be a pure function of
> `(block contents, committed state at H-1, block time)`.
> Nothing else. No environment, no wall clock, no network fetch, no local file.

It is worth being precise about where non-determinism *is* acceptable, because
the current design already gets most of this right:

| Stage | Non-determinism | Verdict |
|---|---|---|
| **Proposer** builds evidence from the epoch store (an HTTP fetch) | Fine | The result is written *into the block*; peers verify what they're given rather than re-fetching |
| **Verifier** checks signature over evidence in the block | Deterministic | ✅ |
| **Verifier** checks the Merkle proof and principal | Deterministic | ✅ |
| **Verifier** checks freshness against `req.Time` | Deterministic | ✅ (block time is identical on every node) |
| **Verifier** selects mode and trusted keys | **From env** | ❌ **This is the whole bug** |

So the architecture is one step away from correct. Evidence already travels in
the block precisely so verification is self-contained. The mode and key set are
the only inputs that escaped that discipline.

---

## 4. The solution

### Layer 1 — Move the policy into consensus state

Introduce an `EntitlementPolicy` held in the application state and committed to
the app hash:

```go
type EntitlementPolicy struct {
    Mode          EntitlementMode  // off | observe | enforce
    TrustedKeys   []PolicyKey      // keyID -> ed25519 pubkey
    Version       uint64           // monotonic; bumped by every update
}
```

`VerifyEntitlement` reads the policy **from committed state at H-1**, never from
the environment. Replay at any height then uses the policy that was actually in
force at that height, and two nodes cannot hold different values because the
value is agreed by consensus.

Environment variables survive only as *genesis seeds*: they initialise the
policy in the genesis block and are never read again. A node whose env disagrees
with chain state is simply ignored rather than being a silent fork risk.

### Layer 2 — Change the policy by transaction, at an activation height

Add a `PolicyUpdate` transaction type carrying the new policy and an
`ActivationHeight` that must exceed `currentHeight + SafetyMargin` (suggest 200
blocks). It commits like any other transaction; the gate consults it only once
the chain reaches the activation height.

This is the standard mechanism — Ethereum fork blocks, Cosmos's upgrade module,
Bitcoin's BIP9 — and it buys three properties at once:

- **Deterministic replay.** The rule at height H is derivable from state at H-1.
- **Coordinated activation.** Every node switches at the same height, without
  anyone touching a config file at the same moment.
- **An audit trail.** "When did enforcement begin, and who authorised it?" is
  answered by a transaction on the chain rather than by shell history.

The update transaction should require an operator quorum signature, not a single
key — turning enforcement on is exactly as consequential as the payments it
gates.

**On putting trusted keys in state.** `entitlement_gate.go` currently argues
keys are pinned per node because "a key set that could be fetched is a key set
an attacker could substitute." That reasoning is right about *fetching* and
wrong about *consensus*. A key set in committed state is not fetched; it is
agreed, quorum-signed, tamper-evident, and identical on every node by
construction. Pinning in env achieves none of that and adds the divergence risk
that just cost two hours of downtime.

### Layer 3 — Version the execution rules, and fail fast

Layers 1 and 2 fix *policy* changes. They do not fix *code* changes: any future
edit to `processValidatorTransaction` that alters accept/reject behaviour will
break replay of blocks committed under the old binary. That is what will happen
next, and it deserves a real answer rather than a runbook note.

Record an `ExecutionRulesVersion` in committed state. At startup, compare it
against the version the binary implements:

- **equal** → proceed
- **binary newer** → refuse to start with an actionable message:
  *"this binary implements execution rules v3; chain state was written under v2.
  A coordinated upgrade at an activation height is required."*
- **binary older** → refuse to start (operator has rolled back past an upgrade)

This does not make old blocks replayable under new rules — that requires
multi-version dispatch, which is worth building only if CERTEN chain history
must survive upgrades. It probably need not: the CERTEN chain is a coordination
and ordering layer, while the system of record is Accumulate and the proofs are
anchored on external chains. We discarded 65 blocks in this incident and lost
nothing verifiable.

What Layer 3 *does* buy is enormous and cheap: it converts a cryptic two-hour
outage into a clear refusal to start, at the moment of the upgrade, naming the
required action. The incident above would have been a one-line error message.

Note a latent bug to fix alongside this: `AppVersion` is reported as `1` in
`abci_validator.go:214` and `2` in `bft_integration.go:2117`. Two different
answers to "what rules does this node implement" is exactly the ambiguity Layer
3 exists to remove.

---

## 5. What we are not doing, and why

**"Record the verdict in the block instead of letting it affect execution."**
This sounds attractive — it removes the app-hash dependency — but it moves the
decision to the proposer and reduces peers to accepting whatever it claims. The
gate's entire value is that it is fleet-wide and non-bypassable
(`validator_block_invariants.go`); a proposer-decided verdict is exactly the
single-node decision the design already rejects as "an optimisation, NOT the
enforcement point."

**"Treat mode changes as a coordinated chain restart."**
This is what we did by accident, and it works only because the chain is
currently disposable. It is an operational convention with no enforcement: one
operator restarting one node at the wrong moment reproduces the outage. Rules
that depend on humans remembering are not rules.

---

## 6. Migration

1. Add `EntitlementPolicy` + `ExecutionRulesVersion` to committed state; seed
   from env at genesis. Gate reads state. **No behaviour change** — mode is
   still whatever the env said, but it now lives in the right place.
2. Add the startup version check (Layer 3). Cheap, independent, immediately
   prevents a repeat of this incident.
3. Add the `PolicyUpdate` transaction and activation-height logic.
4. Exercise it on a throwaway chain: commit an update at height H+200, restart
   nodes across the boundary, confirm replay produces identical app hashes on
   both sides of the switch. **This test is the deliverable** — the failure mode
   only appears on restart, so a test that never restarts proves nothing.
5. Only then schedule enforcement on the live fleet, as a `PolicyUpdate`.

Until step 5, `observe` remains the correct posture. It cannot fork the fleet
because it always returns nil — which is precisely why it was the right place to
start, and why the mistake was leaving it.

---

## 6a. What implementation changed about the design

Layer 2 was built as specified, with one correction the cross-boundary test
forced.

The first implementation stored a *pending* change and, at the activation
height, MUTATED the policy into its new value. That is wrong, and wrong in
exactly the original way: a mutated "current mode" reflects how far the chain
has progressed, so replaying block 10 after the chain reached block 210 judged
block 10 by the rule active at 210. The replay test caught it immediately.

The correct shape is an APPEND-ONLY SCHEDULE with the active rule DERIVED:

    activePolicy(H) = latest scheduled change whose ActivationHeight <= H,
                      else the genesis policy

`ActivePolicyAt` is pure in `(schedule, height)`, so block 10 is judged
identically however many times it is executed and in whatever order. Two
consequences fall out that mutation could not provide:

- **Idempotent application.** Re-executing the block carrying an update finds
  the version already scheduled and changes nothing. Crucially it is still
  ACCEPTED, so its id still reaches the app hash — rejecting it as stale would
  itself diverge.
- **Order independence.** The schedule is a set; `latest activation at or below
  H` does not depend on insertion order.

The general form of the lesson, which is also the original bug: **derive
consensus-relevant state from committed history, never accumulate it by
mutation.** Mutation encodes "when did I last run", and replay is precisely the
case where that is not the answer.

## 7. The general lesson

The gate was built carefully. `entitlement_gate.go` reasons explicitly about
CheckTx versus FinalizeBlock determinism, about ABCI block time versus wall
clock, about fleet-wide agreement. Every one of those observations is correct.

The gap is that the reasoning covered **space** — will all nodes agree right now
— and not **time**: will this node agree with its own past when it replays.
For any consensus-affecting rule, both questions have to be asked, and the
second is easier to miss because nothing exercises it until a restart.
