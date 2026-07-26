# 05 — How Proofs Are Used: Where & When

[← Back to index](./README.md)

The previous doc explained *what proofs contain*. This one explains *how they're
used in practice* — the full life of a proof, and the exact moments where each
proof does its job.

---

## 1. The life of a proof (cradle to grave)

```mermaid
flowchart LR
    req["Requested<br/>(intent finalized)"] --> build["Built<br/>(L1–L4, G0–G2)"]
    build --> agree["Agreed<br/>(validator consensus)"]
    agree --> anchor["Anchored<br/>(committed on external chain)"]
    anchor --> exec["Used to execute<br/>(contract verifies & acts)"]
    exec --> attest["Attested<br/>(BLS quorum co-signs result)"]
    attest --> writeback["Written back<br/>(receipt on Accumulate)"]
    writeback --> store["Stored<br/>(Proofs Service archive)"]
    store --> verify["Verified<br/>(anyone, anytime)"]
```

Each stage is a place where a proof (or part of one) is **used**. Let's go through
the three that matter most: **execution-time on-chain use**, **write-back use**,
and **after-the-fact verification use**.

---

## 2. WHERE proofs are used — the four locations

```mermaid
flowchart TB
    subgraph L1["A) On the external chain (at execution)"]
        a["Anchor + Account + BLS Verifier contracts<br/>check the proof BEFORE acting"]
    end
    subgraph L2["B) Back on Accumulate (write-back)"]
        b["The result + proof summary become<br/>a permanent on-chain receipt"]
    end
    subgraph L3["C) In the Proofs Service (archive)"]
        c["Stored and indexed for retrieval,<br/>bundles, and bulk export"]
    end
    subgraph L4["D) In the hands of auditors/customers"]
        d["Re-verified offline, no trust required"]
    end
```

| Location | When | What the proof does there |
|---|---|---|
| **A. External chain contracts** | At the moment of execution | The proof is the **key** that unlocks action. No valid proof → nothing happens. |
| **B. Accumulate (write-back)** | Right after execution | The proof summary + result is recorded as the **official receipt**, closing the loop. |
| **C. Proofs Service** | Continuously | The proof is **archived, indexed, and served** so anyone can fetch it later. |
| **D. Auditors / customers** | Anytime afterward | The proof is **independently re-verified** with math alone. |

---

## 3. Use A (the critical one): proofs gate on-chain execution

This is the heart of Certen's security. On the external chain, **three contracts
check the proof in sequence**, and execution only proceeds if all checks pass.

```mermaid
sequenceDiagram
    autonumber
    participant Val as Validator
    participant Anchor as Anchor contract
    participant BLS as BLS Verifier contract
    participant Acct as Account contract
    participant Target as Target (token, app, ...)

    Val->>Anchor: createAnchor(commitments, validatorSetRoot, ...)
    Note over Anchor: stores the proof's fingerprints

    Val->>Anchor: executeComprehensiveProof(anchorId, blsProof)
    Anchor->>BLS: verifyBLSSignature(proof, messageHash)
    Note over BLS: ZK-checks: ≥2/3 voting power signed,<br/>bound to THIS anchor's commitments
    BLS-->>Anchor: valid ✅ → mark proofExecuted

    Val->>Acct: executeWithGovernance(target, value, calldata, proof)
    Note over Acct: re-checks Merkle proof, time window,<br/>nonce (anti-replay), execution tie
    Acct->>Anchor: is this proof verified? (proofExecuted?)
    Anchor-->>Acct: yes ✅
    Acct->>Target: perform the action
    Target-->>Acct: done ✅
```

**When each check happens and why:**

| Step | Proof part used | Guards against |
|---|---|---|
| `createAnchor` | The 8 commitments (Merkle root, execution commitment, operationID, validatorSetRoot, …) | Recording an action that wasn't agreed; pins it to the exact operation |
| `executeComprehensiveProof` | BLS aggregate + ZK proof (component from [04 §6](./04-proof-types-and-parts.md#6-the-signature--attestation-pieces-how-the-group-vouches)) | A minority of validators acting alone; only a **2/3 quorum** passes |
| `executeWithGovernance` | Merkle inclusion + governance + **execution tie** | Replays, parameter-swapping, wrong-chain reuse, expired proofs |

The **execution tie** (`executionCommitment`) check is worth repeating: the
contract recomputes `hash(chainId, target, value, calldata)` and demands it match
what the proof committed to. A proof authorizing "send 100 to Alice on Ethereum"
**cannot** be reused to "send 1,000,000 to Mallory" or run on a different chain.

---

## 4. Use B: write-back proofs create the permanent receipt

After execution, the validators don't just walk away — they **observe** the
result, **co-sign** it, and **write it back** to Accumulate. This write-back is
itself proof-backed.

```mermaid
flowchart TB
    obs["Observe result on target chain<br/>(tx hash, block, success, events, state root)"]
    obs --> att["Each validator co-signs the result<br/>→ aggregated BLS attestation"]
    att --> wb["Write-back transaction to Accumulate<br/>data account: …/execution-results"]
    wb --> rec["Permanent on-chain receipt:<br/>'this intent → this result, here's the proof'"]
```

**When:** immediately after the target chain confirms the action.
**Where:** the Certen network's own Accumulate data account
(`acc://certen-protocol.acme/execution-results`).
**Why it matters:** the original decision and its real-world outcome now live
**together on the same trusted ledger** — a complete, tamper-evident audit trail
from "we decided X" to "X happened, proven."

---

## 5. Use C & D: archive and independent verification

```mermaid
sequenceDiagram
    autonumber
    participant Val as Validator
    participant PS as Proofs Service
    actor Consumer as Customer / Auditor / App

    Val->>PS: store full proof bundle
    Consumer->>PS: GET proof by tx hash / account / batch / anchor
    PS-->>Consumer: proof (layers + governance + attestations + anchor ref)
    Consumer->>PS: GET self-contained bundle (+ SHA-256)
    Consumer->>Consumer: re-verify Merkle + signatures + anchor finality
    Note over Consumer: trust math, not Certen
```

- **Archive (C):** the **Proofs Service** indexes every proof so it's findable by
  transaction hash, account, batch, or anchor — and offers bulk export for
  compliance teams.
- **Independent verification (D):** the bundle is **self-contained**. An auditor
  re-hashes the Merkle path, checks the validator/BLS signatures, and confirms the
  anchor transaction is final on the public chain. No part of this requires
  trusting Certen's servers.

---

## 6. WHEN each proof level is required (the rules of thumb)

Not every action needs the maximum proof. The system matches proof strength to
risk:

```mermaid
flowchart TB
    q1{"Does it move value<br/>or change critical state?"}
    q1 -->|No / low risk| g1["Require up to G1<br/>(authority correctness)"]
    q1 -->|Yes| g2["Require G2<br/>(outcome binding)"]

    q2{"Need it immediately?"}
    q2 -->|Yes| od["On-demand: full consensus-bound<br/>chained proof, executed now"]
    q2 -->|Can wait| oc["On-cadence: batched ~15 min,<br/>cheaper amortized anchor"]
```

| Situation | Proof requirement |
|---|---|
| Low-value / read-ish operation | Governance up to **G1** may suffice |
| Value-moving transfer | **G2** outcome binding required (effect must match approval) |
| Time-sensitive | **On-demand** with a full consensus-bound chained proof; bounded retries if a layer isn't ready, rather than downgrading |
| Cost-sensitive, batchable | **On-cadence**: combined into a Merkle batch, one shared anchor |

---

## 7. Who consumes proofs, and why

```mermaid
flowchart LR
    proof["A Certen Proof"]
    proof --> u1["External chain contracts<br/>→ to authorize execution"]
    proof --> u2["Accumulate (receipt)<br/>→ to record the outcome"]
    proof --> u3["Web App (Vault page)<br/>→ to show users their evidence"]
    proof --> u4["Enterprises via API Gateway<br/>→ for compliance & reconciliation"]
    proof --> u5["Auditors / regulators<br/>→ for independent verification"]
    proof --> u6["Counterparties<br/>→ to trust the action without trusting Certen"]
```

The single most important point for founders: **the same proof serves all of
these consumers**, because it's verifiable by anyone. That's the product's core
value — *one piece of evidence that everyone, everywhere, can independently
trust*.

---

Continue to **[06 — The Smart Contracts Explained →](./06-contracts-explained.md)**
