
# CERTEN Governance Proof Specification

## Accumulate v3 — Proof-Grade, Deterministic, Fail-Closed

`services/validator/docs/CERTEN_GOVERNANCE_PROOF_SPEC.md`

**Status:** Draft (Dec 2025)
**Spec Version (normative):** `v3-governance-kpsw-exec-4.0`
**Compatibility:** Accumulate v3 JSON-RPC (`/v3`, `method=query`)
**Baseline:** v3 chained finality spec + DevNet-validated governance traces
**Supersedes:** `v3-governance-kpsw-exec-3.0`

---

## 0. Normative Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

This document defines a governance proof that is:

* **Deterministic:** identical inputs yield identical verification results.
* **Fail-closed:** missing data, ambiguity, unknown transaction types, or unverifiable cryptography causes failure.
* **Receipt-anchored:** every asserted fact is bound to Accumulate commitments via receipts and Certen chained finality proofs.

---

## 1. Scope and Claims

A proof **MUST** declare exactly one claim level.

### 1.1 G0 — Inclusion and Finality Only (No Governance)

G0 proves only that a specific chain entry was committed to Accumulate state and finalized by consensus.

**G0 MUST NOT claim authorization correctness.**

---

### 1.2 G1 — Governance Correctness (Default)

G1 proves:

1. A specific execution chain entry was committed at an execution witness, and
2. The verifier can independently re-derive the rules listed in §1.2.1 **at
   execution time**, and records — rather than re-derives — the rules listed in
   §1.2.2.

An earlier form of this section said the verifier "can independently validate
that Accumulate's governance rules were satisfied". That claimed the whole of
Accumulate's authorization model. It is not the whole, and the gap is not a
detail: the single-key-page assumption looked correct for four hundred
production proofs precisely because nothing here said which rules were in scope.
**An overclaiming spec is its own defect.** The two lists below are exhaustive
and MUST be kept so.

#### 1.2.1 Rules G1 RE-DERIVES

A G1 verifier re-derives each of these from chain data, independently of any
API's opinion:

* **Signer key page identity and version (KPSW-EXEC).** The page's genesis is
  located and every mutation up to the execution block is replayed, each step
  receipt-bound. Every signature is evaluated against the page **as it stood at
  execution** and against no other state. A version that does not match that
  state is a finding; a page that has merely changed *since* is not evaluable
  and MUST NOT be reported as a refusal.
* **Key membership**, over the page's full entry set — key entries and delegate
  entries alike.
* **Accept-threshold satisfaction**, over distinct satisfied entries.
* **The account's whole authority set.** Every authority named on the account
  must be satisfied, not merely the one holding the signer's page; any page of a
  book satisfies that book; a disabled authority is skipped unless the body type
  requires authorization.
* **Additional authorities the transaction itself requires**, derived from the
  body and header exactly as `Transaction.GetAdditionalAuthorities` does — an
  `UpdateKeyPage` that adds or updates a delegate requires that delegate's
  approval, an `UpdateAccountAuth` that adds an authority requires that
  authority's, and the creation transactions require the authorities their body
  names.
* **Execution-time eligibility of signatures** (ordering before execution), by
  `receipt.localBlock <= execMBI` where both indices count the same chain.

#### 1.2.2 Rules G1 RECORDS but does NOT re-derive

Each of these is carried in the proof's evidence, naming the rule, its value and
why it was not re-derived. A proof that reaches any of them and stays silent is
non-conforming.

* **`responseThreshold`.** It gates on votes of every kind — accepts, rejects
  and abstains — per delegation path. G1 enumerates the signatures it can
  validate as accepts and cannot claim to have counted votes it did not
  enumerate. Since the transaction executed, the network's own `SignerWillVote`
  found the threshold met; that fact is **inherited from execution**, not
  re-derived. Recorded as `response-threshold-not-recounted`.
* **`rejectThreshold`.** The executor tests accept before reject and the
  transaction executed, so this cannot have changed the outcome. Recorded as
  `reject-threshold-moot-after-execution` — present, and not in doubt.
* **`blockThreshold`.** `accumulate-core` does not enforce it against the page:
  `blockThresholdIsMet` reads the transaction's `HoldUntil` header, under a TODO
  saying page-level minimum thresholds do not yet exist. Verifying it would
  claim more than the protocol implements. Recorded as
  `block-threshold-not-enforced-by-protocol`.
* **Ordering for a CROSS-PARTITION signer.** The `localBlock <= execMBI`
  comparison is skipped, correctly — those indices count different chains, and
  comparing them is not a weak check but a meaningless one that returns a
  confident answer. Ordering rests instead on **execution inclusion**: Accumulate
  does not execute a transaction whose signatures came after execution, and G0
  proves it executed. That is strictly weaker than a local re-derivation and is
  named per signature in the proof's timing evidence.
* **The state of pages reached THROUGH delegation.** The principal's page is
  replayed to the execution block; pages reached by delegation are queried once
  and their current state used. Every resolution link records which of the two
  it was.

#### 1.2.3 Capability limits — NOT governance verdicts

These are stated as errors and MUST NOT be reported as governance rejections,
threshold shortfalls, or refusals:

* A signature type CERTEN does not verify (only `ed25519` and `delegated` are
  verified).
* A transaction that has **not executed** — pending, or absent — which has no
  authority set to evaluate against.
* An authority, page or signature that could not be READ. An authority that
  could not be read is not an authority that refused.
* A key page operation type this implementation does not recognise, which it
  MUST fail on rather than assume introduces no authority.

---

### 1.3 G2 — Governance Correctness + Outcome Binding

G2 includes G1 and additionally proves a **success-only, receipt-proven outcome** bound under the execution witness.

**G2 MUST NOT be claimed** unless such an outcome leaf exists and is receipt-proven.

---

## 2. Cryptographic Ground Rules

### 2.1 Ground Truth (MUST)

The verifier MUST treat the following as cryptographic ground truth:

1. A **receipt** binds a specific chain entry leaf to an anchor root.
2. A **leaf identity** is a 32-byte hash (`HEX32`).
3. Any missing receipt, mismatched hash, unverifiable signature, or unknown governance mutation **MUST fail**.

---

### 2.2 Expanded JSON Is Not Evidence (MUST)

Responses obtained with `expand=true` are **not cryptographic evidence**.

Any value extracted from expanded content MUST be bound to a receipt-proven chain entry whose leaf hash equals the receipt-proven leaf.

If this binding cannot be proven deterministically, verification MUST fail.

---

## 3. Identifiers and Hash Domains (Normative)

### 3.1 Primitive Types

* `HEX32` — exactly 64 hexadecimal characters.
* `MSGID` — `acc://<HEX32>@<scope>`.

---

### 3.2 Distinct Identifiers (CRITICAL)

The following identifiers are **distinct and MUST NOT be conflated**:

#### 3.2.1 `TXID` — Message ID Hash

* The `<HEX32>` used in `MSGID`.
* Commonly equals the chain entry leaf for transaction-chain entries.

#### 3.2.2 `TX_HASH` — Canonical Transaction Hash

* The value referenced by `signature.transactionHash`.
* Defined by Accumulate’s canonical transaction hashing rules.

#### 3.2.3 `ENTRY_HASH`

* The leaf hash of a specific chain entry.
* For transaction-chain entries, this is typically `TXID`.
* For signature-chain entries, this is the hash component of the `MSGID`.

A proof **MUST explicitly state** which identifier is being proven at each step.

---

## 4. Proof Bundle Requirements

A governance proof MUST be verifiable offline.

### 4.1 Required Artifacts (MUST)

1. **Execution inclusion artifact**

   * v3 response proving inclusion of the execution chain entry (`ENTRY_HASH_exec`) with a receipt.
2. **Expanded execution message artifact**

   * v3 response with `expand=true` for the execution entry (locator only).
3. **Governance message artifacts**

   * v3 responses locating each referenced `MSGID` as a `signature` chain entry with receipt and expansion.
4. **KPSW-EXEC artifacts**

   * `P#main` chain count.
   * Full enumeration of `P#main` entries with receipts and expansion sufficient to classify governance events.
5. **Signature enumeration artifacts**

   * Enumeration of `P#signature` entries and single-entry resolution for each counted candidate.

---

### 4.2 Bundle Integrity (MUST)

Each raw response MUST be hashed (`sha256`) over the exact response bytes.

Verification MUST fail if any artifact hash does not match.

---

## 5. Execution Witness Derivation

### 5.1 Execution Inclusion (MUST)

The proof MUST include a receipt proving inclusion of the **execution chain entry**.

**Verifier MUST enforce:**

1. `receipt.start == chainEntry.entry == ENTRY_HASH_exec`
2. `ENTRY_HASH_exec == TXID` for the execution entry
3. `receipt.localBlock` parses as integer > 0

**Derived values:**

* `EXEC_MBI := receipt.localBlock_int`
* `EXEC_WITNESS := receipt.anchor`

**IMPORTANT:**
The execution receipt **MUST NOT** be required to bind directly to `TX_HASH`.

---

### 5.2 Expanded Execution Binding (MUST)

When using `expand=true` on the execution entry, the verifier MUST assert:

* The expanded object contains a stable identifier (`message.id` or equivalent),
* That identifier equals `acc://<ENTRY_HASH_exec>@<scope>`.

If this equality does not hold, verification MUST fail.

---

## 5.3 Normative Query Templates and Option Sets (MUST)

All queries are JSON-RPC `method:"query"` to the Accumulate v3 endpoint `/v3`.

### 5.3.1 Canonical Request Envelope (MUST)

Every request MUST be of the form:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "query",
  "params": {
    "scope": "acc://<SCOPE>",
    "query": { /* see templates below */ }
  }
}
```

A verifier MUST treat the tuple `(endpoint, scope, query)` as part of the artifact identity recorded in the proof bundle (§4.2).

---

### 5.3.2 Receipt Option Policy (Determinism) (MUST)

To prevent nondeterministic receipt selection, the proof MUST use the following policy:

**A) Single-entry proofs that define witness (`EXEC_MBI`, timing, etc.)**
MUST use:

* `includeReceipt: true` (boolean)
* `expand: true` where decoding is required for binding checks

**B) Range enumeration where receipts are only used as “some anchor for that entry”**
MAY use `includeReceipt: { "forAny": true }` **only** if:

1. every enumerated entry is later re-queried with a single-entry query using `includeReceipt:true` when it is used as evidence, and
2. the verifier rejects any entry that is missing `localBlock` in the receipt.

If an implementation cannot guarantee (B1–B2), it MUST NOT use `forAny:true` and MUST use `includeReceipt:true` everywhere.

---

## 6. Governance Message Location

### 6.1 Locating Messages by MSGID (MUST)

For each `MSGID = acc://<H>@<SCOPE>` used by the proof:

* Query `SCOPE`, chain `signature`, entry `H`, `includeReceipt:true`, `expand:true`.

Verifier MUST enforce:

1. Exactly one chain entry exists.
2. `chainEntry.entry == H`
3. `receipt.start == H`
4. Expanded message ID equals `MSGID`.

---

### 6.2 Execution-Time Eligibility (MUST)

Any governance message asserted as part of execution MUST satisfy:

* `receipt.localBlock_int <= EXEC_MBI`

---

## 7. Signature Evidence Model

### 7.1 Required Page Signature (MUST)

At least one Ed25519 signature message `S_page` MUST exist such that:

* Located on `P#signature`
* `signature.type == "ed25519"`
* `signature.transactionHash == TX_HASH`
* `signature.signer == P`
* `receipt.localBlock_int <= EXEC_MBI`

---

### 7.2 Expanded Signature Binding (MUST)

For each counted signature:

* Expanded message ID MUST equal `acc://<ENTRY_HASH>@<scope>`,
* `ENTRY_HASH` MUST equal the receipt-proven leaf.

---

## 8. KPSW-EXEC — Key Page State at Execution

### 8.1 Scope Constraint (EXPLICIT)

**This specification supports only single-page authority transactions.**

If a transaction requires multiple authorities or signer pages, verification MUST fail.

---

### 8.2 Governance Event Discovery

Governance state is derived exclusively from `P#main`.

Allowed governance events:

**Genesis**

* `syntheticCreateIdentity` containing a Key Page definition for `P`.

**Mutation**

* `updateKeyPage` with `principal == P`.

Any other transaction with `principal == P` **MUST fail**.

---

### 8.3 Enumeration Integrity (MUST)

The verifier MUST:

1. Retrieve `chain(main).count == N`,
2. Enumerate **exactly N** `P#main` entries,
3. Classify every entry deterministically.

---

### 8.4 State Derivation (MUST)

Let `Events_le_exec` be all governance events with `localBlock <= EXEC_MBI`.

Sort by:

1. `localBlock`
2. `chainIndex`

Rules:

1. Exactly one genesis event MUST exist.
2. Apply all mutations ≤ `EXEC_MBI`.
3. Resulting state is `State_exec(P)`.

---

### 8.5 Binding State to Signatures (MUST)

For each counted signature `S_i`:

* `S_i.signerVersion == State_exec(P).version`
* `KeyHash(S_i.publicKey) ∈ State_exec(P).keys`

KeyHash MUST be computed using Accumulate protocol rules.

---

### 8.6 Threshold Satisfaction (MUST)

Let `Threshold := State_exec(P).threshold`.

Verifier MUST:

1. Verify all eligible signatures cryptographically,
2. Count **unique** valid member keys,
3. Require `count >= Threshold`.

---

## 9. Finality Requirements (MUST)

The proof MUST include Certen chained finality proofs for:

* `EXEC_WITNESS`
* Every anchor used by governance events contributing to `State_exec(P)`

Missing finality proof ⇒ fail.

---

## 10. Outcome Binding (G2 Only)

A G2 proof MUST bind a success-only, receipt-proven outcome leaf under `EXEC_WITNESS`.

If such a leaf cannot be proven, the proof MUST fall back to G1.

---

## 11. Deterministic Verification Procedure

A verifier MUST:

1. Validate artifact hashes.
2. Derive execution witness.
3. Bind expanded execution message to receipt leaf.
4. Locate governance messages and enforce timing.
5. Identify signer page `P`.
6. Compute `State_exec(P)`.
7. Bind signatures to state and verify threshold.
8. Verify all required finality proofs.
9. (If G2) verify outcome binding.

Any failure ⇒ proof invalid.

---

## 12. Explicit Fail-Closed Conditions (Normative)

Verification MUST fail if:

* Any receipt hash mismatch occurs,
* Any expanded message ID does not equal its receipt leaf,
* Any counted signature occurs after execution,
* Any unsupported governance mutation appears,
* Multiple signer pages are required,
* Any required finality proof is missing.

---

## 13. Implementation Guidance (Non-Normative)

* Use Accumulate libraries for hashing, signature verification, and key-page mutation logic.
* Never infer hash identity by equality unless explicitly proven.
* Expand governance support only by explicitly extending the allowlist.

---

## Appendix A — Query Templates (Normative)

The following templates are **normative**. A proof bundle MUST record the exact JSON used.

### A.1 Execution Inclusion by Chain Entry (MUST)

Purpose: prove inclusion of `ENTRY_HASH_exec` and derive `EXEC_MBI` and `EXEC_WITNESS`.

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<TX_PRINCIPAL_SCOPE>",
    "query":{
      "queryType":"chain",
      "name":"main",
      "entry":"<ENTRY_HASH_exec>",
      "includeReceipt":true,
      "expand":true
    }
  }
}
```

Verifier MUST enforce:

* `receipt.start == chainEntry.entry == <ENTRY_HASH_exec>`
* expanded `message.id == acc://<ENTRY_HASH_exec>@<TX_PRINCIPAL_SCOPE>`

---

### A.2 Locate Signature Message by MSGID (MUST)

Given `MSGID = acc://<H>@<SCOPE>`:

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<SCOPE>",
    "query":{
      "queryType":"chain",
      "name":"signature",
      "entry":"<H>",
      "includeReceipt":true,
      "expand":true
    }
  }
}
```

Verifier MUST enforce:

* `chainEntry.entry == <H>`
* `receipt.start == <H>`
* expanded `message.id == acc://<H>@<SCOPE>`

---

### A.3 Get `P#main` Chain Count (MUST)

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<P>",
    "query":{
      "queryType":"chain",
      "name":"main"
    }
  }
}
```

Verifier MUST parse:

* `count == N` (must exist and be integer)

---

### A.4 Enumerate `P#main` Entries (Paged) (MUST)

This enumeration is for discovering governance events. Use `forAny:true` only if you also satisfy §5.3.2(B).

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<P>",
    "query":{
      "queryType":"chain",
      "name":"main",
      "range":{"start":<START>,"count":<COUNT>},
      "includeReceipt":{"forAny":true},
      "expand":true
    }
  }
}
```

Verifier MUST enforce:

* exactly `N` total entries are retrieved across pages
* every entry required for classification contains sufficient fields
* any missing receipt fields needed for classification → fail

If you do not use §5.3.2(B), replace `includeReceipt:{forAny:true}` with `includeReceipt:true`.

---

### A.5 Enumerate `P#signature` Entries (Range, Locator Only) (MAY)

Purpose: list candidate entries; **not** evidence until resolved.

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<P>",
    "query":{
      "queryType":"chain",
      "name":"signature",
      "range":{"start":<START>,"count":<COUNT>},
      "includeReceipt":false,
      "expand":false
    }
  }
}
```

---

### A.6 Resolve a Single Signature Entry (Evidence) (MUST)

For each candidate `<ENTRY_HASH_sig>` you intend to count or otherwise use as evidence:

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<P>",
    "query":{
      "queryType":"chain",
      "name":"signature",
      "entry":"<ENTRY_HASH_sig>",
      "includeReceipt":true,
      "expand":true
    }
  }
}
```

Verifier MUST enforce:

* `receipt.start == chainEntry.entry == <ENTRY_HASH_sig>`
* expanded `message.id == acc://<ENTRY_HASH_sig>@<P>`
* `receipt.localBlock_int <= EXEC_MBI` for counted signatures

---

### A.7 Resolve Signature Message by MSGID (MUST)

When resolving a signature message using its complete MSGID (e.g., from canonical signatureSet enumeration):

Given `MSGID = acc://<H>@<SCOPE>`:

```json
{
  "jsonrpc":"2.0","id":1,"method":"query",
  "params":{
    "scope":"acc://<H>@<SCOPE>",
    "query":{
      "queryType":"default",
      "includeReceipt":{"forAny":true},
      "expand":true
    }
  }
}
```

Verifier MUST enforce:

* Response contains exactly one message record
* `message.id == acc://<H>@<SCOPE>` (exact MSGID match)
* `message.type == "signature"`
* `signature.type == "ed25519"` for counted signatures
* `receipt.start == <H>`
* `receipt.localBlock_int <= EXEC_MBI` for counted signatures

**Note:** This template is used when signature messages are referenced by their complete MSGID rather than by chain entry enumeration. The `queryType:"default"` with MSGID scope directly locates the signature message, while `includeReceipt:{"forAny":true}` ensures timing validation capability.

---

## Appendix B — Canonical Curl Templates (Illustrative)

These are non-normative formatting helpers. Proof logic MUST follow the JSON templates above.

**Bash:**

```bash
V3="http://127.0.0.1:26660/v3"
curl -sS -X POST "$V3" -H "Content-Type: application/json" --data-raw @request.json
```

**PowerShell:**

```powershell
$V3="http://127.0.0.1:26660/v3"
curl.exe -sS -X POST $V3 -H "Content-Type: application/json" --data-raw (Get-Content -Raw request.json)
```
