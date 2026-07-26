# L4 Validator-Set API Requirements (for Accumulate core)

**Purpose:** the Certen lite client needs to complete **Layer 4** of its proof chain —
verifying an unbroken, signed chain of DN validator-set transitions from a trusted checkpoint
(weak-subjectivity hash, ultimately rooted at genesis + the external BTC/ETH anchors) up to the
DN block height at which a transaction was finalized. This document specifies the two v3 API
methods required: **`ValidatorSetQuery`** and **`ValidatorTransitionQuery`**.

This unblocks the only remaining trust assumption in the lite client. Today L1–L2 (account → BPT
→ app_hash) are proven; the consensus app_hash is bound; but the **validator signatures and their
lineage to genesis are still trusted from the API**. These two methods make that step trustless.

---

## 0. The non-negotiable design principle: responses must be PROOF-BEARING

The verifier must never have to *trust* that "these are the validators." Every response must carry
the cryptographic material to **recompute** the answer against a consensus-committed `app_hash` and
a signed CometBFT header. Concretely, that means each response includes:

1. **A Merkle receipt** from the on-chain record that holds the data (e.g. `acc://dn.acme/network`)
   up to the **DN state-tree anchor (`app_hash`)** at the requested height — same receipt shape the
   client already verifies for L1/L2 (`{start, anchor, entries:[{hash,right}]}`, recomputed with
   `SHA-256(left||right)`).
2. **The header binding** — the CometBFT `Header.ValidatorsHash` / `NextValidatorsHash` at the
   relevant height, so the validator set can be tied to a *signed* header (via the commit returned
   by the companion `ConsensusProofQuery`).

**Canonical encoding is mandatory and must be documented.** The exact byte encoding used to (a)
hash the validator set into `ValidatorsHash` and (b) hash Merkle receipt nodes MUST be specified so
the client reproduces them bit-for-bit. A single encoding mismatch fails the whole proof. State
explicitly: validator ordering, the per-validator serialized form, and the tree hash function.

### Companion endpoints (referenced, specced separately)
- **`ConsensusProofQuery(partition, height)`** → the CometBFT `SignedHeader` for that height: full
  `Header` (incl. `AppHash`, `ValidatorsHash`, `NextValidatorsHash`) + the `Commit` (per-validator
  signatures + the canonical vote bytes/round/part-set-header needed to reconstruct and verify each
  signature). L4 needs this to check "≥2/3 of set S signed height H."
- **`BlockHeaderQuery(partition, height)`** → full header if not already returned by the above.

`ValidatorSetQuery` and `ValidatorTransitionQuery` below assume those exist (or that the signature
data is folded into these two responses — acceptable, but keep it explicit).

---

## 1. `ValidatorSetQuery` — the canonical validator set at a height, with proof

Returns the DN (or a BVN's) validator set **in effect at a specific block height**, with the proof
binding it to that height's consensus-committed state.

### Request
```jsonc
{
  "partition": "Directory",   // required. "Directory" is authoritative for L4. BVN ids also allowed.
  "height": 4146078,          // required. CometBFT block height — SAME height domain as the commit
                              //   the client binds in L3 (i.e. DN_MBI+1 / the height passed to /commit).
  "includeProof": true        // optional, default true. When true, include the proof block below.
}
```

### Response
```jsonc
{
  "partition": "Directory",
  "height": 4146078,
  "appHash": "95fdabd345b878d6...",        // DN state-tree anchor (== CometBFT Header.AppHash at height)
  "validatorsHash": "….",                  // CometBFT Header.ValidatorsHash at height (Merkle root of the set)
  "nextValidatorsHash": "….",              // Header.NextValidatorsHash — the set that signs height+1 (lineage link)
  "totalVotingPower": 3,
  "acceptThreshold": { "numerator": 2, "denominator": 3 },
  "validators": [
    {
      "publicKey":     "40e6e8b96de7...",   // ed25519 consensus signing key (32 bytes hex)
      "publicKeyHash": "309068791543...",
      "votingPower":   1,                    // REQUIRED — BFT is weighted by power, not validator count
      "operator":      "acc://dn.acme/operators/1", // governance identity (ADI/key page) for this key
      "activePartitions": ["Directory", "BVN1"]
    }
    // ...
  ],
  "proof": {
    // (a) set ↔ signed header binding:
    "validatorSetEncoding": "tendermint/v0.x",      // names the canonical encoding used below
    "validatorsHashRecomputable": true,             // canonical-encode(validators) -> SHA-256 == validatorsHash
    // (b) on-chain record ↔ app_hash binding (same receipt shape as L1/L2):
    "stateProof": {
      "account": "acc://dn.acme/network",           // the account that holds the validator set (CONFIRM canonical loc)
      "receipt": {
        "start":   "….",                            // hash of the network-account state entry
        "anchor":  "95fdabd345b878d6...",           // == appHash above
        "entries": [ { "hash": "….", "right": true } /* ... */ ]
      },
      "value": "….(encoded validator-set record)…"  // the raw committed bytes, so the client re-derives `start`
    }
  }
}
```

### Invariants the client will check (the response MUST satisfy these)
1. `SHA-256(canonical_encode(validators))` == `validatorsHash`.
2. `validatorsHash` == `Header.ValidatorsHash` at `height` (from `ConsensusProofQuery`).
3. `stateProof.receipt` recomputes (SHA-256 Merkle, `start → anchor`) to `anchor` == `appHash` ==
   the consensus-committed `Header.AppHash` at `height`.
4. `totalVotingPower` == Σ `validators[].votingPower`.
5. `start` == hash of `stateProof.value` under the documented account-hashing rule.

### Data sources (for the implementer)
- Consensus set + `votingPower` + `ValidatorsHash`/`NextValidatorsHash`: CometBFT state at `height`
  (this is what actually signs blocks; equivalent to CometBFT `/validators?height=`, but returned
  WITH the state proof so it is trustless).
- `operator` / `activePartitions` / `acceptThreshold`: the on-chain governance record
  (`acc://dn.acme/network`, `acc://dn.acme/globals`, `acc://dn.acme/operators`).
- The binding between the two (consensus set ⇔ on-chain record) flows through ABCI
  `ValidatorUpdates`; the response should make that binding explicit (the `stateProof`).

### Errors
- `height` below the available history / pruned → `ErrPruned` with the earliest available height.
- `height` in the future / beyond head → `ErrFutureHeight` with current head.
- unknown `partition` → `ErrUnknownPartition`.

---

## 2. `ValidatorTransitionQuery` — the signed chain of set changes over a range

Returns the **ordered, contiguous list of validator-set changes** between a trusted checkpoint and a
target height, each as an independently verifiable event. This is what lets the client walk (or
skip) from a trusted set to the set that signed the target block.

### Request
```jsonc
{
  "partition": "Directory",   // required
  "fromHeight": 100,          // required. Trusted checkpoint height (weak-subjectivity / genesis-anchored).
  "toHeight":   4146078,      // required. Target height (where the tx was finalized).
  "limit":      100,          // optional pagination
  "after":      "…cursor…",   // optional pagination cursor
  "includeProof": true
}
```

### Response
```jsonc
{
  "partition": "Directory",
  "fromHeight": 100,
  "toHeight": 4146078,
  "transitions": [
    {
      "height": 250120,                       // height at which the NEW set takes effect
      "previousValidatorsHash": "….",         // set in effect immediately before
      "newValidatorsHash": "….",              // set in effect at/after `height`
      "changeType": "add|remove|powerChange|partitionChange",
      "delta": [
        { "publicKey": "….", "votingPower": 2, "action": "add|remove|update" }
      ],
      // Accumulate-native authorization: WHO approved, and that 2/3 was met:
      "governance": {
        "transactionHash": "….",              // the DN governance tx that enacted the change
        "operatorBook": "acc://dn.acme/operators",
        "approvals": [ { "operator": "acc://dn.acme/operators/1", "signature": "…." } ],
        "thresholdMet": { "got": 2, "required": 2, "of": 3 }
      },
      "proof": {
        // change is committed on-chain AND signed by the PRIOR validator set:
        "inclusionReceipt": { "start": "…(txHash)…", "anchor": "…(appHash@height)…", "entries": [ /* ... */ ] },
        "appHash": "….",                       // DN app_hash at `height`
        "commitRef": { "height": 250120, "blockHash": "…." } // -> full commit via ConsensusProofQuery
      }
    }
    // ...
  ],
  "nextCursor": "….",
  "complete": true   // true ⇔ NO transition in [fromHeight, toHeight] was omitted (see invariant 1)
}
```

### Invariants the client will check (these make completeness self-verifying)
1. **Contiguity / no-omission (critical):**
   - `transitions[0].previousValidatorsHash` == `ValidatorSetQuery(fromHeight).validatorsHash`.
   - For every i: `transitions[i].newValidatorsHash` == `transitions[i+1].previousValidatorsHash`.
   - `transitions[last].newValidatorsHash` == the `ValidatorsHash` of the signed header at `toHeight`.
   - ⇒ A dropped or forged transition breaks the hash chain and is detected. The endpoint cannot
     silently omit a change; if it returns a range it must return *every* change in it.
2. **Each transition is signed by the prior set:** the commit at `transition.height`
   (`ConsensusProofQuery`) verifies as ≥2/3 voting power of the set identified by
   `previousValidatorsHash` (resolved via `ValidatorSetQuery`).
3. **Each transition is on-chain:** `inclusionReceipt` recomputes from `governance.transactionHash`
   to `appHash` at `height` (== the consensus-committed app_hash).
4. **Governance authority (Accumulate-native):** `governance.approvals` satisfy the operator
   `acceptThreshold` (2/3) in effect at that height — ties the consensus-key change to authorized
   operators, not just to whoever held the old keys.
5. Pagination must preserve order and contiguity across pages (cursors are monotonic in height).

### Data sources (for the implementer)
- The set-change events themselves: ABCI `ValidatorUpdates` history + the DN governance txns that
  drove them (`acc://dn.acme/operators` votes in `acc://dn.acme/votes` updating `acc://dn.acme/network`).
- `previous/newValidatorsHash`: the CometBFT `ValidatorsHash` before/after each change.
- `inclusionReceipt`: the DN main/anchor chain receipt for the governance tx (same machinery as L1).

### Errors
- `fromHeight` pruned → `ErrPruned` + earliest retained height (the client then needs a newer
  weak-subjectivity checkpoint — see §4).
- `toHeight` < `fromHeight` → `ErrBadRange`.
- range too large → return a page + `nextCursor` (never silently truncate without a cursor).

---

## 3. End-to-end verification the client performs (why each field exists)

Given a target DN height `H` (where a user tx was finalized) and a trusted checkpoint `C`:

1. `set_C  = ValidatorSetQuery(C)`  — trusted (its `validatorsHash` matches the checkpoint).
2. `trs    = ValidatorTransitionQuery(C → H)`.
3. Verify `trs[0].previousValidatorsHash == set_C.validatorsHash` (chain starts at trust).
4. For each transition t in order:
   a. resolve `prevSet = ValidatorSetQuery(t.height-ε)` (or carry it forward);
   b. `ConsensusProofQuery(t.height)` → check the commit is ≥2/3 power of `prevSet` (signed by prior set);
   c. check `t.inclusionReceipt` → `appHash@t.height` (change is really on-chain);
   d. check `t.governance` meets 2/3 operator threshold (authorized);
   e. check `t.newValidatorsHash == trs[next].previousValidatorsHash` (no omission).
5. `set_H = ValidatorSetQuery(H)`; verify `set_H.validatorsHash == trs[last].newValidatorsHash`.
6. `ConsensusProofQuery(H)` → verify ≥2/3 of `set_H` signed `H`, and `Header.AppHash@H` ==
   the DN state-tree anchor the existing L1–L3 proof already binds the user's tx to.

Result: the user's tx is proven finalized under a validator set whose authority chains, hop by
signed hop, back to the trusted checkpoint — with no trust in the API at any step.

---

## 4. Weak-subjectivity checkpoint & external (BTC/ETH) anchors

The chain of trust is only as strong as checkpoint `C`. Accumulate already anchors DN state roots
into Bitcoin/Ethereum for immutability — please make `C` selectable to **coincide with an
externally-anchored DN major block**, so the checkpoint is independently verifiable against the
external L1 (defeating long-range / "nothing-at-stake" rewrites by rotated-out validators).

**Requested companion (optional but ideal):** `ExternalAnchorQuery(partition, height)` →
`{ l1: "bitcoin|ethereum", l1TxOrBlock, anchoredRoot, dnHeight }` so the client can verify the
checkpoint's DN root appears in Bitcoin/Ethereum. If this already exists under another name, point
us at it.

---

## 5. Open questions for the core dev
1. **Canonical encodings** — exact byte layout for (a) the validator-set → `ValidatorsHash` hash and
   (b) Merkle receipt node hashing. (Client currently assumes `SHA-256(left||right)` for receipts.)
2. **Where is the validator set canonically stored on-chain?** `acc://dn.acme/network`? a dedicated
   validator/anchor chain? We need the exact account + entry the `stateProof` should target.
3. **Height domain** — confirm these methods take the **CometBFT block height** (the same height the
   client passes to `/commit` and at which `AppHash` == the DN state-tree anchor), not major-block index.
4. **Do validator changes ride `NextValidatorsHash` in the standard Tendermint way?** If yes, lineage
   can lean on the header chain and `ValidatorTransitionQuery` is largely an indexing convenience over
   it. If Accumulate applies changes differently, we need the transition records to be primary.
5. **Pruning / retention** — what's the earliest height these can answer for? Drives how recent a
   weak-subjectivity checkpoint must be.
6. **External anchors** — current mainnet BTC/ETH anchoring cadence + how to query the anchor for a
   given DN root (see §4).
