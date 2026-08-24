# Phase 5 — Bind L4 into the governance root

**Status:** IMPLEMENTED on `feat/l4-govroot-binding`; P5.1-P5.6 green, P5.7 (Sepolia) NOT RUN
**Date:** 2026-08-24
**Blast radius:** every TX2 on every chain, if botched

---

## 0. The one-line summary

`L4ConsensusProofH` is **zero in every govRoot signed today**, so the on-chain
commitment does not bind L4 at all. Fixing that is a small, purely Go-side
change. The danger is not the change — it is that **three other govRoot slots
have already moved** as a side effect of the L4/G1/G2 correctness work, and a
mixed-version fleet will revert every TX2.

---

## 1. What was verified, and how

Everything below was executed, not read.

| Claim | Method | Result |
|---|---|---|
| `L4ConsensusProofH` is zero in production | `ConsensusProof` field has **0 assignments** in `pkg/`; `SetL4ConsensusProofFromJSON(nil)` returns early | confirmed |
| That zero is pinned as intended behaviour | `v6_1_binding_test.go:254` asserts `nil L4 -> zero` | confirmed |
| The `"nonempty"` literal is NOT in the production path | `ethereum_contracts.go:2478` feeds only the diagnostic log at `:2495`; the real root comes from `SetL4ConsensusProofFromJSON` at `:2467` | **runbook 5.1 concern is a false alarm** |
| `CanonicalJSONMarshal` differs from `json.Marshal` | read `v6_1_binding.go:332` | **false** - it *is* `json.Marshal` plus nil handling |
| The contract recomputes govRoot | read the LIVE contracts in `certen-contracts/evm/src` | **partly false, corrected below** - govRoot IS passed as an explicit `bytes32` argument, but only as opaque bytes. `CertenAnchorV8_1.createAnchor` (line 656) derives `bundleId` from the 8 args and reverts on mismatch; it never derives govRoot from the gov fields. |
| The Go shim matches the live contract | compared ABI method + domain tag | confirmed - Go packs `createAnchor` with 8 args under `"certen:bundleid:v1.1"`, byte-identical to `CertenAnchorV8_1.sol:657`. The `V6_1` in Go identifiers is legacy naming for a shape V8_1 retains. |
| The account contract gates on governance | `grep governanceRoot\|g2Hash\|governanceLevel` in `CertenAccountV7.sol` + `CertenAccountFactoryV9.sol` | **zero hits** - the account contracts have no governance references at all; the "CertenAccountV8 value-operation check" in L4_DESIGN is proposed, not shipped |
| `BLSZKVerifierV2` sees govRoot | read `BLSZKVerifierV2.sol` | **no** - it binds `messageHash` only |
| Only the validator binary computes govRoot | `grep certen:g0:v1` inside every running container | confirmed - present in `/app/validator`, absent from `proof-service`; `api-bridge` is Node/TS |
| All 7 validators run the same code | `sha256sum /app/validator` in all 7 containers | confirmed identical: `009c0210f0eb...` (the 3 differing image IDs are per-service tags over the same binary) |
| My struct additions changed govRoot slots | marshalled the structs with and without the new fields | **true, all three** |

### 1.1 The false alarm

Runbook 5.1 says to "confirm the production path does not share that shortcut".
It does not. `l4H = HashL4ConsensusProof([]byte("nonempty"))` exists solely to
populate the `EVM-GOV-INPUTS` diagnostic log line.

That log is nonetheless **actively harmful**: it exists to make signer/submitter
divergence identifiable by direct comparison, and it prints an L4 value that is
not the one in the root. Anyone debugging a divergence would be misled. Fix it
in the same change.

### 1.2 The real danger — already introduced

`CanonicalJSONMarshal` is `json.Marshal`. Struct layout therefore *is* the wire
format, and any field added to a result struct changes its govRoot slot.
Three fields were added during phases 4A-4C:

| Field added | Slot it moves | Severity |
|---|---|---|
| `ReceiptData.Entries` | **G0CanonicalHash** | worst - no `omitempty`, so it emits `"entries":null` even when nil, moving G0 for **every** proof unconditionally |
| `G1Result.SignatureRouteStatus` | **G1CanonicalHash** | moves whenever route status is recorded, which is always |
| `G2Result.OutcomeBinding` | **G2CanonicalHash** | moves whenever G2 runs |

Measured: G0 JSON 287 -> 311 bytes; G1 1165 -> 1274; G2 1736 -> 1899.

**These hashes SHOULD move** - the proofs now carry strictly more evidence, and
committing to it is the point. But the move must be deployed atomically.

---

## 2. Consequence: the deploy constraint

```
govRoot ──▶ bundleId(anchorId) ──▶ messageHash ──▶ BLS signature
                 │                                       │
                 └──── passed as calldata ───────────────┴──▶ contract:
                        require(bundleId == deriveV6_1BundleID(8 args))
                        + BLS verify over recomputed messageHash
```

`CertenAnchorV8_1.createAnchor` takes `bytes32 governanceRoot` as an explicit
argument, so govRoot does reach the chain - but only as opaque bytes:

```solidity
bytes32 derivedBundleId = keccak256(abi.encodePacked(
    "certen:bundleid:v1.1", DEPLOYMENT_CHAIN_ID, adiURLHash,
    operationCommitment, crossChainCommitment, governanceRoot,
    executionCommitment, operationID, accumulateBlockHeight));
if (!(bundleId == derivedBundleId)) revert BundleIdMustDeriveFromCommitmentsOpID();
```

The contract checks that the `bundleId` it was handed matches a re-derivation
from the 8 arguments it was handed. **It has no opinion on how govRoot was
computed.** Elsewhere it only ever wraps the value
(`keccak256("certen:gov:", governanceRoot)`) for a merkle leaf.

The failure mode is therefore not a contract mismatch, it is a signer/submitter
mismatch:

- validators SIGN `messageHash` derived from *their* `govRoot -> bundleId`
- the elected submitter builds calldata from *its* `govRoot -> bundleId`
- if those differ, the aggregated BLS signature does not verify against the
  messageHash the contract recomputes, and **TX2 reverts**

This is true *today*, before Phase 5, purely from the 4A-4C struct changes.

### What actually has to be redeployed

| Component | Redeploy? | Why |
|---|---|---|
| **`certen-validator-1..7`** | **YES, all seven, atomically** | `/app/validator` is the only binary that computes govRoot. It contains BOTH `pkg/consensus` (BLS signer) and `pkg/execution` (EVM submitter), so one image covers both roles - but the submitter is an *elected* node, and it must not be running different code from the signers. |
| **Smart contracts** | **NO** | Verified against the four live contracts, not the legacy ones: `CertenAnchorV8_1` takes govRoot as opaque `bytes32`, stores it, merkles it and compares it, but never derives it; `CertenAccountV7` and `CertenAccountFactoryV9` contain **no** governance references whatsoever; `BLSZKVerifierV2` binds `messageHash` only. Changing how govRoot is computed changes the VALUE, not the ABI, the contract logic, or any address. No Solidity change, no redeploy. |
| `api-bridge` | NO | Node/TypeScript; computes no govRoot. |
| `certen-proof-service` | NO | verified: no `certen:g0:v1` / `certen:bls:v1:pre` domain tags in its binary. |

So the answer to "do we need to update the validator nodes, or redeploy
contracts?" is: **validator nodes only, and all seven together.**

### Requirement

**All seven validators must upgrade in one atomic step.** There is no partial
rollout. Options, in order of preference:

1. **Atomic fleet deploy.** Stop all 7 validators, deploy, restart. Simplest;
   requires a maintenance window with no in-flight intents.
2. **Version the govRoot computation.** Add an explicit `govRootVersion` to the
   inputs and a `ComputeAccumulateGovRootV2`. Old nodes keep signing v1, new
   nodes sign v2, and the submitter selects by version carried on the intent.
   Safer for a live fleet, materially more work, and adds a permanent branch.
3. **Freeze the struct layout.** Give the three new fields `json:"-"` so they
   never enter the hash. Rejected: `Entries` is genuine evidence that *should*
   be committed to, and `OutcomeBinding` is the entire G2 claim. Excluding them
   would recreate the defect this work removed - a proof whose commitment is
   weaker than its content.

Recommendation: **(1)** if a window is available, **(2)** if not. Do not ship
(3).

### Concrete procedure for option (1)

Preconditions, each verified before touching anything:

1. `P5.7` (Sepolia cycle) green on the new binary.
2. No intents in flight: `SELECT count(*) FROM certen_intents WHERE status NOT
   IN ('completed','failed');` returns 0.
3. New binary built once and its sha256 recorded, so all seven can be checked
   to be identical afterwards - today they are `009c0210f0eb...`.

Then:

```
# stop all seven together, so no node signs with one version while
# another submits with the other
docker compose stop certen-validator-{1..7}
# deploy the new image, start all seven
docker compose up -d certen-validator-{1..7}
# verify homogeneity BEFORE releasing traffic
for i in $(seq 1 7); do docker exec certen-validator-$i sha256sum /app/validator; done | sort -u | wc -l   # MUST be 1
# verify the payload verifier survived the rebuild (4B deploy assert)
for i in $(seq 1 7); do docker exec certen-validator-$i sh -c 'test -x /app/txhash || echo MISSING'; done
```

Rollback is the same procedure with the previous image. Because the govRoot
change is deterministic and stateless, rolling back restores the old hashes
exactly; no data migration is involved either way.

---

## 3. The Phase 5 change itself

Small, and the atomicity requirement is satisfied structurally: signer
(`v6_1_signing.go`, 7 call sites) and submitter (`ethereum_contracts.go:2467`)
call the **same function on the same field of the same object**. Populate that
field once and both sides move together.

### 3.1 Replace the L4 payload type

`proof.ConsensusProof` is the old CometBFT shape and nothing writes it:

```go
type ConsensusProof struct {
    BlockHash           []byte
    ValidatorSignatures [][]byte
    SignedPower         int64
    TotalPower          int64
}
```

It cannot represent the real L4: two legs, per-partition validator sets, per-leg
thresholds, and the canonical signed bytes. Replace the field's contents with a
structure derived from the stored `Layer4BVN` + `Layer4DN`.

**Hash exactly what the verifier checks.** Do not hash the whole `Layer4` struct
- it carries `SequencedMessage` (up to ~2 KB of hex per leg) and the full
validator set, which are needed to *verify* but bloat the preimage and couple
the hash to incidental encoding. Hash the conclusions instead:

```go
// L4GovRootPayload is what the govRoot commits to for L4. Every field is a
// value the offline verifier independently establishes; nothing here is
// asserted.
type L4GovRootPayload struct {
    Version string `json:"v"` // "certen:l4gov:v1" - explicit, so a later
                              // change is a visible version bump, not a
                              // silent hash move
    BVN struct {
        Partition       string   `json:"partition"`
        SignedHash      string   `json:"signedHash"`      // what the quorum signed
        StateTreeAnchor string   `json:"stateTreeAnchor"` // what it binds
        RootChainAnchor string   `json:"rootChainAnchor"`
        MinorBlockIndex uint64   `json:"minorBlockIndex"`
        Threshold       uint64   `json:"threshold"`
        Signers         []string `json:"signers"` // SORTED pubkey hex
    } `json:"bvn"`
    DN struct { /* identical shape */ } `json:"dn"`
}
```

`Signers` **must be sorted**. Signature order is whatever the API returned and
is not stable across queries; an unsorted list would make the hash
nondeterministic between two nodes reading the same anchor. This is the single
easiest way to produce an intermittent, unreproducible TX2 revert.

### 3.2 Populate it where the proof is built

`bft_integration.go`, in the same block that now requires G0-G2, after the
lite-client proof is available:

```go
certenProof.LiteClientProof.ConsensusProof = BuildL4GovRootPayload(
    chainedProof.Layer4BVN, chainedProof.Layer4DN)
```

Both legs are already mandatory (`ProofVerifier.Verify` rejects a nil leg), so
the payload can never be half-populated.

### 3.3 Fail closed

`SetL4ConsensusProofFromJSON` silently returns on `nil` and on a marshal error,
leaving the slot zero. With L4 now mandatory, a zero L4 slot means "we failed to
commit to evidence we hold" and must be an error, not a default. Either:

- add `SetL4ConsensusProofFromJSONStrict` returning an error, or
- assert `L4ConsensusProofH != [32]byte{}` at the signing site.

The second is smaller and catches the same failure.

### 3.4 Fix the misleading diagnostic

Replace `ethereum_contracts.go:2478` with the real value:

```go
if b, err := json.Marshal(lc.ConsensusProof); err == nil {
    l4H = contracts.HashL4ConsensusProof(b)
}
```

---

## 4. Verification plan — nothing ships unverified

| # | Check | Method |
|---|---|---|
| P5.1 | Signer and submitter produce byte-identical govRoot | unit test calling both paths with one proof object; assert equality |
| P5.2 | `L4ConsensusProofH != 0` | assert on a real proof built from live Kermit |
| P5.3 | The hash is deterministic across repeated builds | build the same proof twice, assert identical payload bytes |
| P5.4 | Signer order does not affect the hash | shuffle `Layer4.Signatures`, assert the payload is unchanged |
| P5.5 | A mutated L4 leg changes the hash | flip `StateTreeAnchor`, assert the hash moves |
| P5.6 | The govRoot moves vs today | assert new govRoot != old govRoot for the same intent - this is the deploy-gate evidence, not a regression |
| P5.7 | One full CERTEN cycle succeeds on Sepolia | **e2e, mandatory before fleet deploy - NOT RUN** |
| P5.8 | Mixed-version divergence is detectable | run old and new binaries over one intent, diff the `EVM-GOV-INPUTS` line; must differ visibly in the L4 slot |

**P5.7 is the gate.** Everything up to P5.6 can pass while the on-chain verify
still reverts. It has not been run, and Phase 5 must not ship until it has.

---

## 5. Ordering

1. Fix the misleading diagnostic log (§3.4) - independent, zero risk.
2. Land `L4GovRootPayload` + population + strict check (§3.1-3.3) behind P5.1-P5.6.
3. Run P5.7 on Sepolia.
4. Choose the rollout (§2) and execute it atomically.

Steps 1-2 are safe to land on the branch now; they change no deployed
behaviour until the fleet is upgraded. **Step 4 is the irreversible one.**

---

## 6. Open question for the operator

The govRoot has already moved for G0/G1/G2 (§1.2). That change is on this
branch and is not yet deployed. Whether Phase 5 ships *with* it or *after* it,
the atomic-deploy requirement is the same and applies once. Shipping them
together costs one window instead of two.


---

## 7. Implementation record

Landed on `feat/l4-govroot-binding`.

| Plan item | What was done |
|---|---|
| §3.1 payload type | `ConsensusProof` in `healing_proof.go` REPLACED, not extended. Its CometBFT shape (BlockHash / ValidatorSignatures / SignedPower / TotalPower) was fully dead - zero writers - and could not represent two legs. It now carries `Version` + `BVN`/`DN` `L4LegSummary`. |
| §3.1 sorted signers | `summarizeL4Leg` lowercases, sorts, and de-duplicates. Pinned by `TestP5_SignerOrderDoesNotAffectTheHash` across 4 orderings, duplicates, and mixed case. |
| §3.2 population | One origin only: `ChainedProofToCompleteProof`. It flows to the signer via `CompleteProof.ConsensusProof` -> `LiteClientProofData.ConsensusProof`. **The 7 signing call sites and the 1 submitter call site were NOT touched**, which is what guarantees they cannot diverge. |
| §3.3 fail closed | `RequireL4Committed`, called once at the proof-assembly point in `bft_integration.go` beside the G0-G2 requirement. Rejects nil payload, missing leg, no version, zero threshold, signers-below-threshold, and both-legs-same-partition. |
| §3.4 diagnostic | `ethereum_contracts.go` now hashes the real payload instead of the literal `"nonempty"`. |

### One thing the plan did not anticipate

`ethereum_contracts.go:1991` read `ConsensusProof.SignedPower` as an override for
signed voting power. A grep for `ConsensusProof.` missed it because the variable
is named `cp`. The branch had **never executed** (ConsensusProof was always
nil), so removing it preserves current behaviour exactly - but it would have
started firing the moment the field was populated. L4 threshold signing is a
count of distinct signers against a per-partition threshold, not voting power;
remapping one to the other would have been a category error. The override was
deleted rather than translated.

### Verification actually run

| # | Result |
|---|---|
| P5.1 signer/submitter agree | PASS - byte-identical, non-zero |
| P5.2 slot non-zero | PASS - and still zero when a leg is genuinely absent |
| P5.3 deterministic | PASS - 20 builds identical |
| P5.4 order-independent | PASS - 4 orderings, duplicates collapse, case-insensitive |
| P5.5 mutation changes hash | PASS - 10 mutations, all move the hash |
| P5.6 govRoot moves | PASS - `70570381...` -> `e23ce107...` |
| guard fails closed | PASS - 10 rejection cases |
| **live proof** | PASS - real Kermit proof commits `aae1cb5763...`; BVN1 1/1 and Directory 3 signers/threshold 2; both legs bind L2/L3 |
| **P5.7 Sepolia cycle** | **NOT RUN - this is the deploy gate** |

The govRoot now moves for a second reason (L4), on top of the G0/G1/G2 moves
already on `main`. The atomic-deploy requirement in §2 is unchanged and still
applies exactly once.
