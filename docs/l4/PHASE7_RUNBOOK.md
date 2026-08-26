# Phase 7 — Implementation Runbook

**Companion to:** `PHASE7_DELEGATION_PLAN.md`
**Date:** 2026-08-24
**Estimated:** ~19 working days
**Blast radius:** `consolidated_governance-proof/`, `working-proof_do_not_edit/`, `pkg/proof/`, `pkg/consensus/` — and **govRoot**

> ⚠️ Every step is gated. Do not proceed past a failed gate.
>
> ⚠️ **This phase moves govRoot.** Unlike Phase 6, that is expected — once, at
> the end, under a bumped `L4GovRootVersion`. If govRoot moves *twice*, or moves
> before Phase 8, stop: the change has leaked into a slot that was not planned
> to move.
>
> ⚠️ **`working-proof_do_not_edit/` is edited in this phase.** The directory
> name is a warning, not a prohibition — §4 changes `ChainedProof` itself.
> Treat every edit there as load-bearing.

---

## Phase 0 — Safety (MANDATORY, do first)

### 0.1 Backup

A verified backup already exists for this work:

```
_PROOF_BACKUPS/20260824_210857   180 files, sha256sum -c → all OK
```

Take a fresh one anyway if any time has passed:

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator/accumulate-lite-client-2/liteclient/proof"
TS=$(date +%Y%m%d_%H%M%S); BK="_PROOF_BACKUPS/$TS"; mkdir -p "$BK"
cp -r working-proof_do_not_edit consolidated_governance-proof healing_proof.go "$BK/"
(cd "$BK" && find . -type f \( -name "*.go" -o -name "*.md" -o -name "*.MD" -o -name "*.json" \) | sort | xargs sha256sum > MANIFEST.sha256)
```

### 0.2 Gate 0

```bash
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
```

✅ Every line `OK`. ❌ Otherwise stop.

### 0.3 Record the govRoot baseline

```bash
go test ./pkg/proof/ -run TestP5_GovRootMovesVersusZeroL4 -v 2>&1 | grep "govRoot moves"
```

Record both values. This phase will change the right-hand one **once**, at
Phase 8, deliberately.

### 0.4 Rollback

```bash
cd ".../liteclient/proof"
rm -rf working-proof_do_not_edit consolidated_governance-proof
cp -r "_PROOF_BACKUPS/<TS>/working-proof_do_not_edit"     .
cp -r "_PROOF_BACKUPS/<TS>/consolidated_governance-proof" .
cp "_PROOF_BACKUPS/<TS>/healing_proof.go"                 .
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
```

---

## Phase 1 — The corpus (step 7.2). Do this before writing any production code.

Everything after this is measured against the corpus. Building it second is how
a self-consistent wrong implementation passes its own tests.

### 1.1 Provision real governance on Kermit

Create ADIs exercising, at minimum:

| Case | Shape |
|---|---|
| A | 1-of-1 ed25519 (today's baseline — must still pass) |
| B | 2-of-3 ed25519, single key page |
| C | 1-of-1 delegated, depth 1 |
| D | 2-of-3 with one entry delegated, depth 1 |
| E | delegated depth 3 |
| F | delegation across ADIs on **different BVNs** (§2 of the plan) |
| G | depth 21 — must be refused |
| H | a delegation cycle — must be refused |
| I | duplicate key signing twice — must count once |
| J | correct inner key, **wrong** delegator chain — must be refused |
| K | non-ed25519 (RCD1 or ETH) — must fail closed with a distinct reason |

Record for each: the raw Accumulate JSON, the transaction hash, the signer
partitions, and the **expected verdict**.

### 1.2 Verdicts come from `accumulate-core`, not from us

For every corpus signature compute the expected result with the protocol
package itself:

```go
protocol.VerifyUserSignature(sig, protocol.SignableHash(txHash))
```

This is the reference. Our verifier's job is to agree with it. A corpus
verdicted by our own code proves only that we are consistent.

### 1.3 Confirm the corpus fails today

### Gate 1

✅ Cases C–F and I–J **fail** against unmodified code (delegated types are
rejected at `signature_verifier.go:438`).
✅ Case A passes.
❌ If a delegated case passes today, the corpus is not exercising delegation —
fix the corpus.

---

## Phase 2 — Digests (step 7.3)

### 2.1 `AcceptedDigests`

```go
func AcceptedDigests(sig SignatureData, txHash [32]byte) [][]byte
```

Returns the metadata digest and the `Initiator()` merkle digest. Build the
nesting with real `protocol.DelegatedSignature` / `protocol.ED25519Signature`
values and call `.Metadata().Hash()`.

> **Do not reimplement the canonical encoding.** It is field-tagged,
> omit-if-zero, varint-length (`types_gen.go:8996`). Hand-rolling it is how the
> JSON/field-strictness bugs happened before.

### 2.2 Record which form matched

Put it in the G1 evidence. If the merkle form never appears, that is worth
knowing; if it does, §1.4 was a live bug rejecting valid signatures.

### Gate 2

```bash
go test ./...  -run 'TestP7_DigestParity' -count=1 -v
```

✅ For **every** corpus signature, our digest set contains the digest
`accumulate-core` verifies against.
✅ At least one case matches only under the merkle form (P7.3).
❌ Any mismatch: stop. Every later gate depends on this one.

---

## Phase 3 — Authority resolution (steps 7.4, 7.5)

### 3.1 Implement `satisfied(page, version)` per plan §3.3

All five rules explicitly, each with its own test:

1. distinct entries — one key satisfies at most one entry
2. version binding (KPSW-EXEC)
3. depth bound at `DelegationDepthLimit = 20`
4. cycle refusal via a visited set
5. path binding — resolution path must equal the digest's delegator chain

### 3.2 Enumerate `P#signature` per signer account

Finishes governance spec §4.1 item 5, recorded as half-satisfied in
`L4_DESIGN.md` §1.3 Defect C. Enumeration must cover **every signer account**,
which under delegation means several.

### 3.3 Fail closed on unsupported types

RCD1 / BTC / ETH / RSA / EcdsaSha256 / TypedData get a **distinct reason code**.
Never skip silently — a skipped signature reads as a threshold shortfall, which
reads as "the institution did not authorize this".

### Gate 3

✅ Corpus B, C, D, E, F resolve and satisfy their thresholds.
✅ G (depth 21), H (cycle), I (duplicate), J (wrong chain) all refused, each
with a distinct, readable reason.
✅ K refused with an unsupported-type reason, not a threshold reason.
✅ Case A unchanged — the 1-of-1 path must not regress.

---

## Phase 4 — Multi-partition ChainedProof (step 7.6)

**This is where `working-proof_do_not_edit/` is edited.**

### 4.1 Widen the struct

```go
Layer1    []Layer1
Layer2    []Layer2
Layer4BVN []*Layer4
Layer3    Layer3      // Directory — single
Layer4DN  *Layer4     // Directory — single
```

### 4.2 Canonical ordering

Sort legs by partition ID. Non-deterministic ordering is the exact failure that
`summarizeL4Leg` sorts signers to prevent: two validators reading identical
chain data must produce identical bytes.

### 4.3 Build one leg per distinct **counted** signer partition

Not per signature, and not per partition-that-exists. A signature that does not
contribute to the threshold needs no proof.

### 4.4 Widen Phase 6's persistence in the same step

Phase 6 writes exactly two layer-4 rows (one BVN, one DN) and its
`ChainedProofFromStorage` reassembles that fixed shape. Both must widen here or
Phase 6's Gate P6.5 is silently no longer testing what it claims:

- emit **N + 1** layer-4 rows, `bvn_partition` distinguishing them
- reassemble a variable number of legs in canonical partition order
- **fail closed** if the summary names a leg that has no stored row — never
  truncate to what happens to be present

### Gate 4

✅ Corpus F (signers on ≥2 BVNs) builds with ≥2 BVN legs.
✅ A multi-partition proof writes N+1 layer-4 rows and reads back through
`ChainedProofFromStorage`; a missing leg fails closed (P7.9b).
✅ Case A builds with exactly one, byte-identical to the Phase 0 baseline.
✅ Shuffling partition discovery order yields identical bytes (P7.10).

---

## Phase 5 — Multi-partition verification (step 7.7)

### 5.1 Verify every leg

Reject if **any** leg fails. Extend `layer4_crossbind_test.go` from two legs to
N: a valid leg from another proof must not be graftable into any position.

### 5.2 Offline

The whole point of L4. Verification must pass with the network disabled, as
`offline_verify_test.go` already does for the single-partition case.

### Gate 5

✅ Corpus F verifies offline.
✅ Corrupting leg *i* fails, **for every i** — loop it; do not spot-check one.
✅ Cross-bind refused at N legs.
✅ All 34 existing single-partition mutations still rejected.

---

## Phase 6 — govRoot, deliberately, once (step 7.8)

### 6.1 Bump the version

```go
const L4GovRootVersion = "certen:l4gov:v2"
```

The field exists precisely so this is a visible bump and not a silent move.

### 6.2 Extend `summarizeL4Leg` over N legs

Sorted, de-duplicated, same discipline as today.

### 6.3 Record the new govRoot

### Gate 6

✅ govRoot differs from the Phase 0 baseline.
✅ It differs **once** — recompute at the start and end of this phase; they
must agree with each other.
✅ `L4GovRootVersion == "certen:l4gov:v2"`.
✅ Signer and submitter still agree byte-for-byte (the P5.1 test, re-run).

---

## Phase 7 — Live end to end (step 7.9)

### 7.1 Provision a real delegated multi-sig ADI on Kermit

### 7.2 Submit on base-sepolia

```bash
node scripts/e2e_matrix.mjs --legs 1 --chains base --class on_demand
```

base-sepolia is $0.35 flat; ethereum-sepolia is ~$3.30/proof and its cost-basis
gate goes stale after 48h of no traffic
(`api-gateway/scripts/refresh-chain-cost-basis.mjs`).

### 7.3 Watch the elected executor

Settlement happens on one validator chosen by `BFT-DETERMINISTIC`, not
validator-1:

```bash
docker logs --since 15m certen-validator-1 2>&1 | grep -E "DETERMINISTIC|Selected executor"
```

then read that node. Confirmation can lag the consensus-complete log by ~90s —
check `chain_execution_results` and the chain itself before calling it a
failure.

### Gate 7

✅ G1 reports the real M-of-N with delegation resolved.
✅ Settlement `status = 1` on-chain.
✅ The stored proof carries every BVN leg.

---

## Phase 8 — Atomic fleet upgrade (step 7.10)

> **The irreversible step.** govRoot has moved, so a mixed-version fleet
> produces different roots and **every TX2 on every chain reverts**.

1. Confirm Phase 6 Gate is green and the new govRoot is recorded.
2. Build once; deploy the **same** binaries to all seven validators.
3. Verify identity before starting any of them — for **every** proof-bearing
   binary, not only the validator:

```bash
for B in validator govproof txhash; do
  printf '%-10s ' "$B"
  for i in 1 2 3 4 5 6 7; do docker exec certen-validator-$i sha256sum /app/$B; done \
    | awk '{print $1}' | sort -u | wc -l
done
```

✅ Exactly `1` for each of the three.

> **Why three, and why this check used to be wrong.**
>
> The image ships three binaries and the proof is split across all of them:
>
> | binary | carries | how it reaches the validator |
> |---|---|---|
> | `/app/validator` | L1–L5 chained proof, govRoot assembly, signing | `working-proof_do_not_edit` is `package chained_proof` and is **imported**, so it compiles in |
> | `/app/govproof` | G0 / G1 / G2 | `consolidated_governance-proof` is `package main` and **cannot** be imported; it is a separate executable invoked via `GOV_PROOF_CLI_PATH` |
> | `/app/txhash` | G2 payload verification | separate executable, invoked via `TXHASH_CLI_PATH` |
>
> This step checked `/app/validator` alone. Two nodes can carry an identical
> `/app/validator` and a **different** `/app/govproof` — and G1 feeds
> `G1CanonicalHash`, which feeds govRoot. The check would have reported a clean
> fleet while the governance verdicts diverged, which is precisely the
> mixed-version hazard it exists to prevent, in the one binary it did not look at.
>
> Observed on 2026-08-26: commit `df6af20` changed only the governance package,
> so `/app/validator` was byte-identical before and after while `/app/govproof`
> moved `be6aadef…` → `1cd8d059…`. Under the old check that deploy looked like a
> no-op.
>
> Verify the same three **on the built images, before anything starts** — that is
> what "before starting any of them" means, and a container must exist to be
> exec'd into:
>
> ```bash
> for B in validator govproof txhash; do
>   for i in 1 2 3 4 5 6 7; do
>     docker run --rm --entrypoint sha256sum certen-validators-validator-$i /app/$B
>   done | awk '{print $1}' | sort -u | wc -l
> done
> ```
>
> If a binary is ever added to the final stage of the `Dockerfile`, add it here.
> The list is `grep 'COPY --from=builder' Dockerfile`.

4. Start all seven. Confirm `git log -1` on `/root/certen-validators` matches
   the intended commit.
5. Re-run Phase 7 and confirm Gate 7.

### Final gate

```bash
go build ./... && go test ./pkg/... -count=1
cd accumulate-lite-client-2/liteclient && go test ./proof/working-proof_do_not_edit/ -count=1
```

✅ All green, except the three pre-existing failures in
`consolidated_governance-proof` — `TestURLUtils`, `TestG0Layer`,
`TestCompleteWorkflow` — which fail identically at baseline `adb5cae` and are
stub tests pointing at a literal `"test"` endpoint. Confirm they are unchanged;
do not "fix" them here.
