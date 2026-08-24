# CERTEN L4 — Implementation Runbook

**Companion to:** `L4_DESIGN.md`
**Date:** 2026-08-24
**Estimated:** 8–12 working days (Phase 4A is the largest single item)
**Blast radius:** `working-proof_do_not_edit/`, `consolidated_governance-proof/{g1_layer.go,g2_layer.go,go_verifier.go}`, `pkg/proof/liteclient_adapter.go`, `pkg/execution/contracts/v6_1_binding.go`

> ⚠️ These are the foundational proof systems. Every step below is gated. Do not
> proceed past a failed gate — roll back and diagnose.

---

## Phase 0 — Safety (MANDATORY, do first)

### 0.1 Backup

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator/accumulate-lite-client-2/liteclient/proof"
TS=$(date +%Y%m%d_%H%M%S); BK="_PROOF_BACKUPS/$TS"
mkdir -p "$BK"
cp -r working-proof_do_not_edit        "$BK/"
cp -r consolidated_governance-proof    "$BK/"
cp healing_proof.go                    "$BK/"
(cd "$BK" && find . -name "*.go" -o -name "*.md" -o -name "*.MD" | sort | xargs sha256sum > MANIFEST.sha256)
echo "BACKUP: $(pwd)/$BK"
```

**An existing backup is at `_PROOF_BACKUPS/20260824_053303` (32 files manifested).**

### 0.2 Gate 0 — backup integrity

```bash
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
```

✅ Every line reports `OK`. ❌ Otherwise stop; re-take the backup.

### 0.3 Rollback procedure (keep visible)

```bash
cd ".../liteclient/proof"
rm -rf working-proof_do_not_edit consolidated_governance-proof
cp -r "_PROOF_BACKUPS/<TS>/working-proof_do_not_edit"     .
cp -r "_PROOF_BACKUPS/<TS>/consolidated_governance-proof" .
cd "_PROOF_BACKUPS/<TS>" && sha256sum -c MANIFEST.sha256
```

### 0.4 Capture the pre-change baseline

Run the existing end-to-end proof once against Kermit and archive the output
JSON. Every later gate compares L1–L3 field-for-field against this baseline.
**L1–L3 values must not change. If they do, the refactor broke something.**

---

## Phase 1 — Characterization tests (before any edit)

Write tests that pass against the **current** code. They are the regression net.

### 1.1 Receipt gotcha test

```
GIVEN a ChainQuery with includeReceipt and a Range
THEN  the response carries NO receipt        (documents the silent-ignore bug)

GIVEN a ChainQuery with includeReceipt and Index or Entry
THEN  the response carries a receipt with entries > 0
```

### 1.2 Signature digest fixture

Pin the verified vector from the design doc:

```
txHash    e6dd1988102e29aa5206cc1c5fcb0f3ff5b4cac0b4580928029d03ed93035572
pubkey    40e6e8b96de7e7ed4c38815448abe22ab555236418d813b3a02cb6a7bc42871b
signature f9b81b4634ab6280ef423aa70133962a41a6b70985ef9703778868a9f3a298fb
          5f3c7626e376e19173d34e12b4721ec3dde77b696ee94954f6d8b18b5423500b
signer    acc://dn.acme/network
timestamp 1787562303142
signerVersion 0
EXPECT    ed25519.Verify == true
```

### 1.3 Gate 1

✅ Both tests pass against unmodified code.

---

## Phase 2 — Add `Layer4` (additive only)

No existing behaviour changes in this phase.

### 2.1 Types

Add `Layer4`, `AnchorSignature`, `ValidatorKey` to `types.go`. Add
`Layer4BVN` / `Layer4DN` fields to `ChainedProof`. Both optional for now.

### 2.2 Builder — `layer4.go` (new)

For each leg:

1. Locate the anchor. BVN leg: scan `acc://dn.acme/anchors` for a
   `blockValidatorAnchor` whose `source == acc://bvn-<BVN>.acme` and
   `minorBlockIndex == Layer1.BVNMinorBlockIndex`. DN leg: scan
   `acc://bvn-<BVN>.acme/anchors` for a `directoryAnchor` whose
   `source == acc://dn.acme` and `minorBlockIndex == Layer2.DNMinorBlockIndex`.
2. `query {scope: <txid>}` → collect `signatures.records[].signatures.records[]`.
3. `network-status` → validator set, per-partition `active`, threshold.
4. Populate `Layer4`.

**Do not** compute the threshold locally from a hardcoded fraction. Read
`globals.validatorAcceptThreshold` and apply `Rational.Threshold(activeCount)`
so the value tracks the network.

### 2.3 Verifier — extend `proof_verifier.go`

Implement §3.4 of the design doc. Reuse `ComputeAccumulateDigest` and
`VerifyEd25519` from `consolidated_governance-proof/signature_verifier.go` —
do **not** reimplement the digest.

### 2.4 Gate 2

- ✅ `Layer4BVN` and `Layer4DN` populate against live Kermit.
- ✅ Both verify offline with **no** comet client and **no** network access.
- ✅ `Layer4DN.StateTreeAnchor == Layer3.DNStateTreeAnchor`.
- ✅ `Layer4BVN.StateTreeAnchor == Layer2.BVNStateTreeAnchor`.
- ✅ Unique verified signers ≥ threshold on both legs.
- ✅ Baseline L1–L3 values byte-identical to Phase 0.4.

### 2.5 Negative tests (all MUST fail closed)

| Mutation | Expected |
|---|---|
| Flip one byte of a signature | reject |
| Drop signatures below threshold | reject |
| Substitute a pubkey not in the validator set | reject |
| Substitute a validator not `active` on that partition | reject |
| Duplicate one signer to reach the count | reject |
| Alter `StateTreeAnchor` | reject (cross-layer mismatch) |
| Alter `AnchorTxHash` | reject (digest mismatch) |
| Alter `Timestamp` or `SignerVersion` | reject (digest mismatch) |

✅ All eight reject. **A negative test that passes is a critical defect.**

---

## Phase 3 — Retire the CometBFT bind

Only after Gate 2 is green.

### 3.1 Remove

- `bindConsensusAppHash` (`proof_builder.go:104`)
- Both call sites (`:77`, `:88`)
- `CometDN` / `CometBVN` from `ProofBuilder` and `ProofVerifier`
- The `github.com/cometbft/cometbft/rpc/client/http` import
- The `"proof-grade verification requires comet clients"` hard-fail

### 3.2 Update callers

`pkg/proof/liteclient_adapter.go` — `GenerateChainedProof` requires
`g.cometDN` and a BVN comet client. Remove those preconditions and the
`selectBVNCometClient` plumbing if nothing else uses it.

### 3.3 Gate 3

- ✅ `grep -rn "cometbft" working-proof_do_not_edit/` returns nothing.
- ✅ Full proof builds and verifies end-to-end against Kermit.
- ✅ Verification succeeds with **all** network access blocked.
- ✅ L1–L3 baseline still byte-identical.

---

## Phase 4 — G2 correction

G2 failures are **not caused by G2**. All nine observed failures are G1
failures that prevent G2 from ever running. This phase has three parts:
**4A** fixes the real cause (signature evidence), **4B** hardens a dormant
fail-open in the payload check, **4C** makes G2's defining claim (outcome
binding) real. Do 4A first — it is the one costing you proofs. **4B and 4C are
one correctness item**: 4B's bypass is guarded by checks that 4C shows to be
tautologies, so shipping either alone leaves a hole.

### Evidence (from `certen_proofs.governance_proof_levels`, 2026-08-24)

| Funnel | Proofs | Range |
|---|---|---|
| G0+G1+G2 ✅ | 355 | 2026-01-26 → 2026-08-22 |
| G0 only | 35 | 2026-01-26 → 2026-03-11 (historical, resolved) |
| G0+G1, **no G2** | 9 | 2026-07-03 → 2026-08-09 |

All nine: `G0 verified=true`, `G1 verified=false`, no G2 row. `level_json`
reads `{"threshold_m":1,"threshold_n":1,"attestation_count":1,"threshold_met":false}`
— arithmetically satisfied, recorded as unmet. Expected count 1, validated
count 0.

Failures correlate with **load, not recency**: 8 of 9 fall in the single
highest-volume week (69 proofs vs a typical 13–32); zero in the two weeks since.
This is contention, not a block+1 anchor race — the failure is at G1, before any
outcome leaf is required.

---

## Phase 4A — Signature evidence: make it real, complete, correct

### 4A.0 What the trace found

Call-graph analysis of `g1_layer.go`:

| Symbol | Callers | State |
|---|---|---|
| `enumerateSignatureEntries` (:259) | **0** | dead |
| `filterAndValidateSignatures` (:312) | **0** | dead |
| `signatureValidationWorker` (:393) | 1 (from dead code) | dead |
| `processSignatureEntry` (:431) | 1 (from dead code) | dead |
| `resolveSignatureEntry` (:487) | 1 (from dead code) | dead |
| `validateSignaturesDirectFromTransaction` (:763) | 1 (live fallback) | **stub, returns `[], nil`** |
| `validateSignaturesFromTransaction` (:606) | 1 | **the only live path** |

The entire receipt-bound, timing-validated, worker-pooled enumeration
subsystem is unreachable. `getSignatureChainCount` (:225) still runs on every
proof (goroutine 2, :116) and its result is used only for "enumeration
planning" that never happens.

**Spec gap:** §4.1 Required Artifacts item 5 mandates *"Enumeration of
`P#signature` entries and single-entry resolution for each counted candidate."*
The live path performs single-entry resolution but **never enumerates**. Item 5
is therefore only half-satisfied today.

**Second defect, in the live path:** `validateSignaturesFromTransaction`
(:606–:705) is cryptographically correct — it binds receipts via
`BuildNormativeChainQuery`, validates timing against `ExecTerms.MBI`, and runs
full ed25519 + key-page membership through `ValidateSignature`. But **every
failure is `continue`.** Eleven of them. An RPC timeout and a genuinely invalid
signature are treated identically: silently dropped. Under load, N signatures
time out → N silently skipped → count falls below threshold → false governance
rejection. **This is the same defect class as the stub, sitting in the primary
path.** Fixing only the stub leaves this intact.

### 4A.1 Fix the live path's silent drops (do this first — highest value)

In `validateSignaturesFromTransaction`, classify every `continue` into one of
two kinds and handle them differently:

```go
type sigOutcome int
const (
    sigRejected sigOutcome = iota // genuinely not a valid counted signature
    sigUnavailable                // could not be evaluated — infrastructure
)
```

**`sigRejected` (skip, count as evidence of rejection):**
- `ValidateTransactionHash` mismatch — belongs to a different transaction (§7.1)
- `ValidateSignatureTiming` fail — signed after execution (§6.2)
- `ValidateSignature` fail — bad ed25519, or key not in `State_exec(P).keys` (§8.5)

**`sigUnavailable` (MUST NOT be silently skipped):**
- message-ID parse failure
- `SaveRPCArtifact` RPC error (message query)
- `ExpectResult` extraction failure
- `ExtractSignatureFromMessageResult` failure
- receipt query RPC error
- receipt result extraction failure
- `ExtractReceiptFromChainEntry` failure

Accumulate the unavailable set. After the loop:

```go
if len(unavailable) > 0 {
    return nil, &SignatureEvidenceIncomplete{
        Requested: len(sigData.MessageIDs),
        Evaluated: len(sigData.MessageIDs) - len(unavailable),
        Unavailable: unavailable,   // messageID + underlying error, each
    }
}
```

A threshold verdict computed over an incomplete evidence set is not a verdict.
Fail closed and say why.

### 4A.2 Implement enumeration for real — delete the stub

Replace `validateSignaturesDirectFromTransaction` (:763) entirely. Do **not**
leave a stub, and do **not** leave a `return nil, error` placeholder as the
end state.

Wire the existing, already-correct subsystem:

```
getSignatureChainCount(principal)             // :225 — already runs per proof
  → enumerateSignatureEntries(principal, n)   // :259 — paged, currently dead
    → filterAndValidateSignatures(entries, …) // :312 — worker pool, dead
      → signatureValidationWorker             // :393
        → processSignatureEntry               // :431
          → resolveSignatureEntry             // :487 — returns sigData + RECEIPT
          → ValidateSignatureTiming(receipt, snapshot.ExecTerms.MBI)   // §6.2/§7.1
          → ValidateTransactionHash(signature, txHash)                 // §7.1
```

This is a wiring job, not new cryptography. Every stage exists and is
receipt-bound.

**Two corrections to make while wiring:**

1. `processSignatureEntry` (:431) currently `return nil` on
   `resolveSignatureEntry` failure after pushing to `errChan` — the same
   silent-drop bug. Apply the 4A.1 classification here too. A worker that
   cannot resolve an entry must surface `sigUnavailable`, not vanish.
2. `filterAndValidateSignatures` (:380–:389) logs only the first three errors
   and returns `nil` error regardless. It must propagate.

**Spec note:** this is not "extraction from expanded JSON," which §2.2 forbids
as evidence. Every entry passes through `resolveSignatureEntry`, which returns
a receipt, and timing is validated against it. Receipt-bound throughout.

### 4A.3 Make enumeration primary, with cross-check

`signatureSet` is a shortcut; §4.1 requires enumeration regardless, so running
it always costs nothing extra and buys spec compliance plus an independent
check. The two routes have genuinely different failure surfaces — one queries
the *transaction message* and picks a signatureSet for the key page, the other
queries the *key page's own `P#signature` chain* by range.

```
run BOTH routes
  ├─ both succeed, sets AGREE            → proceed, record both artifacts
  ├─ both succeed, sets DISAGREE         → FAIL CLOSED, report the diff
  ├─ one succeeds, other unavailable     → proceed on the successful one,
  │                                        emit a distinct metric
  └─ both unavailable                    → FAIL as SignatureEvidenceIncomplete
```

Compare on the set of `(messageID, transactionHash, publicKey)` triples of
**counted** signatures — not raw counts, which can coincide.

Disagreement between two independent routes to the same evidence is a finding,
not something to average. It is the exact opposite of the failure mode that
produced this phase.

**Never wire this as a silent fallback.** If either route degrades, that must
be visible in metrics. Silent degradation is the thread running through every
defect in this review.

### 4A.4 Retry with backoff — only after 4A.1–4A.3

Retry is safe only once `sigUnavailable` and `sigRejected` are distinguishable.
Retrying a governance rejection is wrong; retrying a timeout is correct; today
they are the same value.

- Retry **only** `sigUnavailable`, per-signature, with jittered exponential
  backoff inside the CLI's existing budget.
- Both routes can time out under contention — two paths lower the failure rate
  but do not handle load. Retry is what handles load.
- Cap and surface: if retries exhaust, fail as `SignatureEvidenceIncomplete`.
  Never downgrade to a threshold verdict.

### 4A.5 Backfill the nine

Their G0 rows are verified and anchored, and Kermit's DN node is an archive
node (`earliest_block_height: 2`), so the history is retrievable. Re-run G1→G2
for the nine `proof_id`s that have no G2 row. Expect success — the failures
were transient.

### 4A.6 Gate 4A

- ✅ `grep -rn "not yet implemented" g1_layer.go` returns nothing.
- ✅ `validateSignaturesDirectFromTransaction` no longer exists (replaced, not stubbed).
- ✅ No `continue` in `validateSignaturesFromTransaction` discards an
  infrastructure error.
- ✅ Both routes run; artifacts for §4.1 item 5 are produced.
- ✅ Fault injection — RPC error on one signature's message query ⇒
  `SignatureEvidenceIncomplete`, **never** `threshold_met: false`.
- ✅ Fault injection — one genuinely invalid signature ⇒ counted as rejected,
  threshold evaluated over the complete set.
- ✅ Route disagreement injected ⇒ fail closed with a diff.
- ✅ All nine backfilled proofs reach G2; coverage 399/399.
- ✅ Load test at 3× the 2026-08-03 peak (≈200 proofs/week equivalent burst)
  produces zero `threshold_met:false` with `attestation_count > 0`.

---

## Phase 4B — G2 payload check: close the latent fail-open

> **Verified precondition:** payload verification is already wired and working —
> `/app/txhash` present and executable in every running validator,
> `TXHASH_CLI_PATH=/app/txhash` set, `main.go:1371` calls `SetTxHashPath`,
> `governance_adapter.go:228` passes `--txhash` for G2. **This phase does not
> make G2 start failing.** Re-verify on your fleet before applying 4B.3.

### 4B.1 Fail fast at configuration time

The bypass exists because the failure is discovered at *proof* time, when the
only options are lie or abort. Move detection to *startup*:

- `main.go` — G2 enabled and `txhashPath` empty/missing/non-executable ⇒ refuse
  to start.
- `CLIGovernanceProofGenerator` — validate in the constructor, not in
  `buildCLIArgs`.
- `govproof` CLI — `--level G2` with empty `--txhash` ⇒ exit non-zero before
  any work.

### 4B.2 Assert at deploy time

```bash
test -x /app/txhash        || { echo "FATAL: /app/txhash missing"; exit 1; }
test -n "$TXHASH_CLI_PATH" || { echo "FATAL: TXHASH_CLI_PATH unset"; exit 1; }
```

### 4B.3 Remove the runtime bypass

Only after 4B.1 and 4B.2. `g2_layer.go:122`:

```go
g2ProofComplete := payloadVerification.Verified && effectVerification.Verified &&
                   receiptBinding.Verified && witnessConsistency.Verified
```

Delete `payloadConfigFailure` and the `[WARNING] Payload verification skipped`
branch. On failure return a typed fallback so the caller records **G1** and
emits `g2Hash = 0` — per spec §10.

Also delete the `goVerifyPath == ""` early return in `VerifyPayloadWithRawJSON`
(`go_verifier.go:60`), which manufactures a `PayloadVerification` echoing
`ComputedTxHash: expectedTxHash`. That is the object the bypass keys on, and it
is booby-trapped for anyone who later compares those two fields.

### 4B.4 Gate 4B

- ✅ Verifier configured: G2 succeeds, `g2Hash != 0`, payload verified true.
- ✅ Path unset: **process refuses to start** (not a degraded proof).
- ✅ Binary absent from image: deploy check fails.
- ✅ Configured but hash mismatches: result is **G1**, `g2Hash == 0`.
- ✅ `grep -rn "partial" g2_layer.go` returns nothing.
- ✅ A previously passing G2 still passes — no regression on the live fleet.

## Phase 4C — G2 outcome binding: make the defining claim real

G2's whole reason to exist over G1 is **outcome binding**: spec §1.3, *"proves a
success-only, receipt-proven outcome bound under the execution witness,"* and
§10, *"A G2 proof MUST bind a success-only, receipt-proven outcome leaf under
`EXEC_WITNESS`."*

Two of the four components that decide `g2ProofComplete` do not verify that.
They are tautologies over flags set by earlier stages.

### 4C.0 What the trace found

**`verifyReceiptBinding` (`g2_layer.go:258`)**

```go
// Receipt binding is verified through G0/G1 inclusion proofs
// If we reached this point, receipt binding is valid
verified := g1Result.G0ProofComplete &&
            g1Result.Receipt.Start != "" && g1Result.Receipt.Anchor != ""
```

A **non-empty string check** on G0's receipt fields, plus a flag. No merkle
recomputation. No reference to an outcome leaf at all — it inspects G0's
receipt, not the outcome's.

**`verifyWitnessConsistency` (`g2_layer.go:280`)**

```go
// If we reached this point with valid G1, witness consistency is valid
verified := g1Result.G1ProofComplete && g1Result.ExecWitness != ""
```

Same shape: a flag and a non-empty string.

**`verifyTransactionEffect` (`g2_layer.go:243`)** compares
`payloadVerification.ComputedTxHash` against `ExpectedTxHash`. This is real —
**except** when the 4B bypass fires: `go_verifier.go:60` returns
`ComputedTxHash: expectedTxHash`, so effect verification compares a value to
itself and passes.

### 4C.1 Severity — this changes 4B

`g2CoreComplete := effectVerification.Verified && receiptBinding.Verified &&
witnessConsistency.Verified` is the guard that permits the 4B bypass. When the
bypass fires, all three pass trivially:

| Component | Behaviour when bypass fires |
|---|---|
| effect | compares `expectedTxHash` to `expectedTxHash` → **true** |
| receiptBinding | G0 flag + non-empty strings → **true** |
| witnessConsistency | G1 flag + non-empty string → **true** |

So `g2CoreComplete` is not a meaningful safety net. The earlier characterization
of the bypass as *"core G2 components succeeded"* overstated what those
components check. Treat 4B and 4C as one correctness item: fixing 4B alone
leaves an unguarded claim; fixing 4C alone leaves the bypass reachable.

### 4C.2 Implement real outcome binding

Per §10 and §2.1 (*"a receipt binds a specific chain entry leaf to an anchor
root"*), outcome binding must prove:

1. **An outcome leaf exists** — a receipt-proven chain entry recording the
   execution result, located under `EXEC_WITNESS`.
2. **It is success-only** — §10. A failed or pending outcome MUST NOT satisfy
   G2. Read the transaction status; anything other than delivered-success falls
   back to G1.
3. **Its receipt recomputes to the anchor** — actual merkle recomputation, not
   a non-empty check. `working-proof_do_not_edit/receipt_verifier.go`'s
   `ValidateIntegrity` already implements exactly this (SHA-256 `hashPair`
   walk, `start` → `anchor`); reuse it rather than writing a second one.
4. **The leaf is bound to `EXEC_WITNESS`** — the receipt-proven leaf must be
   the one under the execution witness derived in G0, not merely *a* valid
   receipt somewhere.
5. **`ENTRY_HASH` equality** — §7.2 / §2.2: the expanded message ID MUST equal
   `acc://<ENTRY_HASH>@<scope>` and `ENTRY_HASH` MUST equal the receipt-proven
   leaf.

Replace both tautologies:

```go
func (g2 *G2Layer) verifyOutcomeBinding(ctx context.Context, g1 *G1Result) (OutcomeBinding, error) {
    // 1. locate the outcome entry under EXEC_WITNESS
    // 2. require delivered + success  (else -> fall back to G1, not "unverified")
    // 3. fetch its receipt (includeReceipt with index/entry — NOT range)
    // 4. ValidateIntegrity(receipt)                       <- real merkle recomputation
    // 5. require receipt.Start == outcomeLeafHash
    // 6. require expandedMessageID == "acc://" + ENTRY_HASH + "@" + scope
    // fail closed on every step; no boolean defaults to true
}
```

`witnessConsistency` becomes: the outcome receipt's anchor chain terminates at
the same `EXEC_WITNESS` G0 derived — a hash comparison against a derived value,
not a non-empty test.

### 4C.3 No boolean may default to true

Audit every `VerificationResult` construction in `g2_layer.go`. A component that
did not run must produce `Verified: false`, never an unset struct field that
reads as `false` only by accident — and never `true` because an earlier stage
set a flag. Prefer an explicit tri-state (`NotRun` / `Failed` / `Verified`) so
"never executed" cannot be confused with "executed and passed."

### 4C.4 Gate 4C

- ✅ `verifyReceiptBinding` and `verifyWitnessConsistency` no longer contain
  `!= ""` as their verification predicate.
- ✅ Outcome receipt is merkle-recomputed via `ValidateIntegrity`; a mutated
  receipt entry is rejected.
- ✅ Outcome leaf bound to `EXEC_WITNESS`; substituting a valid receipt from a
  different transaction is rejected.
- ✅ `ENTRY_HASH` ≠ receipt-proven leaf ⇒ rejected (§7.2).
- ✅ A **failed** or **pending** transaction outcome ⇒ result is **G1**,
  `g2Hash == 0` (§10 success-only).
- ✅ With the 4B bypass artificially re-enabled, `g2CoreComplete` is now
  **false** — the tautologies no longer rubber-stamp it.
- ✅ All 355 existing G2 proofs re-verify under the new logic, **or** each
  regression is explained. ⚠️ Expect some to fail: they were accepted by
  checks that verified less than the spec requires. That is the point of the
  phase — a drop in the G2 count here is a correction, not a regression.

---

## Phase 5 — Propagate L4 into the gov root

### 5.1 Change

`pkg/execution/contracts/v6_1_binding.go` — `ComputeAccumulateGovRoot` takes
`L4ConsensusProofH`. Feed it a hash over the **stored** `Layer4BVN` + `Layer4DN`
rather than the current placeholder. Note `ethereum_contracts.go:2478` currently
computes a diagnostic `l4H` from the literal bytes `"nonempty"` — confirm the
production path does not share that shortcut.

### 5.2 Gate 5

- ✅ `L4ConsensusProofH` is a real digest of real evidence.
- ✅ Signer and verifier agree bit-for-bit (`v6_1_signing.go` vs
  `ethereum_contracts.go`) — a divergence here reverts every TX2 on chain.
- ✅ One full CERTEN cycle succeeds end-to-end on Sepolia.

---

## Phase 6 — Acceptance

| # | Criterion | Method |
|---|---|---|
| 1 | Proof carries L1, L2, L3, L4-BVN, L4-DN | inspect JSON |
| 2 | Verifies fully offline | run with network disabled |
| 3 | No `cometbft` import anywhere in the proof tree | `grep -rn` |
| 4 | All 8 negative tests reject | test suite |
| 5 | No "partial G2" path exists | `grep -rn "partial"` |
| 5a | No stub in signature extraction | `grep -rn "not yet implemented"` |
| 5b | Infra errors never become threshold verdicts | fault injection |
| 5c | Both signature routes run and agree | test suite |
| 5d | G2 coverage 399/399 after backfill | SQL funnel query |
| 5e | Outcome binding merkle-recomputed, not string-checked | test suite |
| 5f | Failed/pending outcome ⇒ G1, `g2Hash==0` | fault injection |
| 5g | No `VerificationResult` defaults to true | code audit |
| 6 | Unconfigured verifier ⇒ startup failure | manual |
| 7 | L1–L3 unchanged from baseline | diff |
| 8 | Full cycle succeeds on Sepolia | e2e run |
| 9 | Backup manifest still verifies | `sha256sum -c` |

---

## Known gotchas

1. **`includeReceipt` is silently ignored on `range` queries.** Use `index` or
   `entry`. Pinned by test 1.1.
2. **`signerVersion` is omitted from JSON when zero.** Absent ⇒ 0. Passing a
   wrong value produces a wrong digest and a valid signature fails.
3. **Use `sig.TransactionHash`, not the outer tx hash.** `ComputeAccumulateDigest`
   already prefers the former — preserve that.
4. **`hashPair` is SHA-256(left‖right)** with a comment noting it matches
   *observed* DevNet behaviour. If Accumulate ever changes receipt hashing this
   breaks silently. Consider pinning against `protocol`'s own merkle package.
5. **Anchors gather their quorum a few blocks after production.** A just-produced
   anchor may be below threshold. Retry or walk back, as
   `findLatestQuorumAnchor` does.
6. **Do not shape the design around current validator counts.** Kermit BVNs have
   one validator each today; that is a deployment parameter, not an invariant.

---

## Rollback triggers

Roll back immediately if any of:

- A negative test passes (fail-open reintroduced).
- L1–L3 baseline values change.
- Offline verification requires network access.
- A CERTEN cycle that previously succeeded now reverts on chain.
