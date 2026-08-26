# Phase 8 — Implementation Runbook

**Companion prompt:** `PHASE8_CLAUDE_PROMPT.md`
**Predecessor:** `PHASE7_RUNBOOK.md` (delegated + multi-sig governance, closed)
**Date:** 2026-08-26
**Blast radius:** `consolidated_governance-proof/`, `pkg/proof/`, the Phase 7
corpus, one **production key page**, and — in Phase 1 only — a **live
base-sepolia settlement**

> ⚠️ Every step is gated. Do not proceed past a failed gate.
>
> ⚠️ **Phase 1 modifies a production key page** (`acc://certen-kermit-12.acme/book/1`).
> It is reversible, and §1.2 says how, but it is a real governance change to the
> account every production intent signs from. Read §1.1 before touching it.
>
> ⚠️ **Phase 2 touches a struct inside the govRoot preimage.** Done wrong it
> moves govRoot a second time. §2.1 is the whole point of that phase.

---

## Why these six, in this order

Phase 7 closed delegated and multi-signature governance. It left six things, and
they are ordered here by *what breaks if they are wrong*, not by effort:

| # | Item | If wrong |
|---|---|---|
| 1 | Cross-partition path through settlement | **TX2 reverts on chain** |
| 2 | Weakened cross-partition timing not recorded | A weaker claim reads as the stronger one |
| 3 | Multi-authority / page-2 proven offline only | False governance rejection, live |
| 4 | Dead invented digest still in the tree | A future wiring produces a digest that never verifies |
| 5 | Reject/Response/Block thresholds unmodelled | G1 verifies less than the page requires |
| 6 | Body-derived extra authorities not derived | A required approval is not required |

Items 5 and 6 are **"narrower claim than advertised"**, not "wrong answer".
Items 1–3 can produce a confidently wrong result. That is the ordering.

---

## Phase 0 — Safety and baseline (MANDATORY, do first)

### 0.1 Backup

```bash
cd "C:/Accumulate_Stuff/certen/independant_validator/accumulate-lite-client-2/liteclient/proof"
TS=$(date +%Y%m%d_%H%M%S); BK="_PROOF_BACKUPS/$TS"; mkdir -p "$BK"
cp -r working-proof_do_not_edit consolidated_governance-proof healing_proof.go "$BK/"
(cd "$BK" && find . -type f \( -name "*.go" -o -name "*.md" -o -name "*.MD" -o -name "*.json" \) \
  | sort | xargs sha256sum > MANIFEST.sha256)
cd "$BK" && sha256sum -c MANIFEST.sha256 | grep -v ': OK$'
```

✅ No non-OK lines. `_PROOF_BACKUPS/` is gitignored; do not commit it.

### 0.2 Record the baseline that must not move

```bash
go test ./pkg/proof/ -run TestP5_GovRootMovesVersusZeroL4 -count=1 -v 2>&1 | grep "govRoot moves"
go test ./pkg/execution/contracts/ -run 'TestP6_|TestP7_' -count=1 -v 2>&1 | grep -E "^--- |govRoot moves ONCE"
```

Expected at the start of this phase:

```
govRoot moves: d375630fb8c1f224 -> 15d8808e2ea6ab77
L4GovRootVersion == "certen:l4gov:v2"
v1 payload still hashes to b694a71e…, v1 root to bb293c64…
```

**Record `15d8808e2ea6ab77`.** Only Phase 2 may move it, and only deliberately.

### 0.3 Record the fleet baseline

```bash
ssh -i ~/.ssh/certen_server root@116.202.214.38 \
 'cd /root/certen-validators && git rev-parse --short HEAD; \
  for B in validator govproof txhash; do printf "%-10s " "$B"; \
    for i in 1 2 3 4 5 6 7; do docker exec certen-validator-$i sha256sum /app/$B; done \
    | awk "{print \$1}" | sort -u | wc -l; done'
```

✅ One commit, and `1` for each of the three binaries.

> **Three binaries, not one.** `working-proof_do_not_edit` is `package
> chained_proof` and compiles **into** `/app/validator`. `consolidated_governance-proof`
> is `package main` and ships as a **separate** `/app/govproof`, invoked via
> `GOV_PROOF_CLI_PATH`; `/app/txhash` is a third, invoked via `TXHASH_CLI_PATH`.
> A change to the governance package leaves `/app/validator` byte-identical.
> Checking only the validator would have read commit `df6af20` as a no-op.

### Gate 0

✅ Manifest verified, govRoot recorded, fleet homogeneous on all three binaries.

---

## Phase 1 — Cross-partition path, through settlement (item 1)

**This is the only item where being wrong reverts money on chain.**

### 1.0 What has never run

```
multi-leg proofs ever stored:     0
proofs with >2 layer-4 rows:      0
additionalLegs ever persisted:    0
```

Every piece is individually tested. The **composition** has never run once:
production discovers two signer partitions → builds two legs → writes N+1
layer-4 rows → reassembles from storage → verifies offline → computes a v2
govRoot **with `BVNs` populated for the first time** → TX2 settles.

`ConsensusProof.BVNs` is `omitempty`. Every govRoot ever computed in production
has had it **absent**. A cross-partition intent produces the first preimage
where it is present, and govRoot is what TX2 verifies against.

### 1.1 The provisioning decision — read before acting

A CERTEN intent settles from a `CertenAccount` derived by CREATE2, and the
derivation includes the ADI: the deployed account for base-sepolia
(`0x3850C52C22Eb5ac1d727784DeFdCa7C5DB050389`) has
`adiURL() == acc://certen-kermit-12.acme`. **A different ADI has no account on
base-sepolia**, so routing the test through `certen-p7f-alpha.acme` would first
require deploying a factory-derived account and pinning it to the V6.1 anchor —
a path with known version-drift hazards.

There is a much cheaper route, and it was verified on chain:

```
acc://certen-kermit-12.acme   -> BVN1     (production ADI, account deployed)
acc://certen-p7f-omega.acme   -> BVN2     (Phase 7 corpus, key f2 in keys.json)
```

**Add `acc://certen-p7f-omega.acme/book` as a DELEGATE ENTRY on
`acc://certen-kermit-12.acme/book/1`.** The ADI does not change, so the existing
CertenAccount and anchor keep working, and the account's authority now spans
BVN1 and BVN2. A signature via that delegate is a genuine cross-partition
governance transaction on the production path.

**Hazards, all of which must be checked, not assumed:**

- It is a **real change to the production signing page**, and the page version
  increments. **Verified 2026-08-26:** `scripts/e2e_matrix.mjs:261` reads the
  version from the chain —
  `Signer.forPage(KEY_PAGE, key).withVersion(kp?.result?.account?.version || 1)`
  — so the bump does not break it. Anything else that signs with a *hardcoded*
  version would; check before assuming the e2e is the only signer.
- A 1-of-1 page gains a second **entry**, not a second required signature. The
  threshold stays 1, so ordinary single-key intents keep working. Verify this
  against the page after the change rather than trusting it — read back
  `acceptThreshold` and the entry list.
- Delegation is **two-sided**: the delegate's page must co-sign the same pending
  transaction, and needs its own credits. See `PHASE7_CORPUS_MANIFEST.md` §6 —
  all three failure modes there return `code: ok` while nothing executes.

### 1.2 Rollback

```
Remove the delegate entry from acc://certen-kermit-12.acme/book/1 via
updateKeyPage { operation: [{ type: "remove", entry: { delegate: "acc://certen-p7f-omega.acme/book" }}] }
```

Confirm against the page, not against the submit result. Removing it restores
the page to a single entry and the pre-phase version + 2.

### 1.3 Steps

1. Add the delegate entry (both sides sign). Verify **against the page**:
   `acceptThreshold`, entry count, and the new `version`.
2. Confirm an ordinary single-key intent still settles — run the e2e once and
   require `status = 1`. **Do this before the cross-partition attempt**: if the
   page change broke normal traffic, that must be found now, not blamed on the
   multi-leg path later.
3. Submit an intent to `acc://certen-kermit-12.acme/data` signed **via the
   delegated path** (omega's key, delegator `acc://certen-kermit-12.acme/book/1`).
4. Follow it through: `intent_lifecycle`, the elected executor's logs, and
   `chain_execution_results`.

> Intent discovery **scans all partitions** for `CERTEN_INTENT`
> (`SearchCertenTransactions` → `getPartitions` → per-partition
> `queryMinorBlocks`), so no account allow-list has to change for this to be
> picked up.

### Gate 1

```sql
-- N+1 layer-4 rows, partitions distinguished
SELECT layer_number, layer_name, bvn_partition FROM chained_proof_layers
WHERE proof_id = :proof ORDER BY layer_number, layer_name;

-- additionalLegs actually persisted
SELECT layer_json::text LIKE '%additionalLegs%' FROM chained_proof_layers
WHERE proof_id = :proof AND layer_number = 1;
```

✅ The proof carries **≥ 2** BVN legs plus the DN leg (≥ 3 layer-4 rows).
✅ `additionalLegs` is present on the L1 row.
✅ `ChainedProofFromStorage` reassembles it and it **verifies offline**
   (`cmd/proofverify --offline`, exit 0).
✅ The stored `ConsensusProof` has `bvns` **populated** — the first time in
   production.
✅ **Settlement `status = 1` on base-sepolia.**
❌ If TX2 reverts, STOP. Do not retry blind: capture the govRoot the fleet
   computed and the one the contract expected, and compare the preimages. A
   revert here means the `bvns` slot changed a root the contract did not expect.

---

## Phase 2 — Record the weakened cross-partition timing basis (item 2)

### 2.1 The constraint that defines this phase

For a cross-partition signer, `evaluateCandidate` **skips** the
`receipt.localBlock <= execMBI` comparison — correctly, because those indices
count different chains. Ordering is instead established by execution inclusion:
Accumulate does not execute a transaction whose signatures came after execution,
and G0 proves it executed.

That reasoning currently lives in a **comment**, and `sameClock` is a **local
variable**. A reader of the proof sees `TimingVerified: true` and cannot tell
that this signer's timing rests on a weaker basis than the others'.

**`TimingVerified` is a field of `ValidatedSignature`, which is inside
`G1Result`, which is hashed into the govRoot (`SetG1FromJSON`).** Adding a field
there moves every govRoot.

So the marker goes **beside** the hashed struct, exactly as `GovReceiptEvidence`
did for receipt paths — never inside it. `pkg/proof/governance_evidence.go`
documents that pattern and why; follow it.

### 2.2 Steps

1. Add a non-hashed evidence type recording, per counted signature: the signer's
   partition, the principal's partition, whether the local ordering check was
   applied, and — when it was not — that ordering rests on execution inclusion.
2. Populate it where `sameClock` is computed.
3. Carry it beside the summary, on the same side of the line as
   `GovReceiptEvidence`.

### Gate 2

✅ `go test ./pkg/execution/contracts/ -run 'TestP6_|TestP7_'` green — in
   particular `TestP6_CanonicalShapesUnchanged` and
   `TestP7_GovRootMovesOnceAndOnlyInTheL4Slot`.
✅ **govRoot is still `15d8808e2ea6ab77`.** If it moved, the marker went inside
   a hashed struct. Revert and put it beside.
✅ A cross-partition proof's evidence names the weaker basis; a same-partition
   one does not.

---

## Phase 3 — Prove multi-authority and page-2 against the network (item 3)

### 3.1 Why this is not "already tested"

`TestP7_Auth_*` pins five rules against a purpose-built source. That is a test of
the **rules**. The corpus contains no account with two authorities and no book
whose page 2 signs, so the code path that reads those from the chain has never
run against Accumulate.

Phase 7's record on this is unambiguous: **five defects were findable only by
running** — enumeration stopping at the principal's page, receipts read from the
wrong page, `acceptThreshold` absent when zero, a silent `continue` that hid it,
and block indices compared across partitions. Offline-green was five-for-five
not enough.

### 3.2 Provision (extend `docs/l4/phase7_corpus/provision.py`)

| Case | Shape | Proves |
|---|---|---|
| **L** | account with **two** authorities, both books must sign | `userTransactionIsReady`: ALL enabled authorities vote |
| **M** | one authority, book with **two pages**, **page 2** signs | `AuthorityWillVote`: ANY page satisfies the book |
| **N** | account with a **disabled** authority | disabled is skipped |

Follow the existing conventions: keys persisted to `scripts/phase7_corpus/keys.json`
**before** anything is created on chain, every step verified against the account
rather than against a submit result, and the manifest written from what was
observed.

### 3.3 Capture and verdict

Extend `cmd/p7corpus` so L, M and N get traces verdicted by
`protocol.VerifyUserSignature`, exactly as A–K are. **Verdicts come from
accumulate-core, never from our own code.**

### Gate 3

✅ L: satisfied only when **both** authorities sign; refused when one does.
✅ M: the book is satisfied, and the evidence names **page 2** as the satisfier.
✅ N: the disabled authority is skipped, and is **not** skipped under
   `ignoreDisabled`.
✅ All three run through the **real G1 prover** against Kermit, not only through
   the resolver.
✅ Cases A, D and F still resolve unchanged.

---

## Phase 4 — Delete the dead invented digest (item 4)

`g1_enhanced_crypto.go` verifies against
`sha256("accumulate/" ‖ txHash ‖ version ‖ timestamp)` via
`CryptographicVerifier.ComputeAccumulateDigest` (`common.go`). That is **not**
the Accumulate digest and never was: the real one is
`sha256(sig.Metadata().Hash() ‖ txHash)`, or the `Initiator()` merkle form.

`processSignaturesWithSuperiorCrypto` has **no callers**, so it is inert today.
It is a loaded gun: wiring it up yields a digest that never verifies, and the
failure surfaces as a *governance rejection* — indistinguishable from "the
institution did not authorize this".

### Steps

1. Confirm it is still unreachable: `grep -rn processSignaturesWithSuperiorCrypto`
   returns only its own declaration.
2. Delete the dead path **and** the invented digest, or — if anything is found to
   depend on it — make it delegate to `AcceptedDigests`.
3. Do not leave a "deprecated" copy. A second digest implementation is a thing
   that can drift; that is why there is one now.

### Gate 4

✅ No second digest implementation remains: `grep -rn '"accumulate/"'` finds
   nothing that builds a signing preimage.
✅ `TestP7_DigestParity` still green.
✅ `go build ./...` clean and the three pre-existing failures unchanged.

---

## Phase 5 — Reject / Response / Block thresholds (item 5)

`KeyPage` carries `AcceptThreshold`, `RejectThreshold`, `ResponseThreshold` and
`BlockThreshold`. `KeyPageState` models **only the accept threshold**; the other
three are dropped at parse.

For a page that leaves them unset — every page in the corpus and in production —
that is complete. For a page that sets them, G1's claim of "threshold
satisfaction" is narrower than the page's actual rules.

### Steps

1. Carry all four on `KeyPageState`.
2. Decide, explicitly and in a comment, what each means for a proof that a
   transaction *already executed*: Accumulate enforced them, and G0 proves
   execution — so the question is whether we **re-derive** them or **record that
   we did not**. Both are defensible; silently ignoring them is not.
3. Whichever is chosen, a page that sets a threshold we do not evaluate must say
   so in the evidence.

### Gate 5

✅ A page with a non-zero reject/response/block threshold is either evaluated or
   **explicitly marked** as carrying rules this proof did not verify.
✅ Pages that leave them unset behave exactly as before — cases A, D, F
   unchanged.
✅ govRoot unmoved (see Phase 2: `KeyPageState` is reachable from `G1Result`; if
   it must widen, it widens beside).

---

## Phase 6 — Body-derived extra authorities (item 6)

`ResolveAccount` takes `extraAuthorities` and nothing derives them. Accumulate
adds `Header.Authorities` from V2Baikonur, and the Accumulate explorer
(`src/components/common/Signatures.tsx`) additionally derives them from the
body:

- `UpdateKeyPage` with an `Add` operation carrying a **delegate** → that delegate
  book becomes a required authority
- `UpdateAccountAuth` with `AddAuthority` → that authority becomes required

The first is the two-sided delegation approval `PHASE7_CORPUS_MANIFEST.md` §6
learned the hard way.

### Steps

1. Derive extras from `Header.Authorities` **and** from the body for those two
   transaction types.
2. Feed them into `ResolveAccount`.
3. Fail closed on an unrecognised operation type in those bodies rather than
   assuming it adds no authority.

### Gate 6

✅ `TestP7_Auth_ExtraAuthoritiesAreRequired` extended to derive rather than be
   handed the extras.
✅ An `UpdateKeyPage` that adds a delegate requires that delegate's approval.
✅ Ordinary `writeData` intents gain no extra authority — cases A, D, F
   unchanged.

---

## Phase 7 — Reconcile the spec claim

`CERTEN_GOVERANCE_PROOF_SPEC.MD` §1.2 says a G1 verifier can independently
validate that **Accumulate's governance rules** were satisfied.

After Phases 5 and 6, either that is true, or the sentence must name what is out
of scope. **An overclaiming spec is its own defect** — it is what let the
single-page assumption look correct for as long as it did.

### Gate 7

✅ Every rule the spec claims is either implemented or explicitly excluded, and
   the exclusions are in the spec rather than only in commit messages.

---

## Phase 8 — Fleet upgrade

Only if code shipped. Follow `PHASE7_RUNBOOK.md` Phase 8 **as amended**: build
once, verify **all three** binaries (`validator`, `govproof`, `txhash`) are
single-distinct **on the images, before any container starts**, then recreate,
then re-verify on the running containers, then re-run the e2e.

If Phase 2 moved govRoot despite the gate, the upgrade is **atomic or broken** —
a mixed fleet reverts every TX2 on every chain.

### Final gate

```bash
go build ./... && go test ./pkg/... -count=1
cd accumulate-lite-client-2/liteclient && go test ./proof/working-proof_do_not_edit/ -count=1
```

✅ Green, except the three pre-existing `consolidated_governance-proof` failures
   — `TestURLUtils`, `TestG0Layer`, `TestCompleteWorkflow` — which are stub tests
   pointing at a literal `"test"` endpoint, fail identically at baseline
   `adb5cae`, and **must be left alone**.
✅ A live e2e settles `status = 1`.
✅ govRoot is either `15d8808e2ea6ab77` or has moved **once**, deliberately,
   under a bumped `L4GovRootVersion`, with the previous value still reproducible.
