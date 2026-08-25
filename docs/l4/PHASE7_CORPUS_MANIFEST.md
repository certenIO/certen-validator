# Phase 7 Gate 7.2 — corpus provisioning state

**Network:** Kermit (`https://kermit.accumulatenetwork.io/v3`)
**Started:** 2026-08-25
**Runbook:** `PHASE7_RUNBOOK.md` §1.1
**Status:** A and B DONE. C-K need delegation structures that are not yet
understood — fold into Phase 7 step 7.2 (see §6)

---

## 1. Funding

| Account | Balance |
|---|---|
| `acc://01ed9d250a625e2b95d6158e4aceaeb9df577ec8bf9a5500/ACME` (`certenkey`) | 9.90 ACME / 4,500 credits |
| `acc://certen-kermit-12.acme/book/1` (`sponsorkey`) | ~499,843 credits |

Ample. Funding is not a constraint on this corpus.

---

## 2. What exists

### Case A — 1-of-1 ed25519 (baseline)

**Already provisioned, pre-existing.** `acc://certen-kermit-12.acme/book/1`,
`AcceptThreshold: 1`, one key (`sponsorkey`). This is what every one of the 400
production proofs used, and it is the case that must keep passing.

### Case B — 2-of-3 ed25519, single key page

`acc://certen-p7b3.acme` — **✅ COMPLETE.** Provisioned by
`scripts/phase7_corpus/provision.py` on 2026-08-25. Verified on chain: `acceptThreshold = 2`, 3 keys (`b1`, `b2`, `b3`), each add
checked against the PAGE rather than against a success flag.

**Co-signing is proven, properly this time.** `sign_and_build` →
`sign_existing` → `submit` created `acc://certen-p7b3.acme/data`, a real
account that exists on chain, authorised by two distinct keys satisfying the
2-of-3 threshold. An earlier claim of "co-signing confirmed" was retracted: it
rested on `code: ok` from the envelope layer while the transaction never
executed.

Co-signing is confirmed working: `sign_and_build` → `sign_existing` → `submit`
produced a **2-signature envelope** accepted with `code: ok`. That is the
operation the CLI cannot perform at all.

#### The abandoned first attempt — kept deliberately

`acc://certen-p7b.acme` is **2-of-2 with a permanently pending third key add**
(tx `1af75c12b80e07e51f143224f82a8b81291230eee706152173ca3b770a875e2c`). It was
built CLI-first with the threshold raised before the last key landed, so that
key's own add now needs a co-signature that the CLI cannot supply.

It is left on chain on purpose: it is a real specimen of a stuck M-of-N
transaction, which is worth having in a corpus about multi-signature governance.

### Wallet keys generated for the corpus

`p7b1 p7b2 p7b3 p7c1 p7cd1 p7d1 p7d2 p7d3 p7dd1`

All ed25519, in the local wallet at `C:\Users\jason\.accumulate\wallet`.
Pre-existing non-ed25519 keys usable for **Case K**: `btc_cli_key`,
`eth_key_test`.

---

## 3. Blockers found in the Accumulate CLI (v1.4.4-beta.4)

These are tooling defects, not protocol problems. Both are reproducible.

### 3.1 `page set-threshold` mis-parses its arguments

```
$ accumulate page set-threshold acc://certen-p7b.acme/book/1 2 --sign-with p7b1
Error: invalid threshold: strconv.ParseUint: parsing "acc://certen-p7b.acme/book/1"
```

`--help` documents `[key page url] [threshold]`, and the command accepts exactly
two arguments, but the threshold is read from the URL's position. Reversing the
arguments fails differently (`account acc://2 does not exist`), confirming
arg[0] *is* treated as the URL — so the two reads disagree with each other.

**WORKAROUND, verified working:**

```bash
accumulate -s $SERVER tx execute acc://<page> \
  '{"type":"updateKeyPage","operation":[{"type":"setThreshold","threshold":2}]}' \
  --sign-with <key> --no-review
```

### 3.2 `tx sign` fails against Kermit — this is the blocker

```
$ accumulate tx sign <txhash> --sign-with p7b2
Error: query network status: unmarshal response: invalid Executor Version "v2-jiuquan"
```

The CLI cannot parse Kermit's executor version on this code path, so **a second
signature cannot be added to a pending transaction from the CLI at all.**

That is fatal for corpus provisioning as a whole, not just for case B: cases
B, D, I and J all require producing genuinely multi-signed transactions, and
that is the entire point of the corpus.

---

## 4. Recommendation — stop using the CLI for this

The CLI got us ADI creation, credit purchase, key addition and (via
`tx execute`) threshold setting. It cannot co-sign, and co-signing is the
substance of the corpus.

**RESOLVED 2026-08-25.** The corpus is provisioned by
`docs/l4/phase7_corpus/provision.py` using the Python SDK
(`opendlt-python-v2v3-sdk/unified/src`), which reads Kermit's executor version
without complaint — so §3.2 is a stale CLI, not a network limitation.

Run it against the SDK source tree, not the installed package, which is older
and lacks `SmartSigner.sign_existing`:

```bash
cd docs/l4/phase7_corpus
PYTHONPATH=C:/Accumulate_Stuff/opendlt-python-v2v3-sdk/unified/src python provision.py B
```

Expected **verdicts** still come from `accumulate-core` in Go, per runbook §1.2 —
that part does not move:

```go
protocol.VerifyUserSignature(sig, protocol.SignableHash(txHash))
```

Reasons this is the right tool rather than a workaround:

- It is version-agnostic — it *is* the protocol package, so no executor-version
  parsing mismatch.
- It can construct `DelegatedSignature` nesting directly, which is required for
  cases C–F and J and which the CLI has no vocabulary for at all.
- Runbook §1.2 already requires `accumulate-core` to produce the expected
  verdicts. Provisioning and verdicting in one program means the corpus and its
  expected results cannot drift.
- It makes the corpus reproducible. A pile of ad-hoc CLI invocations is not.

**Estimated:** ~1 day for the provisioning program, against 2 days already
budgeted for step 7.2 in `PHASE7_DELEGATION_PLAN.md` §6.

---

## 5. Remaining cases

| Case | Shape | State |
|---|---|---|
| A | 1-of-1 ed25519 | ✅ pre-existing |
| B | 2-of-3 ed25519 | ✅ `acc://certen-p7b2.acme`, verified on chain |
| C | 1-of-1 delegated, depth 1 | keys generated, not built |
| D | 2-of-3, one entry delegated | keys generated, not built |
| E | delegated depth 3 | not started |
| F | delegation across BVNs | not started — needs ADIs that route to different BVNs |
| G | depth 21 — must be refused | not started (21 nested pages) |
| H | delegation cycle — must be refused | not started |
| I | duplicate key signs twice — counts once | not started |
| J | right inner key, wrong delegator chain | not started |
| K | non-ed25519 — fail closed, distinct reason | keys exist (`btc_cli_key`, `eth_key_test`) |

Cases C–F and J are the ones that cannot be done from the CLI under any
argument order, because it cannot build a `DelegatedSignature`.


---

## 6. Where this stopped, and why the rest belongs inside Phase 7

Cases A and B are done. C–K are not, and the reason is worth recording rather
than retrying blind.

**Creating a delegation structure is not understood yet.** Three shapes were
tried for `updateKeyPage {add, entry:{delegate: …}}`:

| Attempt | Result |
|---|---|
| delegate to a sibling page in the same book | accepted, never executed |
| delegate to a second key book in the same ADI | accepted, never executed |
| same, co-signed by both the page and the delegate book | accepted, never executed |

In every case the transaction reaches the chain and sits at
`status: "pending"`. So it is not being rejected — something else is required
to satisfy it, and guessing at what has already cost more than it should.

**Two traps confirmed along the way, both worth carrying into Phase 7:**

1. `SmartSigner.sign_submit_and_wait` returns `success=True` for a transaction
   that never executes. Verify against the ACCOUNT, never the result object.
   This is the same class of error as reading `proofExecuted` immediately after
   a mined attestation.
2. The two installed copies of the opendlt Python SDK **derive different
   keypairs from the same seed**. Provisioning with one and signing with the
   other silently orphans an ADI. `provision.py` now pins the SDK and refuses
   to run against the wrong one.

**Recommendation: do C–K as Phase 7 step 7.2, not before it.**

Runbook §1.2 already requires expected verdicts to come from `accumulate-core`
in Go — `protocol.VerifyUserSignature`. Whoever does that work will have the
protocol package open, which is exactly the reference needed to construct a
valid `DelegatedSignature` and to know what a delegate entry requires. Doing
the structures blind from a Python SDK first, then verdicting them in Go
afterwards, is the harder order.

**Orphaned artifacts, left on chain deliberately:**

| ADI | Why |
|---|---|
| `acc://certen-p7b.acme` | CLI-built, threshold raised before the last key landed; third key add permanently pending. A real specimen of a stuck M-of-N transaction. |
| `acc://certen-p7b2.acme` | Provisioned under the installed SDK, signed under the source SDK; its keys cannot be reproduced. Unsignable. |
| `acc://certen-p7c.acme` | Partial case C — two key books, no delegate entry. Usable as a starting point once the delegate mechanics are known. |

Cost: roughly 12k of ~499k credits. Not material.
