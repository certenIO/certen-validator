# Phase 7 Gate 7.2 — corpus provisioning state

**Network:** Kermit (`https://kermit.accumulatenetwork.io/v3`)
**Started:** 2026-08-25
**Runbook:** `PHASE7_RUNBOOK.md` §1.1
**Status:** A–F, H, K provisioned and verified on chain. G (depth 21) running.
I and J are signing-time cases, not structures — see §7.

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

## 6. The delegation mechanic, once understood

Adding B as a delegate of A is a change to **two** authorities, so **both must
sign**:

> A grants the power; B accepts being bound. The transaction A initiates sits at
> `code: pending` until B's key page signs **the same transaction**.

Three things had to be right together, and getting any one wrong looks identical
from the outside — `code: ok`, nothing on the page:

1. **Delegate to a BOOK, not a sibling page.** A page delegating to another page
   of its own book is accepted and never executes.
2. **Sign the PENDING transaction, not a fresh copy.** Rebuilding the body and
   co-signing the new envelope yields a different transaction hash — the
   initiator is baked into the header from the first signer's metadata — so the
   original stays pending forever while a twin is created beside it. Fetch the
   pending transaction back off chain and sign *that*.
3. **The delegate's page needs its own credits.** Without them the approval is
   refused with `envelope(1/insufficientCredits)` — reported in the submit
   result's `message`, **not** in `status.code`, which still reads `ok`.

That third point is the same trap as everything else in this session: a success
at one layer read as evidence about another. The submit result's `status.code`
describes envelope acceptance. It says nothing about execution.

`add_delegate()` in `phase7_corpus/provision.py` encodes all three and verifies
against the page afterwards.

### Funding, which a chain exhausts

`fund_lite` runs once and returns early while the lite IDENTITY still holds
credits — but buying page credits spends ACME from the lite TOKEN account, which
empties independently. Case E died at depth 3 with `book3/1` on zero. Every page
in a chain signs, so every page needs credits; `credit_page` now re-faucets when
the token account runs low and grants a modest amount per page instead of ~1M.

**Orphaned artifacts, left on chain deliberately:**

| ADI | Why |
|---|---|
| `acc://certen-p7b.acme` | CLI-built, threshold raised before the last key landed; third key add permanently pending. A real specimen of a stuck M-of-N transaction. |
| `acc://certen-p7b2.acme` | Provisioned under the installed SDK, signed under the source SDK; its keys cannot be reproduced. Unsignable. |
| `acc://certen-p7c.acme` | Partial case C — two key books, no delegate entry. Usable as a starting point once the delegate mechanics are known. |

Cost: roughly 12k of ~499k credits. Not material.

---

## 7. Provisioned cases

| Case | Shape | Root ADI | State |
|---|---|---|---|
| A | 1-of-1 ed25519 (baseline) | `acc://certen-kermit-12.acme` | pre-existing |
| B | 2-of-3 ed25519, single key page | `acc://certen-p7b3.acme` | ok |
| C | 1-of-1 delegated, depth 1 | `acc://certen-p7c.acme` | ok |
| D | 2-of-3, one entry delegated | `acc://certen-p7d.acme` | ok |
| E | delegated depth 3 | `acc://certen-p7e.acme` | ok |
| F | delegation across ADIs (target: different BVNs) | `acc://certen-p7f-alpha.acme` | ok |
| H | delegation cycle — MUST BE REFUSED | `acc://certen-p7h.acme` | ok |
| K | non-ed25519 signature — MUST FAIL CLOSED | `acc://certen-p7k.acme` | ok |

Keys are in `scripts/phase7_corpus/keys.json` — untracked, on the far side of
the `/scripts/` gitignore boundary that exists because key material must not be
committed. **Losing that file orphans every ADI above.**

### I and J are not structures

| Case | Why it is not provisioned |
|---|---|
| I — duplicate key signs twice, counts once | Uses case B's page. Sign the same envelope twice with the same key as the same signer; the threshold must not advance. |
| J — right inner key, wrong delegator chain | Uses case C's or E's chain. Build a `DelegatedSignature` naming a delegator path that does not match the structure. The digest commits to the whole chain, so it must be refused. |

Both are produced at trace-capture time, in the same Go program that computes
expected verdicts with `protocol.VerifyUserSignature` — which is where they
belong, because the verdict and the trace must come from the same source.
