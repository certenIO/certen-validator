# Phase 7 Gate 7.2 — corpus provisioning state

**Network:** Kermit (`https://kermit.accumulatenetwork.io/v3`)
**Started:** 2026-08-25
**Runbook:** `PHASE7_RUNBOOK.md` §1.1
**Status:** IN PROGRESS — 1 of 11 cases partially provisioned, blocked (see §3)

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

`acc://certen-p7b.acme` — **PARTIAL. Currently 2-of-2, not 2-of-3.**

| Item | Value |
|---|---|
| ADI | `acc://certen-p7b.acme` |
| Key book | `acc://certen-p7b.acme/book` |
| Key page | `acc://certen-p7b.acme/book/1` |
| Credits | ~1,994 |
| AcceptThreshold | 2 |
| Keys landed | `p7b1` (index 0), `p7b2` (index 1) |
| Key PENDING | `p7b3` — tx `1af75c12b80e07e51f143224f82a8b81291230eee706152173ca3b770a875e2c` |

**Why it is stuck:** the threshold was raised to 2 *before* the third key
landed, so the `addKeyPageEntry` for `p7b3` now needs two signatures and sits
pending with one. See §3.2 — the second signature cannot currently be supplied
from the CLI.

**Lesson for every remaining case: add all keys FIRST, set the threshold LAST.**

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

The corpus should be provisioned by a **Go program using
`gitlab.com/accumulatenetwork/accumulate` directly** — the same package the
runbook already mandates for computing expected verdicts:

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
| B | 2-of-3 ed25519 | ⚠️ 2-of-2, third key pending |
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
