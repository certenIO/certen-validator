# Fee layer × on-cadence batching — implementation plan

**Status:** Phase −1 in progress. Phases 0–3 approved, not started.
**Scope:** `ethereum-sepolia` (11155111), `base-sepolia` (84532), `arbitrum-sepolia` (421614).
Those are the only chains carrying AnchorV8_1 / AccountV7 / AccountFactoryV9. Non-EVM chains
are deprecated for now and deliberately out of scope.

**Guiding constraint:** on-cadence proof_class took 20 hours to get working. Nothing in this
plan may change the proof cycle's behaviour. Every phase is additive, and each one is
shippable and verifiable on its own.

---

## 1. What the code actually does today

### Pricing is flat, so gas is not billed at all

Live price book `2026-07-25.phase-a`, every entry `mode: "flat"`:

| sku | chain | platform fee |
|---|---|---|
| `proof.execute` | `base-sepolia` | $0.35 |
| `proof.execute` | `*` | $0.50 |
| `proof.governance` | `*` | $0.10 |
| `account.deploy` | `*` | $1.00 |
| `identity.provision` | `*` | $5.00 |

`settlement.service.ts` zeroes gas on flat SKUs (`billableGas = isFlat ? 0n : measured`),
because a receipt whose computation includes gas would not recompute to a fee-only capture.

**So CERTEN currently absorbs 100% of gas on every intent, batched or not.** Amortisation is
a MARGIN question today, not a customer-fairness one. That is the headroom this plan spends:
Phases −1 to 2 can land without any customer-visible price moving.

### The batch path reports no cost at all

`reportExecutionCosts` has exactly one call site — `bft_target_chain_integration.go:346`, the
per-intent path. `grep` for `billing.` / `CostReporter` / `ObserveAndReport` across
`pkg/execution/batch_*.go` returns nothing. `BatchResult.GasAnchor` is captured at
`batch_orchestrator.go:296`, logged, and discarded.

Consequence: a batched intent produces no `cost_events` row → `measuredCostFor` returns `0n`
→ settled at platform fee only.

### Chain identifiers do not match between the two sides

```
quotes.chain      : ethereum-sepolia (90), base-sepolia (15), polygon-amoy (1), accumulate (4)
cost_events.chain : Ethereum Sepolia (197)   ← the only value that has ever been written
cost_events.chain_id : NULL on all 197 rows
```

Everything keyed by chain is therefore inert:

- `pricingGate.assess('ethereum-sepolia')` → `events === 0` → `unavailable`
- `estimateGasLegs('ethereum-sepolia')` → no rows → **median 0 → zero gas estimate per leg**

This does not bite yet only because the gate is gated on quoted pricing:

```ts
// quote.service.ts:133
if (!params.skipChainGate && item.mode === 'quoted') await pricingGate.assertPriceable(chain);
```

The moment any SKU moves to `quoted`, it fails immediately.

### What already works — do not disturb

- **The settlement join.** `cost_events → gateway_intents` on the normalised Accumulate tx
  hash (`ACCUM_TX_MATCH`). 179 of 197 rows join. Per-intent attribution is sound, and the
  per-member design in Phase 1 rests on it.
- **Hold/settle lifecycle.** 68 captured, 21 released, 73 receipts. Quote → hold (capped) →
  settle at measured actual is already a pre-authorisation model. No refund path is needed
  and none should be added.
- **Per-chain pricing.** Quotes price each chain independently; a multi-chain request gates
  and estimates every chain it touches. Correct as-is.

### Known gaps not covered by the phases below

- **`execute_legs` is never reported.** Only `anchor`, `verify`, `vault_execute` appear;
  `EXPECTED_LEGS = 4`. If that cost is currently being mislabelled as `anchor` (see the
  fallback in `cost_reporting.go`), the anchor p50 is inflated and Phase 2's split would
  inherit the error. Investigate in Phase 0.5.
- **`chain_id` is never populated**, though `reportExecutionCosts` parses
  `result.Metadata["chainId"]`. Harmless today; worth fixing so normalisation can key on the
  number rather than a display string.
- **Coverage is thin**: 5 distinct days (gate requires 30), newest event 61h old (limit 48h).
  Both must be satisfied before any SKU moves to `quoted`.

---

## Phase −1 — canonical chain identifier  *(in progress)*

**Why first:** nothing chain-keyed can work until both sides agree on a string. Phases 1–3
would be building on a key that never joins.

**Change**

1. New `api-gateway/src/utils/chain-name.ts` — single source of truth:
   - `CHAIN_ID_TO_NAME`, moved from `billing-guard.ts` so there is one copy, not two that
     drift.
   - `canonicalChain(chain, chainId)`: prefer the numeric id (exact); otherwise normalise the
     string (`"Ethereum Sepolia"` → `ethereum-sepolia`).
2. Apply at the **ingest boundary** — `routes/internal-billing.routes.ts` — not in the
   validator. One place to change, the validator needs no redeploy, and replayed WAL events
   from older builds normalise correctly too.
3. Populate `chain_id` at ingest when it can be derived from the canonical name, so future
   rows are unambiguous.
4. `normalizeChainName` in `reconciliation.service.ts` delegates to the new module and stays
   exported (other callers depend on it).
5. Migration: backfill `cost_events.chain` and `chain_id` for existing rows.

**Verification**

- `normalizeChainName('Ethereum Sepolia') === 'ethereum-sepolia'` — confirmed against prod
  data before writing the migration.
- After backfill: `chain_cost_coverage()` reports `ethereum-sepolia`, and
  `estimateGasLegs('ethereum-sepolia')` returns non-zero medians.
- No customer-visible change: all SKUs remain flat, so neither the gate nor the estimator is
  on the critical path.

**Risk:** low. Additive plus a data backfill. The idempotency key is unchanged, so no rows
are duplicated or dropped.

---

## Phase 0 — batch path reports cost  *(URGENT — corrected 2026-08-04)*

### Correction: multi-member batching is live

An earlier revision of this document deprioritised Phase 0 on the grounds that prod showed
"no batching". **That was wrong, and the reasoning was circular:** this document had already
established that the batch path emits no cost events, and then used the resulting absence of
shared tx hashes in `cost_events` as evidence that batches do not occur. The emptiness was
guaranteed by the very defect being investigated.

The question spans TWO databases. Batching is recorded in the validator's `certen_proofs`,
not the gateway's `certen_gateway`. From `anchor_batches`, last 30 days:

| members | batches |
|---|---|
| 8 | 7 |
| 5 | 14 |
| 4 | 7 |
| 3 | 22 |
| 2 | 146 |

**196 multi-member batches covering 512 intents, mean 2.61 members, max 8.**

Scale, stated precisely: those 512 sit inside ~53,500 intents across closed batches in the
same window, so multi-member is roughly **1% of volume today** — a live, structural mechanism
reaching 8×, not yet the common case. (The ~53,140 closed batches in 30 days is about one per
48s and looks like scheduler churn rather than 53k real intents; confirm before sizing any
work off that denominator.)

### Why this outranks Phase −1

The chain-naming defect is **latent** — gated behind `mode === 'quoted'`, and every live SKU
is flat. It breaks the first SKU moved to quoted pricing.

The batching blind spot **mis-bills real traffic the moment quoted pricing goes live**. When
8 intents share one anchor, the anchor is ~81% of the cost and is incurred once. A fee layer
built on "one anchor per intent" attributes a full anchor to each of the 8 — 2.61× over on
average, 8× at the tail.

### The modelling correction

Cost must be attributed **per anchor, then divided across members** — never assumed per
intent. That is the entire economic point of `createBatchAnchor`. Phase 2's split rule would
otherwise inherit the per-intent assumption backwards.

### Blocking data gaps — SUPERSEDED, see Phase 0a below

`anchor_batches` records that a batch had N members but not what it cost or where it landed:

```
rows=66699   anchor_tx_hash non-null = 0   gas_used non-null = 0
```

The original conclusion — "populate both from the orchestrator" — was wrong. See Phase 0a.

Note `anchor_batches.target_chain` ALREADY carries the slug (`ethereum-sepolia`,
`base-sepolia`, `arbitrum-sepolia`). The validator knows the canonical form; it is
specifically the cost reporter that emits the anchor-config display name. Point the reporter
at the same source.

### Work — items 2-4 DONE 2026-08-05/06

2. ~~Call the reporting hook after `settleMember`~~ — done (`a3e88be`). Verified live: anchor
   `0x5f3a33b6` split 139,041 + 139,040 = 278,081 across its two members.
3. ~~Emit the slug~~ — done (`20e9c8c`). All three chains, `chain_id` on 100% of rows.
4. ~~Emit `execute_legs`~~ — resolved by decision (`1fdbf7c`): there is no fourth on-chain
   transaction, so `EXPECTED_LEGS = 3`.

---

## Phase 0a — RESCOPED: `anchor_batches` is a PER-VALIDATOR record

The original plan said "populate `anchor_batches.anchor_tx_hash` from the orchestrator". That
is not implementable as written, and the reason matters.

**Every validator writes its own row for the same logical batch.** Intent
`10ab4f77` sits in 7 batch rows, one per validator, created within 4 seconds of each other:

```
validator-7 closed  root=cb0973cd…      validator-1 closed  root=5fd308a2…
validator-6 closed  root=cb0973cd…      validator-2 FAILED  root=5fd308a2…
validator-5 closed  root=cb0973cd…      validator-3 closed  root=5fd308a2…
                                        validator-4 closed  root=5fd308a2…
```

So there is no single row to write the anchor tx into. Only the elected validator sends that
transaction; the other six never see it. Writing to the leader's row alone means the answer to
"what did this batch cost" depends on which validator you ask.

**This also corrects the scale figures in this document and in the external review.** Both
counted per-validator duplicates:

```
multi-member on_cadence rows (30d) : 203
DISTINCT merkle_roots              :  39     <- the real number of logical batches
```

~39 multi-member batches in 30 days, not 196/203. Intents covered ≈ 512 / 7 ≈ 73, not 512.
Batching is live and structural — the split is proven on chain — but an order of magnitude
rarer than previously stated. Nobody should size work off the 512 figure.

**`merkle_root` is the logical batch identity.** It is written by every validator, it is what
`BatchOrchestrator` computes as its `BatchTree` root, and it is what the EVM anchor commits
to. Any batch↔cost reconciliation must key on the root, never on a per-validator row id.

**And `BatchOrchestrator` has no database access at all** — its struct is `{attempts, ecm,
anchorV7, prover, mempool, logf}`. It holds no repository, no batch UUID. It could not write
`anchor_batches` without being given a DB handle it was deliberately not given.

### Is Phase 0a still needed?

Its original justification is largely gone. `cost_events.breakdown` already carries
`{shared_tx, shared_with, shared_total_gas}`, and members are identifiable by
`accum_tx_hash` — so batch↔cost reconciliation is ALREADY possible from gateway data alone.

What `anchor_batches` would add is **independence**: a record of the anchor tx and its gas
from a source that is not the cost reporter, so the reporter's claimed divisor can be checked
rather than trusted. That is worth having in an auditable billing stack, but it is
defence-in-depth, not a blocker.

If it is done, the shape is: key on `(merkle_root, target_chain)`, written by the anchoring
validator only, into its own small table rather than a nullable column on a per-validator row.
Do NOT broadcast it to all seven — that is consensus traffic for a bookkeeping field.

---

## Phase 0.5 — why is `execute_legs` never reported

Likely the `looksLikeTxHash(result.TxHash)` fallback in `cost_reporting.go`, which attributes
everything to `anchor` when the per-leg fields are empty. Confirm before Phase 2, since the
split rule depends on separating fixed legs from marginal ones.

---

## Phase 1 — per-member attribution

1. `reporter.go:88` — idempotency key gains the intent id:
   `cost:{chain}:{tx}:{leg}` → `cost:{chain}:{tx}:{leg}:{intentID}`.
   Without this, N members sharing an anchor tx produce N identical keys and
   `ON CONFLICT (idempotency_key) DO NOTHING` keeps all but the first.
2. `cost_events` gains `batch_tx_hash`, `batch_member_count`, `batch_total_microusd`.
3. Validator reports one event per member per leg, carrying the member's own
   `accum_tx_hash` (which the settlement join already uses) and the shared anchor tx hash as
   a value.
4. **Same change**: `estimateGasLegs` switches to
   `COALESCE(batch_total_microusd, cost_microusd)`.
   `cost_microusd` = the member's billed share; the batch total = the unamortised fact. The
   cap must be estimated from the unamortised figure or it silently drifts downward as
   batches grow, and "cap = solo cost" stops being true.

---

## Phase 2 — the split rule

- **Fixed** (`anchor`, `verify`): divide equally by member count.
- **Marginal** (each member's own `execute_legs`, `vault_execute`, per-leg calldata): charged
  in full to that member.

Measured on Sepolia, anchor+verify are 802,128 of 987,644 gas (81.2%) — the amortisable part.
An equal split of the *whole* batch would let a 4-leg multi-chain intent free-ride on a 1-leg
Base intent in the same batch; this rule prevents that.

Quote at `batch_size = 1` as the cap. `N=1 is a legitimate batch`
(`batch_mempool_ondemand.go`), so the cap is a real case, not a hypothetical. Batching then
only ever reduces a bill — which also removes any incentive to game batch timing.

---

## Phase 3 — keep the receipt recomputable

- `CHARGE_FORMULA` is carried inside each receipt (`ChargeComputationResult.formula`), so old
  receipts keep recomputing when the constant changes — but only if a NEW formula string is
  added rather than the existing one edited in place.
- The divisor must be verifiable. The batch anchor stores only a `batchRoot`, so a member can
  prove their own inclusion but cannot derive N. **Publish the batch's leaf hashes** with the
  receipt: enough to rebuild the root and count members, no payloads, no counterparty
  identities. Without it, `member_count` is an unverifiable assertion by the party doing the
  billing — the one thing this billing stack otherwise never does.
- Integer division truncates. State the remainder policy: CERTEN absorbs the ≤(N−1) micro-USD
  of dust.

---

## Order of operations

```
Phase −1  canonical chain id          ← DONE (8bf8eaa), migration not yet applied
Phase 0   batch cost reporting        ← URGENT. Data being lost now, unrecoverably
  0a      populate anchor_tx_hash + gas_used on anchor_batches
  0b      report per-member cost events from the batch path
Phase 0.5 execute_legs investigation  ← read-only; gates Phase 2's split rule
Phase 1   per-member attribution      ← schema + key + estimator, together
Phase 2   split rule (per anchor ÷ members, NOT per intent)
Phase 3   receipt + leaf publication  ← ships with or before Phase 2
```

Phase 0a is the one piece that cannot wait. Every batch that anchors without recording its
tx hash and gas is a cost that can never be reconciled — the chain charged us and the only
record of how much is gone. Everything else in this plan can be reconstructed later from
data that still exists.

Do not switch a SKU to `mode: "quoted"` until Phases −1, 0 and 1 are live AND the pricing
gate reports 30 distinct days with events newer than 48h for that chain.

---

## Methodology note

The wrong conclusion in this document's first revision came from asking a two-database
question of one database. Cost lives in `certen_gateway`; batch structure lives in
`certen_proofs`. Any future claim about batching economics has to be checked against both,
and a claim of the form "X does not happen" must not rest on a table that a known defect
prevents X from ever reaching.
