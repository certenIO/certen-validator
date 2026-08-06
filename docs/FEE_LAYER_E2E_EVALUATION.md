# Fee layer — end-to-end evaluation and Phase 4–7 plan

**Date:** 2026-08-06
**Scope:** `ethereum-sepolia`, `base-sepolia`, `arbitrum-sepolia` (AnchorV8_1 / AccountV7 /
AccountFactoryV9). Non-EVM deprecated for now.
**Companion to:** `FEE_LAYER_BATCH_INTEGRATION_PLAN.md` (Phases −1 to 3).

---

## The counting trap, stated once so it stops recurring

Three separate wrong conclusions — two mine, one from an external review — came from the same
mistake: **counting rows in a schema that duplicates them.** Almost every validator-side table
stores one row per validator (there are 7), often with several batch attempts per intent. Row
counts run 7–70× the number of real intents.

| table | rows | distinct intents |
|---|---|---|
| `batch_transactions` | 68,909 | **934** |
| `anchor_batches` (multi-member, 30d) | 203 | **39** merkle roots |
| `intent_lifecycle` | 542 | **542** (one row per intent) |

Two rules before any future claim:

1. Count `DISTINCT accum_tx_hash`, never rows.
2. Before claiming "X never happens", confirm the table being read is one that *could* show X.

---

## Corrected findings

### `intent_lifecycle` is not missing activity — it is missing COLUMNS

An external review reported it "captures 0.8% of production" (542 rows against 68,909). That
compared rows to rows. On distinct intents over 30 days:

```
batch_transactions distinct : 286
intent_lifecycle   distinct : 279
in bt but not in il         :  17      ->  97.5% coverage
```

All **34** multi-leg intents are present in `intent_lifecycle`. They are invisible because
`UpsertOnDiscovery` (`repository_intent_lifecycle.go:72`) writes only:

```
intent_id, accum_tx_hash, block_height, user_id, proof_class, target_chain,
status, submitted_at, authorized_at, created_at, updated_at
```

It never writes `leg_count`, `legs_completed`, `legs_failed`, `target_chains` or
`execution_mode`, so those keep their schema defaults (1, 0, 0, NULL, NULL).

**The tell: 238 completed intents, 0 of them with `legs_completed > 0`.**

That makes Phase 4 far smaller than "rebuild the lifecycle table" — it is "write five columns
that are already declared".

### The matrix

Distinct intents, 30 days:

| | `on_demand` | `on_cadence` |
|---|---|---|
| total | 192 | 87 |
| complete | 102 | 14 |
| reached the gateway | 99 | **0** |
| captured a charge | 68 (43%) | **0 (0%)** |

Live, and previously reported by me as "never exercised":

- **34 multi-leg intents**, 14–56 legs each — verified as distinct leg UUIDs, one batch and
  one validator each, so not per-validator duplicates
- **20 multi-chain intents**, all of them multi-leg
- on-cadence has run since **2026-01-30**

Corrections to the external review, for the record: on-cadence is 55–87 distinct intents in
30 days (its "455" was an all-time row count), and the original "14 completed on-cadence" was
correct as stated. Neither the claimed 30× understatement nor the 0.8% coverage figure holds.

### What survives from the first evaluation

- The gateway has **no `proof_class` column anywhere** — 0 rows in `information_schema`.
- **`extraChains` appears nowhere outside tests**, so a multi-chain intent is priced entirely
  on its first leg's chain. With 20 such intents live, that is exposure, not theory.
- **73 receipts, 0 with gas legs** — every SKU is flat, so the recomputable-receipt work
  (including `7af315c`) is correct but dormant until a SKU moves to `quoted`.

### Two defects neither evaluation set out to find

- **Chain naming is inconsistent again in `batch_transactions`**: `ton testnet` (618) beside
  `ton-testnet` (259); `solana devnet` (471) beside `solana-devnet` (300). Same class as
  Phase −1, different table. The three in-scope EVM chains are clean, so it is not urgent —
  but it recurs anywhere a chain name is written without normalisation.
- **88% of `batch_transactions` rows carry no `proofClass`** (60,936 rows, all from
  2026-07-13 to 07-28). Payload-derived class counts are incomplete for that window.

---

## Phase 4 — write the lifecycle counters

**Why first:** it is what every future analysis reaches for, and its silence caused three
wrong conclusions. Small, self-contained, no billing impact.

**Change** — `pkg/database/repository_intent_lifecycle.go`

1. `UpsertOnDiscovery` gains `legCount`, `targetChains`, `executionMode`, taken from the
   intent payload the caller already holds at `discovery.go:864`.
2. New `IncrementLegProgress(intentID, completed, failed)`, called where legs settle.
3. `UpdateStatus` sets `legs_completed = leg_count` on `complete`, so a completed intent can
   never again report 0 of N.

**Tests**

- unit — upsert with 1 / 14 / 56 legs and 1 / 3 chains reads back exactly
- unit — a second upsert (`ON CONFLICT DO NOTHING`) does not zero an existing count
- unit — `IncrementLegProgress` is monotonic and never exceeds `leg_count`
- integration — replay multi-leg intent `0463b225…` (30 legs, arbitrum-sepolia) and assert
  `leg_count = 30`
- backfill verification — afterwards, `SELECT count(*) FROM intent_lifecycle WHERE
  status='complete' AND legs_completed=0` must return **0**
- regression — intent counts and statuses over the previous 24h identical before and after
  deploy; the proof cycle must not observe this change at all

**Backfill:** derive `leg_count` and `target_chains` from `batch_transactions` grouped by
`accumulate_tx_hash`. 934 intents — safe in one transaction.

## Phase 5 — `proof_class` into the gateway

**Why:** 55–87 on-cadence intents a month execute unpriced, and the gateway cannot express
the distinction at all. Batching makes on-cadence ~81% cheaper to serve. That is a product,
and today it is given away.

**Change**

1. `gateway_intents.proof_class`, and accept `proof_class` on `POST /v1/transaction`
   (default `on_demand`, so existing callers are unaffected).
2. Price book gains a `proof_class` dimension; `quoteService.create` takes it.
3. Persist it on quotes and holds so reconciliation can group by it.

**Tests**

- unit — an absent `proof_class` still quotes exactly as today (byte-identical quote row)
- unit — an on-cadence quote differs from on-demand only where the price book says so
- unit — the quote/work mismatch guard rejects an on-cadence quote spent on an on-demand
  intent, as it already does for chain and leg count
- integration — submit one intent of each class, assert two holds with the right SKUs
- **coverage assertion** — a scheduled check that
  `on_cadence captured / on_cadence complete` stays near 1.0, alerting on drift. The absence
  of exactly this metric is what let a 0% billing rate run since January.

## Phase 6 — `extraChains` for multi-chain intents

**Why:** 20 live multi-chain intents, each priced on its first leg's chain only. Bounded today
by flat pricing; under `quoted` this is the ~150× Polygon-vs-Ethereum error the code's own
comment warns about.

**Change:** `billingGuard` collects the distinct chains across `body.intent.legs` and passes
all but the first as `extraChains` to `quoteService.create`. The parameter already exists and
already gates and gas-estimates each chain independently.

**Tests**

- unit — a single-chain intent produces a quote identical to today's
- unit — a 2-chain intent gates and estimates BOTH chains
- unit — an unpriceable second chain refuses the whole quote rather than pricing the half it
  can; a partial price is a wrong price
- unit — the mismatch guard rejects a single-chain quote spent on a multi-chain intent
- regression — replay the 20 known multi-chain intents and assert each produces a quote
  covering every chain it touched

## Phase 7 — multi-leg pricing

**Why:** 34 intents with up to 56 legs, priced today as `legCount` legs on one chain.

**Depends on** Phase 4 (leg counts must be recorded before they can be priced) and Phase 6
(a multi-leg intent is usually the multi-chain one).

**Tests:** per-leg marginal cost against measured `execution_gas_used`; a 56-leg intent must
not price as 56× a single leg, because anchor and verify are shared across the whole intent —
the same fixed-versus-marginal split as Phase 2, one level down.

---

## Order and gates

```
Phase 4  lifecycle counters   <- no billing impact; unblocks measurement of 5-7
Phase 5  proof_class          <- the revenue gap
Phase 6  extraChains          <- live exposure, 20 intents
Phase 7  multi-leg pricing    <- needs 4 and 6
```

No SKU moves to `mode: "quoted"` until 4, 5 and 6 are live AND the pricing gate reports 30
distinct days with events newer than 48h for that chain. Today: ethereum-sepolia 7 of 30
days; base-sepolia and arbitrum-sepolia 1 of 30.
