# Spec: resolve `org_id` gateway-side on cost-event ingest

**For:** whoever owns `certen/api-gateway`
**Route:** `POST /internal/v1/billing/cost-events` — `src/routes/internal-billing.routes.ts`
**Status:** validator side shipped; gateway side is the remaining half.

---

## The bug, precisely

`cost_events.org_id` is `uuid NULL`. The handler passes the validator's value straight through:

```ts
b.org_id ?? null,   // -> uuid column
```

The validator was sending the intent's `created_by` (`"v8_1-cadence-825dc808"`). Postgres rejects
it:

```
DatabaseError: invalid input syntax for type uuid: "v8_1-ca…"
POST /internal/v1/billing/cost-events -> 500
```

Every cost event from the batch settlement path failed. They are not lost — the validator's WAL
retries them — but nothing lands until this is fixed.

## Why the validator cannot just send the right value

`org_id` is a UUID from the gateway's own `organizations` table. **The validator has no access to
it and never will**: it authenticates Accumulate identities (`acc://certen-kermit-12.acme`), not
gateway orgs. There is no lookup available to it.

The existing code already knew this — `reportExecutionCosts` has always passed `""` with the
comment *"org attribution happens gateway-side from the intent"*. That intent was never
implemented, which is why **`org_id` is NULL on all 197 existing rows**.

## What changed on the validator (already shipped)

1. **Stopped sending `org_id`.** `CostEvent.OrgID` is now documented as gateway-populated and is
   always empty on the wire. Pinned by `TestCostEventNeverCarriesAnOrgIDFromTheValidator`.
2. **Added `adi_url`** — the authorising Accumulate identity, e.g.
   `"acc://certen-kermit-12.acme"`. Taken from the batch member itself, which is authoritative:
   it is the same string hashed into the member's Merkle leaf and recomputed on chain by
   `CertenAccountV7`. This gives you a second resolution key when `accum_tx_hash` misses.
3. **Anchor cost is now shared, not duplicated.** A batch anchor is measured once and split
   across its members; each share carries `breakdown.shared_tx`, `shared_with`, and
   `shared_total_gas`. Shared events use idempotency key
   `cost:{chain}:{tx}:{leg}:{intent_id}` — **not** the 4-part default, which would collapse all N
   shares into one row.

## Required gateway changes

### 1. Accept the new fields (schema)

`adi_url` and `breakdown` are currently undeclared. Add to `body.properties`:

```ts
adi_url:   { type: 'string', maxLength: 256 },
breakdown: { type: 'object', additionalProperties: { type: 'string' } },
```

Note `accum_tx_hash` is **also undeclared today** despite being inserted and being the primary
join key — worth adding at the same time:

```ts
accum_tx_hash: { type: 'string', maxLength: 128 },
```

### 2. Never trust a client-supplied `org_id`

Replace `b.org_id ?? null` with a resolved value. Even after the validator stops sending one, an
unvalidated pass-through of a UUID-typed column from a client payload is the wrong shape.

### 3. Resolve the org, in this order

```ts
async function resolveOrgId(b): Promise<string | null> {
  // 1. The intent, if it came through this gateway. Authoritative.
  if (b.accum_tx_hash) {
    const r = await txQuery<{ org_id: string }>(
      'SELECT org_id FROM gateway_intents WHERE accum_tx_hash = $1 LIMIT 1',
      [b.accum_tx_hash],
    );
    if (r.rows[0]?.org_id) return r.rows[0].org_id;
  }

  // 2. The ADI, which IS bound to an org — verified: identities(org_id, adi_url).
  //    This is the case step 1 cannot cover: an intent that reached Accumulate without
  //    passing through the gateway still belongs to a registered ADI.
  if (b.adi_url) {
    const r = await txQuery<{ org_id: string }>(
      'SELECT org_id FROM identities WHERE adi_url = $1 AND deleted_at IS NULL LIMIT 1',
      [b.adi_url],
    );
    if (r.rows[0]?.org_id) return r.rows[0].org_id;
  }

  // 3. Genuinely unattributable — store the cost, leave org NULL.
  return null;
}
```

Step 2 is **verified against the live schema**, not assumed: `identities` has
`id, org_id, adi_url, adi_name, …, deleted_at`, and `identities.repo.ts` already queries
`WHERE adi_url = $1 AND org_id = $2`. The `deleted_at IS NULL` guard matters — a soft-deleted
identity should not silently keep attributing new spend to its old org.

**NULL must remain valid.** An intent submitted straight to Accumulate never passes through the
gateway, so it has no org and is not billable to anyone. Dropping or rejecting those events would
lose real spend data — CERTEN still paid that gas. Record it unattributed.

`identities` needs confirming: it has an `org_id`, but I have not verified it carries the ADI URL
or under what column name. If it does not, step 2 is a no-op and step 1 carries the load.

### 4. Backfill the existing rows

```sql
UPDATE cost_events ce
   SET org_id = gi.org_id
  FROM gateway_intents gi
 WHERE gi.accum_tx_hash = ce.accum_tx_hash
   AND ce.org_id IS NULL
   AND gi.org_id IS NOT NULL;
```

Measured before writing this: that join resolves **0 of 197** rows today, because those events
predate `accum_tx_hash` being populated. Expect it to be a no-op on history and to matter only
going forward. Run it anyway — it is idempotent and costs nothing.

The ADI backfill will likely recover more, since `identities` is populated independently of
whether an intent transited the gateway:

```sql
UPDATE cost_events ce
   SET org_id = i.org_id
  FROM identities i
 WHERE i.adi_url = ce.adi_url
   AND ce.org_id IS NULL
   AND i.deleted_at IS NULL;
```

This one only helps rows written **after** `adi_url` starts arriving — the existing 197 have no
ADI recorded, so it is a no-op on them too. Both backfills exist so the columns are correct from
the first new event onward rather than needing a cleanup pass later.

## Verification

The validator has **2 events sitting in its WAL** for intent `825dc808-…` (Base Sepolia, anchor +
vault_execute) that have been retrying since 19:41 UTC on 2026-08-05. They will deliver on their
own once ingest stops 500ing — no resubmission needed. Confirm with:

```sql
SELECT chain, chain_id, leg, gas_used, org_id, adi_url,
       breakdown->>'shared_with' AS shared_with
FROM cost_events WHERE created_at > now() - interval '1 day' ORDER BY created_at;
```

Expect: `base-sepolia` / `84532`, legs `anchor` and `vault_execute`, `shared_with = 1`,
`adi_url = acc://certen-kermit-12.acme`, and `org_id` NULL (that intent was submitted directly to
Accumulate, so it is correctly unattributed).

## Two things worth knowing

**Chain normalisation is now done twice.** The handler already normalises via
`canonicalChain(b.chain, b.chain_id)`. The validator now also emits the canonical slug at source.
Both are idempotent so this is harmless, and the gateway-side one is still worth keeping — it
fixes events replayed from an older validator's WAL. Flagging it so nobody removes one thinking
the other is redundant in the wrong direction: **keep the gateway's**.

**`EXPECTED_LEGS = 4` is wrong.** There is no `execute_legs` transaction. Settlement is three
transactions — `createAnchor`, `executeComprehensiveProof`, `executeGovernanceProofDirect` — and
the validator records exactly three workflow steps (393/319/280 rows). The `execute_legs`
constant exists with no emitter. Recommend dropping the expectation to 3 rather than synthesising
a fourth leg, which would put fabricated cost into the estimator.
