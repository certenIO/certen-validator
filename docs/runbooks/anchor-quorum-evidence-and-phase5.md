# Runbook — anchor quorum evidence: Phase 5 is empty and L5 rows bind the wrong root

Status: ready to implement. Owner: validator (`pkg/batch`, `pkg/execution`, `pkg/database`) + proofs_service.
Base: `4fa751b` (origin/main).
Severity: **correctness of published evidence**. Some L5 rows assert a binding that is false, and every
intent reports `batch_quorum_met = false` even at 7/7 quorum.

---

## 1. What is wrong

Three separate facts, all confirmed against production:

1. **The only Phase 5 writer never runs.** `ConsensusCoordinator` (`pkg/batch/consensus_coordinator.go`)
   is never constructed: `NewConsensusCoordinator(` has no non-test caller. Therefore
   `UpdateBatchPhase5` and `MarkConsensusQuorumMet` are dead code.
2. **`anchor_batches` holds shadow rows.** The only insert is `pkg/batch/collector.go:215`, reached from
   `discovery.routeIntentToBatchSystem`, on **every** validator with a **random UUID** (~8.6 rows per
   intent). Their leaves are `sha256(4 blobs)` (`discovery.go:1211`), not the on-chain leaf
   `keccak("certen:batchleaf:v1"…)` (`batch_tree.go:27`), so their roots are **never** the roots that are
   published. The old anchoring path fails every time (`processor.go:444`: ABI parse errors, "nonce too
   low"); `anchor_records` has **0 rows, ever**.
3. **The real quorum evidence is discarded.** `BatchQuorumAttestor.prove`
   (`pkg/execution/batch_quorum_attestor.go:157`) builds a `QuorumAggregate` (aggregate signature,
   aggregate pubkey, signers, signed/total voting power — `pkg/consensus/batch_quorum_aggregate.go:59`)
   and returns **only `error`**. Live example: `[BATCH-QUORUM] quorum formed: 700 of 700 voting power from
   7 signer(s)`. Nothing is persisted.

### Production numbers (read-only queries)

| Query | Result |
|---|---|
| `anchor_batches` all time | 70,236 on_demand + 852 on_cadence; **0** ever had `quorum_reached` |
| last 3 days | 476 rows for 55 intents; `awaiting_elected_anchor` 394, `failed to create anchor` 82 |
| `anchor_records` | 0 rows, ever |
| `consensus_entries` ↔ `anchor_batches` | 0 join by id, 0 by `merkle_root` (7,756 rows) |
| `validator_attestations.batch_id` | never set (2,671 rows) |
| gateway `cost_events` | 325 `verify` + 281 `anchor` legs since 2026-07-26, keyed by `accum_tx_hash` — **the backfill source** |

### User-visible consequences

- `proofs_service.GetProofByIntentID` (`pkg/database/proof_artifact_repository.go:2821`) returns
  `COALESCE(ab.quorum_reached,FALSE)` → always false; its `anchor_records` join → `anchor_tx_hash` always
  null. The web Transaction Center shows `batchQuorumMet=false` for every intent.
- **False binding (worst item):** `GetLayer5Binding` (`layer5_binding.go:80`) picks the newest *shadow*
  row and `WriteLayer5Row` records the **settlement** tx as the anchor tx. Live example: L5 claims root
  `d2d24ab3…` is in tx `0x9e4ff6ab…`, but that tx settled root `2fd899ae…`. ~25 such rows in 3 days.

---

## 2. Target design

**One owner, one key, one write, written only after the chain confirms.**

- **Owner:** the batching/on-demand lane that actually anchors (`pkg/execution`), at the moment quorum is
  proven and `AnchorProofExecutedConfirmed` holds. Nothing else writes Phase 5.
- **Key:** `(chain_id, bundle_id)` — deterministic across all 7 validators and identical to the contract's
  own key. Row id `uuid.NewSHA1(certenAnchorNS, chainID‖bundleID)` so every validator and every retry
  converge on one row.
- **Write:** one transaction inserting the anchor row (Phase 5 columns set), its member
  `batch_transactions` (on-chain leaf, index, branch, intent id, accum tx), and one `batch_attestations`
  row per signer. **Write-once**: `ON CONFLICT DO NOTHING`; a *different* signature for the same key is an
  alert, never an overwrite. The chain is the source of truth; the database is a projection.
- **Durability:** a failed write goes to an outbox; a reconciler replays it and also covers the
  "already attested by another leader" path.

Rejected alternatives:

| Alternative | Why not |
|---|---|
| Wire up `ConsensusCoordinator` | It runs a second, weaker count-based quorum over roots that are never published — it would invent evidence |
| Match shadow rows by `merkle_root` or `intent_id` | Roots differ by construction (0 matches); by intent it would stamp quorum on 7–9 rows whose root nobody signed |
| Key off `consensus_entries` | Different thing entirely (0 of 7,756 join); it records one validator's own single signature |
| Fill from `aggregated_attestations` | A different signed message (Phase 8 execution result), no `proof_id` |
| Read-time chain lookup or a SQL view | No durable record, an RPC per read, and nothing underneath to view |

---

## 3. Implementation

### Step 1 — return the evidence instead of dropping it

`pkg/consensus/batch_quorum_aggregate.go`: add

```go
type AnchorQuorumEvidence struct {
    ChainID, BundleID, Root, BatchOperationID, MessageHash string
    AnchorCreateTx, VerifyTx string
    VerifyBlock uint64
    VerifyBlockTime time.Time
    AggregateSignature, AggregatePubKey []byte
    Signers []string          // EVM addresses
    SignerPowers []uint64
    SignedVotingPower, TotalVotingPower uint64
    Members []AnchorMember    // intent id, accum tx, leaf, index, branch
}
```

`pkg/execution/batch_quorum_attestor.go:157` — change `prove(...) error` to
`prove(...) (*consensus.AnchorQuorumEvidence, error)`; populate it from the `QuorumAggregate` plus the
confirmed verify receipt. Propagate through `FlushChain` and `SettleOnDemandMember`.

### Step 2 — hook, following the existing `SetLegProgressHook` pattern

```go
func (x *BatchQuorumAttestor) SetAnchorAttestedHook(fn func(context.Context, *consensus.AnchorQuorumEvidence))
```

Call it **only** when `prove` succeeds AND `proofExecuted` is true. Never on `QuorumNotReadyError`, never
on a mismatch. The hook must not block the caller: hand off to the writer's queue (same non-blocking
pattern as `consensusPersister.enqueue`).

### Step 3 — migration 018 (expand-only)

```sql
ALTER TABLE anchor_batches
  ADD COLUMN IF NOT EXISTS chain_id            BIGINT,
  ADD COLUMN IF NOT EXISTS bundle_id           VARCHAR(80),
  ADD COLUMN IF NOT EXISTS batch_operation_id  VARCHAR(80),
  ADD COLUMN IF NOT EXISTS anchor_create_tx    VARCHAR(80),
  ADD COLUMN IF NOT EXISTS verify_tx           VARCHAR(80),
  ADD COLUMN IF NOT EXISTS verify_block        BIGINT,
  ADD COLUMN IF NOT EXISTS message_hash        VARCHAR(80),
  ADD COLUMN IF NOT EXISTS signed_voting_power BIGINT,
  ADD COLUMN IF NOT EXISTS total_voting_power  BIGINT,
  ADD COLUMN IF NOT EXISTS signers             JSONB,
  ADD COLUMN IF NOT EXISTS evidence_source     VARCHAR(32),   -- live | chain_backfill | legacy_shadow
  ADD COLUMN IF NOT EXISTS lane                VARCHAR(16);   -- on_demand | on_cadence

CREATE UNIQUE INDEX IF NOT EXISTS uq_anchor_batches_chain_bundle
  ON anchor_batches(chain_id, bundle_id) WHERE bundle_id IS NOT NULL;

ALTER TABLE batch_attestations
  ADD COLUMN IF NOT EXISTS evm_address  VARCHAR(64),
  ADD COLUMN IF NOT EXISTS voting_power BIGINT;
ALTER TABLE batch_attestations ALTER COLUMN bls_signature DROP NOT NULL;  -- backfilled signers
```

Follow the conventions this repo now uses (see `017_consensus_persistence_progress.sql`):
`pg_advisory_xact_lock`, `IF NOT EXISTS`, and the file inserts its own `schema_migrations` row.

### Step 4 — `RecordAnchorQuorum` (one transaction)

`pkg/database/repository_batch.go`:

```go
func (r *BatchRepository) RecordAnchorQuorum(ctx context.Context, ev *AnchorQuorumRecord) (Written bool, err error)
```

- Upsert the anchor row by `(chain_id, bundle_id)` with `quorum_reached=true`,
  `attestation_count=len(signers)`, aggregate sig/pubkey, `consensus_completed_at = verify block time`,
  `proof_data_included=true`, `evidence_source='live'`.
- Insert members and per-signer attestations, each row inside a SAVEPOINT (same approach as
  `PersistCommittedBlock`) so one bad row cannot abort the batch.
- `ON CONFLICT DO NOTHING`; if a row exists with a **different** `aggregate_signature`/root, log
  `anchor_quorum_conflict` at error, increment a counter, and return `Written=false`. Never overwrite.

### Step 5 — writer + outbox

A small `anchorQuorumWriter` mirroring `consensusPersister`: buffered queue, bounded DB call timeouts,
retry with backoff, metrics (`certen_anchor_quorum_written_total`, `…_conflicts_total`,
`…_outbox_depth`). On permanent failure, persist to an `anchor_quorum_outbox` table and let a reconciler
replay it. The reconciler also scans recent verify txs for anchors this node never wrote (the
"already attested by another leader" path).

### Step 6 — switch readers

- `layer5_binding.go`: select canonical rows (`bundle_id IS NOT NULL`); L5 `anchor_tx` becomes
  `anchor_create_tx`; never the settlement tx.
- proofs_service `proof_artifact_repository.go:2821`: read the canonical row; keep the column name
  `batch_quorum_met` so the web app is unchanged.

### Step 7 — retire the shadow pipeline

Behind `LEGACY_BATCH_PIPELINE=off` (default off after soak): stop `routeIntentToBatchSystem` writing
`anchor_batches`, stop the old processor's anchoring. Then delete `ConsensusCoordinator`,
`AttestationBroadcaster`, `MarkConsensusQuorumMet` and the `attestation.Service` batch wiring.

### Step 8 — backfill (separate command, dry-run first)

`certen-validator backfill anchor-quorum --from 2026-07-26 --dry-run`:

1. Source: gateway `cost_events` verify legs + `AnchorCreated`/`ProofExecuted` logs on the V7 anchors of
   chains 11155111, 84532, 421614.
2. For each: fetch the receipt, decode `executeComprehensiveProof` calldata (bundleId, root, aggregate
   signature, validator addresses, signed voting power).
3. Assert `anchors(bundleId).proofExecuted == true`.
4. Recompute `msgHash` and **verify the aggregate signature against registry pubkeys**. A row that does
   not verify is reported and skipped — never written.
5. Upsert with `evidence_source='chain_backfill'`; map members via `accum_tx_hash`.
6. Old shadow rows: set `evidence_source='legacy_shadow'`, `lane` as recorded, and exclude them from all
   readers. **Never** set `quorum_reached` on them.
7. Rebuild or mark superseded the ~25 false L5 rows.

---

## 4. Verification — proving it is 100% correct

### A. Unit

| # | Test | Assertion |
|---|---|---|
| A1 | evidence mapping | `AnchorQuorumEvidence` fields equal the `QuorumAggregate` (signature, pubkey, signers, powers) |
| A2 | hook firing | fires exactly once on success; never on `QuorumNotReadyError`, root mismatch, or `proofExecuted=false` |
| A3 | already-settled path | "already attested by another leader" never fabricates a signature |
| A4 | conflict | a second write with a different signature returns `Written=false`, logs the conflict, leaves the row unchanged |

### B. Postgres integration (pattern of `repository_consensus_persist_test.go`)

| # | Test | Assertion |
|---|---|---|
| B1 | 7 concurrent writers, same `(chain,bundle)` | exactly 1 anchor row, 1 member set, 7 attestation rows |
| B2 | idempotency | re-running the same write changes nothing (compare full row snapshots) |
| B3 | atomicity | a forced failure mid-write leaves no partial rows |
| B4 | migration 018 | applies on a fleet-schema copy, self-registers, 7 concurrent MigrateUp all succeed |

### C. Golden vectors (the anti-`d2d24ab3` tests)

| # | Test | Assertion |
|---|---|---|
| C1 | leaf/root | stored leaf equals `CertenAccountV7.computeLeaf`; stored root equals the on-chain root |
| C2 | regression, intent `f6cea77e` | a shadow root (`d2d24ab3…`) can never be bound to a tx |
| C3 | L5 binding | `anchor_tx` is the anchor-create tx, never the settlement tx |

### D. Backfill

| # | Check | Gate |
|---|---|---|
| D1 | dry run | report lists every candidate with verify result; **0 signature-verification failures**, or they are listed and skipped |
| D2 | sample of 10 | manually cross-checked against the block explorer |
| D3 | after apply | `select count(*) from anchor_batches where quorum_reached and evidence_source='chain_backfill'` equals the dry-run count |
| D4 | no shadow contamination | `select count(*) from anchor_batches where quorum_reached and evidence_source='legacy_shadow'` = **0** |

### E. Live end-to-end (the real gate)

Run one on-demand intent on Base Sepolia:

1. Exactly **one** canonical row: `select count(*) from anchor_batches where chain_id=84532 and bundle_id=$1` → 1.
2. `quorum_reached=true`, `attestation_count=7`, `signed_voting_power = total_voting_power`.
3. `verify_tx` matches the on-chain verify transaction; `anchors(bundleId).proofExecuted` is true.
4. `batch_attestations` has 7 rows with distinct `evm_address`.
5. proofs_service returns `batch_quorum_met=true`; the web Transaction Center shows it.
6. The L5 row's `anchor_tx` equals `anchor_create_tx`, and its root equals the on-chain root.
7. No `anchor_quorum_conflict` logged on any of the 7 validators.
8. Monitor query returns empty: settled intents from the last hour with no canonical quorum row.

All eight must hold, on two separate intents (one on-demand, one cadence) before the pipeline retirement
in Step 7.

---

## 5. Rollout and rollback

1. Migration 018 (additive; old code ignores the columns).
2. Writer behind `ANCHOR_QUORUM_WRITER=on`, one validator first, then the fleet. Verify with §4.E.
3. Switch readers (proofs_service + L5) once canonical rows exist for current traffic.
4. Backfill: dry run → review → apply → rebuild false L5 rows.
5. Retire the shadow pipeline; delete dead code.

**Rollback:** turn the writer off (env). Readers fall back to the previous query behind the same flag.
Migration 018 is additive and needs no rollback; the canonical rows are inert without the readers.

---

## 6. Sign-off checklist

- [ ] A1–A4, B1–B4, C1–C3 green in CI.
- [ ] §4.E observed on two live intents, all eight checks.
- [ ] Backfill dry run reviewed and signed off; D1–D4 green after apply.
- [ ] Every false L5 row rebuilt or marked superseded; C2 regression test covers it.
- [ ] Monitor + alert live: settled intent without quorum row, and `anchor_quorum_conflict`.
- [ ] Dead code deleted; `grep -r ConsensusCoordinator` returns nothing outside history.
