# Runbooks

Implementation runbooks: what is wrong, the target design, step-by-step changes, the verification gates
that prove correctness, rollout and rollback. Each is written to be handed to whoever implements it.

| Runbook | Problem | Severity |
|---|---|---|
| [anchor-quorum-evidence-and-phase5.md](anchor-quorum-evidence-and-phase5.md) | Phase 5 columns never written (the writer is never constructed), `anchor_batches` holds per-validator shadow rows, real quorum evidence discarded, and ~25 L5 rows bind a shadow root to a settlement tx | High — published evidence is wrong |
| [inclusion-confirmation-from-blocks.md](inclusion-confirmation-from-blocks.md) | A broadcast is judged from the tx index, which is last-write-wins, so a committed ValidatorBlock can be reported failed; and `REQUIRE_BFT_COMMIT` is off, so intents can proceed without a proven commit | Medium |
| [schema-ownership-and-migrations.md](schema-ownership-and-migrations.md) | Migrations cannot build a fresh database (010 needs columns only proofs_service creates), production drifts from the files, and two migrations re-run on every start | Medium |

Related, in the gateway repo: `docs/runbooks/transparency-log-audit-event-loop-freeze.md` — the hourly
~150 s event-loop freeze caused by the transparency-log audit.

Background: the 2026-09-15 validator incident (Commit doing O(cache) database work, which made every
concurrent `BroadcastTxSync` time out) is already fixed — see `pkg/consensus/consensus_persistence.go`
and `pkg/consensus/bft_broadcast_confirm.go`.
