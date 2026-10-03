# Runbooks

Implementation runbooks: what is wrong, the target design, step-by-step changes, the verification gates
that prove correctness, rollout and rollback. Each is written to be handed to whoever implements it. A
runbook that has shipped keeps its plan as written and records, in its own status block and closing section,
what shipped, where it differs and what is still open.

| Runbook | Problem | Status |
|---|---|---|
| [anchor-quorum-evidence-and-phase5.md](anchor-quorum-evidence-and-phase5.md) | Phase 5 columns never written, `anchor_batches` held per-validator shadow rows, real quorum evidence discarded, and L5 rows bound a shadow root to a settlement tx | Implemented and merged |
| [inclusion-confirmation-from-blocks.md](inclusion-confirmation-from-blocks.md) | A broadcast was judged from the tx index, which is last-write-wins, so a committed ValidatorBlock could be reported failed; and intents could proceed without a proven commit | Implemented and merged. The commit requirement shipped stricter, with no opt-out (RB3-F98). Open: the `INCLUSION_SCAN=off` switch (§7.6) |
| [schema-ownership-and-migrations.md](schema-ownership-and-migrations.md) | Migrations could not build a fresh database, production drifted from the files, and two migrations re-ran on every start | Implemented; §7 records what shipped, the anchor evidence repair run and what is open |
| [schema-and-evidence-hardening.md](schema-and-evidence-hardening.md) | Eight pieces of work so that the defects of 2026-09-15..18 cannot recur silently | Work list; §3 (retire the shadow pipeline) is done |
| [apphash-idempotency.md](apphash-idempotency.md) | A restarting validator could not rejoin (`wrong Block.Header.AppHash`); the XOR state commitment was weak | Both changes are in `pkg/consensus/abci_validator.go`: staged idempotency and the SHA256 app-hash chain |
| [bls-key-rotation.md](bls-key-rotation.md) | Every validator's BLS key was computable from public inputs | Rotation done on all three anchors on 2026-09-26 |
| [admin-set-rotation.md](admin-set-rotation.md) | The admin set could change only by a one-time rules repair (v11 re-seal); a lost or compromised admin key needed another | Rules v12 built and rehearsed on a live 4-node network; not deployed. No key is created unless the owner rotates |

Related, in the gateway repo: the hourly ~150 s event-loop freeze caused by the transparency-log audit is
fixed on the gateway's main (the audit checkpoint, migration `044_transparency_audit_checkpoint.sql`, and
the split database pools). Its runbook was never merged; it is on the gateway branch
`docs/runbook-transparency-log-freeze`.

Background: the 2026-09-15 validator incident (Commit doing O(cache) database work, which made every
concurrent `BroadcastTxSync` time out) is fixed. See `pkg/consensus/consensus_persistence.go` and
`pkg/consensus/bft_broadcast_confirm.go`.
