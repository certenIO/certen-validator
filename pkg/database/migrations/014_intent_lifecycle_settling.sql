-- Stage 1 — a state for "the chain write is still in flight", so 'complete' stops lying.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  intent_lifecycle.status had submitted, pending_signatures, authorized, in_process, complete and
--  failed. There was no value for CONSENSUS DONE, TARGET-CHAIN WRITE IN FLIGHT — and that state very
--  much exists: the measured base-sepolia settlement lag is ~51 seconds against a 60-second submit
--  window, so it is the ORDINARY case, not an edge.
--
--  With nowhere to put it, it went into 'complete'. Measured on intent
--  1638327d-af2c-439c-a188-be53cdb5c854, 2026-08-25:
--
--    07:33:41  "target-chain execution did NOT confirm ... gas may have been spent on a reverted
--               transaction", targetChainError=""
--    07:33:41  "Intent 1638327d... processed successfully and marked complete"
--    07:34:32  chain_execution_results: base-sepolia status=1 block=45937480
--
--  Both lines are wrong, in opposite directions, fifty-one seconds before the truth arrived. A
--  missing state does not make the state stop existing; it makes some other state lie about it.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  NO CHECK CONSTRAINT TO EXTEND
--
--  Verified against production before writing this: pg_constraint has no CHECK on intent_lifecycle,
--  and status is varchar(32), so 'settling' (8 chars) needs no schema change to be storable. Written
--  anyway to RECORD THE INTENT — same reason 013 is mostly a comment — and because settling_at is a
--  real column that did not exist.
--
--  No CHECK is added here either. Enumerating the states in the database would mean a future state
--  requires a migration and an atomic deploy to introduce, which is how a lifecycle table acquires
--  the same defect this migration is fixing.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY settling_at RATHER THAN REUSING in_process_at
--
--  in_process means the proof cycle is running. settling means it is specifically waiting on the
--  target chain's receipt. The interval BETWEEN them is the measurement — it is how long settlement
--  actually takes, and it is exactly what nobody could see when the two were one state. Writing both
--  into one column would erase the number this stage exists to expose.
--
--  settling_at is a projection for querying and for operators. status is authoritative.
--
--  Historical rows keep settling_at NULL, which is correct and must not be backfilled: those intents
--  were never observed in this state, and inventing a timestamp for them would be fabricating
--  evidence about when a settlement was in flight. Absent and honest beats present and invented.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

ALTER TABLE intent_lifecycle
  ADD COLUMN IF NOT EXISTS settling_at timestamp with time zone;

COMMENT ON COLUMN intent_lifecycle.status IS
  'submitted | pending_signatures | authorized | in_process | settling | complete | failed. '
  'settling = consensus committed and the target-chain write is IN FLIGHT (submitted, no terminal '
  'receipt yet). It is NOT a failure and NOT terminal: Phase 7 observation of the real receipt '
  'resolves it to complete or failed. Deliberately no CHECK constraint — enumerating the states '
  'here would make adding the next one require a migration and an atomic deploy.';

COMMENT ON COLUMN intent_lifecycle.settling_at IS
  'When the target-chain write was last known to be in flight for this intent. NULL on every row '
  'written before Stage 1, and deliberately never backfilled: those intents were not observed in '
  'this state and a synthesized timestamp would be evidence about a settlement nobody watched. '
  'The interval settling_at -> completed_at is the real settlement latency (~51s measured on '
  'base-sepolia, 2026-08-25).';

-- "Show me everything still waiting on a chain receipt" is the operator question this state creates,
-- and it is a scan over a table that is mostly terminal rows. Partial, so it costs nothing to keep.
CREATE INDEX IF NOT EXISTS idx_intent_lifecycle_settling
  ON intent_lifecycle (settling_at)
  WHERE status = 'settling';

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('014_intent_lifecycle_settling',
        'Add the settling state so a pending target-chain write is never reported as complete or failed',
        NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
