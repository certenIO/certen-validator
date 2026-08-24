-- What a transaction committed in advance to doing.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY THIS COLUMN EXISTS
--
--  RB-4 already gives the validator the strongest statement in the system: for a contract-call leg
--  carrying `expectedEvents`, the validator REFUSES TO ATTEST unless those events appear in the
--  inclusion-proven receipt logs. So an attestation on such a leg is not evidence the call did not
--  revert — it is evidence the call did what it said it would do.
--
--  Nothing downstream could ever say so, because the condition was not written down. `expectedEvents`
--  arrives in the intent's CrossChainData blob, is used during execution, and is then dropped:
--  `batch_transactions.intent_data` holds IntentData (blob 0), and the legs live in CrossChainData
--  (blob 1), which is not persisted at all.
--
--  The consequence reached the far end of the system. The evidence report (certen-approval-console,
--  Runbook C) has to answer "did it do what was intended?" for an auditor, and could only answer
--  "it cannot be shown from this record" — for every transaction, including the ones where the
--  validator had in fact checked exactly that. See that repo's docs/PHASE-C1B-ASSURANCE.md.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  NULL AND '[]' MEAN DIFFERENT THINGS, AND THE DIFFERENCE IS THE WHOLE POINT
--
--    NULL   we do not know what this transaction committed to. The envelope was absent or would not
--           parse. Every row written before this migration is in this state, correctly.
--
--    '[]'   the envelope parsed and NO leg declared any expected events. A native value transfer is
--           the ordinary case. The question "were the declared effects observed" does not arise.
--
--    [...]  the legs declared these events, and an attestation therefore speaks to them.
--
--  Collapsing the first two — which `omitempty` on a Go slice does silently — makes the report state
--  that a transaction committed to no effects when it may well have committed to several. That is a
--  claim, manufactured from silence, in an audit record. Hence a NULLABLE jsonb and not a DEFAULT
--  '[]'::jsonb, and hence the reader downstream distinguishes an ABSENT key from an EMPTY array.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

BEGIN;

ALTER TABLE batch_transactions
  ADD COLUMN IF NOT EXISTS declared_effects jsonb;

COMMENT ON COLUMN batch_transactions.declared_effects IS
  'Events the intent''s legs committed to emitting (RB-4), as a JSON array. NULL means the commitment '
  'is unknown for this row — NOT that there was none. An empty array means the envelope parsed and '
  'nothing was declared. The two are never interchangeable.';

-- Partial, and on the "we know something was declared" case only. The query that wants this is the
-- proof lookup, which already selects the row by tx hash and joins here — so this exists for the
-- reporting question "which transactions committed to effects at all", not for the hot path.
CREATE INDEX IF NOT EXISTS idx_batch_tx_declared_effects
ON batch_transactions ((jsonb_array_length(declared_effects)))
WHERE declared_effects IS NOT NULL AND jsonb_typeof(declared_effects) = 'array';

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('012_declared_effects', 'Persist the events an intent committed to emitting (RB-4)', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
