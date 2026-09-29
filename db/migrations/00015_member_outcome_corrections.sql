-- Corrections to intent outcomes are recorded (RB4-F58).
--
-- A chain member's recorded outcome is replaced by a later report for the same chain, and the intent's status is
-- derived again from every member (RecordMemberOutcome). The replacement overwrote the member row and, when the
-- intent went from failed to complete, erased failed_at, error_message and failure_class: a published outcome
-- rewritten with nothing left to say it was. On 2026-09-29 intent 000ac79a's base member was recorded failed by a
-- proof cycle a fleet restart broke (RB4-F55) although its settlement landed; repairing it replaces that record.
--
-- Every change to a recorded member outcome, and every change to an intent's terminal outcome, is now written to
-- evidence_corrections in the same transaction under these two record types:
--   intent_member_outcome   record_id <intent_id>/<chain_id>; previous and corrected member rows
--   intent_lifecycle        record_id <intent_id>; previous and corrected terminal status, times, message, class
--
-- schema: destructive-approved   (the evidence_corrections record_type CHECK is replaced by a wider one)

ALTER TABLE public.evidence_corrections DROP CONSTRAINT evidence_correction_record_type;
ALTER TABLE public.evidence_corrections ADD CONSTRAINT evidence_correction_record_type
    CHECK (record_type IN ('anchor_batch', 'layer5', 'certen_anchor_proof', 'proof_artifact', 'anchor_reference',
                           'validator_attestation', 'consensus_entry', 'batch_attestation',
                           'intent_member_outcome', 'intent_lifecycle'));
