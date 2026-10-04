-- Execution outcome states (RB6, DESIGN_RB6_execution_outcome_states.md; owner decision 2026-10-04).
--
-- An action that EXECUTED on its chain is never reported failed. It is in exactly one of:
--   proof_pending      executed; its proof bundle is not produced yet (retried automatically)
--   written            its proof bundle is produced and written back
--   proof_unavailable  executed; its proof can never be produced (declared by an operator, with evidence)
-- and a member refused by name before any chain transaction is `refused` until its non-settlement is attested.
--
-- intent_member_outcomes:
--   proof_cycle        gains proof_pending, proof_unavailable and refused
--   executed_never_failed   a settled or reverted member is written, proof_pending or proof_unavailable - never failed
--   refused_has_no_settlement   only a member with no settlement transaction is refused
--   reported_by        the validator that reported the outcome: the one that recovers a proof_pending member
--   refusal            the named cause of a refusal before any chain transaction; set, the intent's class is `refused`
--   proof_attempts, next_proof_attempt_at   the automatic recovery of a proof_pending member (attempts, backoff)
--
-- intent_lifecycle.status (no CHECK by design) gains executed_proof_pending, executed_proof_unavailable and
-- refused_pending_attestation; only its column comment changes here.
--
-- The proof_cycle column is widened (varchar(16) -> varchar(32): 'proof_unavailable' is 17 characters) and its constraint
-- dropped and re-created WIDER: every value it allowed is still allowed, no row changes.
-- schema: destructive-approved (column and constraint widened in place; no data is dropped or rewritten)

ALTER TABLE public.intent_member_outcomes ALTER COLUMN proof_cycle TYPE character varying(32);
ALTER TABLE public.intent_member_outcomes DROP CONSTRAINT intent_member_outcome_proof_cycle;
ALTER TABLE public.intent_member_outcomes ADD CONSTRAINT intent_member_outcome_proof_cycle CHECK (
    proof_cycle IN ('written', 'failed', 'proof_pending', 'proof_unavailable', 'refused')
);

ALTER TABLE public.intent_member_outcomes ADD CONSTRAINT intent_member_outcome_executed_never_failed CHECK (
    settlement NOT IN ('settled', 'reverted') OR proof_cycle IN ('written', 'proof_pending', 'proof_unavailable')
);

ALTER TABLE public.intent_member_outcomes ADD CONSTRAINT intent_member_outcome_refused_has_no_settlement CHECK (
    proof_cycle <> 'refused' OR settlement = 'none'
);

ALTER TABLE public.intent_member_outcomes ADD COLUMN reported_by character varying(64);
ALTER TABLE public.intent_member_outcomes ADD COLUMN refusal text;
ALTER TABLE public.intent_member_outcomes ADD COLUMN proof_attempts integer DEFAULT 0 NOT NULL;
ALTER TABLE public.intent_member_outcomes ADD COLUMN next_proof_attempt_at timestamp with time zone;

ALTER TABLE public.intent_member_outcomes ADD CONSTRAINT intent_member_outcome_proof_attempts_nonnegative CHECK (proof_attempts >= 0);

CREATE INDEX idx_intent_member_outcomes_proof_pending ON public.intent_member_outcomes (next_proof_attempt_at)
    WHERE proof_cycle = 'proof_pending';

COMMENT ON COLUMN public.intent_member_outcomes.proof_cycle IS
  'written: proof bundle produced and written back | proof_pending: executed, bundle not produced yet (recovered automatically) | proof_unavailable: executed, bundle can never be produced (operator-declared, evidence recorded) | refused: refused by name before any chain transaction, non-settlement not yet attested | failed: no execution and no write-back.';
COMMENT ON COLUMN public.intent_member_outcomes.reported_by IS 'The validator that reported this outcome; it recovers a proof_pending member.';
COMMENT ON COLUMN public.intent_member_outcomes.refusal IS 'The named cause of a refusal before any chain transaction; set, the intent fails with failure_class refused.';
COMMENT ON COLUMN public.intent_member_outcomes.proof_attempts IS 'Automatic recovery attempts of a proof_pending member.';
COMMENT ON COLUMN public.intent_member_outcomes.next_proof_attempt_at IS 'When the automatic recovery next re-drives a proof_pending member.';

COMMENT ON COLUMN public.intent_lifecycle.status IS 'submitted | pending_signatures | authorized | in_process | settling | refused_pending_attestation | executed_proof_pending | complete | executed_proof_unavailable | failed. settling = consensus committed and the target-chain write is IN FLIGHT. refused_pending_attestation = refused by name before any chain transaction; its non-settlement attestation is pending. executed_proof_pending = every member resolved, at least one EXECUTED with its proof bundle not produced yet: NOT a failure, NOT terminal. executed_proof_unavailable = executed, its proof can never be produced (terminal; not a failure of the action). Deliberately no CHECK constraint.';
