-- Why an intent failed, as a class a client can act on (RB4-F13).
--
-- A failed intent was status = 'failed' with error_message text only. Nothing told the intent's own defect (it
-- will never settle; do not resubmit it as is) from a governance verdict, a missing entitlement, a chain member
-- that did not settle, or CERTEN failing to process it. The class is set from typed errors where the failure is
-- recorded, never parsed from the message. NULL on a failed intent means it failed before the class was recorded.
--
--   refused                 the intent itself cannot be settled (its bytes are final on Accumulate)
--   not_entitled            its principal holds no CERTEN entitlement
--   governance_unsatisfied  its governance proof shows it lacks the authority it needs
--   governance_unavailable  its governance proof could not be produced (not a verdict on the intent)
--   settlement_failed       a chain member did not settle, or was not proven or written back
--   processing_failed       CERTEN could not complete processing it

ALTER TABLE public.intent_lifecycle ADD COLUMN failure_class character varying(32);

ALTER TABLE public.intent_lifecycle ADD CONSTRAINT intent_lifecycle_failure_class_known CHECK (
  failure_class IS NULL OR failure_class IN (
    'refused', 'not_entitled', 'governance_unsatisfied', 'governance_unavailable', 'settlement_failed', 'processing_failed'
  )
);

-- Only a failed intent has a failure class.
ALTER TABLE public.intent_lifecycle ADD CONSTRAINT intent_lifecycle_failure_class_only_when_failed CHECK (
  failure_class IS NULL OR status = 'failed'
);

COMMENT ON COLUMN public.intent_lifecycle.failure_class IS
  'Why the intent failed (RB4-F13): refused | not_entitled | governance_unsatisfied | governance_unavailable | settlement_failed | processing_failed. NULL on a failed intent: failed before the class was recorded.';
