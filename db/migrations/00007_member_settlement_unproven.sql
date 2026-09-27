-- Whether a member's committed effects were proven.
--
-- A contract-call leg commits the effects its success is proven by - events it must emit, storage it
-- must set (RB-4/RB-5). A settlement can execute (status 1) under the member's leaf and still lack a
-- committed effect: an event absent from its inclusion-proven receipt, or a committed slot proven to hold
-- another value. Such a member settled but did not do what the intent committed to. It is now attested
-- by quorum and written back as such (RB3-F67), and recorded here:
--   NULL  the member committed no effect to prove (a native transfer), or its cycle did not assess them;
--   TRUE  every committed effect was proven;
--   FALSE a committed effect is provably absent - the member counts as failed in the intent's status.
--
-- Expand-only: one nullable column.

ALTER TABLE public.intent_member_outcomes ADD COLUMN effects_proven boolean;

COMMENT ON COLUMN public.intent_member_outcomes.effects_proven IS
  'Whether the member''s committed contract-call effects were proven: NULL none committed or not assessed, '
  'TRUE proven, FALSE provably absent (the member failed; RB3-F67).';
