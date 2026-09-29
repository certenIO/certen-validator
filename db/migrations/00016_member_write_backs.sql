-- A chain member's outcome is written back to Accumulate once (RB4-F59).
--
-- Phase 9 submitted a write-back for whatever cycle reached it, and the proof bundle was stored before it, so a
-- second proof cycle for a member already written back - a re-driven or re-discovered one - wrote a second
-- Accumulate entry and stored a second proof artifact for the same member. This register is claimed before a
-- write-back is submitted and states its outcome:
--   claimed   a cycle is submitting it, or submitted it and its outcome is not known (the submission may have
--             reached Accumulate): no other cycle writes this member back until that is established
--   written   written back as write_back_tx: no other cycle writes it back
--   not_sent  the claiming cycle failed before anything was sent: another cycle may claim it
--
-- Expand-only: one table.

CREATE TABLE public.member_write_backs (
    intent_id     character varying(256) NOT NULL,
    chain_id      bigint NOT NULL,
    state         character varying(16) NOT NULL,
    cycle_id      character varying(256) NOT NULL,
    validator_id  character varying(128) NOT NULL,
    write_back_tx character varying(256),
    reason        text,
    claimed_at    timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at   timestamp with time zone,
    CONSTRAINT member_write_backs_pkey PRIMARY KEY (intent_id, chain_id),
    CONSTRAINT member_write_back_state CHECK (state IN ('claimed', 'written', 'not_sent')),
    CONSTRAINT member_write_back_written_has_tx CHECK ((state = 'written') = (write_back_tx IS NOT NULL)),
    CONSTRAINT member_write_back_not_sent_says_why CHECK (state <> 'not_sent' OR reason IS NOT NULL)
);

COMMENT ON TABLE public.member_write_backs IS
  'One row per chain member written back to Accumulate (RB4-F59): claimed before submission, written with its transaction, or not_sent when the claiming cycle failed before sending. A claimed row whose outcome is unknown blocks another write-back of the member.';
