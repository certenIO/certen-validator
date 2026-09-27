-- Record each chain member's outcome, and derive an intent's status from all of them.
--
-- A multi-chain intent is settled as one batch member per chain, each settling and closing its proof
-- cycle on its own. Each member used to write the WHOLE intent's status, so the first to finish decided
-- it: a two-chain intent read 'complete' while its other chain was unsettled, and the terminal guard in
-- UpdateStatus then froze it there - a later revert on the other chain could never be recorded
-- (RB3-F50). The intent's status is now a function of every member's recorded outcome
-- (IntentLifecycleRepository.RecordMemberOutcome):
--   in progress  while any member in member_chains has no outcome;
--   complete     only when every member settled and its result was written back;
--   failed       otherwise, with each chain's outcome in error_message.
--
-- settlement is what the chain shows for the member: settled (status 1), reverted (status 0, final),
-- unobserved (the cycle could not observe it), none (no settlement transaction reached the chain).
-- proof_cycle is whether that outcome was written back to Accumulate under a quorum attestation.
--
-- Expand-only: one table, one nullable column.

CREATE TABLE public.intent_member_outcomes (
    intent_id     character varying(256) NOT NULL,
    chain_id      bigint NOT NULL,
    settlement    character varying(16) NOT NULL,
    proof_cycle   character varying(16) NOT NULL,
    legs          integer NOT NULL,
    settlement_tx character varying(128),
    write_back_tx character varying(128),
    cycle_id      character varying(256),
    reason        text,
    recorded_at   timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT intent_member_outcomes_pkey PRIMARY KEY (intent_id, chain_id),
    CONSTRAINT intent_member_outcome_settlement CHECK (settlement IN ('settled', 'reverted', 'unobserved', 'none')),
    CONSTRAINT intent_member_outcome_proof_cycle CHECK (proof_cycle IN ('written', 'failed')),
    CONSTRAINT intent_member_outcome_legs CHECK (legs > 0)
);

COMMENT ON TABLE public.intent_member_outcomes IS
  'One row per chain member of an intent: what its chain shows (settlement) and whether that was written '
  'back under a quorum attestation (proof_cycle). The intent''s status in intent_lifecycle is derived from '
  'these rows over member_chains, in the same transaction that writes them.';

ALTER TABLE public.intent_lifecycle ADD COLUMN member_chains bigint[];

COMMENT ON COLUMN public.intent_lifecycle.member_chains IS
  'The chains the intent was split into, one batch member each - the set its status is derived over.';
