-- A consensus entry's commit counts may be unknown (RB3-F138).
--
-- The chain has restarted more than once, and each incarnation began its heights again at 1. Entries
-- committed by an earlier incarnation cannot have their commit read - those blocks are in no block store -
-- so their signer count, required power and quorum fraction were never measured. The old mapping wrote
-- 1 / 5 / 0.1429 for them regardless. NULL states "not known"; `validator repair consensus-records` sets it
-- for those entries, and restates the current chain's from their commit.
--
-- schema: destructive-approved   (NOT NULL and defaults are dropped)

ALTER TABLE public.consensus_entries ALTER COLUMN attestation_count DROP NOT NULL;
ALTER TABLE public.consensus_entries ALTER COLUMN attestation_count DROP DEFAULT;
ALTER TABLE public.consensus_entries ALTER COLUMN required_count DROP NOT NULL;
ALTER TABLE public.consensus_entries ALTER COLUMN quorum_fraction DROP NOT NULL;
ALTER TABLE public.consensus_entries ALTER COLUMN quorum_fraction DROP DEFAULT;

COMMENT ON COLUMN public.consensus_entries.attestation_count IS
  'The validators whose precommit is in the CometBFT commit that committed this entry''s height (RB3-F138). NULL where that commit is not known: the entry was committed by an earlier incarnation of the chain.';
