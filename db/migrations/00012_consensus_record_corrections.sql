-- Corrections to consensus records (RB3-F138).
--
-- consensus_entries and their batch_attestations rows were written by a mapping that stated a governance
-- level as the consensus state, one self-attestation and a compiled-in count of seven as the quorum, a
-- single validator's V6.1 signature as the batch's aggregate, and that signature as verified
-- (signature_valid = true) when nothing had verified it. `validator repair consensus-records` restates each
-- entry from the commit that committed its height, read from the node's block store, and withdraws the
-- unverified validity; every change is recorded in evidence_corrections under these two record types.
--
-- schema: destructive-approved   (the evidence_corrections record_type CHECK is replaced by a wider one)

ALTER TABLE public.evidence_corrections DROP CONSTRAINT evidence_correction_record_type;
ALTER TABLE public.evidence_corrections ADD CONSTRAINT evidence_correction_record_type
    CHECK (record_type IN ('anchor_batch', 'layer5', 'certen_anchor_proof', 'proof_artifact', 'anchor_reference',
                           'validator_attestation', 'consensus_entry', 'batch_attestation'));

COMMENT ON COLUMN public.consensus_entries.attestation_count IS
  'The validators whose precommit is in the CometBFT commit that committed this entry''s height (RB3-F138).';
COMMENT ON COLUMN public.consensus_entries.required_count IS
  'The voting power a commit of that height needs: more than two thirds of the validator set''s.';
COMMENT ON COLUMN public.consensus_entries.quorum_fraction IS
  'The share of the validator set''s voting power that signed the commit.';
COMMENT ON COLUMN public.consensus_entries.aggregate_signature IS
  'An aggregate signature over the entry, when one exists. None does for a committed validator block: its single V6.1 pre-execution signature is in result_json, unverified.';
