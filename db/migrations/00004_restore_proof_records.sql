-- Give the proof records the repositories write a home in the shared schema.
--
-- The prepare gate (A9) found repository code for proof-cycle completions, validator-set snapshots, the
-- external-result hash chain, BLS result attestations, the four-component Certen anchor proof and proof
-- requests whose SQL named tables and columns production does not have. That code is restored and wired
-- into the proof cycle; this migration is the schema it needs.
--
-- Two tables are new because nothing in production records their concept:
--   validator_set_snapshots   the validator set a cycle's attestations were counted against
--   proof_cycle_completions   one row per proof tracking levels 1-4 and the cross-level binding
--
-- Everything else extends the live table that already holds the concept rather than creating a parallel
-- one: the hash chain the orchestrator computes goes on chain_execution_results / external_chain_results,
-- the snapshot link goes on the attestation tables, and the missing Certen-proof and proof-request fields
-- go on certen_anchor_proofs and proof_requests.
--
-- Expand-only. Two statements replace or relax a constraint, which is why this file is marked
-- destructive; both only admit more rows than before:
--   proof_requests.valid_request_status gains 'batched' (every previously valid status stays valid);
--   certen_anchor_proofs.batch_id becomes nullable (an on-demand proof can exist before, or without,
--   a batch row; batch_id is filled in when the batch is known).
-- schema: destructive-approved

CREATE TABLE public.validator_set_snapshots (
    snapshot_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    block_number     bigint NOT NULL,
    block_hash       bytea,
    validators_json  jsonb NOT NULL,
    validator_root   bytea NOT NULL,
    validator_count  integer NOT NULL,
    total_weight     bigint NOT NULL,
    threshold_weight bigint NOT NULL,
    snapshot_hash    bytea NOT NULL,
    chain_id         varchar(100) NOT NULL,
    chain_name       varchar(256) NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT unique_snapshot_hash UNIQUE (snapshot_hash),
    CONSTRAINT snapshot_counts_positive CHECK (validator_count > 0 AND total_weight > 0 AND threshold_weight > 0 AND threshold_weight <= total_weight)
);
CREATE INDEX idx_vss_chain_block ON public.validator_set_snapshots USING btree (chain_id, block_number DESC);
CREATE INDEX idx_vss_created ON public.validator_set_snapshots USING btree (created_at DESC);
COMMENT ON TABLE public.validator_set_snapshots IS 'The validator set a proof cycle''s attestations were counted against: members, weights, total and threshold weight, their merkle root, and a hash over all of it. One row per distinct set (snapshot_hash is unique); attestation rows point here by snapshot_id.';

CREATE TABLE public.proof_cycle_completions (
    completion_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id            uuid NOT NULL REFERENCES public.proof_artifacts(proof_id) ON DELETE CASCADE,
    cycle_id            varchar(255),
    level1_complete     boolean NOT NULL DEFAULT false,
    level1_proof_id     uuid,
    level1_hash         bytea,
    level2_complete     boolean NOT NULL DEFAULT false,
    level2_proof_id     uuid,
    level2_hash         bytea,
    level3_complete     boolean NOT NULL DEFAULT false,
    level3_proof_id     uuid,
    level3_hash         bytea,
    level4_complete     boolean NOT NULL DEFAULT false,
    level4_result_id    uuid,
    level4_hash         bytea,
    bindings_valid      boolean NOT NULL DEFAULT false,
    cycle_hash          bytea,
    all_levels_complete boolean NOT NULL DEFAULT false,
    level1_at           timestamptz,
    level2_at           timestamptz,
    level3_at           timestamptz,
    level4_at           timestamptz,
    completed_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT unique_proof_completion UNIQUE (proof_id),
    CONSTRAINT complete_means_every_level CHECK (NOT all_levels_complete OR (level1_complete AND level2_complete AND level3_complete AND level4_complete AND completed_at IS NOT NULL))
);
CREATE INDEX idx_pcc_incomplete ON public.proof_cycle_completions USING btree (created_at) WHERE (all_levels_complete = false);
CREATE INDEX idx_pcc_complete ON public.proof_cycle_completions USING btree (completed_at DESC) WHERE (all_levels_complete = true);
CREATE INDEX idx_pcc_cycle ON public.proof_cycle_completions USING btree (cycle_id) WHERE (cycle_id IS NOT NULL);
COMMENT ON TABLE public.proof_cycle_completions IS 'One row per proof: level 1 (chained proof L1-L3), level 2 (governance), level 3 (anchor), level 4 (external execution result), each with the hash that level committed to, then the cycle hash binding all four. Written by the proof cycle as each level is persisted, completed when write-back confirms.';

ALTER TABLE public.external_chain_results
    ADD COLUMN sequence_number bigint,
    ADD COLUMN previous_result_hash bytea,
    ADD COLUMN anchor_proof_hash bytea,
    ADD COLUMN return_data bytea,
    ADD COLUMN storage_proof_json jsonb,
    ADD COLUMN storage_proof_hash bytea,
    ADD COLUMN artifact_json jsonb,
    ADD COLUMN verified boolean NOT NULL DEFAULT false,
    ADD COLUMN verified_at timestamptz,
    ADD COLUMN snapshot_id uuid REFERENCES public.validator_set_snapshots(snapshot_id);
CREATE UNIQUE INDEX idx_ecr_proof_sequence ON public.external_chain_results USING btree (proof_id, sequence_number) WHERE (proof_id IS NOT NULL AND sequence_number IS NOT NULL);
COMMENT ON COLUMN public.external_chain_results.sequence_number IS 'Position in this target chain''s result hash chain (0 is the first result). NULL on rows written before the chain was persisted.';
COMMENT ON COLUMN public.external_chain_results.previous_result_hash IS 'result_hash of the previous result in the same chain; all zeros for sequence 0.';

ALTER TABLE public.chain_execution_results
    ADD COLUMN sequence_number bigint,
    ADD COLUMN previous_result_hash bytea,
    ADD COLUMN anchor_proof_hash bytea,
    ADD COLUMN chain_result_hash bytea;
CREATE UNIQUE INDEX idx_cer_hash_chain ON public.chain_execution_results USING btree (observer_validator_id, chain_id, sequence_number) WHERE (sequence_number IS NOT NULL);
COMMENT ON COLUMN public.chain_execution_results.sequence_number IS 'Position in the observing validator''s result hash chain for this target chain, as bound into the write-back bundle. NULL on rows written before the chain was persisted and on observations that were not the cycle''s primary result.';
COMMENT ON COLUMN public.chain_execution_results.chain_result_hash IS 'The result hash the chain links: the bundle''s result hash, computed with the chain binding (sequence, previous hash, anchor proof). result_hash is the observation hash, computed before the binding. The next link''s previous_result_hash equals this.';

ALTER TABLE public.bls_result_attestations
    ADD COLUMN snapshot_id uuid REFERENCES public.validator_set_snapshots(snapshot_id),
    ADD COLUMN weight bigint NOT NULL DEFAULT 1,
    ADD COLUMN subgroup_valid boolean NOT NULL DEFAULT false;
CREATE INDEX idx_bra_snapshot ON public.bls_result_attestations USING btree (snapshot_id) WHERE (snapshot_id IS NOT NULL);

ALTER TABLE public.aggregated_bls_attestations
    ADD COLUMN snapshot_id uuid REFERENCES public.validator_set_snapshots(snapshot_id),
    ADD COLUMN participant_ids jsonb,
    ADD COLUMN message_consistency_valid boolean NOT NULL DEFAULT false;

ALTER TABLE public.unified_attestations
    ADD COLUMN snapshot_id uuid REFERENCES public.validator_set_snapshots(snapshot_id);
CREATE INDEX idx_ua_snapshot ON public.unified_attestations USING btree (snapshot_id) WHERE (snapshot_id IS NOT NULL);

ALTER TABLE public.aggregated_attestations
    ADD COLUMN snapshot_id uuid REFERENCES public.validator_set_snapshots(snapshot_id),
    ADD COLUMN message_consistency_valid boolean NOT NULL DEFAULT false;

ALTER TABLE public.proof_requests
    ADD COLUMN priority varchar(20) NOT NULL DEFAULT 'normal',
    ADD COLUMN requester_id varchar(256),
    ADD COLUMN batch_id uuid REFERENCES public.anchor_batches(id);
ALTER TABLE public.proof_requests DROP CONSTRAINT IF EXISTS valid_request_status;
ALTER TABLE public.proof_requests ADD CONSTRAINT valid_request_status
    CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'batched'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])));
ALTER TABLE public.proof_requests ADD CONSTRAINT valid_request_priority
    CHECK (((priority)::text = ANY ((ARRAY['low'::character varying, 'normal'::character varying, 'high'::character varying, 'urgent'::character varying])::text[])));
CREATE INDEX idx_requests_requester ON public.proof_requests USING btree (requester_id, created_at DESC) WHERE (requester_id IS NOT NULL);
CREATE INDEX idx_requests_batch ON public.proof_requests USING btree (batch_id) WHERE (batch_id IS NOT NULL);

ALTER TABLE public.certen_anchor_proofs
    ALTER COLUMN batch_id DROP NOT NULL,
    ADD COLUMN proof_artifact_id uuid REFERENCES public.proof_artifacts(proof_id) ON DELETE CASCADE,
    ADD COLUMN transaction_id bigint,
    ADD COLUMN merkle_root bytea,
    ADD COLUMN anchor_chain varchar(50),
    ADD COLUMN anchor_tx_hash varchar(128),
    ADD COLUMN anchor_block_number bigint,
    ADD COLUMN anchor_block_hash varchar(128),
    ADD COLUMN anchor_confirmations integer NOT NULL DEFAULT 0,
    ADD COLUMN accumulate_block_height bigint,
    ADD COLUMN accumulate_bvn varchar(64),
    ADD COLUMN governance_valid boolean NOT NULL DEFAULT false,
    ADD COLUMN validator_id varchar(256),
    ADD COLUMN validator_signature bytea,
    ADD COLUMN verification_details jsonb;
CREATE UNIQUE INDEX idx_proofs_artifact ON public.certen_anchor_proofs USING btree (proof_artifact_id) WHERE (proof_artifact_id IS NOT NULL);
COMMENT ON TABLE public.certen_anchor_proofs IS 'The four-component Certen proof per whitepaper 3.4.1: transaction inclusion (merkle_proof_json), anchor reference (anchor_ref_json + anchor_* columns), state proof (chained_proof_json) and authority proof (governance_proof_json), with proof_hash over the canonical full_proof_json. One row per proof artifact.';
