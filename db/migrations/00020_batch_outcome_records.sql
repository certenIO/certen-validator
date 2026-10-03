-- The quorum-certified outcome of each V8.2 batch anchor, as CertenOutcomeRegistryV1 recorded it (RB5 owner decision D4).
--
-- A batch anchor's quorum signs what its members were AUTHORIZED to do. Once every member is decided on its chain, the
-- same quorum signs what they DID: a root over one outcome leaf per anchor leaf (RB5_CLOSEOUT_PLAN.md section 1b), which one
-- elected validator records, write-once, in the chain's outcome registry. These tables keep that record with everything
-- needed to verify it offline:
--   batch_outcome_records   one row per recorded anchor:
--     chain_id, bundle_id            the anchor
--     registry                       the CertenOutcomeRegistryV1 it was recorded in
--     outcome_root                   the root over the outcome leaves
--     message_hash                   the outcome message the quorum signed (certen:bls:v2:outcome), as the registry
--                                    emitted it
--     certen_validator_set_root      the anchor's currentValidatorSetRoot the message covers
--     accumulate_set_root, accumulate_incarnation   the anchor's own Accumulate commitment the message covers
--     leaf_count                     the anchor's batchLeafCount; exactly that many leaves are stored
--     record_tx, record_block, recorder   the recordBatchOutcome transaction, its block, and the validator that sent it
--     signers, signer_powers         the signers, ascending, each at its registered power (aligned arrays)
--     signed_voting_power, total_voting_power
--     quorum_proof                   the Groth16 proof of the aggregate the registry verified (BLSProofData.aggregateSignature)
--     aggregate_signature, aggregate_public_key   the BLS aggregate and its key, 0x-hex: held only by the validator
--                                    that recorded (evidence_source 'recorder'); a row rebuilt from the record
--                                    transaction ('chain') carries the proof the registry verified, not the aggregate
--   batch_outcome_leaves    one row per outcome leaf, every field the leaf hashes, and the leaf hash itself
--
-- Expand-only: two new tables. A record is written once; a second write must state the same record (a 'recorder' write
-- may complete a 'chain' row with the aggregate it alone holds).

CREATE TABLE public.batch_outcome_records (
    chain_id                  bigint NOT NULL
        CONSTRAINT batch_outcome_chain_is_positive CHECK (chain_id > 0),
    bundle_id                 character varying(66) NOT NULL
        CONSTRAINT batch_outcome_bundle_is_hex CHECK (bundle_id ~ '^0x[0-9a-f]{64}$'),
    registry                  character varying(42) NOT NULL
        CONSTRAINT batch_outcome_registry_is_address CHECK (registry ~ '^0x[0-9a-f]{40}$'),
    outcome_root              character varying(66) NOT NULL
        CONSTRAINT batch_outcome_root_is_hex CHECK (outcome_root ~ '^0x[0-9a-f]{64}$' AND outcome_root <> '0x' || repeat('0', 64)),
    message_hash              character varying(66) NOT NULL
        CONSTRAINT batch_outcome_message_is_hex CHECK (message_hash ~ '^0x[0-9a-f]{64}$'),
    certen_validator_set_root character varying(66) NOT NULL
        CONSTRAINT batch_outcome_certen_set_is_hex CHECK (certen_validator_set_root ~ '^0x[0-9a-f]{64}$'),
    accumulate_set_root       character varying(66) NOT NULL
        CONSTRAINT batch_outcome_accumulate_set_is_hex CHECK (accumulate_set_root ~ '^0x[0-9a-f]{64}$'),
    accumulate_incarnation    character varying(66) NOT NULL
        CONSTRAINT batch_outcome_incarnation_is_hex CHECK (accumulate_incarnation ~ '^0x[0-9a-f]{64}$'),
    leaf_count                bigint NOT NULL
        CONSTRAINT batch_outcome_leaf_count_is_positive CHECK (leaf_count > 0),
    record_tx                 character varying(66) NOT NULL
        CONSTRAINT batch_outcome_record_tx_is_hex CHECK (record_tx ~ '^0x[0-9a-f]{64}$'),
    record_block              bigint NOT NULL
        CONSTRAINT batch_outcome_record_block_is_positive CHECK (record_block > 0),
    recorder                  character varying(42) NOT NULL
        CONSTRAINT batch_outcome_recorder_is_address CHECK (recorder ~ '^0x[0-9a-f]{40}$'),
    signers                   jsonb NOT NULL
        CONSTRAINT batch_outcome_signers_is_array CHECK (jsonb_typeof(signers) = 'array' AND jsonb_array_length(signers) > 0),
    signer_powers             jsonb NOT NULL
        CONSTRAINT batch_outcome_powers_align CHECK (jsonb_typeof(signer_powers) = 'array'
            AND jsonb_array_length(signer_powers) = jsonb_array_length(signers)),
    signed_voting_power       numeric(78,0) NOT NULL
        CONSTRAINT batch_outcome_signed_power_is_positive CHECK (signed_voting_power > 0),
    total_voting_power        numeric(78,0) NOT NULL
        CONSTRAINT batch_outcome_power_within_total CHECK (total_voting_power >= signed_voting_power),
    quorum_proof              bytea NOT NULL
        CONSTRAINT batch_outcome_quorum_proof_is_present CHECK (octet_length(quorum_proof) > 0),
    aggregate_signature       character varying(194)
        CONSTRAINT batch_outcome_aggregate_is_hex CHECK (aggregate_signature ~ '^0x[0-9a-f]+$'),
    aggregate_public_key      character varying(194)
        CONSTRAINT batch_outcome_aggregate_key_is_hex CHECK (aggregate_public_key ~ '^0x[0-9a-f]+$'),
    evidence_source           character varying(16) NOT NULL
        CONSTRAINT batch_outcome_evidence_source_is_known CHECK (evidence_source IN ('recorder', 'chain')),
    recorded_at               timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT batch_outcome_records_pkey PRIMARY KEY (chain_id, bundle_id),
    CONSTRAINT batch_outcome_recorder_holds_the_aggregate CHECK (
        (evidence_source = 'recorder') = (aggregate_signature IS NOT NULL AND aggregate_public_key IS NOT NULL))
);

COMMENT ON TABLE public.batch_outcome_records IS
  'The quorum-certified outcome root of each V8.2 batch anchor as CertenOutcomeRegistryV1 recorded it (RB5 D4), with the signers, their powers, the proof the registry verified and the anchor commitments the outcome message covers, for offline verification.';

CREATE TABLE public.batch_outcome_leaves (
    chain_id      bigint NOT NULL,
    bundle_id     character varying(66) NOT NULL,
    leaf_index    bigint NOT NULL
        CONSTRAINT batch_outcome_leaf_index_is_natural CHECK (leaf_index >= 0),
    batch_leaf    character varying(66) NOT NULL
        CONSTRAINT batch_outcome_batch_leaf_is_hex CHECK (batch_leaf ~ '^0x[0-9a-f]{64}$'),
    operation_id  character varying(66) NOT NULL
        CONSTRAINT batch_outcome_operation_is_hex CHECK (operation_id ~ '^0x[0-9a-f]{64}$'),
    status        smallint NOT NULL
        CONSTRAINT batch_outcome_status_is_known CHECK (status BETWEEN 1 AND 4),
    tx            character varying(66) NOT NULL
        CONSTRAINT batch_outcome_tx_is_hex CHECK (tx ~ '^0x[0-9a-f]{64}$'),
    block_number  bigint NOT NULL
        CONSTRAINT batch_outcome_block_is_positive CHECK (block_number > 0),
    block_hash    character varying(66) NOT NULL
        CONSTRAINT batch_outcome_block_hash_is_hex CHECK (block_hash ~ '^0x[0-9a-f]{64}$'),
    receipts_root character varying(66) NOT NULL
        CONSTRAINT batch_outcome_receipts_root_is_hex CHECK (receipts_root ~ '^0x[0-9a-f]{64}$'),
    effects_hash  character varying(66) NOT NULL
        CONSTRAINT batch_outcome_effects_is_hex CHECK (effects_hash ~ '^0x[0-9a-f]{64}$'),
    leaf_hash     character varying(66) NOT NULL
        CONSTRAINT batch_outcome_leaf_hash_is_hex CHECK (leaf_hash ~ '^0x[0-9a-f]{64}$'),
    CONSTRAINT batch_outcome_leaves_pkey PRIMARY KEY (chain_id, bundle_id, leaf_index),
    CONSTRAINT batch_outcome_leaves_record_fkey FOREIGN KEY (chain_id, bundle_id)
        REFERENCES public.batch_outcome_records (chain_id, bundle_id) ON DELETE RESTRICT,
    CONSTRAINT batch_outcome_executed_names_its_tx CHECK (status = 3 OR tx <> '0x' || repeat('0', 64)),
    CONSTRAINT batch_outcome_unsettled_has_no_effects CHECK (status IN (1, 2) OR effects_hash = '0x' || repeat('0', 64))
);

COMMENT ON TABLE public.batch_outcome_leaves IS
  'Each outcome leaf of a recorded batch outcome (RB5 D4 section 1b): the member, its status (1 executed, 2 executed with a committed effect proven absent, 3 not settled by its deadline, 4 consumed under another anchor), the transaction and finalized block that prove it, the effects hash, and the leaf hash the outcome root is built from.';
