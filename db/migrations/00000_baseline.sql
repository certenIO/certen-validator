--
-- PostgreSQL database dump
--

\restrict TgnH5aCqMdD9L15husBWEmC3wwPvaXkFk6xSdC2oKxe7Vc8NwSYm6iaTUWETdJM

-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: check_leg_dependencies_satisfied(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.check_leg_dependencies_satisfied(p_leg_id uuid) RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN NOT EXISTS (
        SELECT 1 FROM leg_dependencies
        WHERE leg_id = p_leg_id AND is_satisfied = FALSE
    );
END;
$$;


--
-- Name: satisfy_leg_dependency(uuid, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.satisfy_leg_dependency(p_completed_leg_id uuid, p_condition character varying DEFAULT 'success'::character varying) RETURNS TABLE(ready_leg_id uuid, ready_leg_intent_id character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Mark dependencies as satisfied
    UPDATE leg_dependencies
    SET is_satisfied = TRUE, satisfied_at = NOW()
    WHERE depends_on_leg_id = p_completed_leg_id
      AND (condition_type = p_condition OR condition_type = 'completion');

    -- Return legs that are now ready (all dependencies satisfied)
    RETURN QUERY
    SELECT DISTINCT d.leg_id, i.intent_id
    FROM leg_dependencies d
    JOIN intent_legs l ON d.leg_id = l.leg_id
    JOIN certen_intents i ON l.intent_id = i.intent_id
    WHERE d.depends_on_leg_id = p_completed_leg_id
      AND l.status = 'pending'
      AND check_leg_dependencies_satisfied(d.leg_id);
END;
$$;


--
-- Name: update_intent_on_leg_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_intent_on_leg_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_total INTEGER;
    v_completed INTEGER;
    v_failed INTEGER;
    v_pending INTEGER;
    v_new_status VARCHAR(30);
BEGIN
    -- Count leg statuses
    SELECT
        COUNT(*),
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END),
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END),
        SUM(CASE WHEN status IN ('pending', 'ready', 'processing', 'batched') THEN 1 ELSE 0 END)
    INTO v_total, v_completed, v_failed, v_pending
    FROM intent_legs
    WHERE intent_id = NEW.intent_id;

    -- Determine new intent status
    IF v_completed = v_total THEN
        v_new_status := 'completed';
    ELSIF v_failed > 0 AND v_pending = 0 THEN
        v_new_status := 'partial_complete';
    ELSIF v_failed = v_total THEN
        v_new_status := 'failed';
    ELSIF v_completed > 0 OR v_failed > 0 THEN
        v_new_status := 'processing';
    ELSE
        v_new_status := 'discovered';
    END IF;

    -- Update intent
    UPDATE certen_intents
    SET legs_completed = v_completed,
        legs_failed = v_failed,
        legs_pending = v_pending,
        status = v_new_status,
        completed_at = CASE WHEN v_new_status IN ('completed', 'partial_complete', 'failed')
                           THEN NOW() ELSE NULL END
    WHERE intent_id = NEW.intent_id;

    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: aggregated_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aggregated_attestations (
    aggregation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    cycle_id character varying(255) NOT NULL,
    scheme character varying(32) NOT NULL,
    message_hash bytea NOT NULL,
    aggregated_signature bytea,
    aggregated_public_key bytea,
    participant_ids jsonb NOT NULL,
    participant_count integer NOT NULL,
    total_weight bigint NOT NULL,
    achieved_weight bigint NOT NULL,
    threshold_weight bigint NOT NULL,
    threshold_met boolean NOT NULL,
    aggregated_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    validator_bitfield bytea,
    threshold_numerator integer DEFAULT 2,
    threshold_denominator integer DEFAULT 3,
    aggregation_valid boolean,
    verified_at timestamp with time zone,
    verification_notes text,
    attestation_ids jsonb,
    first_attestation_at timestamp with time zone,
    last_attestation_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE aggregated_attestations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.aggregated_attestations IS 'Stores aggregated/collected attestations after quorum threshold is reached';


--
-- Name: aggregated_bls_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aggregated_bls_attestations (
    aggregation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    result_id uuid NOT NULL,
    result_hash bytea NOT NULL,
    bundle_id bytea NOT NULL,
    message_hash bytea NOT NULL,
    attested_block_number bigint NOT NULL,
    aggregate_signature bytea NOT NULL,
    aggregate_public_key bytea,
    validator_bitfield bytea NOT NULL,
    validator_count integer NOT NULL,
    validator_addresses bytea[] NOT NULL,
    validator_indices integer[] NOT NULL,
    attestation_ids uuid[] NOT NULL,
    total_voting_power numeric(78,0) NOT NULL,
    signed_voting_power numeric(78,0) NOT NULL,
    voting_power_percentage numeric(5,2) NOT NULL,
    threshold_numerator integer DEFAULT 2 NOT NULL,
    threshold_denominator integer DEFAULT 3 NOT NULL,
    threshold_met boolean NOT NULL,
    first_attestation_at timestamp with time zone NOT NULL,
    last_attestation_at timestamp with time zone NOT NULL,
    finalized_at timestamp with time zone,
    aggregate_verified boolean,
    verified_at timestamp with time zone,
    verification_error text,
    aggregation_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_threshold CHECK (((threshold_numerator > 0) AND (threshold_denominator > 0)))
);


--
-- Name: anchor_batches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.anchor_batches (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_type character varying(20) DEFAULT 'on_cadence'::character varying NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    merkle_root bytea,
    tx_count integer DEFAULT 0 NOT NULL,
    transaction_count integer DEFAULT 0 NOT NULL,
    target_chain character varying(50) DEFAULT 'ethereum'::character varying NOT NULL,
    anchor_tx_hash character varying(66),
    anchor_block_num bigint,
    gas_used bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    anchored_at timestamp with time zone,
    confirmed_at timestamp with time zone,
    batch_start_time timestamp with time zone DEFAULT now(),
    batch_end_time timestamp with time zone,
    validator_id character varying(100),
    error_message text,
    accumulate_block_height bigint,
    accumulate_block_hash character varying(66),
    bpt_root bytea,
    governance_root bytea,
    proof_data_included boolean DEFAULT false,
    attestation_count integer DEFAULT 0,
    aggregated_signature bytea,
    aggregated_public_key bytea,
    quorum_reached boolean DEFAULT false,
    consensus_completed_at timestamp with time zone,
    chain_id bigint,
    bundle_id character varying(80),
    batch_operation_id character varying(80),
    anchor_create_tx character varying(80),
    verify_tx character varying(80),
    verify_block bigint,
    message_hash character varying(80),
    signed_voting_power numeric(78,0),
    total_voting_power numeric(78,0),
    signers jsonb,
    evidence_source character varying(32),
    lane character varying(16),
    CONSTRAINT valid_batch_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'closed'::character varying, 'anchoring'::character varying, 'anchored'::character varying, 'confirmed'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT valid_batch_type CHECK (((batch_type)::text = ANY ((ARRAY['on_cadence'::character varying, 'on_demand'::character varying])::text[])))
);


--
-- Name: COLUMN anchor_batches.anchor_tx_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.anchor_batches.anchor_tx_hash IS 'The external-chain transaction that published this batch''s merkle_root. NULL on every row written before stage 3. Without it the batch root is a number nobody can point at a chain, and the L5 claim degenerates to "this leaf is under some root". Written once and never overwritten: a second, different hash means a re-anchor or a bug, and replacing the first would erase the evidence needed to tell which.';


--
-- Name: COLUMN anchor_batches.bundle_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.anchor_batches.bundle_id IS 'The anchor''s own identifier on-chain (0x-hex, 32 bytes). NULL on legacy shadow rows, which were never published and must not be read as evidence.';


--
-- Name: COLUMN anchor_batches.signers; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.anchor_batches.signers IS 'JSON array of {address, voting_power} for the validators whose partials the aggregate covers — the set the anchor itself re-derives signedVotingPower from.';


--
-- Name: COLUMN anchor_batches.evidence_source; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.anchor_batches.evidence_source IS 'live = written by the validator that proved the quorum; chain_backfill = reconstructed from the verify transaction and verified against the registry; legacy_shadow = pre-2026-09 per-validator row with no published root.';


--
-- Name: anchor_records; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.anchor_records (
    anchor_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    target_chain character varying(50) NOT NULL,
    chain_id character varying(50),
    network_name character varying(50),
    contract_address character varying(66),
    anchor_tx_hash character varying(66) NOT NULL,
    anchor_block_number bigint NOT NULL,
    anchor_block_hash character varying(66),
    anchor_timestamp timestamp with time zone,
    merkle_root character varying(66),
    accumulate_height bigint,
    operation_commitment character varying(66),
    cross_chain_commitment character varying(66),
    governance_root character varying(66),
    confirmations integer DEFAULT 0 NOT NULL,
    required_confirmations integer DEFAULT 12 NOT NULL,
    confirmed_at timestamp with time zone,
    is_final boolean DEFAULT false NOT NULL,
    gas_used bigint,
    gas_price_wei character varying(50),
    total_cost_wei character varying(50),
    total_cost_usd numeric(20,8),
    validator_id character varying(256),
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    finalized_at timestamp with time zone,
    intent_id character varying(128),
    leg_ids uuid[],
    chain_group_id uuid,
    CONSTRAINT valid_anchor_chain CHECK (((target_chain)::text = ANY ((ARRAY['ethereum'::character varying, 'bitcoin'::character varying, 'polygon'::character varying, 'arbitrum'::character varying])::text[]))),
    CONSTRAINT valid_anchor_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'confirming'::character varying, 'finalized'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: anchor_references; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.anchor_references (
    reference_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    target_chain character varying(64) NOT NULL,
    chain_id character varying(64) NOT NULL,
    network_name character varying(64),
    anchor_tx_hash character varying(128) NOT NULL,
    anchor_block_number bigint NOT NULL,
    anchor_block_hash character varying(128),
    anchor_timestamp timestamp with time zone,
    contract_address character varying(64),
    confirmations integer DEFAULT 0,
    is_confirmed boolean DEFAULT false,
    confirmed_at timestamp with time zone,
    gas_used bigint,
    gas_price_wei character varying(78),
    total_cost_wei character varying(78),
    created_at timestamp with time zone DEFAULT now(),
    required_confirmations integer DEFAULT 12
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    key_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_hash bytea NOT NULL,
    client_name character varying(256) NOT NULL,
    client_type character varying(50) NOT NULL,
    can_read_proofs boolean DEFAULT true NOT NULL,
    can_request_proofs boolean DEFAULT false NOT NULL,
    can_bulk_download boolean DEFAULT false NOT NULL,
    rate_limit_per_min integer DEFAULT 100 NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    expires_at timestamp with time zone,
    description text,
    contact_email character varying(256),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT valid_client_type CHECK (((client_type)::text = ANY ((ARRAY['auditor'::character varying, 'service'::character varying, 'institution'::character varying, 'developer'::character varying, 'internal'::character varying])::text[])))
);


--
-- Name: batch_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.batch_attestations (
    attestation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    validator_id character varying(256) NOT NULL,
    merkle_root bytea NOT NULL,
    bls_signature bytea,
    bls_public_key bytea NOT NULL,
    tx_count integer NOT NULL,
    block_height bigint NOT NULL,
    attestation_time timestamp with time zone NOT NULL,
    signature_valid boolean,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    evm_address character varying(64),
    voting_power numeric(78,0)
);


--
-- Name: batch_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.batch_transactions (
    id bigint NOT NULL,
    batch_id uuid NOT NULL,
    accumulate_tx_hash character varying(128) NOT NULL,
    account_url character varying(512) NOT NULL,
    tree_index integer NOT NULL,
    merkle_path jsonb,
    transaction_hash bytea,
    chained_proof jsonb,
    chained_proof_valid boolean DEFAULT false,
    governance_proof jsonb,
    governance_level character varying(10),
    governance_valid boolean DEFAULT false,
    intent_type character varying(100),
    intent_data jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id character varying(256),
    intent_id character varying(256),
    from_chain character varying(64),
    to_chain character varying(64),
    from_address character varying(256),
    to_address character varying(256),
    amount character varying(78),
    token_symbol character varying(32),
    adi_url character varying(256),
    created_at_client timestamp with time zone,
    leg_id uuid,
    multi_leg_intent_id character varying(128),
    declared_effects jsonb,
    CONSTRAINT valid_gov_level_tx CHECK (((governance_level IS NULL) OR ((governance_level)::text = ANY ((ARRAY['G0'::character varying, 'G1'::character varying, 'G2'::character varying])::text[]))))
);


--
-- Name: COLUMN batch_transactions.declared_effects; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.batch_transactions.declared_effects IS 'Events the intent''s legs committed to emitting (RB-4), as a JSON array. NULL means the commitment is unknown for this row — NOT that there was none. An empty array means the envelope parsed and nothing was declared. The two are never interchangeable.';


--
-- Name: batch_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.batch_transactions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: batch_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.batch_transactions_id_seq OWNED BY public.batch_transactions.id;


--
-- Name: bls_result_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bls_result_attestations (
    attestation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    result_id uuid NOT NULL,
    result_hash bytea NOT NULL,
    bundle_id bytea NOT NULL,
    message_hash bytea NOT NULL,
    validator_id character varying(256) NOT NULL,
    validator_address bytea NOT NULL,
    validator_index integer NOT NULL,
    bls_signature bytea NOT NULL,
    bls_public_key bytea NOT NULL,
    signature_domain character varying(50) DEFAULT 'CERTEN_RESULT_ATTESTATION_V1'::character varying NOT NULL,
    attested_block_number bigint NOT NULL,
    attested_block_hash bytea,
    confirmations_at_attest integer NOT NULL,
    signature_valid boolean,
    verified_at timestamp with time zone,
    verification_error text,
    attestation_time timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: certen_anchor_proofs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certen_anchor_proofs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    accum_tx_hash character varying(128) NOT NULL,
    account_url character varying(512) NOT NULL,
    batch_id uuid NOT NULL,
    anchor_id uuid,
    governance_level character varying(10) DEFAULT 'G0'::character varying NOT NULL,
    proof_version character varying(20) DEFAULT '1.0.0'::character varying NOT NULL,
    chained_proof_json text,
    governance_proof_json text,
    anchor_ref_json text,
    merkle_proof_json text,
    full_proof_json text,
    proof_hash bytea,
    is_verified boolean DEFAULT false NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_gov_level CHECK (((governance_level)::text = ANY ((ARRAY['G0'::character varying, 'G1'::character varying, 'G2'::character varying])::text[])))
);


--
-- Name: certen_intents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certen_intents (
    intent_id character varying(128) NOT NULL,
    operation_id character varying(128) NOT NULL,
    user_id character varying(256),
    organization_adi character varying(512),
    accumulate_tx_hash character varying(128) NOT NULL,
    account_url character varying(512),
    partition character varying(50),
    leg_count integer DEFAULT 1 NOT NULL,
    execution_mode character varying(20) DEFAULT 'sequential'::character varying NOT NULL,
    proof_class character varying(20) DEFAULT 'on_demand'::character varying NOT NULL,
    status character varying(30) DEFAULT 'discovered'::character varying NOT NULL,
    current_leg_index integer DEFAULT 0 NOT NULL,
    legs_completed integer DEFAULT 0 NOT NULL,
    legs_failed integer DEFAULT 0 NOT NULL,
    legs_pending integer DEFAULT 0 NOT NULL,
    intent_data jsonb NOT NULL,
    cross_chain_data jsonb NOT NULL,
    governance_data jsonb NOT NULL,
    replay_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone,
    error_message text,
    CONSTRAINT valid_execution_mode CHECK (((execution_mode)::text = ANY ((ARRAY['sequential'::character varying, 'parallel'::character varying, 'atomic'::character varying])::text[]))),
    CONSTRAINT valid_intent_status CHECK (((status)::text = ANY ((ARRAY['discovered'::character varying, 'processing'::character varying, 'anchoring'::character varying, 'completed'::character varying, 'partial_complete'::character varying, 'failed'::character varying, 'rolled_back'::character varying, 'expired'::character varying])::text[]))),
    CONSTRAINT valid_leg_count CHECK ((leg_count >= 1)),
    CONSTRAINT valid_proof_class CHECK (((proof_class)::text = ANY ((ARRAY['on_demand'::character varying, 'on_cadence'::character varying])::text[])))
);


--
-- Name: TABLE certen_intents; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.certen_intents IS 'Master registry for multi-leg intents (1-N legs per intent)';


--
-- Name: COLUMN certen_intents.leg_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.certen_intents.leg_count IS 'Total number of legs in this intent';


--
-- Name: COLUMN certen_intents.execution_mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.certen_intents.execution_mode IS 'sequential: legs execute in order; parallel: all at once; atomic: all or nothing';


--
-- Name: chain_execution_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chain_execution_results (
    result_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    cycle_id character varying(255) NOT NULL,
    chain_platform character varying(32) NOT NULL,
    chain_id character varying(64) NOT NULL,
    network_name character varying(64),
    tx_hash character varying(128) NOT NULL,
    block_number bigint,
    block_hash character varying(128),
    status smallint DEFAULT 0,
    gas_used bigint,
    confirmations integer DEFAULT 0,
    is_finalized boolean DEFAULT false,
    result_hash bytea,
    submitted_at timestamp with time zone,
    finalized_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    block_timestamp timestamp with time zone,
    gas_cost character varying(78),
    required_confirmations integer,
    merkle_proof bytea,
    receipt_proof bytea,
    state_root bytea,
    transactions_root bytea,
    receipts_root bytea,
    raw_receipt jsonb,
    logs jsonb,
    platform_data jsonb,
    observer_validator_id character varying(255),
    workflow_step smallint,
    anchor_id bytea,
    confirmed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE chain_execution_results; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.chain_execution_results IS 'Stores results of anchor operations across all supported blockchain platforms';


--
-- Name: COLUMN chain_execution_results.chain_platform; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chain_execution_results.chain_platform IS 'Blockchain platform: evm, cosmwasm, solana, move, ton, near';


--
-- Name: COLUMN chain_execution_results.workflow_step; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chain_execution_results.workflow_step IS 'Anchor workflow step: 1=create, 2=verify, 3=governance';


--
-- Name: chained_proof_layers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chained_proof_layers (
    layer_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    layer_number integer NOT NULL,
    layer_name character varying(64),
    bvn_partition character varying(64),
    receipt_anchor bytea,
    bvn_root bytea,
    dn_root bytea,
    anchor_sequence bigint,
    bvn_partition_id character varying(64),
    dn_block_hash bytea,
    dn_block_height bigint,
    consensus_timestamp timestamp with time zone,
    layer_json jsonb,
    created_at timestamp with time zone DEFAULT now(),
    verified boolean DEFAULT false,
    verified_at timestamp with time zone,
    receipt_entries jsonb,
    source_hash bytea,
    target_hash bytea,
    signature_count integer,
    threshold integer,
    signed_hash bytea,
    superseded_at timestamp with time zone,
    superseded_reason text
);


--
-- Name: COLUMN chained_proof_layers.layer_number; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.layer_number IS '1..3 state layers; 4 = quorum signature leg (one row per partition, BVN and DN); 5 = external anchor binding (leaf -> batch root -> external chain tx). 0 records a failed L1-L3 attempt. No CHECK constraint: a future L6 must not be rejected by this table, whose defect history is precisely a hardcoded upper bound. Layer 5 is NOT committed to by the govRoot and structurally cannot be — it describes the anchoring of a govRoot that must already exist before the anchor is written.';


--
-- Name: COLUMN chained_proof_layers.signature_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.signature_count IS 'Layer 4 only: number of signatures carried in layer_json. A projection for querying — layer_json is the authoritative evidence and the only thing the offline verifier reads.';


--
-- Name: COLUMN chained_proof_layers.threshold; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.threshold IS 'Layer 4 only: distinct valid signers required, recomputed by the verifier from acceptThreshold over the validators active on this partition. Stored for querying, never trusted.';


--
-- Name: COLUMN chained_proof_layers.signed_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.signed_hash IS 'Layer 4 only: the 32 bytes the validator quorum actually signed — the hash of the SequencedMessage wrapping the anchor transaction, NOT the transaction hash. The two differ; conflating them yields a well-formed digest that never verifies.';


--
-- Name: COLUMN chained_proof_layers.superseded_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.superseded_at IS 'When this layer row was withdrawn as a claim. NULL means the row stands. A superseded row is kept verbatim: it is the evidence of what was published, and deleting it would erase the record of the claim rather than correct it. Readers presenting layer rows as current must filter superseded_at IS NULL.';


--
-- Name: COLUMN chained_proof_layers.superseded_reason; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.chained_proof_layers.superseded_reason IS 'Why the row was withdrawn, in words an auditor can act on — not an error code.';


--
-- Name: consensus_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.consensus_entries (
    entry_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    merkle_root bytea NOT NULL,
    anchor_tx_hash character varying(66),
    block_number bigint,
    tx_count integer NOT NULL,
    state character varying(30) DEFAULT 'initiated'::character varying NOT NULL,
    attestation_count integer DEFAULT 0 NOT NULL,
    required_count integer NOT NULL,
    quorum_fraction numeric(5,4) DEFAULT 0.667 NOT NULL,
    aggregate_signature bytea,
    aggregate_pubkey bytea,
    start_time timestamp with time zone NOT NULL,
    last_update timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    result_json jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_consensus_state CHECK (((state)::text = ANY ((ARRAY['initiated'::character varying, 'collecting'::character varying, 'quorum_met'::character varying, 'completed'::character varying, 'failed'::character varying, 'timeout'::character varying])::text[])))
);


--
-- Name: consensus_persistence_progress; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.consensus_persistence_progress (
    writer_id character varying(256) NOT NULL,
    persisted_height bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT consensus_persistence_progress_persisted_height_check CHECK ((persisted_height >= 0))
);


--
-- Name: custody_chain_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custody_chain_events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid NOT NULL,
    event_type character varying(50) NOT NULL,
    event_timestamp timestamp with time zone DEFAULT now() NOT NULL,
    actor_type character varying(50) NOT NULL,
    actor_id character varying(256),
    previous_hash bytea,
    current_hash bytea NOT NULL,
    event_details jsonb,
    signature bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_actor_type CHECK (((actor_type)::text = ANY ((ARRAY['validator'::character varying, 'coordinator'::character varying, 'api'::character varying, 'system'::character varying, 'external'::character varying, 'auditor'::character varying])::text[]))),
    CONSTRAINT valid_event_type CHECK (((event_type)::text = ANY ((ARRAY['created'::character varying, 'pending'::character varying, 'batched'::character varying, 'anchored'::character varying, 'attested'::character varying, 'verified'::character varying, 'failed'::character varying, 'retrieved'::character varying, 'bundle_created'::character varying, 'bundle_downloaded'::character varying, 'expired'::character varying])::text[])))
);


--
-- Name: external_chain_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_chain_results (
    result_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    bundle_id bytea NOT NULL,
    operation_id bytea NOT NULL,
    chain_type character varying(50) NOT NULL,
    chain_id bigint NOT NULL,
    network_name character varying(50),
    tx_hash bytea NOT NULL,
    tx_index integer NOT NULL,
    tx_gas_used bigint NOT NULL,
    tx_from_address bytea NOT NULL,
    tx_to_address bytea,
    block_number bigint NOT NULL,
    block_hash bytea NOT NULL,
    block_timestamp timestamp with time zone NOT NULL,
    state_root bytea NOT NULL,
    transactions_root bytea NOT NULL,
    receipts_root bytea NOT NULL,
    execution_status smallint NOT NULL,
    execution_success boolean NOT NULL,
    revert_reason text,
    contract_address bytea,
    logs_json jsonb,
    confirmation_blocks integer DEFAULT 0 NOT NULL,
    required_confirmations integer DEFAULT 12 NOT NULL,
    is_finalized boolean DEFAULT false NOT NULL,
    finalized_at timestamp with time zone,
    result_hash bytea NOT NULL,
    observer_validator_id character varying(256) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_chain_type CHECK (((chain_type)::text = ANY ((ARRAY['ethereum'::character varying, 'bitcoin'::character varying, 'solana'::character varying, 'polygon'::character varying])::text[]))),
    CONSTRAINT valid_execution_status CHECK ((execution_status = ANY (ARRAY[0, 1])))
);


--
-- Name: governance_proof_levels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.governance_proof_levels (
    level_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    gov_level character varying(8) NOT NULL,
    level_name character varying(64),
    block_height bigint,
    finality_timestamp timestamp with time zone,
    anchor_height bigint,
    is_anchored boolean,
    authority_url character varying(255),
    key_page_count integer,
    threshold_m integer,
    threshold_n integer,
    signature_count integer,
    outcome_type character varying(64),
    outcome_hash bytea,
    binding_enforced boolean,
    level_json jsonb,
    verified boolean DEFAULT false,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    receipt_entry_count integer,
    receipt_anchor bytea
);


--
-- Name: COLUMN governance_proof_levels.level_json; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.governance_proof_levels.level_json IS 'Verdict flags, PLUS the real G0/G1/G2 result under "result" and its receipt merkle path under "receipt". The flags (inclusion_verified, finality_achieved, threshold_m/n, authority_url, confirmations) are unchanged and still read by the evidence report and the approval console — the two new keys are ADDITIVE. Rows written before stage 2 have the flags only and are summary_only: their evidence was never captured and CANNOT be reconstructed.';


--
-- Name: COLUMN governance_proof_levels.receipt_entry_count; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.governance_proof_levels.receipt_entry_count IS 'Number of merkle steps in level_json->''receipt''->''entries''. A projection for querying — level_json is the authoritative evidence and the only thing the offline recomputation reads. NULL means no receipt evidence was stored, i.e. this level is summary-only. Note that 0 is NOT the same as NULL: a zero-length path is legitimate for a single-leaf receipt, where the leaf IS the anchor, and that case verifies only because start == anchor.';


--
-- Name: COLUMN governance_proof_levels.receipt_anchor; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.governance_proof_levels.receipt_anchor IS 'The 32-byte anchor the receipt path must reach. A projection, never trusted: the recomputation reads the anchor out of level_json so the stored evidence is checked against itself rather than against a column an operator could edit independently.';


--
-- Name: intent_chain_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intent_chain_groups (
    group_id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent_id character varying(128) NOT NULL,
    target_chain character varying(50) NOT NULL,
    chain_id bigint,
    chain_key character varying(100) NOT NULL,
    leg_count integer DEFAULT 0 NOT NULL,
    leg_ids uuid[],
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    batch_id uuid,
    anchor_id uuid,
    anchor_tx_hash character varying(256),
    anchor_block bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    anchored_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT valid_chain_group_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'batched'::character varying, 'anchoring'::character varying, 'anchored'::character varying, 'confirmed'::character varying, 'executed'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: TABLE intent_chain_groups; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.intent_chain_groups IS 'Legs grouped by target chain for efficient anchoring';


--
-- Name: COLUMN intent_chain_groups.chain_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.intent_chain_groups.chain_key IS 'Unique key for chain (e.g., ethereum:1, polygon:137)';


--
-- Name: intent_legs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intent_legs (
    leg_id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent_id character varying(128) NOT NULL,
    leg_index integer NOT NULL,
    leg_external_id character varying(128),
    target_chain character varying(50) NOT NULL,
    chain_id bigint,
    network_name character varying(50),
    role character varying(30) DEFAULT 'destination'::character varying NOT NULL,
    sequence_order integer DEFAULT 0 NOT NULL,
    depends_on_legs text[],
    from_address character varying(256),
    to_address character varying(256),
    amount character varying(100),
    token_symbol character varying(32),
    token_address character varying(256),
    asset_native boolean DEFAULT false,
    asset_decimals integer DEFAULT 18,
    gas_limit bigint,
    max_fee_per_gas character varying(50),
    max_priority_fee character varying(50),
    gas_payer character varying(256),
    anchor_contract character varying(256),
    function_selector character varying(20),
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    execution_tx_hash character varying(256),
    execution_block bigint,
    execution_gas_used bigint,
    execution_error text,
    batch_id uuid,
    anchor_id uuid,
    proof_id uuid,
    retry_count integer DEFAULT 0 NOT NULL,
    max_retries integer DEFAULT 3,
    last_retry_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT valid_leg_role CHECK (((role)::text = ANY ((ARRAY['source'::character varying, 'destination'::character varying, 'intermediate'::character varying])::text[]))),
    CONSTRAINT valid_leg_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying, 'processing'::character varying, 'batched'::character varying, 'anchored'::character varying, 'confirmed'::character varying, 'executed'::character varying, 'completed'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[])))
);


--
-- Name: TABLE intent_legs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.intent_legs IS 'Individual legs within a multi-leg intent';


--
-- Name: COLUMN intent_legs.sequence_order; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.intent_legs.sequence_order IS 'Order for sequential execution (0-indexed)';


--
-- Name: COLUMN intent_legs.depends_on_legs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.intent_legs.depends_on_legs IS 'Array of leg_external_ids this leg depends on';


--
-- Name: intent_lifecycle; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intent_lifecycle (
    id bigint NOT NULL,
    intent_id character varying(256) NOT NULL,
    accum_tx_hash character varying(128) NOT NULL,
    user_id character varying(256),
    status character varying(32) DEFAULT 'submitted'::character varying NOT NULL,
    target_chain character varying(64),
    proof_class character varying(20),
    error_message text,
    block_height bigint,
    cycle_id character varying(256),
    write_back_tx character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    submitted_at timestamp with time zone,
    authorized_at timestamp with time zone,
    in_process_at timestamp with time zone,
    completed_at timestamp with time zone,
    failed_at timestamp with time zone,
    target_chains text[],
    leg_count integer DEFAULT 1,
    execution_mode character varying(20),
    legs_completed integer DEFAULT 0,
    legs_failed integer DEFAULT 0,
    settling_at timestamp with time zone
);


--
-- Name: COLUMN intent_lifecycle.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.intent_lifecycle.status IS 'submitted | pending_signatures | authorized | in_process | settling | complete | failed. settling = consensus committed and the target-chain write is IN FLIGHT (submitted, no terminal receipt yet). It is NOT a failure and NOT terminal: Phase 7 observation of the real receipt resolves it to complete or failed. Deliberately no CHECK constraint — enumerating the states here would make adding the next one require a migration and an atomic deploy.';


--
-- Name: COLUMN intent_lifecycle.settling_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.intent_lifecycle.settling_at IS 'When the target-chain write was last known to be in flight for this intent. NULL on every row written before Stage 1, and deliberately never backfilled: those intents were not observed in this state and a synthesized timestamp would be evidence about a settlement nobody watched. The interval settling_at -> completed_at is the real settlement latency (~51s measured on base-sepolia, 2026-08-25).';


--
-- Name: intent_lifecycle_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.intent_lifecycle_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: intent_lifecycle_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.intent_lifecycle_id_seq OWNED BY public.intent_lifecycle.id;


--
-- Name: leg_dependencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.leg_dependencies (
    dependency_id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent_id character varying(128) NOT NULL,
    leg_id uuid NOT NULL,
    depends_on_leg_id uuid NOT NULL,
    condition_type character varying(20) DEFAULT 'success'::character varying NOT NULL,
    is_satisfied boolean DEFAULT false NOT NULL,
    satisfied_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT no_self_dependency CHECK ((leg_id <> depends_on_leg_id)),
    CONSTRAINT valid_condition_type CHECK (((condition_type)::text = ANY ((ARRAY['success'::character varying, 'completion'::character varying, 'confirmation'::character varying])::text[])))
);


--
-- Name: TABLE leg_dependencies; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.leg_dependencies IS 'Explicit dependencies between legs for execution ordering';


--
-- Name: multi_leg_pending_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.multi_leg_pending_state (
    intent_id character varying(128) NOT NULL,
    operation_id character varying(128) NOT NULL,
    total_legs integer NOT NULL,
    execution_mode character varying(20) DEFAULT 'parallel'::character varying NOT NULL,
    leg_mapping jsonb NOT NULL,
    leg_indices_per_chain jsonb NOT NULL,
    completed_cycles jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '02:00:00'::interval) NOT NULL
);


--
-- Name: proof_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.proof_artifacts (
    proof_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_type character varying(50) NOT NULL,
    proof_version character varying(20) DEFAULT '1.0'::character varying NOT NULL,
    accum_tx_hash character varying(128) NOT NULL,
    account_url character varying(512) NOT NULL,
    batch_id uuid,
    batch_position integer,
    anchor_id uuid,
    anchor_tx_hash character varying(128),
    anchor_block_number bigint,
    anchor_chain character varying(50),
    merkle_root bytea,
    leaf_hash bytea,
    leaf_index integer,
    gov_level character varying(10),
    proof_class character varying(20) NOT NULL,
    validator_id character varying(128) NOT NULL,
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    verification_status character varying(30),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    anchored_at timestamp with time zone,
    verified_at timestamp with time zone,
    artifact_json jsonb NOT NULL,
    artifact_hash bytea NOT NULL,
    user_id character varying(256),
    intent_id character varying(256),
    attestation_scheme character varying(32) DEFAULT 'bls12-381'::character varying,
    chain_platform character varying(32) DEFAULT 'evm'::character varying,
    target_chain character varying(64),
    unified_attestation_id uuid,
    chain_execution_id uuid,
    merkle_path jsonb,
    leg_id uuid,
    multi_leg_intent_id character varying(128),
    CONSTRAINT valid_gov_level CHECK (((gov_level IS NULL) OR ((gov_level)::text = ANY ((ARRAY['G0'::character varying, 'G1'::character varying, 'G2'::character varying])::text[])))),
    CONSTRAINT valid_proof_class CHECK (((proof_class)::text = ANY ((ARRAY['on_cadence'::character varying, 'on_demand'::character varying])::text[]))),
    CONSTRAINT valid_proof_type CHECK (((proof_type)::text = ANY ((ARRAY['certen_anchor'::character varying, 'chained'::character varying, 'governance'::character varying])::text[])))
);


--
-- Name: COLUMN proof_artifacts.batch_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.proof_artifacts.batch_id IS 'The anchor_batches row whose merkle root covers this proof''s leaf. NULL on every row written before stage 3, and on proofs that settled outside the batch path — those are one-member trees whose root IS their leaf. The join, not the evidence: chained_proof_layers layer 5 carries the path and is what the offline recomputation reads.';


--
-- Name: COLUMN proof_artifacts.merkle_path; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.proof_artifacts.merkle_path IS 'This proof''s leaf -> batch-root path, copied from batch_transactions.merkle_path so the proof can be read without a join. A projection for querying and display — layer 5''s layer_json is authoritative. NULL means no path was recorded; an empty ARRAY means the path IS empty, i.e. the leaf is the root. Those are different facts and must not be conflated: an empty path that is accepted without leaf == root makes every proof verify vacuously.';


--
-- Name: proof_bundles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.proof_bundles (
    bundle_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid NOT NULL,
    bundle_format character varying(20) DEFAULT 'certen_v1'::character varying NOT NULL,
    bundle_version character varying(20) DEFAULT '1.0'::character varying NOT NULL,
    bundle_data bytea NOT NULL,
    bundle_hash bytea NOT NULL,
    bundle_size_bytes integer NOT NULL,
    includes_chained boolean DEFAULT true NOT NULL,
    includes_governance boolean DEFAULT true NOT NULL,
    includes_merkle boolean DEFAULT true NOT NULL,
    includes_anchor boolean DEFAULT true NOT NULL,
    attestation_count integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT valid_bundle_format CHECK (((bundle_format)::text = ANY ((ARRAY['certen_v1'::character varying, 'json'::character varying, 'cbor'::character varying])::text[])))
);


--
-- Name: proof_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.proof_requests (
    request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    accum_tx_hash character varying(128),
    account_url character varying(512),
    proof_class character varying(20) NOT NULL,
    governance_level character varying(10),
    api_key_id uuid,
    callback_url character varying(1024),
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    proof_id uuid,
    error_message text,
    retry_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT request_has_target CHECK (((accum_tx_hash IS NOT NULL) OR (account_url IS NOT NULL))),
    CONSTRAINT valid_request_class CHECK (((proof_class)::text = ANY ((ARRAY['on_cadence'::character varying, 'on_demand'::character varying])::text[]))),
    CONSTRAINT valid_request_gov_level CHECK (((governance_level IS NULL) OR ((governance_level)::text = ANY ((ARRAY['G0'::character varying, 'G1'::character varying, 'G2'::character varying])::text[])))),
    CONSTRAINT valid_request_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying(64) NOT NULL,
    description text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: unified_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.unified_attestations (
    attestation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    cycle_id character varying(255) NOT NULL,
    scheme character varying(32) NOT NULL,
    validator_id character varying(255) NOT NULL,
    validator_index integer,
    public_key bytea NOT NULL,
    signature bytea NOT NULL,
    message_hash bytea NOT NULL,
    weight bigint DEFAULT 1,
    signature_valid boolean,
    verified_at timestamp with time zone,
    attested_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    verification_notes text,
    attested_block_number bigint,
    attested_block_hash bytea,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: TABLE unified_attestations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.unified_attestations IS 'Stores individual validator attestations across all cryptographic schemes (BLS, Ed25519, etc.)';


--
-- Name: COLUMN unified_attestations.scheme; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.unified_attestations.scheme IS 'Cryptographic scheme: bls12-381, ed25519, schnorr, threshold';


--
-- Name: v_attestation_stats; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_attestation_stats AS
 SELECT unified_attestations.scheme,
    count(*) AS total_attestations,
    count(DISTINCT unified_attestations.validator_id) AS unique_validators,
    count(
        CASE
            WHEN unified_attestations.signature_valid THEN 1
            ELSE NULL::integer
        END) AS valid_signatures,
    (avg(unified_attestations.weight))::numeric(10,2) AS avg_weight,
    min(unified_attestations.attested_at) AS first_attestation,
    max(unified_attestations.attested_at) AS latest_attestation
   FROM public.unified_attestations
  GROUP BY unified_attestations.scheme;


--
-- Name: v_chain_execution_stats; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_chain_execution_stats AS
 SELECT chain_execution_results.chain_platform,
    chain_execution_results.chain_id,
    chain_execution_results.network_name,
    count(*) AS total_executions,
    count(
        CASE
            WHEN (chain_execution_results.status = 1) THEN 1
            ELSE NULL::integer
        END) AS successful,
    count(
        CASE
            WHEN (chain_execution_results.status = 2) THEN 1
            ELSE NULL::integer
        END) AS failed,
    count(
        CASE
            WHEN chain_execution_results.is_finalized THEN 1
            ELSE NULL::integer
        END) AS finalized,
    (avg(chain_execution_results.gas_used))::bigint AS avg_gas_used,
    (avg(chain_execution_results.confirmations))::integer AS avg_confirmations
   FROM public.chain_execution_results
  GROUP BY chain_execution_results.chain_platform, chain_execution_results.chain_id, chain_execution_results.network_name;


--
-- Name: v_chain_group_details; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_chain_group_details AS
SELECT
    NULL::uuid AS group_id,
    NULL::character varying(128) AS intent_id,
    NULL::character varying(50) AS target_chain,
    NULL::bigint AS chain_id,
    NULL::character varying(100) AS chain_key,
    NULL::integer AS leg_count,
    NULL::character varying(30) AS group_status,
    NULL::character varying(256) AS anchor_tx_hash,
    NULL::character varying(20) AS execution_mode,
    NULL::character varying(20) AS proof_class,
    NULL::character varying(30) AS intent_status,
    NULL::uuid[] AS ordered_leg_ids,
    NULL::character varying[] AS leg_statuses;


--
-- Name: v_intent_leg_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_intent_leg_summary AS
SELECT
    NULL::character varying(128) AS intent_id,
    NULL::character varying(128) AS operation_id,
    NULL::character varying(256) AS user_id,
    NULL::character varying(128) AS accumulate_tx_hash,
    NULL::integer AS leg_count,
    NULL::character varying(20) AS execution_mode,
    NULL::character varying(20) AS proof_class,
    NULL::character varying(30) AS intent_status,
    NULL::integer AS legs_completed,
    NULL::integer AS legs_failed,
    NULL::integer AS legs_pending,
    NULL::timestamp with time zone AS created_at,
    NULL::timestamp with time zone AS completed_at,
    NULL::character varying[] AS target_chains,
    NULL::bigint AS chain_count,
    NULL::bigint AS actual_completed,
    NULL::bigint AS actual_failed,
    NULL::bigint AS actual_pending;


--
-- Name: v_legs_ready_for_execution; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_legs_ready_for_execution AS
 SELECT l.leg_id,
    l.intent_id,
    l.leg_index,
    l.leg_external_id,
    l.target_chain,
    l.chain_id,
    l.status,
    l.sequence_order,
    i.execution_mode,
    i.proof_class
   FROM (public.intent_legs l
     JOIN public.certen_intents i ON (((l.intent_id)::text = (i.intent_id)::text)))
  WHERE (((l.status)::text = 'pending'::text) AND ((i.status)::text = ANY ((ARRAY['discovered'::character varying, 'processing'::character varying])::text[])) AND (NOT (EXISTS ( SELECT 1
           FROM public.leg_dependencies d
          WHERE ((d.leg_id = l.leg_id) AND (d.is_satisfied = false))))));


--
-- Name: v_multi_leg_progress; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_multi_leg_progress AS
 SELECT i.intent_id,
    i.operation_id,
    i.user_id,
    i.leg_count,
    i.execution_mode,
    i.status AS intent_status,
    i.created_at,
        CASE
            WHEN (i.leg_count = 0) THEN (0)::numeric
            ELSE round((((i.legs_completed)::numeric / (i.leg_count)::numeric) * (100)::numeric), 1)
        END AS progress_percent,
    ( SELECT count(DISTINCT intent_legs.target_chain) AS count
           FROM public.intent_legs
          WHERE ((intent_legs.intent_id)::text = (i.intent_id)::text)) AS unique_chains,
    ( SELECT jsonb_object_agg(s.status, s.cnt) AS jsonb_object_agg
           FROM ( SELECT intent_legs.status,
                    count(*) AS cnt
                   FROM public.intent_legs
                  WHERE ((intent_legs.intent_id)::text = (i.intent_id)::text)
                  GROUP BY intent_legs.status) s) AS leg_status_breakdown,
        CASE
            WHEN (((i.execution_mode)::text = 'sequential'::text) AND ((i.status)::text = 'processing'::text)) THEN ( SELECT l.leg_external_id
               FROM public.intent_legs l
              WHERE (((l.intent_id)::text = (i.intent_id)::text) AND ((l.status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying, 'processing'::character varying])::text[])))
              ORDER BY l.sequence_order
             LIMIT 1)
            ELSE NULL::character varying
        END AS current_leg
   FROM public.certen_intents i
  WHERE (i.leg_count > 1);


--
-- Name: v_proof_with_attestations; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_proof_with_attestations AS
 SELECT pa.proof_id,
    pa.intent_id,
    pa.proof_type,
    pa.proof_class,
    pa.attestation_scheme,
    pa.chain_platform,
    pa.target_chain,
    pa.status,
    pa.created_at,
    aa.aggregation_id,
    aa.participant_count,
    aa.achieved_weight,
    aa.threshold_weight,
    aa.threshold_met,
    aa.aggregation_valid,
    cer.result_id AS execution_result_id,
    cer.tx_hash AS anchor_tx_hash,
    cer.is_finalized AS anchor_finalized
   FROM ((public.proof_artifacts pa
     LEFT JOIN public.aggregated_attestations aa ON ((pa.proof_id = aa.proof_id)))
     LEFT JOIN public.chain_execution_results cer ON (((pa.proof_id = cer.proof_id) AND (cer.workflow_step = 1))));


--
-- Name: validator_attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.validator_attestations (
    attestation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    batch_id uuid,
    validator_id character varying(128) NOT NULL,
    validator_pubkey bytea NOT NULL,
    attested_hash bytea NOT NULL,
    signature bytea NOT NULL,
    anchor_tx_hash character varying(128),
    merkle_root bytea,
    block_number bigint,
    signature_valid boolean DEFAULT false,
    verified_at timestamp with time zone,
    attested_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT attestation_has_parent CHECK (((proof_id IS NOT NULL) OR (batch_id IS NOT NULL)))
);


--
-- Name: verification_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verification_history (
    verification_id uuid DEFAULT gen_random_uuid() NOT NULL,
    proof_id uuid,
    verification_type character varying(64) NOT NULL,
    passed boolean NOT NULL,
    error_message text,
    verifier_id character varying(255),
    duration_ms integer,
    artifacts_json jsonb,
    created_at timestamp with time zone DEFAULT now(),
    error_code character varying(64),
    verification_method character varying(64)
);


--
-- Name: batch_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.batch_transactions ALTER COLUMN id SET DEFAULT nextval('public.batch_transactions_id_seq'::regclass);


--
-- Name: intent_lifecycle id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_lifecycle ALTER COLUMN id SET DEFAULT nextval('public.intent_lifecycle_id_seq'::regclass);


--
-- Name: aggregated_attestations aggregated_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aggregated_attestations
    ADD CONSTRAINT aggregated_attestations_pkey PRIMARY KEY (aggregation_id);


--
-- Name: aggregated_attestations aggregated_attestations_proof_id_scheme_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aggregated_attestations
    ADD CONSTRAINT aggregated_attestations_proof_id_scheme_key UNIQUE (proof_id, scheme);


--
-- Name: aggregated_bls_attestations aggregated_bls_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aggregated_bls_attestations
    ADD CONSTRAINT aggregated_bls_attestations_pkey PRIMARY KEY (aggregation_id);


--
-- Name: anchor_batches anchor_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anchor_batches
    ADD CONSTRAINT anchor_batches_pkey PRIMARY KEY (id);


--
-- Name: anchor_records anchor_records_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anchor_records
    ADD CONSTRAINT anchor_records_pkey PRIMARY KEY (anchor_id);


--
-- Name: anchor_references anchor_references_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anchor_references
    ADD CONSTRAINT anchor_references_pkey PRIMARY KEY (reference_id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (key_id);


--
-- Name: batch_attestations batch_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.batch_attestations
    ADD CONSTRAINT batch_attestations_pkey PRIMARY KEY (attestation_id);


--
-- Name: batch_transactions batch_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.batch_transactions
    ADD CONSTRAINT batch_transactions_pkey PRIMARY KEY (id);


--
-- Name: bls_result_attestations bls_result_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bls_result_attestations
    ADD CONSTRAINT bls_result_attestations_pkey PRIMARY KEY (attestation_id);


--
-- Name: certen_anchor_proofs certen_anchor_proofs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certen_anchor_proofs
    ADD CONSTRAINT certen_anchor_proofs_pkey PRIMARY KEY (id);


--
-- Name: certen_intents certen_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certen_intents
    ADD CONSTRAINT certen_intents_pkey PRIMARY KEY (intent_id);


--
-- Name: chain_execution_results chain_execution_results_chain_id_tx_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chain_execution_results
    ADD CONSTRAINT chain_execution_results_chain_id_tx_hash_key UNIQUE (chain_id, tx_hash);


--
-- Name: chain_execution_results chain_execution_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chain_execution_results
    ADD CONSTRAINT chain_execution_results_pkey PRIMARY KEY (result_id);


--
-- Name: chained_proof_layers chained_proof_layers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chained_proof_layers
    ADD CONSTRAINT chained_proof_layers_pkey PRIMARY KEY (layer_id);


--
-- Name: consensus_entries consensus_entries_batch_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consensus_entries
    ADD CONSTRAINT consensus_entries_batch_id_key UNIQUE (batch_id);


--
-- Name: consensus_entries consensus_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consensus_entries
    ADD CONSTRAINT consensus_entries_pkey PRIMARY KEY (entry_id);


--
-- Name: consensus_persistence_progress consensus_persistence_progress_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.consensus_persistence_progress
    ADD CONSTRAINT consensus_persistence_progress_pkey PRIMARY KEY (writer_id);


--
-- Name: custody_chain_events custody_chain_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custody_chain_events
    ADD CONSTRAINT custody_chain_events_pkey PRIMARY KEY (event_id);


--
-- Name: external_chain_results external_chain_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_chain_results
    ADD CONSTRAINT external_chain_results_pkey PRIMARY KEY (result_id);


--
-- Name: governance_proof_levels governance_proof_levels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_proof_levels
    ADD CONSTRAINT governance_proof_levels_pkey PRIMARY KEY (level_id);


--
-- Name: intent_chain_groups intent_chain_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_chain_groups
    ADD CONSTRAINT intent_chain_groups_pkey PRIMARY KEY (group_id);


--
-- Name: intent_legs intent_legs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT intent_legs_pkey PRIMARY KEY (leg_id);


--
-- Name: intent_lifecycle intent_lifecycle_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_lifecycle
    ADD CONSTRAINT intent_lifecycle_pkey PRIMARY KEY (id);


--
-- Name: leg_dependencies leg_dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leg_dependencies
    ADD CONSTRAINT leg_dependencies_pkey PRIMARY KEY (dependency_id);


--
-- Name: multi_leg_pending_state multi_leg_pending_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.multi_leg_pending_state
    ADD CONSTRAINT multi_leg_pending_state_pkey PRIMARY KEY (intent_id);


--
-- Name: proof_artifacts proof_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_artifacts
    ADD CONSTRAINT proof_artifacts_pkey PRIMARY KEY (proof_id);


--
-- Name: proof_bundles proof_bundles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_bundles
    ADD CONSTRAINT proof_bundles_pkey PRIMARY KEY (bundle_id);


--
-- Name: proof_requests proof_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_requests
    ADD CONSTRAINT proof_requests_pkey PRIMARY KEY (request_id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: unified_attestations unified_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unified_attestations
    ADD CONSTRAINT unified_attestations_pkey PRIMARY KEY (attestation_id);


--
-- Name: unified_attestations unified_attestations_proof_id_validator_id_scheme_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unified_attestations
    ADD CONSTRAINT unified_attestations_proof_id_validator_id_scheme_key UNIQUE (proof_id, validator_id, scheme);


--
-- Name: batch_attestations unique_batch_validator_attestation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.batch_attestations
    ADD CONSTRAINT unique_batch_validator_attestation UNIQUE (batch_id, validator_id);


--
-- Name: leg_dependencies unique_dependency; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leg_dependencies
    ADD CONSTRAINT unique_dependency UNIQUE (leg_id, depends_on_leg_id);


--
-- Name: intent_chain_groups unique_intent_chain_group; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_chain_groups
    ADD CONSTRAINT unique_intent_chain_group UNIQUE (intent_id, chain_key);


--
-- Name: intent_legs unique_intent_leg_external_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT unique_intent_leg_external_id UNIQUE (intent_id, leg_external_id);


--
-- Name: intent_legs unique_intent_leg_index; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT unique_intent_leg_index UNIQUE (intent_id, leg_index);


--
-- Name: bls_result_attestations unique_validator_attestation; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bls_result_attestations
    ADD CONSTRAINT unique_validator_attestation UNIQUE (result_id, validator_id);


--
-- Name: validator_attestations validator_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.validator_attestations
    ADD CONSTRAINT validator_attestations_pkey PRIMARY KEY (attestation_id);


--
-- Name: verification_history verification_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_history
    ADD CONSTRAINT verification_history_pkey PRIMARY KEY (verification_id);


--
-- Name: idx_ab_anchor_tx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ab_anchor_tx ON public.anchor_batches USING btree (anchor_tx_hash) WHERE (anchor_tx_hash IS NOT NULL);


--
-- Name: idx_aba_bundle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aba_bundle ON public.aggregated_bls_attestations USING btree (bundle_id);


--
-- Name: idx_aba_result; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_aba_result ON public.aggregated_bls_attestations USING btree (result_id);


--
-- Name: idx_aba_threshold; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aba_threshold ON public.aggregated_bls_attestations USING btree (threshold_met) WHERE (threshold_met = true);


--
-- Name: idx_aggregated_attestations_cycle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aggregated_attestations_cycle ON public.aggregated_attestations USING btree (cycle_id);


--
-- Name: idx_aggregated_attestations_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aggregated_attestations_proof ON public.aggregated_attestations USING btree (proof_id);


--
-- Name: idx_aggregated_attestations_scheme; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aggregated_attestations_scheme ON public.aggregated_attestations USING btree (scheme);


--
-- Name: idx_aggregated_attestations_threshold; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aggregated_attestations_threshold ON public.aggregated_attestations USING btree (threshold_met);


--
-- Name: idx_anchor_batches_bpt_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_batches_bpt_root ON public.anchor_batches USING btree (bpt_root) WHERE (bpt_root IS NOT NULL);


--
-- Name: idx_anchor_batches_canonical; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_batches_canonical ON public.anchor_batches USING btree (bundle_id) WHERE (bundle_id IS NOT NULL);


--
-- Name: idx_anchor_batches_governance_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_batches_governance_root ON public.anchor_batches USING btree (governance_root) WHERE (governance_root IS NOT NULL);


--
-- Name: idx_anchor_batches_quorum; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_batches_quorum ON public.anchor_batches USING btree (quorum_reached) WHERE (quorum_reached = true);


--
-- Name: idx_anchor_chain_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_chain_group ON public.anchor_records USING btree (chain_group_id) WHERE (chain_group_id IS NOT NULL);


--
-- Name: idx_anchor_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_intent ON public.anchor_records USING btree (intent_id) WHERE (intent_id IS NOT NULL);


--
-- Name: idx_anchor_references_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_references_chain ON public.anchor_references USING btree (chain_id, anchor_tx_hash);


--
-- Name: idx_anchor_references_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchor_references_proof ON public.anchor_references USING btree (proof_id);


--
-- Name: idx_anchors_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_batch ON public.anchor_records USING btree (batch_id);


--
-- Name: idx_anchors_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_chain ON public.anchor_records USING btree (target_chain);


--
-- Name: idx_anchors_confirmations; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_confirmations ON public.anchor_records USING btree (confirmations, required_confirmations) WHERE (is_final = false);


--
-- Name: idx_anchors_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_status ON public.anchor_records USING btree (status);


--
-- Name: idx_anchors_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_tx_hash ON public.anchor_records USING btree (anchor_tx_hash);


--
-- Name: idx_anchors_unconfirmed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_unconfirmed ON public.anchor_records USING btree (is_final, status) WHERE ((is_final = false) AND ((status)::text <> ALL ((ARRAY['failed'::character varying, 'finalized'::character varying])::text[])));


--
-- Name: idx_anchors_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_anchors_validator ON public.anchor_records USING btree (validator_id);


--
-- Name: idx_api_keys_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_active ON public.api_keys USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_api_keys_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_api_keys_hash ON public.api_keys USING btree (key_hash);


--
-- Name: idx_attestations_anchor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_anchor ON public.validator_attestations USING btree (anchor_tx_hash);


--
-- Name: idx_attestations_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_batch ON public.validator_attestations USING btree (batch_id);


--
-- Name: idx_attestations_merkle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_merkle ON public.validator_attestations USING btree (merkle_root);


--
-- Name: idx_attestations_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_proof ON public.validator_attestations USING btree (proof_id);


--
-- Name: idx_attestations_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_time ON public.validator_attestations USING btree (attested_at DESC);


--
-- Name: idx_attestations_unique_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_attestations_unique_batch ON public.validator_attestations USING btree (batch_id, validator_id) WHERE (batch_id IS NOT NULL);


--
-- Name: idx_attestations_unique_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_attestations_unique_proof ON public.validator_attestations USING btree (proof_id, validator_id) WHERE (proof_id IS NOT NULL);


--
-- Name: idx_attestations_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attestations_validator ON public.validator_attestations USING btree (validator_id);


--
-- Name: idx_ba_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ba_batch ON public.batch_attestations USING btree (batch_id);


--
-- Name: idx_ba_evm_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ba_evm_address ON public.batch_attestations USING btree (evm_address);


--
-- Name: idx_ba_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ba_time ON public.batch_attestations USING btree (attestation_time DESC);


--
-- Name: idx_ba_valid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ba_valid ON public.batch_attestations USING btree (signature_valid) WHERE (signature_valid = true);


--
-- Name: idx_ba_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ba_validator ON public.batch_attestations USING btree (validator_id);


--
-- Name: idx_batch_tx_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_account ON public.batch_transactions USING btree (account_url);


--
-- Name: idx_batch_tx_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_batch ON public.batch_transactions USING btree (batch_id);


--
-- Name: idx_batch_tx_chains; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_chains ON public.batch_transactions USING btree (from_chain, to_chain) WHERE (from_chain IS NOT NULL);


--
-- Name: idx_batch_tx_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_created ON public.batch_transactions USING btree (created_at DESC);


--
-- Name: idx_batch_tx_declared_effects; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_declared_effects ON public.batch_transactions USING btree (jsonb_array_length(declared_effects)) WHERE ((declared_effects IS NOT NULL) AND (jsonb_typeof(declared_effects) = 'array'::text));


--
-- Name: idx_batch_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_hash ON public.batch_transactions USING btree (accumulate_tx_hash);


--
-- Name: idx_batch_tx_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_intent ON public.batch_transactions USING btree (intent_id) WHERE (intent_id IS NOT NULL);


--
-- Name: idx_batch_tx_leg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_leg ON public.batch_transactions USING btree (leg_id) WHERE (leg_id IS NOT NULL);


--
-- Name: idx_batch_tx_multi_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_multi_intent ON public.batch_transactions USING btree (multi_leg_intent_id) WHERE (multi_leg_intent_id IS NOT NULL);


--
-- Name: idx_batch_tx_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_token ON public.batch_transactions USING btree (token_symbol) WHERE (token_symbol IS NOT NULL);


--
-- Name: idx_batch_tx_tree_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_tree_index ON public.batch_transactions USING btree (batch_id, tree_index);


--
-- Name: idx_batch_tx_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_user ON public.batch_transactions USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: idx_batch_tx_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_user_created ON public.batch_transactions USING btree (user_id, created_at DESC) WHERE (user_id IS NOT NULL);


--
-- Name: idx_batch_tx_user_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batch_tx_user_intent ON public.batch_transactions USING btree (user_id, intent_id) WHERE (user_id IS NOT NULL);


--
-- Name: idx_batches_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batches_chain ON public.anchor_batches USING btree (target_chain);


--
-- Name: idx_batches_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batches_created ON public.anchor_batches USING btree (created_at DESC);


--
-- Name: idx_batches_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batches_pending ON public.anchor_batches USING btree (batch_type, target_chain, status) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_batches_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batches_status ON public.anchor_batches USING btree (status);


--
-- Name: idx_batches_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_batches_type ON public.anchor_batches USING btree (batch_type);


--
-- Name: idx_bra_bundle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bra_bundle ON public.bls_result_attestations USING btree (bundle_id);


--
-- Name: idx_bra_result; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bra_result ON public.bls_result_attestations USING btree (result_id);


--
-- Name: idx_bra_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bra_validator ON public.bls_result_attestations USING btree (validator_id);


--
-- Name: idx_bundles_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bundles_created ON public.proof_bundles USING btree (created_at DESC);


--
-- Name: idx_bundles_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bundles_hash ON public.proof_bundles USING btree (bundle_hash);


--
-- Name: idx_bundles_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bundles_proof ON public.proof_bundles USING btree (proof_id);


--
-- Name: idx_ce_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ce_active ON public.consensus_entries USING btree (state) WHERE ((state)::text = ANY ((ARRAY['initiated'::character varying, 'collecting'::character varying])::text[]));


--
-- Name: idx_ce_completed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ce_completed ON public.consensus_entries USING btree (completed_at DESC) WHERE (completed_at IS NOT NULL);


--
-- Name: idx_ce_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ce_state ON public.consensus_entries USING btree (state);


--
-- Name: idx_chain_execution_anchor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_anchor ON public.chain_execution_results USING btree (anchor_id);


--
-- Name: idx_chain_execution_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_chain ON public.chain_execution_results USING btree (chain_id, tx_hash);


--
-- Name: idx_chain_execution_cycle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_cycle ON public.chain_execution_results USING btree (cycle_id);


--
-- Name: idx_chain_execution_finalized; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_finalized ON public.chain_execution_results USING btree (is_finalized);


--
-- Name: idx_chain_execution_platform; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_platform ON public.chain_execution_results USING btree (chain_platform);


--
-- Name: idx_chain_execution_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_proof ON public.chain_execution_results USING btree (proof_id);


--
-- Name: idx_chain_execution_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_execution_status ON public.chain_execution_results USING btree (status);


--
-- Name: idx_chain_groups_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_groups_chain ON public.intent_chain_groups USING btree (target_chain, chain_id);


--
-- Name: idx_chain_groups_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_groups_intent ON public.intent_chain_groups USING btree (intent_id);


--
-- Name: idx_chain_groups_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_groups_pending ON public.intent_chain_groups USING btree (intent_id) WHERE ((status)::text <> ALL ((ARRAY['completed'::character varying, 'failed'::character varying])::text[]));


--
-- Name: idx_chain_groups_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chain_groups_status ON public.intent_chain_groups USING btree (status);


--
-- Name: idx_chained_layers_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chained_layers_number ON public.chained_proof_layers USING btree (layer_number);


--
-- Name: idx_chained_layers_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chained_layers_proof ON public.chained_proof_layers USING btree (proof_id);


--
-- Name: idx_cpl_proof_layer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cpl_proof_layer ON public.chained_proof_layers USING btree (proof_id, layer_number);


--
-- Name: idx_cpl_superseded; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cpl_superseded ON public.chained_proof_layers USING btree (superseded_at) WHERE (superseded_at IS NOT NULL);


--
-- Name: idx_custody_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custody_actor ON public.custody_chain_events USING btree (actor_type, actor_id);


--
-- Name: idx_custody_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custody_event_type ON public.custody_chain_events USING btree (event_type);


--
-- Name: idx_custody_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custody_proof ON public.custody_chain_events USING btree (proof_id);


--
-- Name: idx_custody_proof_timeline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custody_proof_timeline ON public.custody_chain_events USING btree (proof_id, event_timestamp);


--
-- Name: idx_custody_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_custody_timestamp ON public.custody_chain_events USING btree (event_timestamp DESC);


--
-- Name: idx_deps_depends_on; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deps_depends_on ON public.leg_dependencies USING btree (depends_on_leg_id);


--
-- Name: idx_deps_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deps_intent ON public.leg_dependencies USING btree (intent_id);


--
-- Name: idx_deps_leg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deps_leg ON public.leg_dependencies USING btree (leg_id);


--
-- Name: idx_deps_unsatisfied; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deps_unsatisfied ON public.leg_dependencies USING btree (leg_id) WHERE (NOT is_satisfied);


--
-- Name: idx_ecr_bundle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ecr_bundle ON public.external_chain_results USING btree (bundle_id);


--
-- Name: idx_ecr_finalized; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ecr_finalized ON public.external_chain_results USING btree (is_finalized) WHERE (is_finalized = true);


--
-- Name: idx_ecr_result_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ecr_result_hash ON public.external_chain_results USING btree (result_hash);


--
-- Name: idx_ecr_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ecr_tx_hash ON public.external_chain_results USING btree (tx_hash);


--
-- Name: idx_gov_levels_with_receipt; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gov_levels_with_receipt ON public.governance_proof_levels USING btree (proof_id, gov_level) WHERE (level_json ? 'receipt'::text);


--
-- Name: idx_governance_levels_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_governance_levels_level ON public.governance_proof_levels USING btree (gov_level);


--
-- Name: idx_governance_levels_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_governance_levels_proof ON public.governance_proof_levels USING btree (proof_id);


--
-- Name: idx_intent_lifecycle_accum_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_lifecycle_accum_tx_hash ON public.intent_lifecycle USING btree (accum_tx_hash);


--
-- Name: idx_intent_lifecycle_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_lifecycle_created_at ON public.intent_lifecycle USING btree (created_at DESC);


--
-- Name: idx_intent_lifecycle_intent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_intent_lifecycle_intent_id ON public.intent_lifecycle USING btree (intent_id);


--
-- Name: idx_intent_lifecycle_settling; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_lifecycle_settling ON public.intent_lifecycle USING btree (settling_at) WHERE ((status)::text = 'settling'::text);


--
-- Name: idx_intent_lifecycle_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_lifecycle_status ON public.intent_lifecycle USING btree (status);


--
-- Name: idx_intent_lifecycle_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intent_lifecycle_user_id ON public.intent_lifecycle USING btree (user_id);


--
-- Name: idx_intents_accumulate_tx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_accumulate_tx ON public.certen_intents USING btree (accumulate_tx_hash);


--
-- Name: idx_intents_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_created ON public.certen_intents USING btree (created_at DESC);


--
-- Name: idx_intents_execution_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_execution_mode ON public.certen_intents USING btree (execution_mode);


--
-- Name: idx_intents_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_operation_id ON public.certen_intents USING btree (operation_id);


--
-- Name: idx_intents_organization; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_organization ON public.certen_intents USING btree (organization_adi) WHERE (organization_adi IS NOT NULL);


--
-- Name: idx_intents_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_pending ON public.certen_intents USING btree (created_at) WHERE ((status)::text = ANY ((ARRAY['discovered'::character varying, 'processing'::character varying, 'anchoring'::character varying])::text[]));


--
-- Name: idx_intents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_status ON public.certen_intents USING btree (status);


--
-- Name: idx_intents_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intents_user_id ON public.certen_intents USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: idx_legs_anchor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_anchor ON public.intent_legs USING btree (anchor_id) WHERE (anchor_id IS NOT NULL);


--
-- Name: idx_legs_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_batch ON public.intent_legs USING btree (batch_id) WHERE (batch_id IS NOT NULL);


--
-- Name: idx_legs_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_chain ON public.intent_legs USING btree (target_chain, chain_id);


--
-- Name: idx_legs_execution_tx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_execution_tx ON public.intent_legs USING btree (execution_tx_hash) WHERE (execution_tx_hash IS NOT NULL);


--
-- Name: idx_legs_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_intent ON public.intent_legs USING btree (intent_id);


--
-- Name: idx_legs_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_pending ON public.intent_legs USING btree (intent_id, sequence_order) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying])::text[]));


--
-- Name: idx_legs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_legs_status ON public.intent_legs USING btree (status);


--
-- Name: idx_multi_leg_pending_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_multi_leg_pending_created ON public.multi_leg_pending_state USING btree (created_at DESC);


--
-- Name: idx_multi_leg_pending_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_multi_leg_pending_expires ON public.multi_leg_pending_state USING btree (expires_at);


--
-- Name: idx_pa_batch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pa_batch_id ON public.proof_artifacts USING btree (batch_id) WHERE (batch_id IS NOT NULL);


--
-- Name: idx_proof_artifacts_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_account ON public.proof_artifacts USING btree (account_url);


--
-- Name: idx_proof_artifacts_anchor_tx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_anchor_tx ON public.proof_artifacts USING btree (anchor_tx_hash);


--
-- Name: idx_proof_artifacts_attestation_scheme; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_attestation_scheme ON public.proof_artifacts USING btree (attestation_scheme);


--
-- Name: idx_proof_artifacts_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_batch ON public.proof_artifacts USING btree (batch_id);


--
-- Name: idx_proof_artifacts_chain_platform; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_chain_platform ON public.proof_artifacts USING btree (chain_platform);


--
-- Name: idx_proof_artifacts_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_created ON public.proof_artifacts USING btree (created_at DESC);


--
-- Name: idx_proof_artifacts_gov_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_gov_level ON public.proof_artifacts USING btree (gov_level) WHERE (gov_level IS NOT NULL);


--
-- Name: idx_proof_artifacts_has_merkle_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_has_merkle_path ON public.proof_artifacts USING btree (((merkle_path IS NOT NULL))) WHERE (merkle_path IS NOT NULL);


--
-- Name: idx_proof_artifacts_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_intent ON public.proof_artifacts USING btree (intent_id) WHERE (intent_id IS NOT NULL);


--
-- Name: idx_proof_artifacts_merkle_root; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_merkle_root ON public.proof_artifacts USING btree (merkle_root);


--
-- Name: idx_proof_artifacts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_status ON public.proof_artifacts USING btree (status);


--
-- Name: idx_proof_artifacts_target_chain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_target_chain ON public.proof_artifacts USING btree (target_chain);


--
-- Name: idx_proof_artifacts_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_tx_hash ON public.proof_artifacts USING btree (accum_tx_hash);


--
-- Name: idx_proof_artifacts_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_user ON public.proof_artifacts USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: idx_proof_artifacts_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proof_artifacts_validator ON public.proof_artifacts USING btree (validator_id);


--
-- Name: idx_proofs_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_account ON public.certen_anchor_proofs USING btree (account_url);


--
-- Name: idx_proofs_anchor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_anchor ON public.certen_anchor_proofs USING btree (anchor_id) WHERE (anchor_id IS NOT NULL);


--
-- Name: idx_proofs_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_batch ON public.certen_anchor_proofs USING btree (batch_id);


--
-- Name: idx_proofs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_created ON public.certen_anchor_proofs USING btree (created_at DESC);


--
-- Name: idx_proofs_gov_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_gov_level ON public.certen_anchor_proofs USING btree (governance_level);


--
-- Name: idx_proofs_tx_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_tx_hash ON public.certen_anchor_proofs USING btree (accum_tx_hash);


--
-- Name: idx_proofs_verified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_proofs_verified ON public.certen_anchor_proofs USING btree (is_verified);


--
-- Name: idx_requests_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_requests_pending ON public.proof_requests USING btree (created_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_requests_status ON public.proof_requests USING btree (status);


--
-- Name: idx_requests_tx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_requests_tx ON public.proof_requests USING btree (accum_tx_hash) WHERE (accum_tx_hash IS NOT NULL);


--
-- Name: idx_unified_attestations_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_unified_attestations_created ON public.unified_attestations USING btree (created_at DESC);


--
-- Name: idx_unified_attestations_cycle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_unified_attestations_cycle ON public.unified_attestations USING btree (cycle_id);


--
-- Name: idx_unified_attestations_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_unified_attestations_proof ON public.unified_attestations USING btree (proof_id);


--
-- Name: idx_unified_attestations_scheme; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_unified_attestations_scheme ON public.unified_attestations USING btree (scheme);


--
-- Name: idx_unified_attestations_validator; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_unified_attestations_validator ON public.unified_attestations USING btree (validator_id);


--
-- Name: idx_verification_history_proof; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verification_history_proof ON public.verification_history USING btree (proof_id);


--
-- Name: idx_verification_history_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verification_history_type ON public.verification_history USING btree (verification_type);


--
-- Name: unique_tx_leg_in_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_tx_leg_in_batch ON public.batch_transactions USING btree (batch_id, accumulate_tx_hash, COALESCE((leg_id)::text, ''::text));


--
-- Name: INDEX unique_tx_leg_in_batch; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON INDEX public.unique_tx_leg_in_batch IS 'One row per (batch, intent transaction, leg). Replaces unique_tx_in_batch, which allowed only one leg per intent per batch and failed every multi-leg on_cadence intent.';


--
-- Name: uq_anchor_batches_chain_bundle; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_anchor_batches_chain_bundle ON public.anchor_batches USING btree (chain_id, bundle_id) WHERE (bundle_id IS NOT NULL);


--
-- Name: v_chain_group_details _RETURN; Type: RULE; Schema: public; Owner: -
--

CREATE OR REPLACE VIEW public.v_chain_group_details AS
 SELECT cg.group_id,
    cg.intent_id,
    cg.target_chain,
    cg.chain_id,
    cg.chain_key,
    cg.leg_count,
    cg.status AS group_status,
    cg.anchor_tx_hash,
    i.execution_mode,
    i.proof_class,
    i.status AS intent_status,
    array_agg(l.leg_id ORDER BY l.sequence_order) AS ordered_leg_ids,
    array_agg(l.status ORDER BY l.sequence_order) AS leg_statuses
   FROM ((public.intent_chain_groups cg
     JOIN public.certen_intents i ON (((cg.intent_id)::text = (i.intent_id)::text)))
     LEFT JOIN public.intent_legs l ON ((((l.intent_id)::text = (cg.intent_id)::text) AND ((l.target_chain)::text = (cg.target_chain)::text))))
  GROUP BY cg.group_id, i.execution_mode, i.proof_class, i.status;


--
-- Name: v_intent_leg_summary _RETURN; Type: RULE; Schema: public; Owner: -
--

CREATE OR REPLACE VIEW public.v_intent_leg_summary AS
 SELECT i.intent_id,
    i.operation_id,
    i.user_id,
    i.accumulate_tx_hash,
    i.leg_count,
    i.execution_mode,
    i.proof_class,
    i.status AS intent_status,
    i.legs_completed,
    i.legs_failed,
    i.legs_pending,
    i.created_at,
    i.completed_at,
    array_agg(DISTINCT l.target_chain) AS target_chains,
    count(DISTINCT l.target_chain) AS chain_count,
    sum(
        CASE
            WHEN ((l.status)::text = 'completed'::text) THEN 1
            ELSE 0
        END) AS actual_completed,
    sum(
        CASE
            WHEN ((l.status)::text = 'failed'::text) THEN 1
            ELSE 0
        END) AS actual_failed,
    sum(
        CASE
            WHEN ((l.status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying])::text[])) THEN 1
            ELSE 0
        END) AS actual_pending
   FROM (public.certen_intents i
     LEFT JOIN public.intent_legs l ON (((i.intent_id)::text = (l.intent_id)::text)))
  GROUP BY i.intent_id;


--
-- Name: intent_legs trg_update_intent_on_leg_change; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_update_intent_on_leg_change AFTER UPDATE OF status ON public.intent_legs FOR EACH ROW WHEN (((old.status)::text IS DISTINCT FROM (new.status)::text)) EXECUTE FUNCTION public.update_intent_on_leg_change();


--
-- Name: aggregated_attestations update_aggregated_attestations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_aggregated_attestations_updated_at BEFORE UPDATE ON public.aggregated_attestations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: certen_intents update_certen_intents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_certen_intents_updated_at BEFORE UPDATE ON public.certen_intents FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: chain_execution_results update_chain_execution_results_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_chain_execution_results_updated_at BEFORE UPDATE ON public.chain_execution_results FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: intent_legs update_intent_legs_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_intent_legs_updated_at BEFORE UPDATE ON public.intent_legs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: unified_attestations update_unified_attestations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_unified_attestations_updated_at BEFORE UPDATE ON public.unified_attestations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: aggregated_attestations aggregated_attestations_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aggregated_attestations
    ADD CONSTRAINT aggregated_attestations_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: aggregated_bls_attestations aggregated_bls_attestations_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aggregated_bls_attestations
    ADD CONSTRAINT aggregated_bls_attestations_result_id_fkey FOREIGN KEY (result_id) REFERENCES public.external_chain_results(result_id) ON DELETE CASCADE;


--
-- Name: anchor_records anchor_records_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anchor_records
    ADD CONSTRAINT anchor_records_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id);


--
-- Name: anchor_references anchor_references_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.anchor_references
    ADD CONSTRAINT anchor_references_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: batch_transactions batch_transactions_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.batch_transactions
    ADD CONSTRAINT batch_transactions_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id) ON DELETE CASCADE;


--
-- Name: bls_result_attestations bls_result_attestations_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bls_result_attestations
    ADD CONSTRAINT bls_result_attestations_result_id_fkey FOREIGN KEY (result_id) REFERENCES public.external_chain_results(result_id) ON DELETE CASCADE;


--
-- Name: certen_anchor_proofs certen_anchor_proofs_anchor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certen_anchor_proofs
    ADD CONSTRAINT certen_anchor_proofs_anchor_id_fkey FOREIGN KEY (anchor_id) REFERENCES public.anchor_records(anchor_id);


--
-- Name: certen_anchor_proofs certen_anchor_proofs_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certen_anchor_proofs
    ADD CONSTRAINT certen_anchor_proofs_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id);


--
-- Name: chain_execution_results chain_execution_results_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chain_execution_results
    ADD CONSTRAINT chain_execution_results_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: chained_proof_layers chained_proof_layers_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chained_proof_layers
    ADD CONSTRAINT chained_proof_layers_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: custody_chain_events custody_chain_events_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custody_chain_events
    ADD CONSTRAINT custody_chain_events_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id) ON DELETE CASCADE;


--
-- Name: external_chain_results external_chain_results_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_chain_results
    ADD CONSTRAINT external_chain_results_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: intent_legs fk_intent_legs_anchor; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT fk_intent_legs_anchor FOREIGN KEY (anchor_id) REFERENCES public.anchor_records(anchor_id) ON DELETE SET NULL;


--
-- Name: intent_legs fk_intent_legs_batch; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT fk_intent_legs_batch FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id) ON DELETE SET NULL;


--
-- Name: governance_proof_levels governance_proof_levels_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.governance_proof_levels
    ADD CONSTRAINT governance_proof_levels_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: intent_chain_groups intent_chain_groups_anchor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_chain_groups
    ADD CONSTRAINT intent_chain_groups_anchor_id_fkey FOREIGN KEY (anchor_id) REFERENCES public.anchor_records(anchor_id);


--
-- Name: intent_chain_groups intent_chain_groups_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_chain_groups
    ADD CONSTRAINT intent_chain_groups_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id);


--
-- Name: intent_chain_groups intent_chain_groups_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_chain_groups
    ADD CONSTRAINT intent_chain_groups_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.certen_intents(intent_id) ON DELETE CASCADE;


--
-- Name: intent_legs intent_legs_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intent_legs
    ADD CONSTRAINT intent_legs_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.certen_intents(intent_id) ON DELETE CASCADE;


--
-- Name: leg_dependencies leg_dependencies_depends_on_leg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leg_dependencies
    ADD CONSTRAINT leg_dependencies_depends_on_leg_id_fkey FOREIGN KEY (depends_on_leg_id) REFERENCES public.intent_legs(leg_id) ON DELETE CASCADE;


--
-- Name: leg_dependencies leg_dependencies_intent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leg_dependencies
    ADD CONSTRAINT leg_dependencies_intent_id_fkey FOREIGN KEY (intent_id) REFERENCES public.certen_intents(intent_id) ON DELETE CASCADE;


--
-- Name: leg_dependencies leg_dependencies_leg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leg_dependencies
    ADD CONSTRAINT leg_dependencies_leg_id_fkey FOREIGN KEY (leg_id) REFERENCES public.intent_legs(leg_id) ON DELETE CASCADE;


--
-- Name: proof_artifacts proof_artifacts_anchor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_artifacts
    ADD CONSTRAINT proof_artifacts_anchor_id_fkey FOREIGN KEY (anchor_id) REFERENCES public.anchor_records(anchor_id);


--
-- Name: proof_artifacts proof_artifacts_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_artifacts
    ADD CONSTRAINT proof_artifacts_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id);


--
-- Name: proof_bundles proof_bundles_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_bundles
    ADD CONSTRAINT proof_bundles_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id) ON DELETE CASCADE;


--
-- Name: proof_requests proof_requests_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_requests
    ADD CONSTRAINT proof_requests_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(key_id);


--
-- Name: proof_requests proof_requests_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.proof_requests
    ADD CONSTRAINT proof_requests_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: unified_attestations unified_attestations_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unified_attestations
    ADD CONSTRAINT unified_attestations_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- Name: validator_attestations validator_attestations_batch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.validator_attestations
    ADD CONSTRAINT validator_attestations_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.anchor_batches(id) ON DELETE CASCADE;


--
-- Name: validator_attestations validator_attestations_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.validator_attestations
    ADD CONSTRAINT validator_attestations_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id) ON DELETE CASCADE;


--
-- Name: verification_history verification_history_proof_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verification_history
    ADD CONSTRAINT verification_history_proof_id_fkey FOREIGN KEY (proof_id) REFERENCES public.proof_artifacts(proof_id);


--
-- PostgreSQL database dump complete
--

\unrestrict TgnH5aCqMdD9L15husBWEmC3wwPvaXkFk6xSdC2oKxe7Vc8NwSYm6iaTUWETdJM
