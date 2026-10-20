-- Builder status and L1 capture rows for staged finality (V2_SPEC_S7 sections 2.7 and 2.8, RB11 Phase B).
--
-- proof_finality_status (2.7) is the builder's view of a leg, outside the addendum chain and NEVER read by a verifier: for each
-- (proof, target level) the last state the upgrader judged - pending with the level reached, the next level and the eta, a
-- builder-side unavailability, a refusal of built evidence, not applicable, or verified - so the gateway can show "level
-- reached / next / eta". It is MUTABLE by design: a later pass replaces the row.
--   proof_id      the stored proof (proof_artifacts.proof_id); one leg per proof_id
--   chain         the target chain id
--   target_level  2 l1_posted or 3 finalized (level 1 included is derived, never stored, never built)
--   state         the status document (certen-finality-status/1): class, levelReached, nextLevel, eta, and the named state
--   judged_at     when the upgrader judged it
--
-- proof_finality_capture (2.8) holds the leg-independent L1 bytes the two-phase kinds are attested from (Base batch-inbox
-- frames, blobs and SystemConfig proofs, Arbitrum batch and assertion events, near-head proofs of the pinned contracts).
-- Public providers serve eth_getProof only near the head while a kind is verifiable only after the finalized head covers its
-- blocks, so the bytes are captured on every new L1 head and attested later. The key is (chain, l1_block, l1_hash, item): a
-- reorg yields a second row for the same height under another hash. The table is INSERT-ONLY exactly like
-- proof_finality_addenda (migration 00027): a trigger refuses UPDATE, DELETE and TRUNCATE (SQLSTATE 23001), whoever the writer.
-- It is never read by a verifier. The per-leg size bound is enforced by the capturers, not by the table.
--
-- Expand-only: two new tables, one function, two triggers. Nothing reads or alters an existing object.

CREATE TABLE public.proof_finality_status (
    proof_id      uuid NOT NULL,
    chain         bigint NOT NULL
        CONSTRAINT proof_finality_status_chain_is_positive CHECK (chain > 0),
    target_level  smallint NOT NULL
        CONSTRAINT proof_finality_status_level_is_stored CHECK (target_level IN (2, 3)),
    state         jsonb NOT NULL
        CONSTRAINT proof_finality_status_state_is_object CHECK (jsonb_typeof(state) = 'object'),
    judged_at     timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT proof_finality_status_pkey PRIMARY KEY (proof_id, target_level)
);

CREATE INDEX proof_finality_status_judged_idx ON public.proof_finality_status (chain, target_level, judged_at);

COMMENT ON TABLE public.proof_finality_status IS 'Builder status of a leg per target level (V2_SPEC_S7 2.7); mutable, never read by a verifier';

CREATE TABLE public.proof_finality_capture (
    chain       bigint NOT NULL
        CONSTRAINT proof_finality_capture_chain_is_positive CHECK (chain > 0),
    l1_block    bigint NOT NULL
        CONSTRAINT proof_finality_capture_block_is_not_negative CHECK (l1_block >= 0),
    l1_hash     bytea NOT NULL
        CONSTRAINT proof_finality_capture_hash_is_32_bytes CHECK (length(l1_hash) = 32),
    item        character varying(160) NOT NULL
        CONSTRAINT proof_finality_capture_item_is_name CHECK (item ~ '^[a-z0-9_-]+(/[a-z0-9_-]+)*$'),
    bytes       bytea NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT proof_finality_capture_pkey PRIMARY KEY (chain, l1_block, l1_hash, item)
);

CREATE FUNCTION public.proof_finality_capture_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'proof_finality_capture is insert-only: % refused', TG_OP USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER proof_finality_capture_row_guard
    BEFORE UPDATE OR DELETE ON public.proof_finality_capture
    FOR EACH ROW EXECUTE FUNCTION public.proof_finality_capture_guard();

CREATE TRIGGER proof_finality_capture_statement_guard
    BEFORE TRUNCATE ON public.proof_finality_capture
    FOR EACH STATEMENT EXECUTE FUNCTION public.proof_finality_capture_guard();

COMMENT ON TABLE public.proof_finality_capture IS 'Insert-only L1 capture bytes for the two-phase finality kinds (V2_SPEC_S7 2.8); refused UPDATE/DELETE/TRUNCATE, enforced by trigger; never read by a verifier';
