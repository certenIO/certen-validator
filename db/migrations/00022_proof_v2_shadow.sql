-- Proof v2 in shadow (RB6 Phase A, docs/proof/PROOF_V2.md §11). Every validator builds a v2 proof beside each v1
-- proof; only v1 feeds govRoot. These tables keep what the shadow captured, built and verified, so the switch decision
-- rests on stored evidence and every v2 proof can be verified offline.
--   proof_v2_shadow   one row per intent:
--     captured, captured_block, captured_at   the governing pages as of the transaction's block, read at discovery
--                                             while that block is inside the public node's retention
--                                             (proofv2.PageState list), or capture_error naming why not
--     evidence, built_at                      the v2 Accumulate evidence (proofv2.Evidence), built after the v1 proof
--     verdict                                 verified | validator_set_asserted | ... as proofv2.Verify reported it,
--                                             or 'failed' with error naming why
--     anchor_block, certified_block, pages    restated from the verified report for queries
--   proof_v2_spine    the Directory's major-block records from major block 1 (api.MajorHeaderRecord, binary), shared
--                     by every v2 proof; the offline verifier replays them from the pinned incarnation's genesis
--
-- Expand-only: two new tables.

CREATE TABLE public.proof_v2_shadow (
    intent_id        character varying(128) PRIMARY KEY,
    accum_tx_hash    character varying(128) NOT NULL,
    account_url      character varying(512) NOT NULL,
    captured_block   bigint,
    captured         jsonb,
    captured_at      timestamp with time zone,
    capture_error    text,
    evidence         jsonb,
    built_at         timestamp with time zone,
    verdict          character varying(64),
    error            text,
    anchor_block     bigint,
    certified_block  bigint,
    pages            integer,
    created_at       timestamp with time zone DEFAULT now() NOT NULL,
    updated_at       timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT proof_v2_shadow_failed_names_why CHECK (verdict IS DISTINCT FROM 'failed' OR error IS NOT NULL)
);

CREATE INDEX proof_v2_shadow_verdict_idx ON public.proof_v2_shadow (verdict, updated_at);

CREATE TABLE public.proof_v2_spine (
    major_index  bigint PRIMARY KEY CONSTRAINT proof_v2_spine_major_is_positive CHECK (major_index > 0),
    record       bytea NOT NULL,
    recorded_at  timestamp with time zone DEFAULT now() NOT NULL
);
