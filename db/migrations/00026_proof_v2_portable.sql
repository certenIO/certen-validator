-- The proof v2 portable document, stored so a proof service can serve it (RB7b-F30, GET /v1/proof/{id}/v2).
--   proof_v2_portable     one row per intent: the portable document (certen-proof-v2-accumulate-portable/1) WITHOUT its
--                         major blocks, exactly as proofv2.ExportDocument wrote it; how many major blocks from the first it
--                         needs; and, once the intent's certificate is built, the govRoot v3 inputs that are not proof facts
--                         (proofv2.PortableGovRootV3Inputs). Text, not jsonb: a verifier hashes what it is given, and the
--                         bytes served are the bytes written.
--   proof_v2_spine_json   the Directory's major-block records from major block 1 in the portable form (api.MajorHeaderRecord
--                         as JSON), shared by every proof; proof_v2_spine keeps the same records in binary.
-- A proof's document is document with "majors" filled from proof_v2_spine_json[1..majors].
--
-- Expand-only: two new tables.

CREATE TABLE public.proof_v2_portable (
    intent_id          character varying(128) PRIMARY KEY,
    document           text NOT NULL,
    majors             integer NOT NULL CONSTRAINT proof_v2_portable_majors_is_positive CHECK (majors > 0),
    govroot_v3_inputs  text,
    built_at           timestamp with time zone DEFAULT now() NOT NULL,
    updated_at         timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.proof_v2_spine_json (
    major_index  bigint PRIMARY KEY CONSTRAINT proof_v2_spine_json_major_is_positive CHECK (major_index > 0),
    record       text NOT NULL,
    recorded_at  timestamp with time zone DEFAULT now() NOT NULL
);
