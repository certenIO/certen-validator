-- Staged finality evidence for a settled leg (PROOF_V2 section 7, RB11 Phase B, domain tag certen:finality:v1).
--
-- A proof is upgraded append-only: when stronger finality evidence becomes buildable for a leg's settlement (included,
-- then l1_posted, then finalized), one addendum is appended to that leg's chain. The stored proof itself never changes; an
-- addendum commits to the proof's original digest (proof_artifacts.artifact_hash) and to the previous addendum, so the whole
-- chain is tamper-evident, and a verifier recomputes it offline (pkg/finality VerifyChain).
--   proof_id    the stored proof the chain belongs to (proof_artifacts.proof_id as text)
--   seq         1, 2, 3 ... within the proof, contiguous
--   level       1 included, 2 l1_posted, 3 finalized; strictly increasing along the chain
--   chain       the target chain id the evidence is about; one chain per proof_id
--   kind        the evidence kind (e.g. included.eth-mpt/v1), a lowercase identifier
--   evidence    the canonical Evidence container (pkg/finality), whose Subject names the settled block and transaction
--   prev_hash   the previous addendum's own_hash; 32 zero bytes for seq 1
--   own_hash    sha256 over the domain, the original proof digest, prev_hash, seq, level, chain, kind and sha256(evidence)
--
-- The table is INSERT-ONLY, enforced here and not only in the repository: a trigger refuses UPDATE, DELETE and TRUNCATE
-- (SQLSTATE 23001), and refuses an INSERT that does not extend its proof's chain exactly (seq 1 with a zero prev_hash, or
-- the next seq with prev_hash equal to the previous own_hash, a strictly higher level, the same chain). Only the table's
-- owner can disable the trigger, as with any trigger; nothing in the application does.
--
-- Expand-only: one new table, one function, two triggers. Nothing reads or alters an existing object.

CREATE TABLE public.proof_finality_addenda (
    proof_id    character varying(128) NOT NULL
        CONSTRAINT proof_finality_proof_id_is_not_empty CHECK (proof_id <> ''),
    seq         bigint NOT NULL
        CONSTRAINT proof_finality_seq_is_positive CHECK (seq > 0),
    level       smallint NOT NULL
        CONSTRAINT proof_finality_level_is_known CHECK (level BETWEEN 1 AND 3),
    chain       bigint NOT NULL
        CONSTRAINT proof_finality_chain_is_positive CHECK (chain > 0),
    kind        character varying(64) NOT NULL
        CONSTRAINT proof_finality_kind_is_identifier CHECK (kind ~ '^[a-z][a-z0-9._/-]{0,63}$'),
    evidence    bytea NOT NULL
        CONSTRAINT proof_finality_evidence_is_not_empty CHECK (length(evidence) > 0),
    prev_hash   bytea NOT NULL
        CONSTRAINT proof_finality_prev_hash_is_32_bytes CHECK (length(prev_hash) = 32),
    own_hash    bytea NOT NULL
        CONSTRAINT proof_finality_own_hash_is_32_bytes CHECK (length(own_hash) = 32),
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT proof_finality_addenda_pkey PRIMARY KEY (proof_id, seq)
);

CREATE INDEX proof_finality_addenda_level_idx ON public.proof_finality_addenda (proof_id, level);

CREATE FUNCTION public.proof_finality_addenda_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    previous public.proof_finality_addenda%ROWTYPE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'proof_finality_addenda is append-only: % refused', TG_OP USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.seq = 1 THEN
        IF NEW.prev_hash <> decode(repeat('00', 32), 'hex') THEN
            RAISE EXCEPTION 'addendum 1 of % must carry 32 zero bytes as prev_hash', NEW.proof_id USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO previous FROM public.proof_finality_addenda WHERE proof_id = NEW.proof_id AND seq = NEW.seq - 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'addendum % of % has no predecessor', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    IF previous.own_hash <> NEW.prev_hash THEN
        RAISE EXCEPTION 'addendum % of % does not link to the previous own_hash', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.level <= previous.level THEN
        RAISE EXCEPTION 'addendum % of % does not raise the level (% after %)', NEW.seq, NEW.proof_id, NEW.level, previous.level USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.chain <> previous.chain THEN
        RAISE EXCEPTION 'addendum % of % is for chain % but the chain is %', NEW.seq, NEW.proof_id, NEW.chain, previous.chain USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER proof_finality_addenda_row_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.proof_finality_addenda
    FOR EACH ROW EXECUTE FUNCTION public.proof_finality_addenda_guard();

CREATE TRIGGER proof_finality_addenda_statement_guard
    BEFORE TRUNCATE ON public.proof_finality_addenda
    FOR EACH STATEMENT EXECUTE FUNCTION public.proof_finality_addenda_guard();

COMMENT ON TABLE public.proof_finality_addenda IS 'Append-only staged finality evidence per settled leg (certen:finality:v1); refused UPDATE/DELETE/TRUNCATE, enforced by trigger';
