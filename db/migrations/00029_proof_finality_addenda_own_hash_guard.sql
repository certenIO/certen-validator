-- The addendum table refuses a row whose own_hash is not the one the specification computes (RB11-DBFIX, defect D6 of V-DB).
--
-- Migration 00027's trigger only checked that a new row LINKS to its predecessor (seq, prev_hash, level, chain). A direct INSERT by
-- any writer holding INSERT on the table - garbage evidence, a garbage own_hash, correctly linked - was therefore accepted, and
-- because the table is insert-only it could never be removed: it voided the proof's whole chain for every verifier (VerifyChain
-- fails at its own_hash) and held the proof's level for ever. This migration closes that: the trigger now recomputes the hash.
--
-- For every INSERT the trigger
--   1. keeps every linkage check of 00027, in the same order (seq 1 carries 32 zero bytes; the next seq links to the previous
--      own_hash; a level the proof already holds; the same chain), and refuses a level that is not stored (2 or 3) with
--      check_violation, as the column CHECK does;
--   2. parses the CFE1 container header of the evidence (V2_SPEC_S7 3.1, pkg/finality/codec.go ContainerHeader):
--        "CFE1"(4) || u32be len(kind) || kind (ASCII) || u64be chain || u8 level || u64be blockNumber || B32 blockHash
--      and requires the header's kind, chain and level to equal the row's;
--   3. for seq > 1, requires the header's leg block (blockNumber, blockHash) to equal the previous row's: one chain is about one leg;
--   4. derives the leg binding D0 = sha256(lp('certen:finality:d0/v1') || lp(be64 chain) || lp(be64 number) || lp(blockHash))
--      from that header (pkg/finality LegBinding), and recomputes
--        own_hash = sha256(lp('certen:finality:v1') || lp(D0) || lp(prev_hash) || lp(be64 seq) || lp(u8 level) || lp(be64 chain) ||
--                          lp(kind) || lp(sha256(evidence)))
--      (V2_SPEC_S7 2.2, pkg/finality OwnHash) with the builtin sha256(), where lp(x) = u32be(length(x)) || x. A row whose own_hash
--      differs is refused (SQLSTATE 23001, the same class as every other refusal of this table).
--
-- What this binds and what it does not:
--   * The header's leg block NUMBER is bound to proof_artifacts.settlement_block_number whenever the proof records one (the writer sets it
--     from the same observation as the bundle's component 5, and FinalityAddendaRepository.LegSettlement refuses a leg whose bundle proves
--     another block), so a self-consistent row naming a bogus block is refused here for every proof that records its settlement. The
--     binding applies to every row, not only to the first.
--   * It cannot bind a proof that records no settlement yet (the writer records it right after the bundle), a proof with no artifact
--     row, or the block HASH (the column the hash would live in, settlement_block_hash, is not written by the writer; the hash is in the
--     gzip bundle only). Those rows are stored if they are self-consistent, and are judged where the Settlement is: every reader and the
--     repository's Append compare the chain with finality.CheckLegChain under the Settlement's own leg binding D0 and refuse it by name
--     (finality_chain_broken{own_hash}). The trigger cannot judge the evidence itself (that is the registered Kind's job, run inside
--     Append and again by every verifier).
-- It makes the stored hashes internally consistent with the stored evidence, so a garbage row can no longer be linked into a chain.
--
-- Name resolution: all three functions are created with the function attribute search_path = pg_catalog, pg_temp (written on the LANGUAGE
-- line: the runner's lint rejects any line that starts with the session command SET), and the trigger calls the one function
-- of the builtin it needs as pg_catalog.sha256. A writer holding only INSERT on the table but CREATE on a schema it puts first in its
-- own search_path could otherwise define a function of the same name there and forge any own_hash; with pg_catalog,public in the path
-- an overload in public still wins for an unknown-typed literal (convert_to(text, text) over convert_to(text, name)), which is why
-- public is not in the path. Every table and function of this schema that the functions use is qualified with public. The guard reads
-- proof_artifacts, so a role that may INSERT into the table needs SELECT on proof_artifacts too (the application role owns both).
--
-- Expand-only: two new functions and a replaced trigger function body (which reads proof_artifacts); the triggers themselves are unchanged. Existing rows are
-- not touched (they were all written by Append, which forms the hash exactly this way).

CREATE FUNCTION public.proof_finality_lp(field bytea) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
    AS $$ SELECT int4send(length(field)) || field $$;

COMMENT ON FUNCTION public.proof_finality_lp(bytea) IS 'lp(x) of the finality hash preimages: u32be(length(x)) || x';

CREATE FUNCTION public.proof_finality_evidence_header(
    ev bytea,
    OUT well_formed boolean,
    OUT kind bytea,
    OUT chain bytea,
    OUT level integer,
    OUT leg_number bytea,
    OUT leg_hash bytea
) RETURNS record
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    klen bigint;
BEGIN
    well_formed := false;
    IF ev IS NULL OR length(ev) < 57 THEN
        RETURN;
    END IF;
    IF substring(ev from 1 for 4) <> '\x43464531'::bytea THEN
        RETURN;
    END IF;
    klen := get_byte(ev, 4)::bigint * 16777216 + get_byte(ev, 5)::bigint * 65536 + get_byte(ev, 6)::bigint * 256 + get_byte(ev, 7)::bigint;
    IF klen > 255 OR length(ev) < 57 + klen THEN
        RETURN;
    END IF;
    kind := substring(ev from 9 for klen::int);
    chain := substring(ev from (9 + klen)::int for 8);
    level := get_byte(ev, (16 + klen)::int);
    leg_number := substring(ev from (18 + klen)::int for 8);
    leg_hash := substring(ev from (26 + klen)::int for 32);
    well_formed := true;
END;
$$;

COMMENT ON FUNCTION public.proof_finality_evidence_header(bytea) IS 'Reads the CFE1 container header of finality evidence (V2_SPEC_S7 3.1); well_formed is false when it is not one';

CREATE OR REPLACE FUNCTION public.proof_finality_addenda_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
    AS $$
DECLARE
    previous public.proof_finality_addenda%ROWTYPE;
    h record;
    prev_h record;
    d0 bytea;
    want bytea;
    recorded bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'proof_finality_addenda is append-only: % refused', TG_OP USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.level NOT IN (2, 3) THEN
        RAISE EXCEPTION 'addendum % of % has level %, only 2 (l1_posted) and 3 (finalized) are stored', NEW.seq, NEW.proof_id, NEW.level USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.seq = 1 THEN
        IF NEW.prev_hash <> decode(repeat('00', 32), 'hex') THEN
            RAISE EXCEPTION 'addendum 1 of % must carry 32 zero bytes as prev_hash', NEW.proof_id USING ERRCODE = 'restrict_violation';
        END IF;
    ELSE
        SELECT * INTO previous FROM public.proof_finality_addenda WHERE proof_id = NEW.proof_id AND seq = NEW.seq - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'addendum % of % has no predecessor', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
        END IF;
        IF previous.own_hash <> NEW.prev_hash THEN
            RAISE EXCEPTION 'addendum % of % does not link to the previous own_hash', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM public.proof_finality_addenda WHERE proof_id = NEW.proof_id AND level = NEW.level) THEN
            RAISE EXCEPTION 'addendum % of % is a second addendum at level %', NEW.seq, NEW.proof_id, NEW.level USING ERRCODE = 'restrict_violation';
        END IF;
        IF NEW.chain <> previous.chain THEN
            RAISE EXCEPTION 'addendum % of % is for chain % but the chain is %', NEW.seq, NEW.proof_id, NEW.chain, previous.chain USING ERRCODE = 'restrict_violation';
        END IF;
    END IF;

    SELECT * INTO h FROM public.proof_finality_evidence_header(NEW.evidence);
    IF NOT h.well_formed THEN
        RAISE EXCEPTION 'addendum % of % does not carry a CFE1 evidence container header', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    IF h.kind <> convert_to(NEW.kind, 'UTF8') THEN
        RAISE EXCEPTION 'addendum % of %: the evidence header names another kind than the row', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    IF h.chain <> int8send(NEW.chain) THEN
        RAISE EXCEPTION 'addendum % of %: the evidence header names another chain than the row', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    IF h.level <> NEW.level THEN
        RAISE EXCEPTION 'addendum % of %: the evidence header names another level than the row', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    SELECT a.settlement_block_number INTO recorded FROM public.proof_artifacts a WHERE a.proof_id = NEW.proof_id;
    IF FOUND AND recorded IS NOT NULL AND h.leg_number <> int8send(recorded) THEN
        RAISE EXCEPTION 'addendum % of %: the evidence is about a block other than the settlement block the proof records (%)', NEW.seq, NEW.proof_id, recorded USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.seq > 1 THEN
        SELECT * INTO prev_h FROM public.proof_finality_evidence_header(previous.evidence);
        IF NOT prev_h.well_formed OR prev_h.leg_number <> h.leg_number OR prev_h.leg_hash <> h.leg_hash THEN
            RAISE EXCEPTION 'addendum % of %: the evidence is not about the leg block of the chain', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
        END IF;
    END IF;

    d0 := pg_catalog.sha256(
        public.proof_finality_lp(convert_to('certen:finality:d0/v1', 'UTF8')) ||
        public.proof_finality_lp(h.chain) ||
        public.proof_finality_lp(h.leg_number) ||
        public.proof_finality_lp(h.leg_hash));
    want := pg_catalog.sha256(
        public.proof_finality_lp(convert_to('certen:finality:v1', 'UTF8')) ||
        public.proof_finality_lp(d0) ||
        public.proof_finality_lp(NEW.prev_hash) ||
        public.proof_finality_lp(int8send(NEW.seq)) ||
        public.proof_finality_lp(set_byte('\x00'::bytea, 0, NEW.level::int)) ||
        public.proof_finality_lp(int8send(NEW.chain)) ||
        public.proof_finality_lp(convert_to(NEW.kind, 'UTF8')) ||
        public.proof_finality_lp(pg_catalog.sha256(NEW.evidence)));
    IF NEW.own_hash <> want THEN
        RAISE EXCEPTION 'addendum % of % carries an own_hash that is not sha256 of its link, kind and evidence under the leg binding', NEW.seq, NEW.proof_id USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
