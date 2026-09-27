-- anchor_tx_hash must hold a transaction hash or nothing (RB3-F130).
--
-- Migration 00003 removed the sentinel 'already-exists' from anchor_create_tx and constrained that column.
-- The quorum writer had copied the same value into anchor_tx_hash (its INSERT writes the create
-- transaction to both), and 00003 neither cleaned nor constrained that column. Read-only production,
-- 2026-09-27: two canonical rows still said
--
--     anchor_batches.anchor_tx_hash = 'already-exists'    (base-sepolia, 2026-09-18, batches 185d8b0d and 693b7edb)
--
-- in the column documented as "the external-chain transaction that published this batch's merkle_root".
-- Nothing else in the table holds a non-transaction there.
--
-- Each such value is recorded in evidence_corrections (what was stored, and why it is withdrawn) in this
-- migration, then withdrawn to NULL - which says what the writer knew: it did not create the anchor and
-- did not know which transaction did. `validator repair anchor-blocks` then finds the creating transaction
-- from the anchor's own record and its BatchAnchorCreated log and records it with the chain facts
-- (RB3-F33), so NULL is not where these rows end.
--
-- schema: destructive-approved

INSERT INTO public.evidence_corrections (record_type, record_id, reason, previous, corrected, chain_evidence, corrected_by)
SELECT 'anchor_batch', id::text,
       'anchor_tx_hash ' || quote_literal(anchor_tx_hash) || ' is not a transaction hash. The validator that '
       'wrote this row did not create the anchor and did not know which transaction did; a sentinel was '
       'stored where a transaction belonged. Withdrawn to NULL (migration 00010).',
       jsonb_build_object('anchor_tx_hash', anchor_tx_hash),
       jsonb_build_object('anchor_tx_hash', NULL),
       jsonb_build_object('basis', 'the stored value is not a 32-byte transaction hash', 'stored', anchor_tx_hash),
       'migration 00010'
  FROM public.anchor_batches
 WHERE anchor_tx_hash IS NOT NULL
   AND anchor_tx_hash !~ '^0x[0-9a-fA-F]{64}$';

UPDATE public.anchor_batches SET anchor_tx_hash = NULL, updated_at = NOW()
 WHERE anchor_tx_hash IS NOT NULL
   AND anchor_tx_hash !~ '^0x[0-9a-fA-F]{64}$';

ALTER TABLE public.anchor_batches ADD CONSTRAINT anchor_tx_hash_is_a_transaction
    CHECK (anchor_tx_hash IS NULL OR anchor_tx_hash ~ '^0x[0-9a-fA-F]{64}$');

COMMENT ON COLUMN public.anchor_batches.anchor_tx_hash IS
  'The external-chain transaction that published this batch''s merkle_root: the create transaction, equal to anchor_create_tx once that is known. Written once and never overwritten except by a recorded correction (evidence_corrections). Constrained to a transaction hash so a status word can never be stored here again (migration 00010; 00003 constrained only anchor_create_tx).';
