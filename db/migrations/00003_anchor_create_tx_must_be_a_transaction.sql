-- anchor_create_tx must hold a transaction hash or nothing.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WENT WRONG
--
--  createBatchAnchor returns the sentinel 'already-exists' when the anchor is already on chain, created by
--  another validator. As an idempotence signal that is correct: a deterministic bundleId means an existing
--  anchor for this exact tree is a SUCCESS, not a conflict. As a stored value it is a falsehood, because
--  anchor_create_tx is read as "the transaction that published this root" and is copied into layer 5 as
--  `anchorTx`.
--
--  Observed live 2026-09-18, on the first intent after the shadow pipeline was retired:
--
--      anchor_batches.anchor_create_tx = 'already-exists'
--      chained_proof_layers.layer_json->>'anchorTx' = 'already-exists'
--
--  A published claim that a root appears in a transaction which is not a transaction. Structurally the
--  same defect as the d2d24ab3 binding this whole change set exists to remove: a column that reads as
--  evidence holding something nobody can check.
--
--  A validator that did not create the anchor does not know which transaction did. NULL says exactly that
--  and readers already handle it — GetLayer5Binding falls back rather than asserting.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHY A CONSTRAINT AND NOT ONLY A CODE FIX
--
--  The code fix (IsTransactionHash at both orchestrator sites) stops this writer. The constraint stops
--  EVERY writer, including the next one written by someone who has not read this file. The column is
--  evidence; the database should refuse to hold a non-answer in it.
-- schema: destructive-approved

-- The one row this defect produced. NULL, not a guess: this validator genuinely does not know which
-- transaction created that anchor.
UPDATE public.anchor_batches SET anchor_create_tx = NULL
 WHERE anchor_create_tx IS NOT NULL
   AND anchor_create_tx !~ '^0x[0-9a-fA-F]{64}$';

-- And the layer-5 rows that published it. Kept, not deleted: a claim that was made and withdrawn must
-- stay readable. Readers filter superseded_at IS NULL.
UPDATE public.chained_proof_layers SET superseded_at = NOW(),
       superseded_reason =
         'anchorTx ' || COALESCE(layer_json->>'anchorTx', '(null)') || ' is not a transaction hash. The '
         'validator that wrote this row did not create the anchor and did not know which transaction did; '
         'a sentinel was stored where a transaction belonged. See migration 00003.',
       verified = FALSE
 WHERE layer_number = 5
   AND superseded_at IS NULL
   AND layer_json ? 'anchorTx'
   AND layer_json->>'anchorTx' !~ '^0x[0-9a-fA-F]{64}$';

ALTER TABLE public.anchor_batches DROP CONSTRAINT IF EXISTS anchor_create_tx_is_a_transaction;
ALTER TABLE public.anchor_batches ADD CONSTRAINT anchor_create_tx_is_a_transaction
    CHECK (anchor_create_tx IS NULL OR anchor_create_tx ~ '^0x[0-9a-fA-F]{64}$');

COMMENT ON COLUMN public.anchor_batches.anchor_create_tx IS
  'The transaction that PUBLISHED this batch root — createBatchAnchor''s own transaction, never the settlement''s. NULL means this validator did not create the anchor and does not know which transaction did; readers must fall back rather than assert. Constrained to a transaction hash so a status word can never be stored here again (migration 00003).';
