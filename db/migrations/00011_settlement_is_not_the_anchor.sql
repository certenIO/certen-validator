-- The settlement transaction is not the anchor transaction (RB3-F135).
--
-- proof_artifacts, anchor_references and validator_attestations each have a column named anchor_tx_hash (and
-- a block beside it), and the live proof path filled all three with the SETTLEMENT transaction - the
-- Phase 7 observation of the member's account call - while anchor_batches and layer 5 use the name for the
-- transaction that published the batch root. Nothing recorded the difference, and proofs_service showed the
-- settlement to users as "Anchor TX". Read-only production, 2026-09-27: 111 of the 120 proofs with a
-- standing layer 5 named a different transaction in these columns than their own layer 5.
--
-- The columns now mean what they are called: the anchor's transaction (from the proof's layer 5; NULL where
-- the proof has none - the anchor is not established, and the proof is summary-only for it). The settlement
-- gets its own columns. Rows already written are moved by `validator repair projections`, which decides each
-- from chain facts and records every change in evidence_corrections; until it has run, a row whose
-- settlement_* columns are NULL has not been classified.
--
-- schema: destructive-approved   (the evidence_corrections record_type CHECK is replaced by a wider one)

ALTER TABLE public.proof_artifacts
    ADD COLUMN settlement_tx_hash character varying(128),
    ADD COLUMN settlement_block_number bigint;

ALTER TABLE public.anchor_references
    ADD COLUMN settlement_tx_hash character varying(128),
    ADD COLUMN settlement_block_number bigint,
    ADD COLUMN settlement_block_hash character varying(128),
    ADD COLUMN settlement_timestamp timestamp with time zone,
    ADD COLUMN settlement_gas_used bigint;
-- A proof whose anchor is not established has no anchor to state: NULL, rather than the settlement.
ALTER TABLE public.anchor_references ALTER COLUMN anchor_tx_hash DROP NOT NULL;
ALTER TABLE public.anchor_references ALTER COLUMN anchor_block_number DROP NOT NULL;

ALTER TABLE public.validator_attestations
    ADD COLUMN settlement_tx_hash character varying(128),
    ADD COLUMN settlement_block_number bigint;

ALTER TABLE public.evidence_corrections DROP CONSTRAINT evidence_correction_record_type;
ALTER TABLE public.evidence_corrections ADD CONSTRAINT evidence_correction_record_type
    CHECK (record_type IN ('anchor_batch', 'layer5', 'certen_anchor_proof', 'proof_artifact', 'anchor_reference', 'validator_attestation'));

COMMENT ON COLUMN public.proof_artifacts.anchor_tx_hash IS
  'The transaction that published the batch root this proof''s leaf is under - its layer 5''s anchorTx. NULL when the proof has no layer 5. Never the settlement (settlement_tx_hash); rows written before migration 00011 held the settlement until `validator repair projections` moved them (RB3-F135).';
COMMENT ON COLUMN public.proof_artifacts.anchor_block_number IS 'The block of anchor_tx_hash.';
COMMENT ON COLUMN public.proof_artifacts.settlement_tx_hash IS
  'The member''s settlement transaction on the target chain - the Phase 7 observation the proof cycle attested. Not where the root was published.';
COMMENT ON COLUMN public.proof_artifacts.settlement_block_number IS 'The block of settlement_tx_hash.';

COMMENT ON TABLE public.anchor_references IS
  'Where a proof''s batch root was published (anchor_*: layer 5''s anchor-create transaction and block) and the settlement it attests (settlement_*). anchor_* are NULL where the proof has no layer 5 (its anchor is not established). gas_used/gas_price_wei/total_cost_wei are the anchor transaction''s and are NULL where not read; settlement_gas_used is the settlement''s. Rows written before migration 00011 held the settlement in anchor_* until `validator repair projections` moved them (RB3-F135).';
COMMENT ON COLUMN public.anchor_references.anchor_tx_hash IS 'The anchor-create transaction that published the batch root (layer 5''s anchorTx).';
COMMENT ON COLUMN public.anchor_references.settlement_tx_hash IS 'The member''s settlement transaction (the Phase 7 observation).';

COMMENT ON COLUMN public.validator_attestations.anchor_tx_hash IS
  'The transaction that published the batch root (layer 5''s anchorTx); NULL when the proof has none. The attested message names the settlement: settlement_tx_hash (RB3-F135).';
COMMENT ON COLUMN public.validator_attestations.block_number IS 'The block of anchor_tx_hash.';
COMMENT ON COLUMN public.validator_attestations.settlement_tx_hash IS
  'The settlement transaction the attestation message names (its AnchorTxHash field) and the validators attested.';
COMMENT ON COLUMN public.validator_attestations.settlement_block_number IS 'The block of settlement_tx_hash.';
