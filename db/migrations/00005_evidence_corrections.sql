-- Record every correction made to stored evidence, and link a withdrawn layer-5 row to its replacement.
--
-- Until 2026-09-18 the layer-5 binding stated the verify transaction's block for the anchor-create
-- transaction, and the Certen anchor proofs built from it carried the same block. The chain disagrees:
-- the on-demand anchor 0x0e073cf2… is in base-sepolia block 47002138, not 47002149. The writers are
-- fixed; what they already stored is corrected by `validator repair anchor-blocks`, which reads each
-- anchor transaction back from its chain and changes nothing the chain does not prove.
--
-- Evidence that was published is never silently rewritten. Each change is a row here holding what was
-- stored, what replaced it and the chain facts that justified it:
--   anchor_batch          anchor_block_num filled or corrected from the create receipt
--   layer5                a layer-5 row withdrawn (superseded_at, as 019/020) and a corrected row added;
--                         superseded_by points from the withdrawn row to the one that replaces it
--   certen_anchor_proof   the anchor reference revised in place (one proof per artifact), the proof hash
--                         recomputed and re-signed by the validator that signed it; the previous
--                         document, hash and signature are kept here
--
-- Expand-only: one table, one nullable column.

CREATE TABLE public.evidence_corrections (
    correction_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    record_type    varchar(32) NOT NULL,
    record_id      text NOT NULL,
    reason         text NOT NULL,
    previous       jsonb NOT NULL,
    corrected      jsonb NOT NULL,
    chain_evidence jsonb NOT NULL,
    corrected_by   varchar(128) NOT NULL,
    corrected_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evidence_correction_record_type CHECK (record_type IN ('anchor_batch', 'layer5', 'certen_anchor_proof'))
);
CREATE INDEX idx_evidence_corrections_record ON public.evidence_corrections USING btree (record_type, record_id);

COMMENT ON TABLE public.evidence_corrections IS
  'One row per correction of stored evidence: what was stored (previous), what replaced it (corrected) and '
  'the chain facts that prove the replacement (chain_evidence). Written in the same transaction as the '
  'correction, so a corrected row without its record cannot exist.';

ALTER TABLE public.chained_proof_layers ADD COLUMN superseded_by uuid REFERENCES public.chained_proof_layers(layer_id);

COMMENT ON COLUMN public.chained_proof_layers.superseded_by IS
  'The row that replaces this withdrawn one, when the claim was corrected rather than only withdrawn. '
  'NULL on a standing row and on rows 019/020 withdrew without a replacement.';
