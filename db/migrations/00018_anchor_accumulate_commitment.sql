-- A canonical anchor row records everything its anchor derived its bundle id from and its quorum signed (RB5).
--
-- CertenAnchorV8_2 commits, beside the batch root and batch operation id, the Accumulate validator set its members'
-- L4 proofs were verified against and the Accumulate incarnation (which chain that is). The row kept neither, dropped
-- the CERTEN validator-set root the quorum message covers, and never wrote the Accumulate height the bundle id
-- derives from - so no stored anchor could re-derive its bundle id or its signed message offline (RB5-F9).
--   anchor_batches.anchor_version             v8_1 or v8_2: which createBatchAnchor the anchor was created with;
--                                            NULL on a row written before this migration
--   anchor_batches.certen_validator_set_root  the CERTEN validator-set root the quorum message covers, 0x-hex
--   anchor_batches.accumulate_set_root        the Accumulate validator-set root the V8.2 anchor committed, 0x-hex
--   anchor_batches.accumulate_incarnation     the Accumulate incarnation the V8.2 anchor committed, 0x-hex
--   anchor_batches.batch_leaf_count           the anchor's own leaf count, which the bundle id derives from - not
--                                            transaction_count, the members this row records (none on a row rebuilt
--                                            from the chain)
--   anchor_batches.accumulate_block_height    (existing, baseline) now written: the height the bundle id derives from
--
-- Expand-only: five nullable columns; a v8_2 row must carry both Accumulate values.

ALTER TABLE public.anchor_batches
    ADD COLUMN anchor_version character varying(4)
        CONSTRAINT anchor_version_is_known CHECK (anchor_version IN ('v8_1', 'v8_2')),
    ADD COLUMN certen_validator_set_root character varying(66)
        CONSTRAINT certen_validator_set_root_is_hex CHECK (certen_validator_set_root ~ '^0x[0-9a-f]{64}$'),
    ADD COLUMN accumulate_set_root character varying(66)
        CONSTRAINT accumulate_set_root_is_hex CHECK (accumulate_set_root ~ '^0x[0-9a-f]{64}$'),
    ADD COLUMN accumulate_incarnation character varying(66)
        CONSTRAINT accumulate_incarnation_is_hex CHECK (accumulate_incarnation ~ '^0x[0-9a-f]{64}$'),
    ADD COLUMN batch_leaf_count bigint
        CONSTRAINT batch_leaf_count_is_positive CHECK (batch_leaf_count > 0),
    ADD CONSTRAINT v8_2_anchor_commits_accumulate CHECK (
        anchor_version IS DISTINCT FROM 'v8_2' OR (accumulate_set_root IS NOT NULL AND accumulate_incarnation IS NOT NULL));

COMMENT ON COLUMN public.anchor_batches.anchor_version IS
  'The createBatchAnchor generation the anchor was created with: v8_1 (five arguments) or v8_2 (seven, committing the Accumulate set root and incarnation). NULL on a row written before migration 00018.';
COMMENT ON COLUMN public.anchor_batches.batch_leaf_count IS
  'The anchor''s own leaf count (batchLeafCount), which its bundle id derives from (RB5-F9); NULL on a row written before migration 00018.';
COMMENT ON COLUMN public.anchor_batches.certen_validator_set_root IS
  'The CERTEN validator-set root the quorum''s message covers, 0x-hex (RB5-F9).';
COMMENT ON COLUMN public.anchor_batches.accumulate_set_root IS
  'The Accumulate validator-set root a V8.2 anchor committed - the set its members'' L4 Directory legs were verified against (RB5 design D2), 0x-hex.';
COMMENT ON COLUMN public.anchor_batches.accumulate_incarnation IS
  'The Accumulate incarnation a V8.2 anchor committed (docs/l4/INCARNATION_ANCHOR.md), 0x-hex.';
