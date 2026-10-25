-- The capture table is listed by item prefix: a window's entries, the recorded gaps, the fills, the scan rows (RB12 OPS-A2 item 5, ledger CG-5).
--
-- The primary key is (chain, l1_block, l1_hash, item), so a listing of the rows whose item starts with a prefix over a range of blocks
-- can only walk the key range and test every item: a gap lookup, which has to start at block 0 because a gap row is keyed by the FIRST
-- block of its range and a long range can reach far above its key, walked the whole table of the chain up to the end of the window (every
-- blob, every header, every proof) to find a handful of gap rows. The cost grew with the table, not with the window, and the prefix
-- backfill adds about 10 rows per block.
--
-- This index puts the item first: a listing by (chain, item prefix) reads only the rows of that family, in block order, whatever else the
-- table holds. text_pattern_ops makes the prefix test (LIKE 'gap/%') index-served under every collation of the database. The index is
-- additive: nothing reads or writes differently except the listing, which pkg/database ListByRange now states as an anchored LIKE.
CREATE INDEX IF NOT EXISTS proof_finality_capture_item_idx
    ON proof_finality_capture (chain, item text_pattern_ops, l1_block);
