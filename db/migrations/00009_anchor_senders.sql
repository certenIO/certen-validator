-- Who sent each anchor's transactions (RB3-F127).
--
-- An anchor row records the transaction that published its root (anchor_create_tx) and the one that
-- carried the quorum proof (verify_tx), but not which validator sent either: validator_id is written NULL
-- by the quorum writer, and a run-log claim about who executed or submitted (RB3-F23) could not be checked
-- against the evidence store at all. The sender is a fact of the chain - the transaction's signer - so it
-- is recorded here as the chain states it: by the live writer for the transactions it sent or looked up,
-- and by `validator repair anchor-blocks` for rows written before this column existed.
--
-- Expand-only: two nullable columns, each constrained to an address. NULL means not yet read from the
-- chain, never "unknown sender".

ALTER TABLE public.anchor_batches
    ADD COLUMN anchor_create_sender character varying(42)
        CONSTRAINT anchor_create_sender_is_an_address
        CHECK (anchor_create_sender IS NULL OR anchor_create_sender ~ '^0x[0-9a-f]{40}$'),
    ADD COLUMN verify_sender character varying(42)
        CONSTRAINT verify_sender_is_an_address
        CHECK (verify_sender IS NULL OR verify_sender ~ '^0x[0-9a-f]{40}$');

COMMENT ON COLUMN public.anchor_batches.anchor_create_sender IS
  'The signer of anchor_create_tx, lower-case, as the chain states it. NULL until read (RB3-F127).';
COMMENT ON COLUMN public.anchor_batches.verify_sender IS
  'The signer of verify_tx, lower-case, as the chain states it. NULL until read (RB3-F127).';
