-- A canonical anchor row records the governance its batch operation id commits to (RB4-F66).
--
-- The batch operation id - the value the quorum signs and the anchor stores - aggregated the members' operation ids
-- alone, so no anchor committed to who authorised any member. It now aggregates each member's operation id with its
-- governance commitment (keccak of the member's governance decision record). To check a proof against its anchor
-- offline, the row must say which derivation the anchor used and what every member committed to:
--   anchor_batches.batch_operation_id_version  v2 commits to governance, v1 does not (members admitted before it);
--                                             NULL when the row was rebuilt from the chain, which cannot tell
--   batch_transactions.operation_id            the member's operation id, 0x-hex
--   batch_transactions.governance_commitment   the member's governance commitment, 0x-hex; NULL for a v1 member
--
-- Expand-only: three nullable columns.

ALTER TABLE public.anchor_batches
    ADD COLUMN batch_operation_id_version character varying(4)
        CONSTRAINT batch_operation_id_version_is_known CHECK (batch_operation_id_version IN ('v1', 'v2'));

ALTER TABLE public.batch_transactions
    ADD COLUMN operation_id character varying(66)
        CONSTRAINT batch_member_operation_id_is_hex CHECK (operation_id ~ '^0x[0-9a-f]{64}$'),
    ADD COLUMN governance_commitment character varying(66)
        CONSTRAINT batch_member_governance_commitment_is_hex CHECK (governance_commitment ~ '^0x[0-9a-f]{64}$');

COMMENT ON COLUMN public.anchor_batches.batch_operation_id_version IS
  'How batch_operation_id was derived (RB4-F66): v2 commits to every member''s governance decision, v1 to operation ids alone. NULL on a row rebuilt from the chain.';
COMMENT ON COLUMN public.batch_transactions.operation_id IS
  'The member''s operation id (the Accumulate 4-blob intent hash), 0x-hex (RB4-F66).';
COMMENT ON COLUMN public.batch_transactions.governance_commitment IS
  'The member''s commitment to who decided it - keccak of its governance decision record - 0x-hex; NULL for a member of a v1 batch (RB4-F66).';
