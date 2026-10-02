-- CERTEN's per-intent quorum certificates (RB5 owner decision D3).
--
-- Once a BLS registry is in force on the CERTEN chain, every ValidatorBlock carries its validator's BLS signature
-- over the per-intent message - the operation, govRoot v2 over the proof's L1-L4 and canonical G0-G2, the Accumulate
-- validator set its L4 was verified against under the incarnation, the governance commitment, and CERTEN's set root,
-- on that CERTEN chain - and consensus verifies it. When the committed signatures over one operation's message reach
-- the registry's threshold, the chain records their aggregate: the quorum certificate. This table keeps it with
-- everything needed to check it offline:
--   operation_id      the operation, 0x-hex; one certificate per operation (an honest validator signs one block per
--                     operation, so two quorums over different messages cannot both form)
--   message           the certified intent message, 0x-hex
--   registry_version  the BLS registry the signatures were judged under
--   certen_chain_id   the CERTEN chain the message binds
--   certificate       the aggregate signature, the aggregate of the signers' registered keys, the signers, and the
--                     power that signed out of the registry's (ledger.IntentQuorumCertificate)
--   registry          the registry record itself: members, keys, powers, threshold, CERTEN set root, incarnation
--   message_inputs    the inputs the message was computed from (govRoot v2, Accumulate set root, governance
--                     commitment, key page and key book), so a verifier recomputes each one from the stored proof
--   certified_height  the CERTEN block whose commit completed the quorum
--
-- Expand-only: one new table. A row is written once; a second write must carry the same certificate.

CREATE TABLE public.intent_quorum_certificates (
    operation_id     character varying(66) PRIMARY KEY
        CONSTRAINT intent_qc_operation_is_hex CHECK (operation_id ~ '^0x[0-9a-f]{64}$'),
    message          character varying(66) NOT NULL
        CONSTRAINT intent_qc_message_is_hex CHECK (message ~ '^0x[0-9a-f]{64}$'),
    registry_version bigint NOT NULL
        CONSTRAINT intent_qc_registry_version_is_positive CHECK (registry_version > 0),
    certen_chain_id  text NOT NULL
        CONSTRAINT intent_qc_chain_is_named CHECK (certen_chain_id <> ''),
    certificate      jsonb NOT NULL,
    registry         jsonb NOT NULL,
    message_inputs   jsonb NOT NULL,
    certified_height bigint NOT NULL
        CONSTRAINT intent_qc_height_is_positive CHECK (certified_height > 0),
    created_at       timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.intent_quorum_certificates IS
  'CERTEN''s quorum certificate over each operation''s intent message (RB5 D3): the aggregate of the committed ValidatorBlocks'' signatures once their signers held the BLS registry''s threshold, with the registry and the message''s inputs, for offline verification.';
