-- Consensus persistence moves off the ABCI Commit path.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT WAS WRONG
--
--  ABCI Commit rewrote EVERY ValidatorBlock in the node's in-memory cache (up to 1000) into
--  consensus_entries and batch_attestations on every block, then ran one anchor_batches lookup per
--  cached block by a governance merkle root that can never equal a batch root. Measured on the testnet
--  fleet, 2026-09-15: ~350 cached blocks, 44 ms per unmatched lookup (full walk of 71,067 rows), 0 of 231
--  lookups matched in three days, Commit 14-16 s per block.
--
--  CometBFT holds the mempool lock and serialises CheckTx with Commit, and its RPC write timeout is
--  timeout_broadcast_tx_commit + 1 s = 11 s. Every BroadcastTxSync that overlapped a commit answered EOF,
--  validators marked committed ValidatorBlocks as failed, quorum never formed, and intents sat in
--  `anchoring`.
--
--  The rewrite was also destructive: ON CONFLICT DO UPDATE reset state, completed_at, aggregates and
--  result_json on every commit, undoing MarkConsensusQuorumMet and the attestation verification flags.
--
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────
--  WHAT THIS TABLE IS
--
--  Commit now hands only the ValidatorBlocks of the block being committed to a background writer, which
--  inserts them once (ON CONFLICT DO NOTHING) and records here, in the same transaction, the highest
--  CometBFT height it has persisted. The rows are a pure function of the committed block, so a writer that
--  restarts, falls behind, or drops a hand-off rebuilds the missing heights from the block store and
--  resumes from this watermark.
--
--  One row per writer: the validators may share this database, and each tracks its own progress.
-- ─────────────────────────────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS consensus_persistence_progress (
    writer_id           VARCHAR(256) PRIMARY KEY,
    persisted_height    BIGINT NOT NULL CHECK (persisted_height >= 0),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations (version, description, applied_at)
VALUES ('017_consensus_persistence_progress',
        'Track each writer''s persisted CometBFT height so consensus persistence runs off the Commit path',
        NOW())
ON CONFLICT (version) DO NOTHING;
