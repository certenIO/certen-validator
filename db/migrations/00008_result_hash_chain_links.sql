-- Result hash chain links of results that have no chain-execution row.
--
-- Each validator's result hash chain, per target chain, links every result it writes back: sequence
-- numbers are consecutive and each link names its predecessor's chain_result_hash (00004). A settlement's
-- link lives on its chain_execution_results row. A member that never settled (RB3-F49) has no
-- transaction and so no such row, yet its attested result takes the next place in the same chain. Its
-- link was never persisted: after a restart the chain continued from the last settlement and repeated the
-- sequence numbers the non-settlements had used (RB3-F80). Such links are kept here; the head and the
-- continuity check read both tables.
--
-- Expand-only: one new table.

CREATE TABLE public.result_hash_chain_links (
    observer_validator_id character varying(255) NOT NULL,
    chain_id character varying(64) NOT NULL,
    sequence_number bigint NOT NULL,
    previous_result_hash bytea NOT NULL,
    chain_result_hash bytea NOT NULL,
    anchor_proof_hash bytea,
    cycle_id character varying(255) NOT NULL,
    kind character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT result_hash_chain_links_pkey PRIMARY KEY (observer_validator_id, chain_id, sequence_number),
    CONSTRAINT result_hash_chain_links_kind CHECK (((kind)::text = 'non_settlement'::text))
);

COMMENT ON TABLE public.result_hash_chain_links IS
  'Result hash chain links of results with no chain_execution_results row (a non-settlement has no transaction). '
  'Together with chain_execution_results.sequence_number they are each validator''s complete chain per target chain.';
