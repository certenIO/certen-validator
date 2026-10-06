-- schema: no-transaction
-- The proofs_service completed-requests feed (GET /api/v1/proofs/requests/completed) pages proof_requests in an ending
-- status in (completed_at, request_id) order from a cursor; this partial index serves that order and the cursor's row
-- comparison. Its predicate is the feed's status filter, so it holds only ended requests (RB7 Task 5).
--
-- Non-transactional so the index is built CONCURRENTLY, one statement for the reason given in 00023, and no IF NOT
-- EXISTS for the same reason.
--
-- Expand-only: one new index.
CREATE INDEX CONCURRENTLY idx_requests_terminal_feed ON public.proof_requests USING btree (completed_at, request_id) WHERE ((status)::text = ANY ((ARRAY['completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[]));
