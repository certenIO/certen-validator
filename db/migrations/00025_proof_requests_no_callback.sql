-- The proof request callback was removed (RB7 Task 5, T5-4): the fulfiller POSTed an unsigned outcome to a caller-chosen
-- URL from every validator, which nobody used (0 of 483 live rows) and which any caller could aim at an internal address.
-- No row may carry a callback address again. The column stays for one release so that the two deploys are not coupled;
-- it is dropped later.
--
-- Expand-only for old binaries: they insert NULL (or a value this refuses, which is the point).
ALTER TABLE public.proof_requests ADD CONSTRAINT chk_no_callback_url CHECK (callback_url IS NULL);
