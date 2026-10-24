#!/usr/bin/env bash
# RB11 staged finality: READ-ONLY post-deploy check, run on the validator host (116.202.214.38) by a user who can use docker.
#
#   bash rb11-deploy-check.sh                       # last 30 minutes of the 7 validators' logs + the three finality tables
#   SINCE=2h bash rb11-deploy-check.sh              # a longer log window
#   ssh claude@host 'bash -s' < rb11-deploy-check.sh   # from the orchestrator, without copying anything to the host
#
# What it does (and nothing else):
#   (a) per validator container: counts of the named finality states in `docker logs --since $SINCE`; the finality_upgrader_disabled,
#       panic and light-client lines themselves, with every URL / user-info cut out by sed;
#   (b) SELECT-only queries on proof_finality_addenda, proof_finality_status, proof_finality_capture (and the migration history),
#       inside BEGIN TRANSACTION READ ONLY, with PGOPTIONS='-c default_transaction_read_only=on'. No INSERT/UPDATE/DELETE/DDL exists in
#       this file.
# The database password never appears: psql runs INSIDE the postgres container over its local socket as that container's
# $POSTGRES_USER (the pattern of the earlier read-only evidence scripts), so no password is read, printed or put on a command line.
#
# Exit status: 0 unless a panic line is found in a validator log or a validator container is missing (1), or the database cannot be queried (2). Everything else is
# REPORTED, not an exit code: read the EXPECTED block at the bottom.
set -u

SINCE="${SINCE:-30m}"
VALIDATORS="${VALIDATORS:-1 2 3 4 5 6 7}"
PGCONTAINER="${PGCONTAINER:-certen-postgres}"
PGDB="${PGDB:-certen_proofs}"
PSEUDO='ffffffff-ffff-4fff-8fff-%'      # CaptureStatusProofID(chain): the capture loops' rows in proof_finality_status

fail=0
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# every http(s) URL (and anything carrying user:pass@) becomes <url>; long lines are cut
strip() { sed -E 's#[a-zA-Z][a-zA-Z0-9+.-]*://[^[:space:]"'"'"')]*#<url>#g; s#[^[:space:]]*:[^[:space:]@/]*@[^[:space:]]*#<userinfo>#g' | cut -c1-400; }

echo "== (a) validator logs, last $SINCE"
printf '%-20s %-8s %-9s %-11s %-10s %-11s %-9s %-9s %-7s %-9s %-6s\n' container ENABLED DISABLED disabled_st lc_unavail pin_unknown restarts givenup handed gapfill PANIC
for n in $VALIDATORS; do
  c="certen-validator-$n"
  if ! docker inspect "$c" >/dev/null 2>&1; then echo "$c: container not found"; fail=1; continue; fi
  log="$tmp/$c.log"
  docker logs --since "$SINCE" "$c" >"$log" 2>&1
  cnt() { grep -Ec -- "$1" "$log"; }
  panics=$(grep -Eic -- 'panic|fatal error|goroutine [0-9]+ \[' "$log")
  printf '%-20s %-8s %-9s %-11s %-10s %-11s %-9s %-9s %-7s %-9s %-6s\n' "$c" \
    "$(cnt '\[FINALITY\] upgrader ENABLED')" "$(cnt '\[FINALITY\].*DISABLED')" "$(cnt 'finality_upgrader_disabled')" \
    "$(cnt 'finality_lc_unavailable')" "$(cnt 'finality_pin_unknown|pinned ledger has no anchor')" \
    "$(cnt 'capturer .* stopped')" "$(cnt 'given up at head')" "$(cnt 'handed to the gap backfill')" "$(cnt 'gap backfill .*(attempted|closed)')" "$panics"
  [ "$panics" -gt 0 ] && fail=1
done

for n in $VALIDATORS; do
  c="certen-validator-$n"; log="$tmp/$c.log"
  [ -s "$log" ] || continue
  echo; echo "-- $c: wiring and switches"
  grep -E '\[FINALITY\] (runtime wiring|upgrader (ENABLED|DISABLED)|chain [0-9]+ upgrader DISABLED|capturer .* DISABLED)' "$log" | strip | tail -8
  if grep -Eiq 'panic|fatal error|goroutine [0-9]+ \[' "$log"; then
    echo "-- $c: PANIC lines (this makes the exit status 1)"
    grep -Ei -m10 'panic|fatal error|goroutine [0-9]+ \[' "$log" | strip
  fi
  if grep -Eq 'finality_lc_unavailable|finality_pin_unknown|pinned ledger has no anchor|stopped:|given up at head|handed to the gap backfill|recorded as capture gap|gap backfill|has no registered prover|does not verify' "$log"; then
    echo "-- $c: named states / faults (last 6)"
    grep -E 'finality_lc_unavailable|finality_pin_unknown|pinned ledger has no anchor|stopped:|given up at head|handed to the gap backfill|recorded as capture gap|gap backfill|has no registered prover|does not verify' "$log" | strip | tail -6
  fi
  echo "-- $c: appended in this window: $(grep -Ec '\[FINALITY\] leg .* reached ' "$log")"
done

echo; echo "== (b) database (read-only), $PGCONTAINER / $PGDB"
sql() {  # sql <<'SQL' ... SQL  : the statements on stdin run in one READ ONLY transaction
  { echo 'BEGIN TRANSACTION READ ONLY;'; cat; echo 'ROLLBACK;'; } |
    docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on' "$PGCONTAINER" \
      sh -c 'psql -U "$POSTGRES_USER" -d "$1" -X -q -v ON_ERROR_STOP=1 -P pager=off' _ "$PGDB" 2>&1
}
if ! out=$(echo 'SELECT 1;' | sql); then
  echo "cannot query $PGDB in $PGCONTAINER (connection failure)"; printf '%s' "$out" | sed -E 's/(password|passwd)[^ ]*/<redacted>/Ig' | strip | head -3
  exit 2
fi

echo; echo "-- migrations 00027 / 00028 applied (certen_schema_history)"
sql <<'SQL'
SELECT version, name, applied_at, applied_by FROM public.certen_schema_history WHERE version >= '00027' ORDER BY version;
SQL

echo; echo "-- addenda by chain and level (proof_finality_addenda)"
sql <<'SQL'
SELECT chain, level, kind, count(*) AS addenda, max(created_at) AS newest
  FROM proof_finality_addenda GROUP BY 1,2,3 ORDER BY 1,2,3;
SQL

echo; echo "-- builder status by chain / target level / named state (proof_finality_status, legs only)"
sql <<SQL
SELECT chain, target_level, COALESCE(state->'state'->>'code', '-') AS code, state->>'class' AS class, count(*) AS rows, max(judged_at) AS newest
  FROM proof_finality_status WHERE proof_id::text NOT LIKE '$PSEUDO'
 GROUP BY 1,2,3,4 ORDER BY 1,2,3,4;
SQL

echo; echo "-- capture loops' own named states (proof_finality_status under the pseudo proof ids $PSEUDO)"
sql <<SQL
SELECT chain, target_level, state->'state'->>'code' AS code, state->>'class' AS class, judged_at,
       left((state->'state'->'fields')::text, 200) AS fields
  FROM proof_finality_status WHERE proof_id::text LIKE '$PSEUDO' ORDER BY chain, target_level;
SQL

echo; echo "-- captured L1 bytes (proof_finality_capture; insert-only, never deleted)"
sql <<'SQL'
-- the LIVE capture loops' rows: the legacy-header rows (RB12-LEGACY-191, item legacyleg/header) are keyed by the rollup's OWN block number
-- and are written by a reconstruction that finishes within ~15 minutes of a deploy, so they are left out here: counted with them, max_l1_block
-- of chains 84532 / 421614 would read 46.4M / 313.9M and rows_last_30m would be > 0 even with a dead capture loop.
SELECT chain, count(*) AS rows, max(l1_block) AS max_l1_block, pg_size_pretty(sum(octet_length(bytes))::bigint) AS bytes,
       count(*) FILTER (WHERE created_at > now() - interval '30 minutes') AS rows_last_30m, max(created_at) AS newest
  FROM proof_finality_capture WHERE item <> 'legacyleg/header' GROUP BY 1 ORDER BY 1;
-- the reconstructed headers of legacy legs, apart (insert-only; 191 in all once reconstruction has finished: Base 119, Sepolia 65, Arbitrum 7)
SELECT chain, count(*) AS legacy_header_rows, min(l1_block) AS min_block, max(l1_block) AS max_block, max(created_at) AS newest
  FROM proof_finality_capture WHERE item = 'legacyleg/header' GROUP BY 1 ORDER BY 1;
SELECT chain, max(l1_block) AS cursor_block, max(created_at) AS cursor_written
  FROM proof_finality_capture WHERE item IN ('runtime/cursor', 'cursor') GROUP BY 1 ORDER BY 1;
SQL

echo; echo "-- capture gaps (RB12-CAPTURE-GAP; the full report is rb12-capture-gaps.sh): rows by kind, and the blocks still open"
sql <<'SQL'
SELECT chain, split_part(item, '/', 1) AS kind, count(*) AS rows, min(l1_block) AS first_block, max(l1_block) AS last_block
  FROM proof_finality_capture
 WHERE item LIKE 'gap/%' OR item LIKE 'gapfill/%' OR item LIKE 'gapend/%' OR item LIKE 'gapnote/%'
 GROUP BY 1, 2 ORDER BY 1, 2;
SELECT chain, count(*) AS gap_rows, sum(split_part(item, '/', 2)::bigint - l1_block + 1) AS gap_block_span
  FROM proof_finality_capture WHERE item LIKE 'gap/%' GROUP BY 1 ORDER BY 1;
SQL

echo; [ "$fail" -eq 0 ] && echo "RESULT: no panic line in the last $SINCE; read the tables above against the EXPECTED block" || echo "RESULT: FAIL - a panic line (or a missing container) was found; see above"
exit "$fail"

# ------------------------------------------------------------------------------------------------------------------------------
# EXPECTED (healthy deploy of this branch; first column of each block is what the script prints)
#
# (a) Logs, last 30 minutes, each of the 7 validators after its restart:
#     ENABLED = 1, DISABLED = 0, disabled_st = 0 (all four chains are on; a nonzero count is a switch or a missing provider setting,
#     named in env), PANIC = 0, restarts = 0, givenup = 0 (the capture loop never gives a block up any more: a 'given up at head' line
#     means a validator still runs the OLD binary), handed = the blocks older than the provider window that the capture loop handed to the
#     gap backfill (0 in a healthy hour; > 0 after an outage, each is an open capture gap, see rb12-capture-gaps.sh), gapfill = the backfill
#     ticks that attempted or closed blocks (> 0 while a gap is open, 0 when none is).
#     pin_unknown = 0 and lc_unavail = 0: the embedded Sepolia ledger carries the root pin (period 1378), so every LC-based kind anchors
#     there. pin_unknown > 0 is a FAILURE (the embedded ledger or its root pin was lost, or CERTEN_FINALITY_PINS_FILE overrides it).
#     lc_unavail > 0 means every light-client endpoint failed (CERTEN_FINALITY_LC_URLS): a warning, the legs keep 'included' and retry.
#     The wiring line reads: runtime wiring: pins_source=embedded pins_sha256=12217758b3a8... chains_off_by_configuration=[]
#     (a chain listed here for any other reason, or a finality_upgrader_disabled whose env names BASE_SEPOLIA_RPC_URL /
#     ARBITRUM_SEPOLIA_RPC_URL / CERTEN_FINALITY_*, is a configuration that went missing: FIX BEFORE ANYTHING ELSE).
#
# (b) Tables:
#     certen_schema_history: 00027 and 00028 present.
#     proof_finality_addenda: chain 2017 level 3 (adiri/finalized/v1) rows appear within one Adiri epoch (<= 6 h) of the deploy, one per
#       settled Adiri leg. After ~30 min, once the finalized head covers a leg: chain 11155111 level 3 (eth-sepolia/finalized/v1, 13 to 19 min
#       after inclusion; a 4.6k-header spine takes about 3 min on the public Sepolia RPC) and chains 84532 / 421614 level 2 (l1_posted,
#       about 17 to 21 min after a leg). Arbitrum finalized follows at about 65 to 110 min, Base finalized at about 5 days + 15 min.
#     proof_finality_status (legs): codes finality_pending (awaiting_*; Sepolia: the block-not-yet-covered reason until the finalized head
#       passes the leg) and 'verified' rows ('-' code, class verified). The CLASS of a row and its CODE are different things; do not read one as
#       the other:
#       - class 'refused' = evidence was BUILT and the registered Kind refused it (nothing stored); the code is that Kind's own named refusal
#         (finality_verifier_failed is one of them). Any class 'refused' row for an honest leg is a bug to report.
#       - code finality_verifier_failed, whatever its class, means evidence was built and failed verification: a bug to report. A builder error
#         that carries no name of its own (a capture row that vanished, a database or provider error) is class 'unavailable' with the code
#         finality_builder_error{stage=build|append}, never finality_verifier_failed.
#       - class 'unavailable' = the builder could not obtain or build what it needs: l1_proof_window_unavailable / batcher_state_unavailable /
#         l1_blob_unavailable (a missed provider window; OD4 removes the usual cause), l1_capture_not_covering (a leg older than the capture,
#         decided at once with the block it was judged at), finality_game_source_unavailable / finality_covering_game_unavailable,
#         finality_build_timeout (each failed ask carries attempt and next_attempt_at), finality_builder_error.
#       - class 'pending' with code finality_memory_budget_exceeded (next_attempt_at, eta, no attempt) = the process memory budget held the
#         build; the leg is asked again at the pending interval and nothing failed. Many of these with certen_finality_memory_refused_total
#         rising is a budget (CERTEN_FINALITY_MEMORY_BUDGET_BYTES) or concurrency question, not a defect of a leg.
#     capture pseudo rows: none in a healthy first hour; a row there is a capture loop's named unavailability state (see the deploy guide, 3.2).
#     proof_finality_capture (live capture rows only; the legacyleg/header rows are the separate legacy_header_rows table below it, growing to 119 / 65 / 7
#       rows on 84532 / 11155111 / 421614 within about 15 minutes of the deploy and then still): chain 84532 and 421614 rows_last_30m > 0 whenever those chains posted batches in the window (Base posts about
#       every few minutes, Arbitrum batches likewise), and the cursor block within about 60 L1 blocks of the Sepolia head.
#
# FAILURE (investigate now): any panic line; any "stored addendum chain does not verify" (certen_finality_chain_broken_total); capture
#   rows with no growth (rows_last_30m = 0 on a chain that settles) or a cursor that does not move; finality_upgrader_disabled for a chain
#   that should be on; any finality_pin_unknown (embedded ledger lost); finality_build_timeout repeating on chain 11155111 (public Sepolia
#   RPC too slow: raise CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS to 600 or provide ETHEREUM_SEPOLIA_RPC_URL); capturer restarts > 0 repeating; the migrations missing from certen_schema_history (the validators would not have
#   started).
