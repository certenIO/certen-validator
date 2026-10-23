#!/usr/bin/env bash
# RB12-CAPTURE-GAP: READ-ONLY report of the finality capture store's coverage and of every recorded capture gap. Run it on the validator host
# (116.202.214.38) as a user who can use docker, before the deploy (it then shows the holes the old binary left: "runs without a captured
# block not yet audited") and after it (the audit records them, the backfill closes them):
#
#   bash rb12-capture-gaps.sh
#   ssh claude@host 'bash -s' < rb12-capture-gaps.sh        # from the orchestrator, nothing copied to the host
#   GAP_AUDIT_SPACING=40 bash rb12-capture-gaps.sh          # the spacing the validators audit with (default 40)
#
# READ-ONLY, by construction: every statement runs in BEGIN TRANSACTION READ ONLY with PGOPTIONS='-c default_transaction_read_only=on';
# no INSERT/UPDATE/DELETE/DDL exists in this file; psql runs INSIDE the postgres container over its local socket as that container's
# $POSTGRES_USER, so no password is read, printed or on a command line. Only block numbers, counts and item NAMES are printed - never a
# row's bytes (the notes of failed captures hold redacted provider text and are counted, not shown).
#
# The rows it reads (pkg/finality/gaps.go): gap/<to>/<class> at l1_block=<from>; gapfill/<block>; gapend/<block>/<kind>; gapnote/<block>/<class>.
#
# Exit status: 0 the store was read; 1 at least one run of blocks is open or unaudited (the numbers say how many; this is a REPORT, read the
# EXPECTED block at the bottom); 2 the database cannot be queried.
set -u

PGCONTAINER="${PGCONTAINER:-certen-postgres}"
PGDB="${PGDB:-certen_proofs}"
SPACING="${GAP_AUDIT_SPACING:-40}"
case "$SPACING" in ''|*[!0-9]*) SPACING=40 ;; esac
PSQL_LOCAL_URL="${PSQL_LOCAL_URL:-}"   # TEST MODE ONLY (a throwaway PG on the developer machine); on the host it is unset

sql() {  # sql [psql args] <<'SQL' ... SQL : the statements on stdin run in one READ ONLY transaction
  { echo 'BEGIN TRANSACTION READ ONLY;'; cat; echo 'ROLLBACK;'; } |
    if [ -n "$PSQL_LOCAL_URL" ]; then
      PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' psql -X -q -v ON_ERROR_STOP=1 -P pager=off "$@" "$PSQL_LOCAL_URL" 2>&1
    else
      docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' "$PGCONTAINER" \
        sh -c 'db=$1; shift; exec psql -U "$POSTGRES_USER" -d "$db" -X -q -v ON_ERROR_STOP=1 -P pager=off "$@"' _ "$PGDB" "$@" 2>&1
    fi
}
sqlat() { sql -At "$@"; }

if ! out=$(echo 'SELECT 1;' | sql); then
  echo "cannot query $PGDB in $PGCONTAINER (connection failure)"; printf '%s' "$out" | sed -E 's/(password|passwd)[^ ]*/<redacted>/Ig' | head -3
  exit 2
fi

echo "== capture coverage (proof_finality_capture)"
sql <<'SQL'
SELECT chain,
       count(DISTINCT l1_block) FILTER (WHERE item IN ('inbox') OR item LIKE 'batch/%') AS captured_blocks,
       min(l1_block) FILTER (WHERE item IN ('inbox') OR item LIKE 'batch/%')            AS first_captured,
       max(l1_block) FILTER (WHERE item IN ('inbox') OR item LIKE 'batch/%')            AS last_captured,
       min(l1_block) FILTER (WHERE item IN ('runtime/cursor', 'cursor'))                AS cursor_first,
       max(l1_block) FILTER (WHERE item IN ('runtime/cursor', 'cursor'))                AS cursor_last,
       max(created_at) FILTER (WHERE item IN ('runtime/cursor', 'cursor'))              AS cursor_written
  FROM proof_finality_capture WHERE chain IN (84532, 421614) GROUP BY 1 ORDER BY 1;
SQL

echo; echo "== recorded gap bookkeeping, rows by kind"
sql <<'SQL'
SELECT chain, split_part(item, '/', 1) AS kind, count(*) AS rows, min(l1_block) AS first_block, max(l1_block) AS last_block, max(created_at) AS newest
  FROM proof_finality_capture
 WHERE item LIKE 'gap/%' OR item LIKE 'gapfill/%' OR item LIKE 'gapend/%' OR item LIKE 'gapnote/%'
 GROUP BY 1, 2 ORDER BY 1, 2;
SQL

echo; echo "== gap rows by class (gap/<to>/<class>)"
sql <<'SQL'
SELECT chain, split_part(item, '/', 3) AS class, count(*) AS rows, sum(split_part(item, '/', 2)::bigint - l1_block + 1) AS block_span
  FROM proof_finality_capture WHERE item LIKE 'gap/%' GROUP BY 1, 2 ORDER BY 1, 2;
SQL

# the state of every gap block: open (no fill, no end), unavailable_proven / retention_expired (an end and no fill); a fill closes it
STATE_CTE="
WITH g AS (SELECT chain, l1_block AS f, split_part(item, '/', 2)::bigint AS t FROM proof_finality_capture WHERE item LIKE 'gap/%'),
     b AS (SELECT DISTINCT chain, generate_series(f, t) AS blk FROM g),
     fl AS (SELECT DISTINCT chain, l1_block AS blk FROM proof_finality_capture WHERE item LIKE 'gapfill/%'),
     en AS (SELECT chain, l1_block AS blk, max(split_part(item, '/', 3)) AS kind FROM proof_finality_capture WHERE item LIKE 'gapend/%' GROUP BY 1, 2),
     s AS (SELECT b.chain, b.blk, COALESCE(en.kind, 'open') AS state FROM b LEFT JOIN fl USING (chain, blk) LEFT JOIN en USING (chain, blk) WHERE fl.blk IS NULL),
     i AS (SELECT chain, blk, state, blk - row_number() OVER (PARTITION BY chain, state ORDER BY blk) AS grp FROM s)"

echo; echo "== gap blocks not closed, as runs (state: open | unavailable_proven | retention_expired), first 60"
sql <<SQL
$STATE_CTE
SELECT chain, state, min(blk) AS from_block, max(blk) AS to_block, count(*) AS blocks
  FROM i GROUP BY chain, state, grp ORDER BY chain, from_block LIMIT 60;
SQL
OPEN=$(sqlat <<SQL
$STATE_CTE
SELECT count(*) FROM s WHERE state = 'open';
SQL
)
PROVEN=$(sqlat <<SQL
$STATE_CTE
SELECT count(*) FROM s WHERE state <> 'open';
SQL
)

echo; echo "== runs of more than $SPACING blocks between two captured Base inbox blocks that no gap row covers (the spacing audit records these on the first tick)"
sql <<SQL
WITH ib AS (SELECT DISTINCT l1_block AS blk FROM proof_finality_capture WHERE chain = 84532 AND item = 'inbox'),
     d  AS (SELECT blk AS a, lead(blk) OVER (ORDER BY blk) AS z FROM ib)
SELECT a AS captured_before, z AS captured_after, z - a - 1 AS uncaptured_blocks
  FROM d WHERE z - a > $SPACING
   AND NOT EXISTS (SELECT 1 FROM proof_finality_capture g
                    WHERE g.chain = 84532 AND g.item LIKE 'gap/%' AND g.l1_block <= a + 1 AND split_part(g.item, '/', 2)::bigint >= z - 1)
 ORDER BY a DESC LIMIT 20;
SQL
UNAUDITED=$(sqlat <<SQL
WITH ib AS (SELECT DISTINCT l1_block AS blk FROM proof_finality_capture WHERE chain = 84532 AND item = 'inbox'),
     d  AS (SELECT blk AS a, lead(blk) OVER (ORDER BY blk) AS z FROM ib)
SELECT count(*) FROM d WHERE z - a > $SPACING
   AND NOT EXISTS (SELECT 1 FROM proof_finality_capture g
                    WHERE g.chain = 84532 AND g.item LIKE 'gap/%' AND g.l1_block <= a + 1 AND split_part(g.item, '/', 2)::bigint >= z - 1);
SQL
)

echo; echo "== capture-store PREFIX windows (class capture_prefix: legs posted before the capture loop started; RB12-ARCHIVE-BACKFILL)"
echo "   positions and counts only: window, its blocks, filled, proven unavailable / past retention, open"
sql <<'SQL'
WITH w AS (SELECT chain, l1_block AS f, split_part(item, '/', 2)::bigint AS t FROM proof_finality_capture WHERE item LIKE 'gap/%/capture_prefix'),
     b AS (SELECT chain, f, t, generate_series(f, t) AS blk FROM w),
     fl AS (SELECT DISTINCT chain, l1_block AS blk FROM proof_finality_capture WHERE item LIKE 'gapfill/%'),
     en AS (SELECT chain, l1_block AS blk, max(split_part(item, '/', 3)) AS kind FROM proof_finality_capture WHERE item LIKE 'gapend/%' GROUP BY 1, 2)
SELECT b.chain, b.f AS window_from, b.t AS window_to, count(*) AS blocks,
       count(*) FILTER (WHERE fl.blk IS NOT NULL) AS filled,
       count(*) FILTER (WHERE fl.blk IS NULL AND en.kind IS NOT NULL) AS gone,
       count(*) FILTER (WHERE fl.blk IS NULL AND en.kind IS NULL) AS open
  FROM b LEFT JOIN fl USING (chain, blk) LEFT JOIN en USING (chain, blk)
 GROUP BY 1, 2, 3 ORDER BY 1, 2 LIMIT 60;
SQL
echo "   claims on prefix chunks (gapclaim rows, one per chunk and 10-minute period) beacon-slot evidence of ended blocks (gapslot rows) and the L1 ranges whose SequencerInbox logs a prefix scan read (gapscan rows, Arbitrum 421614):"
sql <<'SQL'
SELECT chain, split_part(item, '/', 1) AS kind, count(*) AS rows, min(l1_block) AS first_block, max(l1_block) AS last_block
  FROM proof_finality_capture WHERE item LIKE 'gapclaim/%' OR item LIKE 'gapslot/%' OR item LIKE 'gapscan/%' GROUP BY 1, 2 ORDER BY 1, 2;
SQL

for v in "$OPEN" "$PROVEN" "$UNAUDITED"; do
  case "$v" in
    ""|*[!0-9]*) echo; echo "RESULT: the counts could not be read (a query failed above)"; exit 2 ;;
  esac
done
echo; echo "RESULT: open gap blocks=$OPEN ended (proven unavailable or past retention)=$PROVEN unaudited runs=$UNAUDITED"
if [ "$OPEN" != "0" ] || [ "$UNAUDITED" != "0" ]; then exit 1; fi
exit 0

# ------------------------------------------------------------------------------------------------------------------------------
# EXPECTED
#
# BEFORE the RB12-CAPTURE-GAP deploy (the binary of 2026-10-23): no gap rows at all; "unaudited runs" lists the outage holes of the Base
#   capture: captured_before/captured_after 11975926/11976155, 11976373/11976446, 11976620/11977005 (228 + 72 + 384 = 684 uncaptured blocks).
#
# AFTER the deploy (non-consensus; the validators restart):
#   within one capture tick the spacing audit has recorded those three runs (gap rows of class spacing_unproven, rows by kind: gap = 3
#   per validator-independent key, the rows are identical so the store holds three); "unaudited runs" is then 0.
#   The gap backfill then scans them at CERTEN_FINALITY_GAPFILL_BLOCKS_PER_TICK blocks per tick (default 8 per 12 s, about 11 minutes for
#   684 blocks) and writes a gapfill row per scanned block (rows by kind: gapfill rises to 684 when every block is closed).
#   WITHOUT an archive provider (CERTEN_FINALITY_ARCHIVE_URLS) the ~80 inbox blocks of the holes cannot be proven (eth_getProof beyond the
#   providers' ~100-block window): they stay OPEN with class state_proof_unavailable notes (gapnote rows), the empty blocks close, and a
#   leg judged in the holes is the named state l1_capture_gap{gap_state=open}. With an archive provider that serves historic eth_getProof
#   (the public https://rpc.sepolia.ethpandaops.io answered it at every height on 2026-10-23) the open count goes to 0.
#   Blobs are retained ~18 days by the beacon nodes: the current holes expire about 2026-11-10; after that a still-open blob block becomes
#   retention_expired (an end row), never an open block for ever.
#   PREFIX windows (RB12-ARCHIVE-BACKFILL): each Base leg posted before the capture started asks for its window once (one gap row of class
#   capture_prefix per window; the 31 legs of 2026-10-23 are 26 windows, 7 merged runs, 41,316 blocks); the table above shows each window with
#   its filled / gone / open counts. A window with gone > 0 cannot complete from the default providers: its leg is l1_capture_gap
#   {gap_state=unavailable_proven, needs=blob_archive} until a blob archive (OD4) serves the block.
#   Arbitrum (421614) is gapless; its rows by kind show gap only for a batch found incomplete after a restart, and a gapfill when it completes.
#
# FAILURE: open gap blocks that do not decrease over an hour while no validator logs "gap backfill"; unaudited runs that stay above 0 after
#   a validator has run for a few ticks (the audit is not running: the gap loop is not registered or its chain is switched off); a
#   gapfill count that stops while open blocks remain and the logs show "memory budget" skips (raise CERTEN_FINALITY_MEMORY_BUDGET_BYTES).
