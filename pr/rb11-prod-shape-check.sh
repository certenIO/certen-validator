#!/usr/bin/env bash
# RB11 PRODUCTION-SHAPE check: READ-ONLY comparison of every data-shape assumption of the RB11 code (validator, proofs_service,
# api-gateway) with the LIVE database and the live validator containers. Run it on the validator host (116.202.214.38) as a user who
# can use docker, BEFORE any RB11 merge/deploy and again after:
#
#   bash rb11-prod-shape-check.sh
#   ssh claude@host 'bash -s' < rb11-prod-shape-check.sh        # from the orchestrator, nothing copied to the host
#   SAMPLE=10 bash rb11-prod-shape-check.sh                     # fewer bundles (default and maximum: 20)
#   bash rb11-prod-shape-check.sh --selftest-migrations db/migrations   # offline: embedded checksums == the repo's migration files
#
# WHY IT EXISTS (2026-10-23): the RB11 leg source read proof_artifacts.artifact_json #> '{proof_components,...}', but production's
# artifact_json is only the cycle summary; the full bundle is gzip(JSON) in proof_bundles.bundle_data. The tests had seeded the shape
# their author assumed, so a blocker survived until someone looked at the live database. This script is that look, made repeatable:
# one numbered check per assumption, each with PASS / WARN / FAIL, the expected shape and the observed shape.
#
# READ-ONLY, by construction: every statement runs through sqlro() in BEGIN TRANSACTION READ ONLY with PGOPTIONS
# '-c default_transaction_read_only=on'; no INSERT/UPDATE/DELETE/DDL and no temp table exists in this file; psql runs INSIDE the
# postgres container over its local socket as that container's $POSTGRES_USER, so no password is read, printed or on a command line.
# Bundles are decompressed on the HOST (base64 + gzip, 16 MiB bound) and handed back to the database only as the literal of a
# SELECT, to be examined as jsonb. NOTHING of a bundle is printed: only key names, JSON types, lengths and counts. Provider/env
# VALUES are never printed: container variables are reported as set / empty / unset (switches as on / off / other).
#
# Result vocabulary: PASS (the assumption holds on all the data examined); FAIL (live data contradicts what the code reads: fix the
# code or the data before deploy); WARN (the code names the state - e.g. finality_included_unavailable - but the live data will put
# legs into it, or the data examined is too thin to say: read the numbers). NOT-CHECKED lines state what could not be examined here.
#
# Exit status: 0 no FAIL; 1 at least one FAIL; 2 the database cannot be queried.
set -u

PGCONTAINER="${PGCONTAINER:-certen-postgres}"
PGDB="${PGDB:-certen_proofs}"
VALIDATORS="${VALIDATORS:-1 2 3 4 5 6 7}"
SAMPLE="${SAMPLE:-20}"
HEALTH_URL="${HEALTH_URL:-http://localhost:8080/health/detailed}"
PSQL_LOCAL_URL="${PSQL_LOCAL_URL:-}"   # TEST MODE ONLY (a throwaway PG on the developer machine); on the host it is unset
MAX_JSON=$((16 * 1024 * 1024))         # decompressed bundle bound, same as the validator's maxBundleJSON
MAX_GZ=$((12 * 1024 * 1024))           # compressed bundle bound for sampling
case "$SAMPLE" in ''|*[!0-9]*) SAMPLE=20 ;; esac
[ "$SAMPLE" -gt 20 ] && SAMPLE=20
[ "$SAMPLE" -lt 1 ] && SAMPLE=1

# The supported chains of the S7 table (pkg/finality/table.go): Sepolia, Base Sepolia, Arbitrum Sepolia, Adiri.
CHAINS_SQL="11155111,84532,421614,2017"

# ---- migration checksums: certen-validator db/migrations at pv2/rb12-train2 (00000-00028 as at pv2/rb11-int, == the proofs_service RequiredSchema pins for 00000-00014, 00026-00028; 00029 = the dbfix own-hash guard, RB12-GO-INT)
MIGRATION_SHA='
00000 dacf9261f48333444c3657532a575ae02ed583fe57f516aef7af3e26cd7c6a14
00001 ed6ddda58c77649769ecff8ca5bbc555ab36e93118106339155b48c1443028c6
00002 866449e035d3abb02d988dcfccbebc9d5f78f70f4e959772fe3721306d15b84f
00003 a503d870c7cdb51b41842a6411b41571946c26d62b193577a884968861787f42
00004 9390982904822660f722ed9d92559f2aa16d65c5c08f69296d602922b60b075d
00005 9c1db5f90d9db35b7193b53acd2a439f70557b37aa503ae5e40a8a52a7d5f37e
00006 272898b7365cc3164882877526669a2f9e4507178c6f522a5e23e216ae3bc5bf
00007 9fa7551b0173f6a20ede031c5b6bbf6fdd4ac0c5bacc9b86882874f032791de2
00008 5e46535de7cb1c5be2c201cdbed03edd0876dee6f082b5ae19af3965139e057e
00009 4cd5bc35183e4b5b93642fea2ee5f2a672e393620dcdeae3b4c99c6129edeec1
00010 5b519f1c5ef92e99939a444e74d81d2346d63a9b682c977a630dba2f04656b82
00011 c3ee3fee5ccfa70c48b8f2b08e366c14115c5aadb079d09c87fa7330b4611eca
00012 d36f9f1c4f342d413157e9dcbc90f2f815dffc7393a73a6c20b7706fbf6d57ec
00013 38d31ffa49dec830d79272c9a38962539ecdb00314581c4b32011901a78dd2d1
00014 490c05b0486492537eb72308599cf390cca561c0a65da4924625fdf292058e2f
00015 7a14e512a9637e8b8825401a1dbc18145e277f75b7309cb09837c1ef5067cad1
00016 6c5a1baee7698278a2088cb8a1f925e9c6a1fed76eac33526a1c8ef0d7f6a0dd
00017 2f7a7f549bb93ccb7c5712cb39d7d364b2cc354f4e0bceb044c93bf13e7aa8b9
00018 fc5e517e8c573ddb60c43e1f44eede4f72c070a6c94bc4e321f6bd892f0ff0f7
00019 f17da32e7b5f05cdbe958d9c6f99ef0cc59c4731baa85b181df1035d4e652afc
00020 4e6443c44ec646b24435ad7d178c7fbbe2ab348d1f05fe1997b1ed52139b0428
00021 407256abc9f72b516c06e82c65530101e05d5761b3b8c9ebe67a62db5013859e
00022 f496a1a4b26c593ee2517e79071370042a061ae3bfd67a88588ed1da72ac3fe7
00023 0d50c3c255d1edddb4556e2a06717537e5b6ecaf07488bf90830d26e0d7e5659
00024 9b64ff670430595eab0342082c826cd94e38e82bc6fe1b6e185980d68c0f8297
00025 8c8e2bb2f9032b0ca20cba79fe26b672fde894b5e1cadd452fbfe66e495dd0cc
00026 3c8aab92e4d5bede91b245121f18e7f29459f987e816237d1ce4c0b0357324f8
00027 33111ed2735c8af9581bf4502f422935c1131589f47a9e31b8b874301cfe7d63
00028 759cfbda9571a7a1063a4034fcf7502ce94210800ed49eb53e4e5992ab8b81c5
00029 2cc377c51c1b1269c8173e850e011646a16a7adb6a49945451fb199b1a63b533
'

if [ "${1:-}" = "--selftest-migrations" ]; then
  dir="${2:-db/migrations}"; bad=0; n=0
  while read -r v sum; do
    [ -n "$v" ] || continue
    f=$(ls "$dir"/"$v"_*.sql 2>/dev/null | head -1)
    if [ -z "$f" ]; then echo "selftest: no file for $v in $dir"; bad=1; continue; fi
    got=$(sha256sum "$f" | cut -d' ' -f1); n=$((n + 1))
    [ "$got" = "$sum" ] || { echo "selftest: $v embedded $sum, file $got"; bad=1; }
  done <<EOF
$MIGRATION_SHA
EOF
  extra=$(ls "$dir"/*.sql 2>/dev/null | wc -l)
  [ "$extra" -eq "$n" ] || { echo "selftest: $extra migration files, $n embedded"; bad=1; }
  [ "$bad" -eq 0 ] && echo "selftest ok: $n migrations"
  exit "$bad"
fi

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
ERRF="$tmp/psql.err"

# ------------------------------------------------------------------------------------------------------------------------------
# database access (the only way this file talks to the database)
# ------------------------------------------------------------------------------------------------------------------------------
# sqlro [psql args...] : SQL on stdin, one READ ONLY transaction, tuples-only unaligned '|' rows on stdout, stderr in $ERRF.
sqlro_raw() {
  { echo 'BEGIN TRANSACTION READ ONLY;'; cat; echo 'ROLLBACK;'; } |
    if [ -n "$PSQL_LOCAL_URL" ]; then
      PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' psql -X -q -At -F '|' -v ON_ERROR_STOP=1 -P pager=off "$@" "$PSQL_LOCAL_URL" 2>"$ERRF"
    else
      docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' "$PGCONTAINER" \
        sh -c 'db=$1; shift; exec psql -U "$POSTGRES_USER" -d "$db" -X -q -At -F "|" -v ON_ERROR_STOP=1 -P pager=off "$@"' _ "$PGDB" "$@" 2>"$ERRF"
    fi
}
# sqlro : sqlro_raw with the CR a Windows psql (test mode) writes dropped; the subshell keeps pipefail local, so psql's failure is the status
sqlro() { ( set -o pipefail; sqlro_raw "$@" | tr -d '\r' ); }
# the first ERROR line only (never DETAIL/LINE/STATEMENT context, which can echo data), cut and with credentials-looking text removed
errline() { grep -m1 -E '^(ERROR|FATAL|psql|Error)' "$ERRF" 2>/dev/null | sed -E 's/(password|passwd)[^ ]*/<redacted>/Ig' | cut -c1-160; }

# ------------------------------------------------------------------------------------------------------------------------------
# result bookkeeping
# ------------------------------------------------------------------------------------------------------------------------------
NCHK=0; NPASS=0; NWARN=0; NFAIL=0; NNC=0; FAILIDS=""; WARNIDS=""; NCIDS=""
# rec <PASS|WARN|FAIL|NOT-CHECKED> <id> <title> <expected> <observed>
rec() {
  local st="$1" id="$2" title="$3" exp="$4" obs="$5"
  NCHK=$((NCHK + 1))
  case "$st" in
    PASS) NPASS=$((NPASS + 1)) ;;
    WARN) NWARN=$((NWARN + 1)); WARNIDS="$WARNIDS $id" ;;
    FAIL) NFAIL=$((NFAIL + 1)); FAILIDS="$FAILIDS $id" ;;
    *) NNC=$((NNC + 1)); NCIDS="$NCIDS $id" ;;
  esac
  printf '%03d [%-11s] %-4s %s\n' "$NCHK" "$st" "$id" "$title"
  printf '        expected: %s\n        observed: %s\n' "$exp" "$obs"
}
info() { printf '        info: %s\n' "$*"; }
section() { echo; echo "== $*"; }

# scalar <SQL> : prints the first column of the first row; returns 1 (and sets QERR) when the query fails
scalar() { local out; if out=$(printf '%s\n' "$1" | sqlro); then printf '%s' "$out" | head -1; return 0; fi; QERR=$(errline); return 1; }
QERR=""

section "0. connection"
if ! out=$(echo 'SELECT current_setting($$server_version_num$$)::int, current_database()::text;' | sqlro); then
  echo "cannot query $PGDB in ${PGCONTAINER} (connection failure): $(errline)"; exit 2
fi
PGVERNUM=${out%%|*}; DBNAME=${out#*|}
echo "database $DBNAME, server_version_num $PGVERNUM; read-only transaction; SAMPLE=$SAMPLE"

# ==============================================================================================================================
# (a) every table and column the RB11 SQL names exists with a compatible type
# ==============================================================================================================================
section "(a) schema: tables, columns, types, constraints, privileges"
COLS='
proof_artifacts.proof_id|uuid
proof_artifacts.artifact_json|jsonb
proof_artifacts.settlement_block_number|bigint
proof_artifacts.settlement_tx_hash|character varying
proof_artifacts.created_at|timestamp with time zone
proof_artifacts.intent_id|character varying|text
proof_artifacts.accum_tx_hash|character varying
proof_artifacts.target_chain|character varying
proof_artifacts.chain_platform|character varying
proof_artifacts.leg_id|uuid
proof_artifacts.multi_leg_intent_id|character varying
proof_artifacts.proof_type|character varying
proof_bundles.bundle_id|uuid
proof_bundles.proof_id|uuid
proof_bundles.bundle_format|character varying
proof_bundles.bundle_data|bytea
proof_bundles.bundle_size_bytes|integer
proof_bundles.created_at|timestamp with time zone
chain_execution_results.proof_id|uuid
chain_execution_results.chain_id|character varying
chain_execution_results.tx_hash|character varying
chain_execution_results.block_number|bigint
chain_execution_results.block_hash|character varying
chain_execution_results.chain_platform|character varying
intent_legs.leg_id|uuid
intent_legs.proof_id|uuid
intent_legs.intent_id|character varying
intent_legs.chain_id|bigint
intent_legs.execution_tx_hash|character varying
proof_finality_addenda.proof_id|uuid
proof_finality_addenda.seq|bigint
proof_finality_addenda.level|smallint
proof_finality_addenda.chain|bigint
proof_finality_addenda.kind|character varying
proof_finality_addenda.evidence|bytea
proof_finality_addenda.prev_hash|bytea
proof_finality_addenda.own_hash|bytea
proof_finality_addenda.created_at|timestamp with time zone
proof_finality_status.proof_id|uuid
proof_finality_status.chain|bigint
proof_finality_status.target_level|smallint
proof_finality_status.state|jsonb
proof_finality_status.judged_at|timestamp with time zone
proof_finality_capture.chain|bigint
proof_finality_capture.l1_block|bigint
proof_finality_capture.l1_hash|bytea
proof_finality_capture.item|character varying
proof_finality_capture.bytes|bytea
proof_finality_capture.created_at|timestamp with time zone
proof_v2_portable.intent_id|character varying
proof_v2_portable.document|text
proof_v2_portable.majors|integer
proof_v2_portable.govroot_v3_inputs|text
proof_v2_spine_json.major_index|bigint
proof_v2_spine_json.record|text
proof_v2_spine.major_index|bigint
proof_v2_spine.record|bytea
certen_schema_history.version|character varying
certen_schema_history.name|text
certen_schema_history.sha256|character|character varying|text
certen_schema_history.applied_at|timestamp with time zone
certen_schema_history.applied_by|text
'
vals=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  tc=${line%%|*}; ty=${line#*|}
  vals="${vals:+$vals,}('${tc%%.*}','${tc#*.}','$ty')"
done <<EOF
$COLS
EOF
nwant=$(printf '%s\n' "$COLS" | grep -c '|')
if out=$(sqlro <<SQL
WITH want(t,c,ty) AS (VALUES $vals)
SELECT w.t||'.'||w.c, w.ty, COALESCE(i.data_type, 'MISSING')
  FROM want w LEFT JOIN information_schema.columns i
    ON i.table_schema='public' AND i.table_name=w.t AND i.column_name=w.c
 WHERE i.data_type IS NULL OR NOT (i.data_type = ANY(string_to_array(w.ty,'|')))
 ORDER BY 1;
SQL
); then
  if [ -z "$out" ]; then
    rec PASS A1 "every table.column the RB11 SQL of the three repos names exists with a compatible type" "$nwant columns present, types as listed in this script" "$nwant of $nwant match"
  else
    miss=$(printf '%s\n' "$out" | awk -F'|' '{printf "%s%s(want %s, got %s)", sep, $1, $2, $3; sep="; "}' | cut -c1-900)
    rec FAIL A1 "every table.column the RB11 SQL of the three repos names exists with a compatible type" "$nwant columns present with the listed types" "$(printf '%s\n' "$out" | grep -c .) mismatch: $miss"
  fi
else
  rec FAIL A1 "column catalogue query" "information_schema answers" "query failed: $QERR$(errline)"
fi

# triggers / indexes the code relies on (append-only chain, one addendum per level, insert-only capture, spine keys)
if out=$(sqlro <<'SQL'
WITH want(kind,name) AS (VALUES
 ('index','proof_finality_addenda_level_idx'),('index','proof_finality_addenda_pkey'),('index','proof_finality_status_pkey'),
 ('index','proof_finality_capture_pkey'),('index','proof_v2_portable_pkey'),('index','proof_v2_spine_json_pkey'),
 ('trigger','proof_finality_addenda_row_guard'),('trigger','proof_finality_addenda_statement_guard'),
 ('trigger','proof_finality_capture_row_guard'),('trigger','proof_finality_capture_statement_guard'),
 ('function','proof_finality_addenda_guard'),('function','proof_finality_capture_guard'))
SELECT w.kind||' '||w.name FROM want w
 WHERE NOT ((w.kind='index'   AND EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=w.name AND c.relkind='i'))
         OR (w.kind='trigger' AND EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgname=w.name AND NOT t.tgisinternal))
         OR (w.kind='function' AND EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=w.name)));
SQL
); then
  if [ -z "$out" ]; then rec PASS A2 "the constraints the code leans on exist (unique level index, primary keys, append-only and insert-only guards)" "12 named objects" "12 of 12 present"
  else rec FAIL A2 "the constraints the code leans on exist (unique level index, primary keys, append-only and insert-only guards)" "12 named objects" "missing: $(printf '%s' "$out" | tr '\n' ';' | cut -c1-400)"; fi
else rec FAIL A2 "constraint catalogue query" "pg catalogs answer" "query failed: $(errline)"; fi

# PostgreSQL features the SQL uses: pg_advisory_xact_lock(hashtextextended) needs 11; row-wise comparison, LATERAL, ON CONFLICT, jsonb #> need 9.5
if [ "$PGVERNUM" -ge 110000 ]; then rec PASS A3 "server version supports hashtextextended / LATERAL / ON CONFLICT used by the addenda repository" "server_version_num >= 110000" "$PGVERNUM"
else rec FAIL A3 "server version supports hashtextextended / LATERAL / ON CONFLICT used by the addenda repository" "server_version_num >= 110000" "$PGVERNUM"; fi

# the roles that WRITE proof_artifacts (the validators) must be able to write the new tables; the roles that only read it must read them
if out=$(sqlro <<'SQL'
WITH writers AS (
  SELECT tableowner AS r, 'writer' AS k FROM pg_tables WHERE schemaname='public' AND tablename='proof_artifacts'
  UNION SELECT grantee, 'writer' FROM information_schema.role_table_grants WHERE table_schema='public' AND table_name='proof_artifacts' AND privilege_type='INSERT' AND grantee<>'PUBLIC'
  UNION SELECT grantee, 'reader' FROM information_schema.role_table_grants WHERE table_schema='public' AND table_name='proof_artifacts' AND privilege_type='SELECT' AND grantee<>'PUBLIC'
), roles AS (SELECT r, CASE WHEN bool_or(k='writer') THEN 'writer' ELSE 'reader' END AS k FROM writers GROUP BY r),
need(k,t,p) AS (VALUES
 ('writer','proof_finality_addenda','SELECT'),('writer','proof_finality_addenda','INSERT'),
 ('writer','proof_finality_status','SELECT'),('writer','proof_finality_status','INSERT'),('writer','proof_finality_status','UPDATE'),
 ('writer','proof_finality_capture','SELECT'),('writer','proof_finality_capture','INSERT'),
 ('writer','proof_bundles','SELECT'),('writer','proof_v2_spine','SELECT'),
 ('reader','proof_finality_addenda','SELECT'),('reader','proof_finality_status','SELECT'),
 ('reader','proof_v2_portable','SELECT'),('reader','proof_v2_spine_json','SELECT'),('reader','proof_bundles','SELECT'))
SELECT roles.r||' lacks '||need.p||' on '||need.t FROM roles JOIN need USING (k)
 WHERE NOT has_table_privilege(roles.r, 'public.'||need.t, need.p) ORDER BY 1;
SQL
); then
  nroles=$(echo 'SELECT count(DISTINCT grantee) FROM information_schema.role_table_grants WHERE table_schema=$$public$$ AND table_name=$$proof_artifacts$$ AND grantee<>$$PUBLIC$$;' | sqlro | head -1)
  if [ -z "$out" ]; then rec PASS A4 "roles that read/write proof_artifacts hold the table privileges the RB11 SQL needs on the new tables (migrations may run as a different role)" "no missing privilege" "none missing (roles with a grant on proof_artifacts: ${nroles:-?} + its owner)"
  else rec FAIL A4 "roles that read/write proof_artifacts hold the table privileges the RB11 SQL needs on the new tables (migrations may run as a different role)" "no missing privilege" "$(printf '%s' "$out" | tr '\n' ';' | cut -c1-500)"; fi
else rec FAIL A4 "privilege query" "catalogs answer" "query failed: $(errline)"; fi

# the leg source's prefilter is a join on proof_bundles.proof_id and an ORDER BY created_at: an index keeps it cheap
if out=$(sqlro <<'SQL'
SELECT (SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename='proof_bundles' AND indexdef ~ '\(proof_id[,)]'),
       (SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename='proof_artifacts' AND indexdef ~ '\(created_at[,)]|\(settlement_block_number[,)]');
SQL
); then
  ib=${out%%|*}; ia=${out#*|}
  if [ "$ib" -ge 1 ]; then rec PASS A5 "an index leads with proof_bundles.proof_id (the EXISTS / LATERAL of the leg source is not a sequential scan per leg)" ">= 1 index" "$ib"
  else rec WARN A5 "an index leads with proof_bundles.proof_id (the EXISTS / LATERAL of the leg source is not a sequential scan per leg)" ">= 1 index" "none: each candidate leg scans proof_bundles"; fi
  info "indexes leading with created_at or settlement_block_number on proof_artifacts: $ia (the page is ORDER BY created_at DESC, proof_id DESC; an absent index is a sort per page, not a fault)"
else rec WARN A5 "index query" "catalogs answer" "query failed: $(errline)"; fi

# ==============================================================================================================================
# (e) migration state
# ==============================================================================================================================
section "(e) migrations: certen_schema_history against the repo files"
if out=$(sqlro <<'SQL'
SELECT version||' '||sha256 FROM public.certen_schema_history ORDER BY version;
SQL
); then
  printf '%s\n' "$out" | grep . | sort >"$tmp/hist.txt"
  printf '%s\n' "$MIGRATION_SHA" | grep . | sort >"$tmp/want.txt"
  awk '{print $1}' "$tmp/hist.txt" | sort -u >"$tmp/hist.v"; awk '{print $1}' "$tmp/want.txt" | sort -u >"$tmp/want.v"
  missing=$(comm -13 "$tmp/hist.v" "$tmp/want.v" | tr '\n' ' ')
  wrong=""
  for v in $(awk '{print $1}' "$tmp/want.txt"); do
    h=$(awk -v v="$v" '$1==v{print $2}' "$tmp/hist.txt"); w=$(awk -v v="$v" '$1==v{print $2}' "$tmp/want.txt")
    [ -n "$h" ] && [ "$h" != "$w" ] && wrong="$wrong $v"
  done
  extra=$(comm -23 "$tmp/hist.v" "$tmp/want.v" | tr '\n' ' ')
  has2728=$(grep -cE '^(00027|00028) ' "$tmp/hist.txt")
  if [ "$has2728" -eq 2 ] && ! printf '%s' "$wrong" | grep -qE '0002[78]'; then
    rec PASS E1 "migrations 00027 and 00028 are applied with the checksums of the repo files (the proofs_service RequiredSchema pins the same two)" "00027 and 00028 present, sha256 equal" "both present, equal"
  else
    rec FAIL E1 "migrations 00027 and 00028 are applied with the checksums of the repo files (the proofs_service RequiredSchema pins the same two)" "00027 and 00028 present, sha256 equal" "present: $has2728 of 2; checksum differs for:$(printf '%s' "$wrong" | tr ' ' '
' | grep -E '^0002[78]$' | tr '
' ' ' | sed 's/^/ /; s/^ $/ none/')"
  fi
  if [ -z "$missing" ] && [ -z "$wrong" ]; then
    rec PASS E2 "every migration 00000-00029 of the repo is in the history with its file's checksum (proofs_service refuses to start otherwise; 00029 must be staged before the validators with this binary start)" "30 versions, sha256 equal" "30 of 30 equal; versions in the history beyond the repo list: ${extra:-none}"
  else
    rec FAIL E2 "every migration 00000-00029 of the repo is in the history with its file's checksum (proofs_service refuses to start otherwise; 00029 must be staged before the validators with this binary start)" "30 versions, sha256 equal" "not applied: ${missing:-none}; checksum differs:${wrong:- none}"
  fi
else rec FAIL E1 "certen_schema_history readable" "table answers" "query failed: $(errline)"; fi

# ==============================================================================================================================
# the population: settled legs
# ==============================================================================================================================
section "population: the settled legs the leg source and the portable document serve"
SL='proof_artifacts pa WHERE pa.settlement_block_number IS NOT NULL'
NSL=""
if NSL=$(scalar "SELECT count(*) FROM $SL;"); then
  echo "settled legs (proof_artifacts.settlement_block_number IS NOT NULL): $NSL (the 2026-10-23 live count was 575); proof_artifacts total: $(scalar 'SELECT count(*) FROM proof_artifacts;')"
  echo "by proof_type / chain_platform / target_chain / summary chain_id (type of the JSON value):"
  sqlro <<'SQL' | awk -F'|' '{printf "    %-14s %-9s %-22s chain_id=%-12s (%s)  n=%s\n",$1,$2,$3,$4,$5,$6}'
SELECT pa.proof_type, COALESCE(pa.chain_platform,'-'), COALESCE(pa.target_chain,'-'), COALESCE(pa.artifact_json->>'chain_id','-'),
       COALESCE(jsonb_typeof(pa.artifact_json->'chain_id'),'absent'), count(*)
  FROM proof_artifacts pa WHERE pa.settlement_block_number IS NOT NULL GROUP BY 1,2,3,4,5 ORDER BY 6 DESC, 1,2,3,4;
SQL
else rec FAIL P0 "count the settled legs" "query answers" "failed: $QERR"; NSL=0; fi

# ==============================================================================================================================
# (b) JSON paths in LIVE data - summary rows (SQL over every settled leg)
# ==============================================================================================================================
section "(b1) proof_artifacts.artifact_json (the cycle summary) over every settled leg"
if out=$(sqlro <<SQL
SELECT count(*),
  count(*) FILTER (WHERE jsonb_typeof(pa.artifact_json)='object'),
  count(*) FILTER (WHERE pa.artifact_json ? 'chain_id'),
  count(*) FILTER (WHERE jsonb_typeof(pa.artifact_json->'chain_id') IN ('string','number') AND (pa.artifact_json->>'chain_id') ~ '^[0-9]+\$'),
  count(*) FILTER (WHERE CASE WHEN jsonb_typeof(pa.artifact_json->'chain_id') IN ('string','number') AND (pa.artifact_json->>'chain_id') ~ '^[0-9]{1,18}\$' THEN (pa.artifact_json->>'chain_id')::numeric IN ($CHAINS_SQL) ELSE false END),
  count(*) FILTER (WHERE jsonb_typeof(pa.artifact_json->'chain_id')='string'),
  count(*) FILTER (WHERE pa.artifact_json ? 'proof_components'),
  count(*) FILTER (WHERE pa.chain_platform='evm')
  FROM $SL;
SQL
); then
  IFS='|' read -r s_n s_obj s_has s_dec s_sup s_str s_pc s_evm <<EOF
$out
EOF
  [ "$s_n" -eq "$s_obj" ] && st=PASS || st=FAIL
  rec $st B1 "artifact_json is a JSON object on every settled leg" "$s_n of $s_n objects" "$s_obj of $s_n"
  if [ "$s_n" -eq "$s_has" ] && [ "$s_has" -eq "$s_dec" ]; then st=PASS; elif [ "$s_dec" -eq 0 ]; then st=FAIL; else st=FAIL; fi
  rec $st B2 "artifact_json.chain_id exists on every settled leg and reads as a decimal (SettledLegs: artifact_json ->> 'chain_id' -> ParseUint; an unparsable one is chain 0, no profile)" "$s_n of $s_n decimal" "present $s_has, decimal $s_dec; JSON string typed: $s_str (rest numeric/other)"
  if [ "$s_dec" -eq "$s_sup" ]; then st=PASS; else st=WARN; fi
  rec $st B3 "the summary chain_id of every settled leg is a chain of the S7 table ($CHAINS_SQL); 2017 (Adiri) spelled as the bare decimal" "$s_dec of $s_dec in table" "$s_sup of $s_dec in the table"
  [ "$s_evm" -eq "$s_n" ] && st=PASS || st=WARN
  rec $st B4 "proof_artifacts.chain_platform = 'evm' on every settled leg (the ethproof settlement shape exists only for EVM)" "$s_n of $s_n evm" "$s_evm of $s_n"
  if [ "$s_pc" -eq 0 ]; then st=PASS; else st=WARN; fi
  rec $st B5 "artifact_json carries NO proof_components (the RB11 blocker: the old leg source read the bundle from here)" "0 summaries with proof_components; the code must read proof_bundles" "$s_pc of $s_n summaries carry proof_components (the committed leg source does not read them)"
else rec FAIL B1 "summary shape query" "query answers" "failed: $(errline)"; fi
if out=$(sqlro <<SQL
SELECT c, (SELECT count(*) FROM $SL AND (pa.artifact_json->>'chain_id') = c::text) FROM unnest(ARRAY[$CHAINS_SQL]) c ORDER BY c;
SQL
); then
  nochain=$(printf '%s
' "$out" | awk -F'|' '$2==0{printf "%s ", $1}')
  perchain=$(printf '%s
' "$out" | awk -F'|' '{printf "%s=%s ", $1, $2}')
  if [ -z "$nochain" ]; then st=PASS; else st=WARN; fi
  rec $st B5b "each chain of the S7 table has settled legs in the live data (a chain with none is not exercised by any check here)" "4 of 4 chains with >= 1 settled leg" "settled legs per chain: $perchain"
else rec WARN B5b "per-chain count" "query answers" "failed: $(errline)"; fi

# ==============================================================================================================================
# (c)+(d) cardinality and joins over every settled leg (SQL only; nothing is decompressed here)
# ==============================================================================================================================
section "(c)/(d) cardinality and the joins the code makes, over every settled leg"
if out=$(sqlro <<SQL
WITH sl AS (SELECT pa.* FROM $SL)
SELECT
 (SELECT count(*) FROM sl),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_bundles pb WHERE pb.proof_id=sl.proof_id)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_bundles pb WHERE pb.proof_id=sl.proof_id AND pb.bundle_format='certen_v1')),
 (SELECT count(*) FROM (SELECT pb.proof_id FROM proof_bundles pb JOIN sl USING (proof_id) GROUP BY 1 HAVING count(*)>1) x),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_bundles pb WHERE pb.proof_id=sl.proof_id AND pb.bundle_format<>'certen_v1')),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_bundles pb WHERE pb.proof_id=sl.proof_id AND octet_length(pb.bundle_data) > $MAX_GZ)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM chain_execution_results r WHERE r.proof_id=sl.proof_id)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM chain_execution_results r WHERE r.proof_id=sl.proof_id AND lower(r.tx_hash)=lower(sl.settlement_tx_hash))),
 (SELECT count(*) FROM (SELECT r.proof_id FROM chain_execution_results r JOIN sl USING (proof_id) GROUP BY r.proof_id, r.chain_id HAVING count(*)>1) x),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM intent_legs l WHERE l.proof_id=sl.proof_id)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM intent_legs l WHERE l.proof_id=sl.proof_id AND CASE WHEN (sl.artifact_json->>'chain_id') ~ '^[0-9]{1,18}\$' THEN l.chain_id::numeric=(sl.artifact_json->>'chain_id')::numeric ELSE false END)),
 (SELECT count(*) FROM sl WHERE sl.intent_id IS NOT NULL),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_v2_portable p WHERE p.intent_id=sl.intent_id::text)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_v2_portable p WHERE p.intent_id=sl.intent_id::text AND p.document<>'')),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_finality_addenda f WHERE f.proof_id=sl.proof_id)),
 (SELECT count(*) FROM sl WHERE EXISTS (SELECT 1 FROM proof_finality_status f WHERE f.proof_id=sl.proof_id)),
 (SELECT count(*) FROM (SELECT intent_id FROM sl WHERE intent_id IS NOT NULL GROUP BY 1 HAVING count(*)>1) x),
 (SELECT count(*) FROM (SELECT intent_id FROM sl WHERE intent_id IS NOT NULL GROUP BY 1 HAVING count(DISTINCT artifact_json->>'chain_id')>1) x),
 (SELECT count(*) FROM sl WHERE multi_leg_intent_id IS NOT NULL),
 (SELECT count(*) FROM sl WHERE leg_id IS NOT NULL);
SQL
); then
  IFS='|' read -r d_n d_bun d_v1 d_multi d_nonv1 d_big d_cer d_certx d_cerdup d_il d_ilchain d_int d_port d_portdoc d_add d_stat d_intmulti d_intchains d_mli d_legid <<EOF
$out
EOF
  pct() { awk -v a="$1" -v b="$2" 'BEGIN{ if (b==0) print "n/a"; else printf "%.1f%%", 100*a/b }'; }
  # D1 leg -> bundle
  [ "$d_bun" -eq "$d_n" ] && st=PASS || st=WARN
  rec $st D1 "join leg -> proof_bundles (the SettledLegs prefilter EXISTS): every settled leg has a stored bundle" "$d_n of $d_n" "$d_bun of $d_n resolve ($(pct "$d_bun" "$d_n")); $((d_n - d_bun)) legs have no bundle and are never listed"
  # D2 bundle_format
  if [ "$d_nonv1" -eq 0 ]; then st=PASS; else st=FAIL; fi
  rec $st D2 "bundle_format is certen_v1 for every settled leg's bundle (any other format is the named finality_included_invalid)" "0 other formats" "$d_nonv1 legs have a bundle of another format; certen_v1: $d_v1 of $d_bun"
  # C1 one bundle per proof
  if [ "$d_multi" -eq 0 ]; then st=PASS; else st=WARN; fi
  rec $st C1 "one bundle per proof (the code reads the NEWEST: ORDER BY created_at DESC, bundle_id DESC LIMIT 1)" "0 proofs with 2+ bundles" "$d_multi proofs with 2+ bundles"
  [ "$d_big" -eq 0 ] && st=PASS || st=FAIL
  rec $st C2 "no settled leg's compressed bundle exceeds this script's $MAX_GZ-byte sampling bound (the validator bound is on the DEcompressed size, 16 MiB)" "0" "$d_big"
  # chain_execution_results
  [ "$d_cer" -eq "$d_n" ] && st=PASS || st=WARN
  rec $st D3 "join leg -> chain_execution_results by proof_id (not read by the RB11 code; the closest granular cross-check of a settlement)" "$d_n of $d_n" "$d_cer of $d_n resolve ($(pct "$d_cer" "$d_n")); tx_hash equals settlement_tx_hash for $d_certx"
  [ "$d_cerdup" -eq 0 ] && st=PASS || st=WARN
  rec $st C3 "one chain_execution_results row per (proof, chain)" "0 groups with 2+ rows" "$d_cerdup (proof, chain) groups with 2+ rows"
  # intent_legs
  [ "$d_il" -eq "$d_n" ] && st=PASS || st=WARN
  rec $st D4 "join leg -> intent_legs by proof_id (intent -> legs)" "$d_n of $d_n" "$d_il of $d_n resolve ($(pct "$d_il" "$d_n")); intent_legs.chain_id equals the summary chain_id for $d_ilchain"
  # portable
  [ "$d_int" -eq "$d_n" ] && st=PASS || st=WARN
  rec $st D5 "proof_artifacts.intent_id is set on every settled leg (the portable join key)" "$d_n of $d_n" "$d_int of $d_n"
  [ "$d_portdoc" -eq "$d_n" ] && st=PASS || st=WARN
  rec $st D6 "join leg -> proof_v2_portable ON p.intent_id = pa.intent_id::text AND p.document <> '' (GetPortableV2): every settled leg has a portable document" "$d_n of $d_n" "$d_portdoc of $d_n resolve ($(pct "$d_portdoc" "$d_n")); a row exists for $d_port; the rest answer 404 PROOF_V2_NOT_AVAILABLE (documented, older proofs)"
  info "settled legs with a finality addendum: $d_add; with a builder status row: $d_stat; intents with 2+ settled legs: $d_intmulti (of those, with 2+ distinct chains: $d_intchains); legs with multi_leg_intent_id: $d_mli; with leg_id: $d_legid"
else rec FAIL D1 "join query" "query answers" "failed: $(errline)"; fi

# portable documents themselves
section "(b2) proof_v2_portable documents and the spine (ComposePortable)"
if out=$(sqlro <<'SQL'
SELECT count(*),
  count(*) FILTER (WHERE document=''),
  count(*) FILTER (WHERE majors<1),
  count(*) FILTER (WHERE govroot_v3_inputs IS NOT NULL AND govroot_v3_inputs<>'')
  FROM proof_v2_portable;
SQL
); then
  IFS='|' read -r p_n p_empty p_bad p_gov <<EOF
$out
EOF
  info "proof_v2_portable rows: $p_n (empty document: $p_empty, majors < 1: $p_bad, with govroot_v3_inputs: $p_gov)"
  # every non-empty document is JSON, an object, carries no 'finality' member, and has the keys the verifier family reads
  if out=$(sqlro <<'SQL'
SELECT count(*),
  count(*) FILTER (WHERE jsonb_typeof(document::jsonb)='object'),
  count(*) FILTER (WHERE (document::jsonb) ? 'finality'),
  count(*) FILTER (WHERE (document::jsonb) ?& ARRAY['pin','format','genesis','evidence']),
  count(*) FILTER (WHERE (document::jsonb) ? 'majors'),
  count(*) FILTER (WHERE (document::jsonb) ? 'block_header_rlp'),
  count(DISTINCT (document::jsonb)->>'format')
  FROM proof_v2_portable WHERE document<>'';
SQL
  ); then
    IFS='|' read -r q_n q_obj q_fin q_keys q_maj q_hdr q_fmt <<EOF
$out
EOF
    if [ "$q_n" -eq 0 ]; then rec WARN B6 "portable documents are JSON objects" "rows to examine" "no non-empty document (nothing examined)"
    else
      [ "$q_obj" -eq "$q_n" ] && st=PASS || st=FAIL
      rec $st B6 "every non-empty proof_v2_portable.document parses as a JSON object (ComposePortable json.Unmarshal into a map)" "$q_n of $q_n objects" "$q_obj of $q_n"
      [ "$q_fin" -eq 0 ] && st=PASS || st=FAIL
      rec $st B7 "no stored document carries its own 'finality' member (ComposePortable refuses it: the member is composed at request time)" "0" "$q_fin"
      [ "$q_keys" -eq "$q_n" ] && st=PASS || st=WARN
      rec $st B8 "stored documents carry the keys pin, format, genesis, evidence (majors is replaced from the spine; the 2026-10-23 sample showed pin,format,majors,genesis,evidence)" "$q_n of $q_n with all four" "$q_keys of $q_n; 'majors' key present in $q_maj; distinct format values: $q_fmt"
      [ "$q_hdr" -eq 0 ] && st=PASS || st=WARN
      rec $st B9 "portable documents hold no block_header_rlp (a settlement header comes only from the bundle)" "0" "$q_hdr documents name a block_header_rlp key at top level"
    fi
  else
    rec FAIL B6 "every non-empty proof_v2_portable.document parses as JSON" "all parse" "at least one document is not JSON (the cast fails): $(errline)"
  fi
  # spine: contiguous 1..max(majors) in BOTH spine tables, rows agree
  if out=$(sqlro <<'SQL'
WITH m AS (SELECT COALESCE(max(majors),0) AS mx FROM proof_v2_portable),
 j AS (SELECT count(*) AS n, COALESCE(max(major_index),0) AS mx, count(DISTINCT major_index) AS d FROM proof_v2_spine_json),
 s AS (SELECT count(*) AS n, COALESCE(max(major_index),0) AS mx, count(DISTINCT major_index) AS d FROM proof_v2_spine)
SELECT m.mx, j.n, j.mx, s.n, s.mx,
  (SELECT count(*) FROM generate_series(1, m.mx) g WHERE NOT EXISTS (SELECT 1 FROM proof_v2_spine_json x WHERE x.major_index=g)),
  (SELECT count(*) FROM proof_v2_portable p WHERE (SELECT count(*) FROM proof_v2_spine_json x WHERE x.major_index<=p.majors)<>p.majors),
  (SELECT count(*) FROM proof_v2_spine_json x WHERE NOT EXISTS (SELECT 1 FROM proof_v2_spine y WHERE y.major_index=x.major_index)),
  (SELECT count(*) FROM proof_v2_spine_json x WHERE x.record !~ '^\s*[\{\[]')
FROM m, j, s;
SQL
  ); then
    IFS='|' read -r r_mx r_jn r_jmx r_sn r_smx r_gap r_short r_nospine r_notobj <<EOF
$out
EOF
    if [ "$r_gap" -eq 0 ] && [ "$r_short" -eq 0 ]; then st=PASS; else st=FAIL; fi
    rec $st D7 "every portable document's majors have their major_index 1..majors in proof_v2_spine_json, contiguous (GetPortableV2: 'the document needs N major blocks and M are stored' is a 500)" "no gap up to max(majors)=$r_mx; no document short of its majors" "spine_json rows $r_jn (max index $r_jmx); gaps up to max(majors): $r_gap; documents short of majors: $r_short"
    if [ "$r_nospine" -eq 0 ]; then st=PASS; else st=WARN; fi
    rec $st D8 "proof_v2_spine_json (proofs_service) and proof_v2_spine (proofverify) hold the same major blocks" "every spine_json index present in proof_v2_spine" "spine rows $r_sn (max index $r_smx); spine_json indexes missing from proof_v2_spine: $r_nospine"
    [ "$r_notobj" -eq 0 ] && st=PASS || st=FAIL
    rec $st B10 "every proof_v2_spine_json.record looks like JSON (ComposePortable: json.Valid per major)" "0 records not starting with { or [" "$r_notobj"
  else rec FAIL D7 "spine query" "query answers" "failed: $(errline)"; fi
else rec FAIL B6 "portable query" "query answers" "failed: $(errline)"; fi

# ==============================================================================================================================
# (b3) the bundles: sample at most $SAMPLE newest bundles of settled legs, gunzip on the host, examine as jsonb, print counts only
# ==============================================================================================================================
section "(b3) bundles of settled legs: sampling the $SAMPLE newest (gzip -> JSON -> component 5 -> the ethproof.Settlement fields)"
FACTS="$tmp/facts.txt"; : >"$FACTS"
M_SAMPLED=0; M_JSON=0; M_BADGZ=0; M_SKIPPED=0
TAG='cx7Qm9zT'
P5='proof_components,5_execution_proof'

arr32() {   # SQL boolean: the jsonb expression $1 is a JSON array of 32 integers 0..255 (how Go reads a [32]byte)
  printf "CASE WHEN jsonb_typeof(%s)='array' THEN (jsonb_array_length(%s)=32 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(%s) e WHERE NOT (CASE WHEN jsonb_typeof(e)='number' THEN ((e #>> '{}')::numeric BETWEEN 0 AND 255 AND (e #>> '{}')::numeric = trunc((e #>> '{}')::numeric)) ELSE false END))) ELSE false END" "$1" "$1" "$1"
}
hexn() {    # SQL boolean: path $1 (comma list under component 5) is a 0x-prefixed string of exactly $2 bytes
  printf "(jsonb_typeof(j #> '{%s,%s}')='string' AND (j #>> '{%s,%s}') ~ '^0x[0-9a-fA-F]{%s}\$')" "$P5" "$1" "$P5" "$1" "$(($2 * 2))"
}
incl_sql() {  # facts of one inclusion proof ($1 = tx_inclusion_proof | receipt_inclusion_proof)
  local n="$1" X="(j #> '{$P5,$1}')"
  echo " UNION ALL SELECT 'F:$n.leaf_hash', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN $(arr32 "$X->'leaf_hash'") THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.expected_root', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN $(arr32 "$X->'expected_root'") THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.leaf_index', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN jsonb_typeof($X->'leaf_index')='number' AND ($X->>'leaf_index')::numeric >= 0 AND ($X->>'leaf_index')::numeric = trunc(($X->>'leaf_index')::numeric) THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.proof_hashes', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN jsonb_typeof($X->'proof_hashes')='array' AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements($X->'proof_hashes') h WHERE NOT ($(arr32 h))) THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.proof_nodes', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN jsonb_typeof($X->'proof_nodes')='array' AND jsonb_array_length($X->'proof_nodes')>0 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements($X->'proof_nodes') nd WHERE NOT (CASE WHEN jsonb_typeof(nd)='string' THEN ((nd #>> '{}') ~ '^[A-Za-z0-9+/]+={0,2}\$' AND length(nd #>> '{}') % 4 = 0) ELSE false END)) THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.nodes_eq_hashes', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN jsonb_typeof($X->'proof_nodes')='array' AND jsonb_typeof($X->'proof_hashes')='array' AND jsonb_array_length($X->'proof_nodes')=jsonb_array_length($X->'proof_hashes') THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:$n.leaf_value', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' WHEN jsonb_typeof($X->'leaf_value')='string' AND ($X->>'leaf_value') ~ '^[A-Za-z0-9+/]+={0,2}\$' AND length($X->>'leaf_value') % 4 = 0 THEN 'ok' ELSE 'bad' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'T:$n.verified', CASE WHEN c5 THEN CASE WHEN jsonb_typeof($X)<>'object' THEN 'n/a' ELSE COALESCE(jsonb_typeof($X->'verified'),'absent') END ELSE 'n/a' END FROM b"
}
facts_sql() {  # $1 = settlement_block_number, $2 = settlement_tx_hash, $3 = summary chain_id (all validated), JSON file $4
  printf 'BEGIN TRANSACTION READ ONLY;\nWITH b0 AS (SELECT $%s$' "$TAG"
  cat "$4"
  printf '$%s$::jsonb AS j), b AS (SELECT j, (jsonb_typeof(j #> %s)=%s) AS c5 FROM b0)\n' "$TAG" "'{$P5}'" "'object'"
  echo "SELECT 'T:root', COALESCE(jsonb_typeof(j),'absent') FROM b"
  echo " UNION ALL SELECT 'T:proof_components', COALESCE(jsonb_typeof(j #> '{proof_components}'),'absent') FROM b"
  echo " UNION ALL SELECT 'T:$P5', COALESCE(jsonb_typeof(j #> '{$P5}'),'absent') FROM b"
  local f
  for f in chain_id:string tx_hash:string block_number:number block_hash:string status:number transactions_root:string receipts_root:string block_header_rlp:string raw_receipt:string logs:array tx_inclusion_proof:object receipt_inclusion_proof:object; do
    echo " UNION ALL SELECT 'T:${f%%:*}', CASE WHEN c5 THEN COALESCE(jsonb_typeof(j #> '{$P5,${f%%:*}}'),'absent') ELSE 'n/a' END FROM b"
  done
  for f in block_hash:32 tx_hash:32 transactions_root:32 receipts_root:32; do
    echo " UNION ALL SELECT 'F:${f%%:*}.hex', CASE WHEN NOT c5 THEN 'n/a' WHEN j #> '{$P5,${f%%:*}}' IS NULL THEN 'n/a' WHEN $(hexn "${f%%:*}" "${f##*:}") THEN 'ok' ELSE 'bad' END FROM b"
  done
  echo " UNION ALL SELECT 'F:block_header_rlp.hex', CASE WHEN NOT c5 THEN 'n/a' WHEN j #> '{$P5,block_header_rlp}' IS NULL THEN 'n/a' WHEN jsonb_typeof(j #> '{$P5,block_header_rlp}')='string' AND (j #>> '{$P5,block_header_rlp}') ~ '^0x([0-9a-fA-F]{2})+\$' THEN 'ok' ELSE 'bad' END FROM b"
  echo " UNION ALL SELECT 'F:chain_id.decimal_in_table', CASE WHEN NOT c5 THEN 'n/a' WHEN jsonb_typeof(j #> '{$P5,chain_id}')<>'string' THEN 'n/a' WHEN (j #>> '{$P5,chain_id}') ~ '^[0-9]{1,18}\$' THEN CASE WHEN (j #>> '{$P5,chain_id}')::numeric IN ($CHAINS_SQL) THEN 'ok' ELSE 'bad' END ELSE 'bad' END FROM b"
  echo " UNION ALL SELECT 'S:chain', CASE WHEN c5 AND jsonb_typeof(j #> '{$P5,chain_id}')='string' THEN CASE WHEN (j #>> '{$P5,chain_id}') ~ '^[0-9]{1,12}\$' THEN (j #>> '{$P5,chain_id}') ELSE 'other' END ELSE 'n/a' END FROM b"
  echo " UNION ALL SELECT 'F:chain_id.equals_summary', CASE WHEN NOT c5 OR jsonb_typeof(j #> '{$P5,chain_id}')<>'string' THEN 'n/a' WHEN (j #>> '{$P5,chain_id}') = '$3' THEN 'ok' ELSE 'bad' END FROM b"
  echo " UNION ALL SELECT 'F:block_number.equals_settlement_block_number', CASE WHEN NOT c5 OR jsonb_typeof(j #> '{$P5,block_number}')<>'number' THEN 'n/a' WHEN ('$1' = '') THEN 'n/a' WHEN (j #>> '{$P5,block_number}')::numeric = NULLIF('$1','')::numeric THEN 'ok' ELSE 'bad' END FROM b"
  echo " UNION ALL SELECT 'F:tx_hash.equals_settlement_tx_hash', CASE WHEN NOT c5 OR jsonb_typeof(j #> '{$P5,tx_hash}')<>'string' THEN 'n/a' WHEN ('$2' = '') THEN 'n/a' WHEN lower(j #>> '{$P5,tx_hash}') = lower('$2') THEN 'ok' ELSE 'bad' END FROM b"
  incl_sql tx_inclusion_proof
  incl_sql receipt_inclusion_proof
  echo ";"
  echo "ROLLBACK;"
}

HAVE_TOOLS=1
for t in base64 gzip head awk; do command -v "$t" >/dev/null 2>&1 || { HAVE_TOOLS=0; echo "NOT-CHECKED tool missing on this host: $t"; }; done
if [ "$HAVE_TOOLS" -eq 1 ] && list=$(sqlro <<SQL
SELECT pb.bundle_id, octet_length(pb.bundle_data), COALESCE(pa.settlement_block_number::text,''), COALESCE(pa.settlement_tx_hash,''), COALESCE(pa.artifact_json->>'chain_id','')
  FROM proof_bundles pb JOIN proof_artifacts pa ON pa.proof_id=pb.proof_id
 WHERE pa.settlement_block_number IS NOT NULL
 ORDER BY pb.created_at DESC, pb.bundle_id DESC LIMIT $SAMPLE;
SQL
); then
  while IFS='|' read -r bid size sbn stx sch; do
    [ -n "$bid" ] || continue
    printf '%s' "$bid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || { M_SKIPPED=$((M_SKIPPED + 1)); continue; }
    printf '%s' "$sbn" | grep -Eq '^[0-9]*$' || sbn=''
    printf '%s' "$stx" | grep -Eq '^(0x)?[0-9a-fA-F]*$' || stx=''
    printf '%s' "$sch" | grep -Eq '^[0-9A-Za-z_.:-]*$' || sch='?'
    M_SAMPLED=$((M_SAMPLED + 1))
    if [ "${size:-0}" -gt "$MAX_GZ" ]; then M_SKIPPED=$((M_SKIPPED + 1)); echo "gz|too_big" >>"$FACTS"; continue; fi
    echo "SELECT replace(encode(bundle_data,'base64'), E'\\n', '') FROM proof_bundles WHERE bundle_id = '$bid';" | sqlro >"$tmp/b.b64" || { M_SKIPPED=$((M_SKIPPED + 1)); continue; }
    base64 -d "$tmp/b.b64" 2>/dev/null | gzip -dc 2>"$tmp/gz.err" | head -c $((MAX_JSON + 1)) >"$tmp/b.json"
    jsz=$(wc -c <"$tmp/b.json" | tr -d ' ')
    if [ -s "$tmp/gz.err" ] || [ "$jsz" -eq 0 ]; then M_BADGZ=$((M_BADGZ + 1)); echo "gz|bad" >>"$FACTS"; continue; fi
    if [ "$jsz" -gt "$MAX_JSON" ]; then M_BADGZ=$((M_BADGZ + 1)); echo "gz|past_bound" >>"$FACTS"; continue; fi
    echo "gz|ok" >>"$FACTS"
    facts_sql "$sbn" "$stx" "$sch" "$tmp/b.json" >"$tmp/facts.sql"
    # the SQL file already carries its own BEGIN/ROLLBACK; run it directly (still READ ONLY by PGOPTIONS as well)
    if [ -n "$PSQL_LOCAL_URL" ]; then
      PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' psql -X -q -At -F '|' -v ON_ERROR_STOP=1 -P pager=off "$PSQL_LOCAL_URL" <"$tmp/facts.sql" >"$tmp/facts.out" 2>"$ERRF"
    else
      docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' "$PGCONTAINER" \
        sh -c 'db=$1; shift; exec psql -U "$POSTGRES_USER" -d "$db" -X -q -At -F "|" -v ON_ERROR_STOP=1 -P pager=off "$@"' _ "$PGDB" <"$tmp/facts.sql" >"$tmp/facts.out" 2>"$ERRF"
    fi
    if [ $? -eq 0 ]; then M_JSON=$((M_JSON + 1)); tr -d '\r' <"$tmp/facts.out" >>"$FACTS"; echo "json|ok" >>"$FACTS"
    else echo "json|bad" >>"$FACTS"; echo "        bundle $M_SAMPLED: not examinable as jsonb: $(errline)"; fi
    rm -f "$tmp/b.b64" "$tmp/b.json" "$tmp/facts.sql" "$tmp/facts.out"
  done <<EOF
$list
EOF
elif [ "$HAVE_TOOLS" -eq 1 ]; then
  rec FAIL B20 "list the newest bundles of settled legs" "query answers" "failed: $(errline)"
fi

awk -F'|' '{c[$1"|"$2]++} END{for(k in c) print k"|"c[k]}' "$FACTS" | sort >"$tmp/agg.txt"
cnt() { awk -F'|' -v k="$1|$2" '($1"|"$2)==k{print $3; f=1} END{if(!f) print 0}' "$tmp/agg.txt"; }
dist() { awk -F'|' -v n="$1" '$1==n{printf "%s%s:%s", sep, $2, $3; sep=" "} END{if(sep=="") printf "none"}' "$tmp/agg.txt"; }

if [ "$HAVE_TOOLS" -eq 0 ]; then
  rec NOT-CHECKED B20 "bundle sampling" "base64, gzip on the host" "tool missing (see above): every B2x check below is NOT examined"
elif [ "$M_SAMPLED" -eq 0 ]; then
  rec WARN B20 "bundles of settled legs exist to sample" ">= 1 bundle" "none sampled (settled legs: $NSL)"
else
  gzok=$(cnt gz ok); jsok=$(cnt json ok)
  info "chains of the sampled bundles' execution proofs: $(dist S:chain)"
  info "sampled $M_SAMPLED newest bundles of settled legs; gunzipped ok $gzok, examinable as jsonb $jsok, bad gzip/bound $M_BADGZ, skipped $M_SKIPPED"
  [ "$gzok" -eq "$M_SAMPLED" ] && st=PASS || st=FAIL
  rec $st B20 "proof_bundles.bundle_data of settled legs is gzip(JSON) within 16 MiB decompressed (how the leg source reads it)" "$M_SAMPLED of $M_SAMPLED gunzip" "$gzok of $M_SAMPLED (bad gzip or past bound: $M_BADGZ, too big to sample: $(cnt gz too_big))"
  [ "$jsok" -eq "$gzok" ] && st=PASS || st=FAIL
  rec $st B21 "the decompressed bundle is JSON (jsonb accepts it)" "$gzok of $gzok" "$jsok of $gzok"
  if [ "$jsok" -gt 0 ]; then
    r=$(cnt T:root object); [ "$r" -eq "$jsok" ] && st=PASS || st=FAIL
    rec $st B22 "bundle root is a JSON object" "$jsok of $jsok" "$r of $jsok ($(dist T:root))"
    r=$(cnt T:proof_components object); [ "$r" -eq "$jsok" ] && st=PASS || st=FAIL
    rec $st B23 "bundle.proof_components is an object (the only key the leg source reads at the top)" "$jsok of $jsok" "$r of $jsok ($(dist T:proof_components))"
    r=$(cnt "T:$P5" object); a=$(cnt "T:$P5" absent)
    if [ "$r" -eq "$jsok" ]; then st=PASS; elif [ "$((r + a))" -eq "$jsok" ]; then st=WARN; else st=FAIL; fi
    rec $st B24 "proof_components.5_execution_proof is an object on a SETTLED leg (absent = the named finality_included_unavailable, wrong type = finality_included_invalid)" "$jsok of $jsok objects" "$r objects, $a absent of $jsok ($(dist "T:$P5"))"
    c5=$r
    if [ "$c5" -eq 0 ]; then
      rec WARN B25 "execution-proof members" "component 5 present in at least one sampled bundle" "no sampled bundle carries component 5: member shapes could not be examined"
    else
      n=25
      for f in chain_id:string tx_hash:string block_number:number block_hash:string status:number transactions_root:string receipts_root:string block_header_rlp:string raw_receipt:string logs:array tx_inclusion_proof:object receipt_inclusion_proof:object; do
        fld=${f%%:*}; ty=${f##*:}
        ok=$(cnt "T:$fld" "$ty"); ab=$(cnt "T:$fld" absent)
        case "$fld" in
          chain_id|block_header_rlp|block_hash|tx_hash|tx_inclusion_proof|receipt_inclusion_proof) why="read by the leg source / ethproof.Settlement" ;;
          block_number|status) why="the summary the gateway and verifiers read" ;;
          *) why="in the bundle contract, not read by the finality code" ;;
        esac
        if [ "$ok" -eq "$c5" ]; then st=PASS
        elif [ "$((ok + ab))" -eq "$c5" ]; then st=WARN
        else st=FAIL; fi
        rec $st "B$n" "5_execution_proof.$fld is a JSON $ty ($why)" "$c5 of $c5 $ty" "$ok of $c5 $ty ($(dist "T:$fld"))"
        n=$((n + 1))
      done
      for f in block_hash.hex:"0x + 64 hex" tx_hash.hex:"0x + 64 hex" transactions_root.hex:"0x + 64 hex" receipts_root.hex:"0x + 64 hex" block_header_rlp.hex:"0x + even hex, non-empty (hexutil.Bytes)" chain_id.decimal_in_table:"decimal string, one of $CHAINS_SQL (ParseUint)" chain_id.equals_summary:"equals artifact_json.chain_id" block_number.equals_settlement_block_number:"equals proof_artifacts.settlement_block_number" tx_hash.equals_settlement_tx_hash:"equals proof_artifacts.settlement_tx_hash"; do
        nm=${f%%:*}; desc=${f#*:}
        ok=$(cnt "F:$nm" ok); bad=$(cnt "F:$nm" bad); na=$(cnt "F:$nm" "n/a")
        if [ "$bad" -gt 0 ]; then st=FAIL; elif [ "$ok" -eq 0 ]; then st=WARN; elif [ "$na" -gt 0 ]; then st=WARN; else st=PASS; fi
        rec $st "B$n" "format of 5_execution_proof.$nm: $desc" "$c5 of $c5 ok" "ok $ok, bad $bad, not applicable (member absent or wrong type) $na"
        n=$((n + 1))
      done
      for ip in tx_inclusion_proof receipt_inclusion_proof; do
        for f in leaf_hash:"array of 32 integers 0..255 ([32]byte)" expected_root:"array of 32 integers 0..255 ([32]byte)" leaf_index:"non-negative integer" proof_hashes:"array of arrays of 32 integers" proof_nodes:"non-empty array of padded base64 strings ([][]byte)" nodes_eq_hashes:"len(proof_nodes) = len(proof_hashes)" leaf_value:"padded base64 string ([]byte)"; do
          nm="$ip.${f%%:*}"; desc=${f#*:}
          ok=$(cnt "F:$nm" ok); bad=$(cnt "F:$nm" bad); na=$(cnt "F:$nm" "n/a")
          if [ "$bad" -gt 0 ]; then st=FAIL; elif [ "$ok" -eq 0 ]; then st=WARN; elif [ "$na" -gt 0 ]; then st=WARN; else st=PASS; fi
          rec $st "B$n" "$nm: $desc (ethproof.InclusionProof JSON, strict decode)" "$c5 of $c5 ok" "ok $ok, bad $bad, not applicable $na"
          n=$((n + 1))
        done
        ok=$(cnt "T:$ip.verified" boolean); ab=$(cnt "T:$ip.verified" absent); oth=$(cnt "T:$ip.verified" "n/a")
        if [ "$((ok + ab + oth))" -eq "$c5" ] && [ "$ok" -gt 0 ]; then st=PASS; else st=WARN; fi
        rec $st "B$n" "$ip.verified is a boolean (recomputed by the reader, never trusted)" "boolean" "$(dist "T:$ip.verified")"
        n=$((n + 1))
      done
    fi
  fi
fi
info "components NOT examined: only the newest $SAMPLE bundles are decompressed, so the older settled legs' bundles are judged by the SQL checks above (format, existence), not by their content"

# ==============================================================================================================================
# (c) finality tables: shape of what the validators already wrote
# ==============================================================================================================================
section "(c) finality tables written by the deployed validators (addenda, status, capture)"
if out=$(sqlro <<SQL
SELECT count(*),
  count(*) FILTER (WHERE (chain, level::int, kind) NOT IN ((11155111,3,'eth-sepolia/finalized/v1'),(84532,2,'base-sepolia/l1_posted/v1'),(84532,3,'base-sepolia/finalized/v1'),(421614,2,'arb-sepolia/l1_posted/v1'),(421614,3,'arb-sepolia/finalized/v1'),(2017,3,'adiri/finalized/v1'))),
  count(*) FILTER (WHERE substring(evidence from 1 for 4) <> '\x43464531'::bytea),
  count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM proof_artifacts pa WHERE pa.proof_id=f.proof_id)),
  count(*) FILTER (WHERE EXISTS (SELECT 1 FROM proof_artifacts pa WHERE pa.proof_id=f.proof_id AND CASE WHEN (pa.artifact_json->>'chain_id') ~ '^[0-9]{1,18}\$' THEN (pa.artifact_json->>'chain_id')::numeric<>f.chain ELSE true END)),
  count(*) FILTER (WHERE octet_length(evidence) > 134217728),
  count(DISTINCT proof_id)
  FROM proof_finality_addenda f;
SQL
); then
  IFS='|' read -r f_n f_kind f_magic f_orph f_chain f_big f_proofs <<EOF
$out
EOF
  if [ "$f_n" -eq 0 ]; then
    rec WARN C4 "proof_finality_addenda rows are (chain, level, kind) rows of the S7 table, start with CFE1, and belong to a proof of the same chain" "rows to examine" "the table is empty: nothing examined (expected right after the first deploy; Adiri rows appear within one epoch, <= 6 h)"
  else
    if [ "$f_kind" -eq 0 ] && [ "$f_magic" -eq 0 ] && [ "$f_orph" -eq 0 ] && [ "$f_chain" -eq 0 ]; then st=PASS; else st=FAIL; fi
    rec $st C4 "proof_finality_addenda rows are (chain, level, kind) rows of the S7 table, start with CFE1, and belong to a proof of the same chain" "0 violations in $f_n rows over $f_proofs proofs" "kind/level/chain not in the table: $f_kind; evidence without CFE1 magic: $f_magic; proof_id not in proof_artifacts: $f_orph; chain differs from the summary chain_id: $f_chain; evidence > 128 MiB: $f_big"
  fi
else rec FAIL C4 "addenda query" "query answers" "failed: $(errline)"; fi

if out=$(sqlro <<SQL
WITH s AS (SELECT * FROM proof_finality_status),
 k AS (SELECT s.*, (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(s.state) x) AS keys FROM s)
SELECT count(*),
  count(*) FILTER (WHERE keys IS NOT NULL AND NOT (keys <@ ARRAY['class','eta','format','levelReached','nextLevel','seq','state'])),
  count(*) FILTER (WHERE state->>'format' IS DISTINCT FROM 'certen-finality-status/1'),
  count(*) FILTER (WHERE state->>'class' IS NULL OR state->>'class' NOT IN ('pending','unavailable','refused','not_applicable','verified')),
  count(*) FILTER (WHERE COALESCE(state->>'levelReached','') NOT IN ('none','included','l1_posted','finalized') OR COALESCE(state->>'nextLevel','') NOT IN ('none','included','l1_posted','finalized')),
  count(*) FILTER (WHERE state ? 'eta' AND (jsonb_typeof(state->'eta')<>'string' OR state->>'eta' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9:]+)\$')),
  count(*) FILTER (WHERE (state->>'class'='verified' AND state ? 'state' AND jsonb_typeof(state->'state')<>'null') OR (state->>'class'<>'verified' AND (NOT (state ? 'state') OR jsonb_typeof(state->'state')<>'object'))),
  count(*) FILTER (WHERE state ? 'seq' AND jsonb_typeof(state->'seq')<>'number'),
  count(*) FILTER (WHERE proof_id::text LIKE 'ffffffff-ffff-4fff-8fff-%'),
  count(*) FILTER (WHERE proof_id::text NOT LIKE 'ffffffff-ffff-4fff-8fff-%' AND NOT EXISTS (SELECT 1 FROM proof_artifacts pa WHERE pa.proof_id=k.proof_id))
  FROM k;
SQL
); then
  IFS='|' read -r t_n t_keys t_fmt t_cls t_lvl t_eta t_state t_seq t_pseudo t_orph <<EOF
$out
EOF
  if [ "$t_n" -eq 0 ]; then
    rec WARN C5 "proof_finality_status.state is the certen-finality-status/1 document both readers decode with DisallowUnknownFields" "rows to examine" "the table is empty: nothing examined"
  else
    bad=$((t_keys + t_fmt + t_cls + t_lvl + t_eta + t_state + t_seq))
    [ "$bad" -eq 0 ] && st=PASS || st=FAIL
    rec $st C5 "proof_finality_status.state is the certen-finality-status/1 document both readers (validator ParseBuilderStatusDocument, proofs_service levelFromStatus) decode with DisallowUnknownFields" "0 violating rows of $t_n" "unknown keys $t_keys; wrong format $t_fmt; unknown class $t_cls; unknown level name $t_lvl; eta not RFC3339 $t_eta; state object missing/forbidden $t_state; seq not a number $t_seq"
    [ "$t_orph" -eq 0 ] && st=PASS || st=WARN
    rec $st C6 "every non-pseudo status row names a proof in proof_artifacts (the capture loops' ffffffff-... pseudo ids are excluded: $t_pseudo rows)" "0 orphans" "$t_orph"
  fi
else rec FAIL C5 "status query" "query answers" "failed: $(errline)"; fi

if out=$(sqlro <<SQL
SELECT count(*),
  count(*) FILTER (WHERE chain NOT IN ($CHAINS_SQL)),
  count(*) FILTER (WHERE item !~ '^[a-z0-9_-]+(/[a-z0-9_-]+)*\$'),
  count(*) FILTER (WHERE octet_length(l1_hash)<>32),
  count(DISTINCT chain)
  FROM proof_finality_capture;
SQL
); then
  IFS='|' read -r c_n c_chain c_item c_hash c_chains <<EOF
$out
EOF
  if [ "$c_n" -eq 0 ]; then rec WARN C7 "proof_finality_capture rows are for the capture chains with named items" "rows to examine" "empty (nothing examined)"
  else
    [ "$((c_chain + c_item + c_hash))" -eq 0 ] && st=PASS || st=FAIL
    rec $st C7 "proof_finality_capture rows are for chains of the table, with item names matching the table constraint, and 32-byte L1 hashes" "0 violations in $c_n rows" "chain not in table $c_chain; bad item name $c_item; bad hash length $c_hash; chains with rows: $c_chains"
  fi
else rec FAIL C7 "capture query" "query answers" "failed: $(errline)"; fi

# C8: the capture cursor rows (item runtime/cursor) that finality.CaptureCoverageOf reads (RB12-F2, checked here by RB12-P0LIVE-FIX D7).
# The Base l1_posted builder decides a leg whose whole window lies below the first block the capture loop scanned as
# l1_capture_not_covering (a named unavailable state); that decision rests on three stored-data assumptions, each checked below:
#   (1) the item is named exactly runtime/cursor and chain 84532 has rows of it;
#   (2) a cursor row is keyed at the scanned block under the ZERO hash and holds that block as 8 big-endian bytes;
#   (3) min(l1_block) over the chain's cursor rows is the end of the loop's first range (the loop scanned every block from there minus its
#       first range on and nothing before): rows of other items below it were written before the loop ran (a one-shot recorder) and are
#       NOT evidence of coverage; the builder keeps a slack of max(CaptureBlocks, 32) blocks below the first cursor.
# Positions and classes are printed, never row contents. A chain with capture rows and NO cursor row has an unknown coverage: the builder
# then concludes nothing and every leg of it stays in the window search (pending) - a named WARN, not a FAIL.
CURSOR_ROWS=""
if out=$(sqlro <<SQL
WITH cur AS (
  SELECT chain, count(*) AS n, min(l1_block) AS lo, max(l1_block) AS hi,
    count(*) FILTER (WHERE l1_hash <> decode(repeat('00', 32), 'hex')) AS badhash,
    count(*) FILTER (WHERE octet_length(bytes) <> 8) AS badlen,
    count(*) FILTER (WHERE octet_length(bytes) = 8 AND ('x' || encode(bytes, 'hex'))::bit(64)::bigint <> l1_block) AS badval
  FROM proof_finality_capture WHERE item = 'runtime/cursor' GROUP BY chain),
 oth AS (
  SELECT chain, count(*) AS n, min(l1_block) AS lo, max(l1_block) AS hi
  FROM proof_finality_capture WHERE item <> 'runtime/cursor' GROUP BY chain)
SELECT chain, COALESCE(cur.n, 0), COALESCE(cur.lo::text, '-'), COALESCE(cur.hi::text, '-'),
  COALESCE(cur.badhash, 0), COALESCE(cur.badlen, 0), COALESCE(cur.badval, 0),
  COALESCE(oth.n, 0), COALESCE(oth.lo::text, '-'), COALESCE(oth.hi::text, '-'),
  (SELECT count(*) FROM proof_finality_capture o WHERE o.chain = chain_all.chain AND o.item <> 'runtime/cursor' AND cur.lo IS NOT NULL AND o.l1_block < cur.lo)
FROM (SELECT chain FROM cur UNION SELECT chain FROM oth) chain_all
LEFT JOIN cur USING (chain) LEFT JOIN oth USING (chain) ORDER BY chain;
SQL
); then
  CURSOR_ROWS="$out"
  base_seen=0
  while IFS='|' read -r k_chain k_n k_lo k_hi k_bh k_bl k_bv k_on k_olo k_ohi k_below; do
    [ -z "$k_chain" ] && continue
    [ "$k_chain" = "84532" ] && base_seen=1
    if [ "$((k_bh + k_bl + k_bv))" -ne 0 ]; then
      rec FAIL C8 "chain $k_chain: runtime/cursor rows are keyed under the zero hash and hold their own block as 8 big-endian bytes" "0 violations in $k_n cursor rows" "non-zero hash $k_bh; byte length not 8: $k_bl; value differs from l1_block: $k_bv (first scan ended at $k_lo, latest at $k_hi)"
    elif [ "$k_n" -eq 0 ]; then
      if [ "$k_chain" = "84532" ]; then
        rec WARN C8 "chain 84532 has a runtime/cursor row, so the Base l1_posted builder knows what the capture loop covered" "at least 1 cursor row (min = end of the loop's first range)" "no cursor row, $k_on capture rows between blocks $k_olo and $k_ohi: coverage UNKNOWN, l1_capture_not_covering is never concluded for this chain and its legs stay pending in the window search (the loop writes a cursor row once per tick: a loop that never ticked, or rows written by a one-shot recorder only)"
      else
        info "chain $k_chain: $k_on capture rows between blocks $k_olo and $k_ohi and no runtime/cursor row (the Base builder is the only reader of coverage)"
      fi
    else
      if [ "$k_chain" = "84532" ]; then
        rec PASS C8 "chain 84532: runtime/cursor rows exist and have the written shape; the builder reads min and max of their l1_block" "at least 1 cursor row, zero hash, 8 big-endian bytes equal to l1_block" "$k_n cursor rows; first scan ended at block $k_lo, latest at $k_hi; $k_on other capture rows between blocks $k_olo and $k_ohi, of which $k_below lie below the first cursor (written before the loop ran: not covered by it)"
      else
        info "chain $k_chain: $k_n cursor rows (first scan ended at block $k_lo, latest at $k_hi), shape as written; $k_on other capture rows, $k_below below the first cursor"
      fi
    fi
  done <<EOF
$out
EOF
  if [ "$base_seen" -eq 0 ]; then
    rec WARN C8 "chain 84532 has capture rows (and a runtime/cursor row), so the Base l1_posted builder knows what the capture loop covered" "rows of chain 84532" "no capture row at all for chain 84532: coverage UNKNOWN, every Base leg stays pending in the window search"
  fi
else rec FAIL C8 "capture cursor query" "query answers" "failed: $(errline)"; fi
# (renumbered at the Train 2 integration: C8 is the p0-live cursor-row check above; the capture-gap checks are C9 and C10)
# C9 (RB12-CAPTURE-GAP): the gap bookkeeping rows the code writes and reads are well-formed, and the spacing audit's assumption holds on the
# live Base store (consecutive captured inbox blocks are at most 19 blocks apart outside outage holes; the audit suspects a run above 40).
if out=$(sqlro <<SQL
SELECT count(*) FILTER (WHERE item LIKE 'gap/%'),
  count(*) FILTER (WHERE item LIKE 'gap/%' AND item !~ '^gap/[0-9]+/(block_unavailable|state_proof_unavailable|blob_unavailable|capture_failed|outage_unscanned|spacing_unproven|operator_declared)\$'),
  count(*) FILTER (WHERE item LIKE 'gapfill/%' AND item <> 'gapfill/' || l1_block),
  count(*) FILTER (WHERE item LIKE 'gapend/%' AND item !~ '^gapend/[0-9]+/(unavailable_proven|retention_expired)\$'),
  count(*) FILTER (WHERE item LIKE 'gapnote/%')
  FROM proof_finality_capture;
SQL
); then
  IFS='|' read -r g_n g_badgap g_badfill g_badend g_notes <<EOF
$out
EOF
  [ "$((g_badgap + g_badfill + g_badend))" -eq 0 ] && st=PASS || st=FAIL
  rec $st C9 "gap bookkeeping rows (gap/<to>/<class>, gapfill/<block>, gapend/<block>/<kind>) are well-formed" "0 malformed" "gap rows $g_n (malformed $g_badgap), malformed fills $g_badfill, malformed ends $g_badend, notes $g_notes"
else rec FAIL C9 "gap bookkeeping query" "query answers" "failed: $(errline)"; fi
if out=$(sqlro <<SQL
WITH ib AS (SELECT DISTINCT l1_block AS blk FROM proof_finality_capture WHERE chain = 84532 AND item = 'inbox'),
     d  AS (SELECT blk AS a, lead(blk) OVER (ORDER BY blk) AS z FROM ib),
     r  AS (SELECT a, z FROM d WHERE z IS NOT NULL AND z - a > 40
              AND NOT EXISTS (SELECT 1 FROM proof_finality_capture g WHERE g.chain = 84532 AND g.item LIKE 'gap/%'
                               AND g.l1_block <= a + 1 AND split_part(g.item, '/', 2)::bigint >= z - 1))
SELECT (SELECT count(*) FROM ib),
       COALESCE((SELECT max(z - a) FROM d WHERE z IS NOT NULL AND z - a <= 40), 0),
       (SELECT count(*) FROM r), COALESCE((SELECT sum(z - a - 1) FROM r), 0);
SQL
); then
  IFS='|' read -r s_n s_max s_runs s_blocks <<EOF
$out
EOF
  if [ "$s_n" -eq 0 ]; then rec WARN C10 "Base capture: consecutive inbox blocks are at most 40 apart unless a gap row covers the run" "rows to examine" "no Base inbox rows (nothing examined)"
  elif [ "$s_runs" -eq 0 ]; then rec PASS C10 "Base capture: consecutive inbox blocks are at most 40 apart unless a gap row covers the run" "0 uncovered runs" "$s_n inbox blocks, largest ordinary spacing $s_max, 0 uncovered runs"
  else rec WARN C10 "Base capture: consecutive inbox blocks are at most 40 apart unless a gap row covers the run" "0 uncovered runs (the spacing audit records them on the first tick of the RB12-CAPTURE-GAP binary)" "$s_runs uncovered run(s), $s_blocks uncaptured blocks; $s_n inbox blocks, largest ordinary spacing $s_max"; fi
else rec FAIL C10 "Base capture spacing query" "query answers" "failed: $(errline)"; fi

# RB12-SEPOLIA-SPINE (SP1, SP2): the Sepolia execution-header spine is kept as insert-only capture rows (chain 11155111, item spine/n<count>) and
# its progress is a finality_pending{awaiting_spine} status row. Empty before the first deploy of the fix; on the live store afterwards.
if out=$(sqlro <<SQL
SELECT count(*),
  count(*) FILTER (WHERE octet_length(l1_hash)<>32),
  count(*) FILTER (WHERE item !~ '^spine/n[0-9]{1,2}$' OR (CASE WHEN item ~ '^spine/n[0-9]{1,2}$' THEN substring(item from 8)::int END) NOT BETWEEN 1 AND 40),
  count(*) FILTER (WHERE item = 'spine/n40' AND l1_block % 40 <> 39),
  count(*) FILTER (WHERE get_byte(bytes,0) < 192),
  count(*) FILTER (WHERE item ~ '^spine/n[0-9]{1,2}$' AND (octet_length(bytes) < 400*substring(item from 8)::int OR octet_length(bytes) > 2048*substring(item from 8)::int)),
  COALESCE(min(l1_block),0), COALESCE(max(l1_block),0)
  FROM proof_finality_capture WHERE chain = 11155111 AND item LIKE 'spine/%';
SQL
); then
  IFS='|' read -r sp_n sp_hash sp_item sp_bound sp_list sp_size sp_lo sp_hi <<EOF
$out
EOF
  if [ "$sp_n" -eq 0 ]; then
    rec WARN SP1 "Sepolia spine chunk rows (proof_finality_capture, chain 11155111, item spine/n<1..40>) are 32-byte-hash rows of whole header windows" "rows to examine" "none yet (expected until the spine fix is deployed and a Sepolia leg has been attempted)"
  else
    [ "$((sp_hash + sp_item + sp_bound + sp_list + sp_size))" -eq 0 ] && st=PASS || st=FAIL
    rec $st SP1 "Sepolia spine chunk rows are 32-byte-hash rows of whole header windows: item spine/n<1..40>, a full window ends at a block = 39 mod 40, the bytes are one RLP list of 400..2048 bytes per header" "0 violations in $sp_n rows (blocks $sp_lo..$sp_hi)" "bad hash length $sp_hash; bad item $sp_item; full window off the boundary $sp_bound; not an RLP list $sp_list; implausible size $sp_size"
  fi
else rec FAIL SP1 "spine rows query" "query answers" "failed: $(errline)"; fi

if out=$(sqlro <<SQL
WITH f AS (SELECT chain, state->>'class' AS cls, state->'state'->>'code' AS code, state->'state'->'fields' AS fl FROM proof_finality_status)
SELECT count(*) FILTER (WHERE code = 'finality_pending' AND fl->>'reason' = 'awaiting_spine'),
  count(*) FILTER (WHERE code = 'finality_pending' AND fl->>'reason' = 'awaiting_spine' AND (
      NOT (fl ? 'have' AND fl ? 'need' AND fl ? 'next_attempt_at')
      OR COALESCE(fl->>'have','') !~ '^[0-9]+$' OR COALESCE(fl->>'need','') !~ '^[0-9]+$'
      OR COALESCE(fl->>'next_attempt_at','') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9:]+)$'
      OR (CASE WHEN COALESCE(fl->>'have','') ~ '^[0-9]+$' AND COALESCE(fl->>'need','') ~ '^[0-9]+$' THEN (fl->>'have')::numeric > (fl->>'need')::numeric ELSE true END))),
  count(*) FILTER (WHERE chain = 11155111 AND cls = 'unavailable' AND code = 'finality_build_timeout'),
  count(*) FILTER (WHERE chain <> 11155111 AND code = 'finality_pending' AND fl->>'reason' = 'awaiting_spine')
  FROM f;
SQL
); then
  IFS='|' read -r as_n as_bad as_to as_other <<EOF
$out
EOF
  if [ "$as_n" -eq 0 ]; then
    rec WARN SP2 "awaiting_spine status rows carry numeric have <= need and a next_attempt_at time" "rows to examine" "none yet; Sepolia finality_build_timeout rows still present: $as_to (they are replaced by awaiting_spine rows on the first attempts after the fix is deployed)"
  else
    [ "$((as_bad + as_other))" -eq 0 ] && st=PASS || st=FAIL
    rec $st SP2 "awaiting_spine status rows (only Sepolia legs) carry numeric have <= need and a next_attempt_at time" "0 violations in $as_n rows" "malformed $as_bad; on a chain other than Sepolia $as_other; Sepolia finality_build_timeout rows still present: $as_to"
  fi
else rec FAIL SP2 "awaiting_spine status query" "query answers" "failed: $(errline)"; fi

# ==============================================================================================================================
# (f) container environment hygiene (names only, never values)
# ==============================================================================================================================
section "(f) validator containers: finality and provider variables (SET / EMPTY / UNSET only; values are never read out) and /health/detailed"
if [ -n "$PSQL_LOCAL_URL" ]; then
  rec NOT-CHECKED F1 "container environment and /health/detailed" "docker access to the 7 validator containers" "test mode (PSQL_LOCAL_URL set): no containers here"
elif ! command -v docker >/dev/null 2>&1; then
  rec NOT-CHECKED F1 "container environment and /health/detailed" "docker on this host" "docker not found"
else
  # variable name -> role. Provider lists are read by pkg/ethrpc EndpointsForChain; a chain is DISABLED by name when its list is empty.
  PROVIDER_VARS="BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_URL_FALLBACKS INFURA_BASE_SEPOLIA_URL ALCHEMY_BASE_SEPOLIA_URL ARBITRUM_SEPOLIA_RPC_URL ARBITRUM_SEPOLIA_URL_FALLBACKS INFURA_ARBITRUM_SEPOLIA_URL ALCHEMY_ARBITRUM_SEPOLIA_URL ETHEREUM_SEPOLIA_RPC_URL ETHEREUM_URL ETHEREUM_URL_FALLBACKS INFURA_SEPOLIA_URL ALCHEMY_SEPOLIA_URL TELCOIN_ADIRI_RPC_URL"
  FIN_LISTS="CERTEN_FINALITY_L1_RPC_URLS CERTEN_FINALITY_L1_PROOF_URLS CERTEN_FINALITY_ARCHIVE_URLS CERTEN_FINALITY_LC_URLS CERTEN_FINALITY_BEACON_URLS CERTEN_FINALITY_ADIRI_PUBLIC_URLS CERTEN_FINALITY_PINS_FILE"
  FIN_NUMS="CERTEN_FINALITY_RATE_LIMIT_RPS CERTEN_FINALITY_RATE_BURST CERTEN_FINALITY_MAX_BATCH CERTEN_FINALITY_BACKOFF_RETRIES CERTEN_FINALITY_BACKOFF_MAX_SECONDS CERTEN_FINALITY_CAPTURE_INTERVAL_SECONDS CERTEN_FINALITY_MAX_CAPTURE_BYTES_PER_LEG CERTEN_FINALITY_CAPTURE_MAX_BLOCKS_PER_TICK CERTEN_FINALITY_UPGRADER_CONCURRENCY CERTEN_FINALITY_UPGRADER_INTERVAL_SECONDS CERTEN_FINALITY_BUILD_TIMEOUT_SECONDS"
  FIN_SWITCHES="CERTEN_FINALITY_UPGRADER_ENABLED CERTEN_FINALITY_CHAIN_11155111_ENABLED CERTEN_FINALITY_CHAIN_84532_ENABLED CERTEN_FINALITY_CHAIN_421614_ENABLED CERTEN_FINALITY_CHAIN_2017_ENABLED"
  KNOWN_FIN="$FIN_LISTS $FIN_NUMS $FIN_SWITCHES"
  probe_script='for v in "$@"; do
    case "$v" in *[!A-Z0-9_]*|"") continue;; esac
    eval "val=\${$v-__UNSET__}"
    if [ "$val" = "__UNSET__" ]; then echo "$v unset"
    elif [ -z "$val" ]; then echo "$v empty"
    else
      case "$v" in
        *_ENABLED) case "$val" in [Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]|[Oo][Nn]) echo "$v on";; [Ff][Aa][Ll][Ss][Ee]|0|[Nn][Oo]|[Oo][Ff][Ff]) echo "$v off";; *) echo "$v other";; esac;;
        *) echo "$v set";;
      esac
    fi
  done'
  allvars_fn() { echo "$PROVIDER_VARS $KNOWN_FIN"; }
  cfin_state=PASS; cfin_notes=""
  for n in $VALIDATORS; do
    c="certen-validator-$n"
    if ! docker inspect "$c" >/dev/null 2>&1; then
      rec FAIL "F$n" "$c exists" "container present" "container not found"; continue
    fi
    # shellcheck disable=SC2046
    docker exec "$c" sh -c "$probe_script" _ $(allvars_fn) >"$tmp/env.$n" 2>/dev/null
    # CERTEN_FINALITY_* names present in the container that this build does not read (a typo is a silently ignored setting)
    docker exec "$c" sh -c 'env | sed "s/=.*//" | grep "^CERTEN_FINALITY_" || true' >"$tmp/envnames.$n" 2>/dev/null
    unknown=""
    for nm in $(cat "$tmp/envnames.$n"); do
      case " $KNOWN_FIN " in *" $nm "*) ;; *) unknown="$unknown $nm" ;; esac
    done
    get() { awk -v v="$1" '$1==v{print $2}' "$tmp/env.$n"; }
    setlist=$(awk '$2=="set"||$2=="on"||$2=="off"||$2=="other"||$2=="empty"{printf "%s=%s ", $1, $2}' "$tmp/env.$n" | cut -c1-900)
    base=$(for v in BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_URL_FALLBACKS INFURA_BASE_SEPOLIA_URL ALCHEMY_BASE_SEPOLIA_URL; do [ "$(get $v)" = "set" ] && echo y; done | head -1)
    arb=$(for v in ARBITRUM_SEPOLIA_RPC_URL ARBITRUM_SEPOLIA_URL_FALLBACKS INFURA_ARBITRUM_SEPOLIA_URL ALCHEMY_ARBITRUM_SEPOLIA_URL; do [ "$(get $v)" = "set" ] && echo y; done | head -1)
    sw=$(get CERTEN_FINALITY_UPGRADER_ENABLED)
    offchains=""
    for ch in 11155111 84532 421614 2017; do [ "$(get CERTEN_FINALITY_CHAIN_${ch}_ENABLED)" = "off" ] && offchains="$offchains $ch"; done
    st=PASS; why=""
    [ -n "$base" ] || { st=FAIL; why="$why no Base Sepolia provider variable set (chain 84532 upgrader is DISABLED by name);"; }
    [ -n "$arb" ] || { st=FAIL; why="$why no Arbitrum Sepolia provider variable set (chain 421614 upgrader is DISABLED by name);"; }
    [ "$sw" = "off" ] && { st=FAIL; why="$why CERTEN_FINALITY_UPGRADER_ENABLED is off;"; }
    [ "$sw" = "other" ] && { st=FAIL; why="$why CERTEN_FINALITY_UPGRADER_ENABLED is not a switch (startup is refused);"; }
    [ -n "$offchains" ] && { [ "$st" = PASS ] && st=WARN; why="$why per-chain switch off for:$offchains;"; }
    [ -n "$unknown" ] && { [ "$st" = PASS ] && st=WARN; why="$why unknown CERTEN_FINALITY_ names (ignored by this build):$unknown;"; }
    rec $st "F$n" "$c: finality switches on; a provider variable set for Base Sepolia and Arbitrum Sepolia (names only)" "upgrader switch unset or on; Base and Arbitrum provider variable present; no per-chain switch off; no unknown CERTEN_FINALITY_ name" "${why:-ok;} variables seen: ${setlist:-none}"
  done
  # /health/detailed: the finality block answers (keys and numbers only)
  for n in $VALIDATORS; do
    c="certen-validator-$n"
    docker inspect "$c" >/dev/null 2>&1 || continue
    h=$(docker exec "$c" sh -c "wget -qO- '$HEALTH_URL' 2>/dev/null || curl -fsS '$HEALTH_URL' 2>/dev/null" 2>/dev/null | tr -d '\n ')
    if [ -z "$h" ]; then rec FAIL "H$n" "$c /health/detailed answers (curl/wget inside the container)" "a JSON body with a finality block" "no answer (non-2xx, not listening, or neither wget nor curl in the image)"; continue; fi
    if ! printf '%s' "$h" | grep -q '"finality":{'; then rec FAIL "H$n" "$c /health/detailed has a finality block" "\"finality\":{...}" "answered (${#h} bytes) without a finality block"; continue; fi
    fb=$(printf '%s' "$h" | sed -E 's/.*"finality":(\{.*)/\1/')
    up=$(printf '%s' "$fb" | grep -oE '"upgrader_enabled":(true|false)' | head -1 | cut -d: -f2)
    chains=$(printf '%s' "$fb" | grep -oE '"[0-9]{3,}":\{"capture_lag_blocks":[0-9]+' | sed -E 's/"([0-9]+)":\{"capture_lag_blocks":([0-9]+)/\1(lag=\2)/' | tr '\n' ' ')
    reasons=$(printf '%s' "$fb" | grep -oE '"disabled_reason":"[^"]+"' | wc -l | tr -d ' ')
    enabled_false=$(printf '%s' "$fb" | grep -oE '"enabled":false' | wc -l | tr -d ' ')
    st=PASS; why=""
    [ "$up" = "true" ] || { st=FAIL; why="upgrader_enabled=${up:-absent}"; }
    [ "$reasons" -eq 0 ] || { st=FAIL; why="$why $reasons chain(s) carry a non-empty disabled_reason;"; }
    [ "$enabled_false" -eq 0 ] || { st=FAIL; why="$why $enabled_false chain(s) enabled=false;"; }
    for ch in 11155111 84532 421614 2017; do printf '%s' "$chains" | grep -q "^$ch(\| $ch(" || { [ "$st" = PASS ] && st=WARN; why="$why chain $ch not reported yet;"; }; done
    rec $st "H$n" "$c /health/detailed finality block: upgrader_enabled true, each of the 4 chains reported, no disabled_reason" "upgrader_enabled=true; 4 chains; 0 disabled_reason" "${why:-ok;} upgrader_enabled=${up:-absent}; chains: ${chains:-none}"
  done
fi

# ==============================================================================================================================
# what this script CANNOT check read-only
# ==============================================================================================================================
section "NOT CHECKABLE read-only from here (assumptions that live elsewhere)"
cat <<'EOF'
 N1  The api-gateway's own database: intents.validator_members[].proofId / chain_id (the gateway sends proofId to proofs_service
     GET /api/v1/proofs/{id}/finality and requires summary.proofId and summary.leg.chain to equal what it holds; the leg's chain
     must be a NUMBER equal to a key of FINALITY_STATEMENTS). That database is separate; B2/B3 here show the validator side only.
 N2  Provider behaviour: public RPC / light-client / beacon availability and rate limits, eth_getProof windows, and whether the
     provider text redaction holds. These are runtime facts of RB11's runtime tests, not data shapes.
 N3  The CONTENT of bundles older than the newest SAMPLE (default and maximum 20): only SQL-level facts (existence, format, size) are known for them.
     Re-run with a different window by editing the ORDER BY of the sampling query in a copy, or sample by proof via proofverify.
 N4  Whether the decoded Settlement VERIFIES (keccak256(header) = block_hash, MPT proofs resolve): PostgreSQL has no keccak256 or
     RLP. Shape (hex lengths, array widths, base64) is examined here; verification is `proofverify --finality` / the Go tests on the
     same bytes. A shape PASS here is necessary, not sufficient.
 N5  Concurrency and lock behaviour (advisory locks under 7 validators writing the same table), and trigger behaviour under load.
 N6  Grants of roles that exist only in the application's connection strings: A4 checks every role that holds a grant on
     proof_artifacts; a role with no grant there and a table-level grant elsewhere is invisible to it.
 N7  The wire format of proofs_service responses (certen-finality-summary/1) as the gateway parses it: that is a code-to-code
     contract tested by the two repos' vectors, not a database shape.
EOF

# ==============================================================================================================================
# (g) FINAL SUMMARY
# ==============================================================================================================================
echo
echo "FINAL SUMMARY: $NCHK checks: $NPASS PASS, $NWARN WARN, $NFAIL FAIL, $NNC NOT-CHECKED"
echo "FAIL ids:${FAILIDS:- none}"
echo "WARN ids:${WARNIDS:- none}"
echo "NOT-CHECKED ids:${NCIDS:- none}"
[ "$NFAIL" -eq 0 ] && echo "RESULT: no assumption of the RB11 code is contradicted by the live database (read the WARN lines)" || echo "RESULT: FAIL - the live database contradicts at least one assumption of the RB11 code"
[ "$NFAIL" -eq 0 ] && exit 0 || exit 1
