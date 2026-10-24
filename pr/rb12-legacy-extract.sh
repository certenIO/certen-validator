#!/usr/bin/env bash
# RB12-LEGACY-191: READ-ONLY extraction of the LEGACY execution-proof components (bundle component 5 written before block_header_rlp was
# captured) from the validator database, as JSON lines for `go run ./cmd/finalitylegacyheaders -in FILE` (the offline reconstruction).
#
#   sed 's/\r$//' pr/rb12-legacy-extract.sh | ~/.ssh/certen-ssh 'bash -s' > legacy_comp5.jsonl      # about 90 s; counts go to stderr
#   go run ./cmd/finalitylegacyheaders -in legacy_comp5.jsonl -rpc 84532=URL[,URL...] -rpc 421614=URL -rpc 11155111=URL
#
# What it does: for every proof (oldest first) it reads the NEWEST bundle (the one the leg source reads), decompresses it on the host
# (gzip, 16 MiB bound), and keeps only component 5 of the bundles whose execution proof is a non-empty object WITHOUT a non-empty
# block_header_rlp. The census it prints (stderr) is the same as pr/rb11-prod-shape-check.sh section (b4): at 2026-10-23, 782 bundles,
# 525 without an execution proof, 66 with a header, 191 legacy.
#
# READ-ONLY by construction: every statement runs in BEGIN TRANSACTION READ ONLY with default_transaction_read_only=on through psql inside
# the postgres container (local socket, no password read, printed or on a command line); nothing is written on the host or in the
# database. WHAT IS PRINTED: stdout carries ONLY the component-5 JSON lines (block hash, tx hash, roots, receipt and the two inclusion
# proofs: public chain data), one per legacy bundle, and is a data stream for a file: the script REFUSES to run when stdout is a
# terminal. Nothing else of any bundle is printed; stderr carries counts only.
set -u
if [ -t 1 ]; then echo "rb12-legacy-extract: stdout carries bundle data; redirect it to a file" >&2; exit 2; fi
PGCONTAINER="${PGCONTAINER:-certen-postgres}"; PGDB="${PGDB:-certen_proofs}"
sqlro() { { echo 'BEGIN TRANSACTION READ ONLY;'; cat; echo 'ROLLBACK;'; } | docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c client_min_messages=warning' "$PGCONTAINER" sh -c 'db=$1; shift; exec psql -U "$POSTGRES_USER" -d "$db" -X -q -At -F "|" -v ON_ERROR_STOP=1 -P pager=off "$@"' _ "$PGDB"; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
list=$(sqlro <<'SQL'
SELECT pa.proof_id::text, pb.bundle_id::text, to_char(pa.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'), COALESCE(pa.artifact_json->>'chain_id',''), COALESCE(pa.settlement_block_number::text,''), COALESCE(pa.settlement_tx_hash,''), octet_length(pb.bundle_data), pb.bundle_format
FROM proof_artifacts pa JOIN LATERAL (SELECT bundle_id, bundle_data, bundle_format FROM proof_bundles WHERE proof_id = pa.proof_id ORDER BY created_at DESC, bundle_id DESC LIMIT 1) pb ON true
ORDER BY pa.created_at, pa.proof_id;
SQL
)
total=0; nocomp=0; withhdr=0; legacy=0; bad=0; big=0
while IFS='|' read -r pid bid cat sch sbn stx size fmt; do
  [ -n "$bid" ] || continue
  total=$((total+1))
  printf '%s' "$bid" | grep -Eq '^[0-9a-f-]{36}$' || { bad=$((bad+1)); continue; }
  [ "$fmt" = "certen_v1" ] || { bad=$((bad+1)); continue; }
  [ "${size:-0}" -le $((12*1024*1024)) ] || { big=$((big+1)); continue; }
  echo "SELECT replace(encode(bundle_data,'base64'), E'\n', '') FROM proof_bundles WHERE bundle_id = '$bid';" | sqlro >"$tmp/b64" || { bad=$((bad+1)); continue; }
  base64 -d "$tmp/b64" 2>/dev/null | gzip -dc 2>/dev/null | head -c $((16*1024*1024+1)) >"$tmp/j"
  state=$(jq -r '(.proof_components["5_execution_proof"]) as $e | if ($e|type)!="object" or ($e|length)==0 then "none" elif ($e.block_header_rlp // "") != "" then "hdr" else "legacy" end' "$tmp/j" 2>/dev/null || echo bad)
  case "$state" in
    none) nocomp=$((nocomp+1)) ;;
    hdr) withhdr=$((withhdr+1)) ;;
    legacy) legacy=$((legacy+1))
      jq -c --arg pid "$pid" --arg bid "$bid" --arg cat "$cat" --arg sch "$sch" --arg sbn "$sbn" --arg stx "$stx" '{proof_id:$pid, bundle_id:$bid, created_at:$cat, summary_chain:$sch, settlement_block:$sbn, settlement_tx:$stx, custody:(.bundle_integrity.custody_chain_hash // ""), comp5:.proof_components["5_execution_proof"]}' "$tmp/j" ;;
    *) bad=$((bad+1)) ;;
  esac
done <<EOT
$list
EOT
echo "total=$total no_component=$nocomp with_header=$withhdr legacy=$legacy bad_or_skipped=$bad too_big=$big" >&2
