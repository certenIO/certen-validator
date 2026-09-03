#!/usr/bin/env bash
# Phase 0 re-verification for docs/l4/VALIDATOR_TRUST_ROOT_RUNBOOK.md §9.
#
# Re-runs every measurement behind §9 Phase 0. Read-only throughout:
# accumulate-core is only ever read via `git show <ref>:<path>`, the live
# networks are only queried, and the fleet database is only SELECTed.
#
#   ./phase0_verify.sh            # code + live networks
#   ./phase0_verify.sh --evm      # also the three EVM deployments (needs .env.shared)
#   ./phase0_verify.sh --db       # also the fleet proof database (needs ssh key)
#
# Run from anywhere. CORE and CERTEN can be overridden by env.

set -u
CORE=${CORE:-/c/Accumulate_Stuff/accumulate-core}
CERTEN=${CERTEN:-/c/Accumulate_Stuff/certen}
IV="$CERTEN/independant_validator"
MAIN=origin/main
DAG=origin/dagbft-integration

hr() { printf '\n=== %s ===\n' "$*"; }
show() { git -C "$CORE" show "$1:$2" 2>/dev/null; }

hr "branch HEADs (§9 was run against 56f5ae9b / c01b026e)"
git -C "$CORE" log --oneline -1 $MAIN
git -C "$CORE" log --oneline -1 $DAG

hr "§2.1 protocol constants (both branches)"
for R in $MAIN $DAG; do
  echo "--- $R ---"
  show $R protocol/protocol.go | grep -n "	Network = \|	Globals = \|	GenesisBlock = "
  show $R protocol/types_gen.go | grep -n "type NetworkDefinition struct"
done

hr "§2.2/§2.3 spine machinery — present on dagbft, absent on main"
for f in internal/fastsync/spine.go internal/fastsync/snapshot.go \
         internal/api/v3/major_header.go internal/api/private/api.go; do
  printf '%-40s' "$f"
  git -C "$CORE" cat-file -e $MAIN:$f 2>/dev/null && printf 'main:PRESENT ' || printf 'main:ABSENT  '
  git -C "$CORE" cat-file -e $DAG:$f  2>/dev/null && printf 'dagbft:PRESENT\n' || printf 'dagbft:ABSENT\n'
done
echo "-- rangers on main (expect none) --"
show $MAIN internal/api/private/api.go | grep -n "MajorHeaderRanger\|MinorRootRanger" || echo "   none, as expected"
echo "-- rangers on dagbft --"
show $DAG internal/api/private/api.go | grep -n "type MajorHeaderRanger\|type MinorRootRanger"
show $DAG internal/api/v3/major_header.go | grep -n "func (s \*Sequencer) getNetworkUpdatesInWindow"
show $DAG internal/fastsync/spine.go | grep -n "func NewSpine\|does not start at genesis\|not an active directory validator\|quorum not met"
show $DAG internal/fastsync/snapshot.go | grep -n "only out-of-band"

hr "§2.4 the spine is NOT public on EITHER branch"
for R in $MAIN $DAG; do
  printf '%-28s' "$R"; show $R pkg/api/v3/enums_gen.go | grep -c "case ServiceTypeUnknown, ServiceTypeNode, ServiceTypeConsensus, ServiceTypeNetwork, ServiceTypeMetrics, ServiceTypeQuery, ServiceTypeEvent, ServiceTypeSubmit, ServiceTypeValidate, ServiceTypeFaucet, ServiceTypeSnapshot:"
done
echo "(1 on each = the identical public service list; no proof/spine service)"

hr "§2A.2 WriteToState mandate, and the system-transaction early return (§9.0.7)"
show $MAIN internal/core/execute/v2/block/network_accounts.go \
  | grep -n "IsSystem()\|case \*protocol.WriteData\|ParseNetwork\|must write to state\|Only push updates"

hr "§2B.4a SystemGenesis is an empty struct (both branches, and in the schema)"
for R in $MAIN $DAG; do
  echo "--- $R ---"
  show $R protocol/types_gen.go | grep -n "type SystemGenesis struct" -A 3
  show $R protocol/system.yml   | grep -n "^SystemGenesis:" -A 2
done

hr "§9.0.2 by-hash vs by-index: the genesis entry IS receipt-provable"
python - <<'PY'
import json, hashlib, urllib.request

GEN = "e43be90e349210456662d8b8bdc9cc9e5e46ccb07f2129e7b57a8195e5e916d5"

def rpc(net, params):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"query","params":params}).encode()
    req = urllib.request.Request(f"https://{net}.accumulatenetwork.io/v3", body,
                                 {"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))

def verify(rc):
    cur = bytes.fromhex(rc["start"])
    for e in rc["entries"]:
        h = bytes.fromhex(e["hash"])
        cur = hashlib.sha256(cur+h).digest() if e.get("right") else hashlib.sha256(h+cur).digest()
    return cur.hex() == rc["anchor"], cur.hex()

for net in ("mainnet", "kermit"):
    print(f"--- {net} ---")
    d = rpc(net, {"scope":"acc://dn.acme/network",
                  "query":{"queryType":"chain","name":"main","range":{"start":0,"count":5}}})
    r = d["result"]
    print("  dn.acme/network main-chain entries:", r["total"], "| entry[0]:", r["records"][0]["entry"])
    print("  entry[0] == the cross-network constant:", r["records"][0]["entry"] == GEN)

    d = rpc(net, {"scope":"acc://dn.acme/network",
                  "query":{"queryType":"chain","name":"main","entry":GEN,"includeReceipt":True}})
    print("  by HASH  ->", "ERROR: " + d["error"]["message"][:70] if "error" in d else "unexpectedly OK")

    d = rpc(net, {"scope":"acc://dn.acme/network",
                  "query":{"queryType":"chain","name":"main","index":0,"includeReceipt":True}})
    rc = d["result"]["receipt"]
    ok, got = verify(rc)
    print(f"  by INDEX -> receipt path len {len(rc['entries'])}, localBlock {rc.get('localBlock')},"
          f" majorBlock {rc.get('majorBlock')}")
    print(f"  offline merkle recompute VALID: {ok}  anchor {got}")

    d = rpc(net, {"scope":"acc://dn.acme","query":{"queryType":"block","minor":1}})
    b = d["result"]
    names = [x.get("account") for x in b["entries"]["records"]]
    print(f"  DN block 1 time {b['time']}  entries {b['entries']['total']}"
          f"  includes dn.acme/network: {'acc://dn.acme/network' in names}")

    d = rpc(net, {"scope":"acc://dn.acme/ledger"})
    print("  DN height:", d["result"]["account"]["index"])

print("--- kermit: by-hash failure is not genesis-specific (dn.acme/votes) ---")
for i in (0, 1, 2, 5, 9):
    d = rpc("kermit", {"scope":"acc://dn.acme/votes",
                       "query":{"queryType":"chain","name":"main","index":i}})
    h = d.get("result", {}).get("entry")
    if not h:
        continue
    d2 = rpc("kermit", {"scope":"acc://dn.acme/votes",
                        "query":{"queryType":"chain","name":"main","entry":h}})
    print(f"  index {i} {h[:12]} -> by-hash {'OK' if 'result' in d2 else 'FAIL'}")
PY

if [ "${1:-}" = "--evm" ] || [ "${2:-}" = "--evm" ]; then
hr "§9.0.4 the three deployments are NOT identical — they differ in DEPLOYMENT_CHAIN_ID"
( set -a; . "$IV/.env.shared"; set +a
python - <<'PY'
import json, os, urllib.request, itertools
T = {"sepolia":          (os.environ["ETHEREUM_SEPOLIA_RPC_URL"], "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0"),
     "base-sepolia":     (os.environ["BASE_SEPOLIA_RPC_URL"],     "0xEA9eeeE42a7971792B11Fd2f682C9c1172490272"),
     "arbitrum-sepolia": (os.environ["ARBITRUM_SEPOLIA_RPC_URL"], "0x4b9eA187772E115641Fd40F35BF7a84925e7A035")}

def call(url, payload):
    req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["result"]

code = {}
for k,(u,a) in T.items():
    code[k] = bytes.fromhex(call(u, {"jsonrpc":"2.0","id":1,"method":"eth_getCode",
                                     "params":[a,"latest"]})[2:])
    print(f"  {k:18} {a}  {len(code[k])} bytes")
for a,b in itertools.combinations(T, 2):
    d = [i for i in range(len(code[a])) if code[a][i] != code[b][i]]
    print(f"  {a} vs {b}: {len(d)} differing bytes at {len(d)//3} three-byte sites")
u,_ = T["base-sepolia"]
print("  production CertenAccount 0x3850C52C…050389 anchorContract() ->",
      call(u, {"jsonrpc":"2.0","id":1,"method":"eth_call",
               "params":[{"to":"0x3850C52C22Eb5ac1d727784DeFdCa7C5DB050389",
                          "data":"0x712e267b"},"latest"]}))
PY
)
fi

if [ "${1:-}" = "--db" ] || [ "${2:-}" = "--db" ]; then
hr "§2B.4b/§2B.4d fleet proof database"
ssh -o BatchMode=yes -i ~/.ssh/certen_server root@116.202.214.38 \
  "docker exec certen-postgres psql -U certen -d certen_proofs -A -F'|' -c \"
select 'total', count(*)::text from proof_artifacts
union all select 'anchor_tx_hash', count(*)::text from proof_artifacts where anchor_tx_hash is not null and anchor_tx_hash<>''
union all select 'anchor_references', count(*)::text from anchor_references
union all select 'l5_merkle_path', count(merkle_path)::text from proof_artifacts
union all select 'class_'||proof_class, count(*)::text from proof_artifacts group by proof_class
union all select 'summary_only_proofs', count(distinct proof_id)::text from governance_proof_levels where level_json::text ilike '%summary_only%'
order by 1;
select date(created_at) d, count(*) total, count(merkle_path) with_l5 from proof_artifacts group by 1 order by 1 desc limit 8;\""
fi

hr "done"
