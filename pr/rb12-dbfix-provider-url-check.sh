#!/usr/bin/env bash
# RB12-DBFIX: READ-ONLY check of the provider URL variables of the 7 validator containers against the rule the finality runtime now
# enforces at startup (pkg/finality/runtime/config.go checkURLEntries): EVERY entry of a provider list must be an http(s) URL with a
# host. A ws:// or wss:// entry (or a scheme-less one, or an http:// with no host) in any of these variables REFUSES THE STARTUP of
# the finality upgrader with a named error, so find them BEFORE the merge is deployed:
#
#   bash rb12-dbfix-provider-url-check.sh
#   ssh claude@host 'bash -s' < rb12-dbfix-provider-url-check.sh        # nothing is copied to the host
#
# It reads each variable by EXACT NAME from each validator container (docker exec, `sh`), splits it on the separators the validator
# accepts (comma, semicolon, space, tab, newline), and prints for every entry ONLY its position and its class: https, http,
# no-host (an http(s) scheme with an empty host), other-scheme (e.g. ws, wss, postgres), no-scheme. NO VALUE, NO HOST, NO PATH, NO
# KEY is ever printed or written (a provider URL may carry a credential); an unset or empty variable is reported as such.
# Exit status: 0 no entry would be refused; 1 at least one entry would be refused; 2 docker or a container is not available.
set -u

VALIDATORS="${VALIDATORS:-1 2 3 4 5 6 7}"
# The exact variable names (pkg/ethrpc EndpointsForChain per chain, plus the CERTEN_FINALITY_* lists of pkg/finality/runtime/config.go).
CHAIN_VARS="ETHEREUM_URL ETHEREUM_SEPOLIA_RPC_URL ETHEREUM_URL_FALLBACKS INFURA_SEPOLIA_URL ALCHEMY_SEPOLIA_URL \
BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_URL_FALLBACKS INFURA_BASE_SEPOLIA_URL ALCHEMY_BASE_SEPOLIA_URL \
ARBITRUM_SEPOLIA_RPC_URL ARBITRUM_SEPOLIA_URL_FALLBACKS INFURA_ARBITRUM_SEPOLIA_URL ALCHEMY_ARBITRUM_SEPOLIA_URL \
TELCOIN_ADIRI_RPC_URL TELCOIN_ADIRI_URL_FALLBACKS INFURA_TELCOIN_ADIRI_URL ALCHEMY_TELCOIN_ADIRI_URL"
FIN_VARS="CERTEN_FINALITY_L1_RPC_URLS CERTEN_FINALITY_L1_PROOF_URLS CERTEN_FINALITY_ARCHIVE_URLS CERTEN_FINALITY_LC_URLS \
CERTEN_FINALITY_BEACON_URLS CERTEN_FINALITY_ADIRI_PUBLIC_URLS"

command -v docker >/dev/null 2>&1 || { echo "NOT-CHECKED docker is not available on this host"; exit 2; }

# runs INSIDE the container: prints "<VAR> <index> <class>" per entry, "<VAR> unset" or "<VAR> empty"; never a value
probe='for v in "$@"; do
  case "$v" in *[!A-Z0-9_]*|"") continue;; esac
  eval "val=\${$v-__UNSET__}"
  if [ "$val" = "__UNSET__" ]; then echo "$v unset"; continue; fi
  if [ -z "$val" ]; then echo "$v empty"; continue; fi
  i=0
  for e in $(printf "%s" "$val" | tr ",;\t\r\n" "     "); do
    case "$e" in
      https://*|http://*)
        rest="${e#*://}"; auth="${rest%%/*}"; auth="${auth%%\?*}"; auth="${auth%%#*}"; host="${auth##*@}"
        case "$host" in ""|:*) echo "$v $i no-host";; *) case "$e" in https://*) echo "$v $i https";; *) echo "$v $i http";; esac;; esac;;
      *://*) echo "$v $i other-scheme";;
      *) echo "$v $i no-scheme";;
    esac
    i=$((i+1))
  done
  [ "$i" -eq 0 ] && echo "$v empty"
done'

refused=0; missing=0
for n in $VALIDATORS; do
  c="certen-validator-$n"
  if ! docker inspect "$c" >/dev/null 2>&1; then echo "FAIL  $c: container not found"; missing=1; continue; fi
  # shellcheck disable=SC2086
  out=$(docker exec "$c" sh -c "$probe" _ $CHAIN_VARS $FIN_VARS 2>/dev/null) || { echo "FAIL  $c: the probe could not run"; missing=1; continue; }
  bad=$(printf '%s\n' "$out" | awk '$3=="no-host"||$3=="other-scheme"||$3=="no-scheme"{printf "%s[entry %s]=%s ", $1, $2, $3}')
  nset=$(printf '%s\n' "$out" | awk '$3=="https"||$3=="http"{n++} END{print n+0}')
  if [ -n "$bad" ]; then
    echo "FAIL  $c: the finality runtime would refuse to start: $bad"; refused=1
  else
    echo "PASS  $c: $nset http(s) provider entries, none that would be refused"
  fi
  plain=$(printf '%s\n' "$out" | awk '$3=="http"{printf "%s[entry %s] ", $1, $2}')
  [ -n "$plain" ] && echo "NOTE  $c: plain http (accepted, not refused): $plain"
done
[ "$missing" -ne 0 ] && exit 2
exit "$refused"
