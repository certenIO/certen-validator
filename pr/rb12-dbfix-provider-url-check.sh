#!/usr/bin/env bash
# RB12-DBFIX: READ-ONLY check of the provider URL variables of the 7 validator containers against the rule the finality runtime
# enforces at startup. A provider-list entry that url.Parse rejects, or that is not an http(s) URL with a host, is NOT fatal to the
# validator: the finality runtime stays off as the named state
#   finality_upgrader_disabled{reason: config_invalid, variable, entry, class}
# (log, metric certen_finality_upgrader_disabled_total{chain="0",env=<variable>}, gauge certen_finality_upgrader_enabled 0 and the
# upgrader_disabled_reason of /health/detailed) and the validator keeps running. Find such entries BEFORE the roll, because finality
# is silently absent on every validator that shares the bad variable until it is corrected and the process restarted:
#
#   CHECK_IMAGE=<the validator image built from the commit to deploy> bash rb12-dbfix-provider-url-check.sh
#   ssh claude@host 'CHECK_IMAGE=<image> bash -s' < rb12-dbfix-provider-url-check.sh        # nothing is copied to the host
#
# HOW: the rule is url.Parse's, so it is judged by the validator's OWN code, not by a copy of its rules: for each container the script
# reads the container's configured environment with `docker inspect -f '{{json .Config.Env}}'` (metadata only: nothing runs inside
# the production container) and pipes it to `docker run --rm -i --network none --read-only $CHECK_IMAGE ./validator
# finality-config-check`, a throwaway container of the NEW image with no network and no mounts, which reads that JSON array from
# stdin and prints, for each provider variable, only: unset | ok <n entries> | REFUSED entry <i> <class> (class: no_scheme,
# other_scheme, no_host, bad_escape, bad_port, bad_userinfo, bad_host, control_character, unparseable) | REFUSED holds no entry.
# NO VALUE, NO HOST, NO PATH, NO KEY is ever printed or written; the values only travel through the pipe. Scheme case does not matter
# (HTTPS:// is accepted, as url.Parse reads it). plain http:// is accepted.
#
# SCOPE: only the variables the finality runtime parses and refuses are judged. grep of url.Parse over the validator finds no other provider
# variable that is parsed and refused at startup (pkg/ethrpc agreement.go and health.go only derive host labels from URLs they already hold);
# the provider variables of chains the finality runtime does not read are not judged here.
#
# THE VARIABLES (finruntime.ProviderVariables(), pkg/finality/runtime/config.go; a Go test keeps this list equal to that table and
# to the variables pkg/ethrpc EndpointsForChain reads):
#   ethereum-sepolia: ETHEREUM_SEPOLIA_RPC_URL ETHEREUM_URL ETHEREUM_SEPOLIA_URL_FALLBACKS ETHEREUM_URL_FALLBACKS INFURA_SEPOLIA_URL ALCHEMY_SEPOLIA_URL
#   CERTEN_FINALITY lists: CERTEN_FINALITY_L1_RPC_URLS CERTEN_FINALITY_L1_PROOF_URLS CERTEN_FINALITY_ARCHIVE_URLS CERTEN_FINALITY_LC_URLS CERTEN_FINALITY_BEACON_URLS
#   base-sepolia: BASE_SEPOLIA_RPC_URL BASE_SEPOLIA_URL_FALLBACKS INFURA_BASE_SEPOLIA_URL ALCHEMY_BASE_SEPOLIA_URL
#   arbitrum-sepolia: ARBITRUM_SEPOLIA_RPC_URL ARBITRUM_SEPOLIA_URL_FALLBACKS INFURA_ARBITRUM_SEPOLIA_URL ALCHEMY_ARBITRUM_SEPOLIA_URL
#   telcoin-adiri: TELCOIN_ADIRI_RPC_URL TELCOIN_ADIRI_URL_FALLBACKS INFURA_TELCOIN_ADIRI_URL ALCHEMY_TELCOIN_ADIRI_URL
#   CERTEN_FINALITY_ADIRI_PUBLIC_URLS
#
# Exit status: 0 no entry would be refused; 1 at least one entry would be refused; 2 docker, a container or CHECK_IMAGE is not available
# or the check could not run (nothing was judged).
set -u

VALIDATORS="${VALIDATORS:-1 2 3 4 5 6 7}"
CHECK_IMAGE="${CHECK_IMAGE:-}"

command -v docker >/dev/null 2>&1 || { echo "NOT-CHECKED docker is not available on this host"; exit 2; }
[ -n "$CHECK_IMAGE" ] || { echo "NOT-CHECKED CHECK_IMAGE is not set: the check runs the validator image that will be deployed (its own finality-config-check), build it first"; exit 2; }

refused=0; missing=0
for n in $VALIDATORS; do
  c="certen-validator-$n"
  if ! docker inspect "$c" >/dev/null 2>&1; then echo "FAIL  $c: container not found"; missing=1; continue; fi
  # the throwaway check container reads the environment of $c from stdin; its stdout is only positions and classes
  out=$(docker inspect -f '{{json .Config.Env}}' "$c" 2>/dev/null | docker run --rm -i --network none --read-only "$CHECK_IMAGE" ./validator finality-config-check 2>/dev/null)
  code=$?
  if [ "$code" -ne 0 ] && [ "$code" -ne 1 ]; then echo "FAIL  $c: the check could not run (exit $code)"; missing=1; continue; fi
  bad=$(printf '%s\n' "$out" | awk '$1=="REFUSED" && $3=="entry" {printf "%s[entry %s]=%s ", $2, $4, $5} $1=="REFUSED" && $3=="holds" {printf "%s[no entry] ", $2}')
  nset=$(printf '%s\n' "$out" | awk '$1=="ok"{n+=$3} END{print n+0}')
  if [ -n "$bad" ]; then
    echo "FAIL  $c: finality would be switched off as finality_upgrader_disabled{reason=config_invalid}: $bad"; refused=1
  elif ! printf '%s\n' "$out" | grep -q '^RESULT refused=0$'; then
    echo "FAIL  $c: the check printed no result"; missing=1
  else
    echo "PASS  $c: $nset http(s) provider entries, none that would be refused"
  fi
done
[ "$missing" -ne 0 ] && exit 2
exit "$refused"
