#!/usr/bin/env bash
#
# Safe rebuild + rolling restart of the seven validators.
#
# WHY THIS SCRIPT EXISTS
#
# On 2026-08-02 a plain `docker compose build` on the production host drove the load average
# past 5800 and stopped sshd from forking. Two things caused it, and this script prevents both:
#
#   1. The Dockerfile regenerated the Groth16 ZK keys when they were absent from the build
#      context. That is a trusted setup over a BLS12-381 pairing circuit — multi-GB, all cores.
#      The Dockerfile now hard-fails instead, and PREFLIGHT below catches the missing keys
#      before a build is even started.
#   2. Nothing bounded the build's resource use on a host already running seven validators plus
#      a dozen other containers. Every build here is capped and runs ONE service at a time.
#
# It also protects consensus: restarts roll in groups that keep CometBFT above its 5-of-7
# quorum, and each group must come back healthy before the next is touched.
#
# Usage:  ./deploy/deploy-validators.sh [--preflight-only]
set -euo pipefail

COMPOSE_DIR=${COMPOSE_DIR:-/root/certen-validators}
KEYS_DIR="$COMPOSE_DIR/bls_zk_keys"
SUMS="$COMPOSE_DIR/deploy/bls_zk_keys.SHA256SUMS"
SERVICES=(validator-1 validator-2 validator-3 validator-4 validator-5 validator-6 validator-7)

# Restart groups. Never more than 2 down at once: CometBFT needs 5 of 7 to make progress, so
# taking 3 down stalls the chain and taking 4 down halts it.
# NOT named GROUPS: bash reserves that as a readonly array of the current user's group IDs, so
# the assignment is silently ignored and the loop iterates over group numbers instead of
# service names ("restarting: 0" / "no such service: 0").
RESTART_GROUPS=("validator-1 validator-2" "validator-3 validator-4" "validator-5 validator-6" "validator-7")

# Build limits. The host has other tenants; a build must never be able to starve them.
BUILD_CPUS=${BUILD_CPUS:-2}
# systemd size suffixes are UPPERCASE (K/M/G/T). "4g" is rejected with
# "Failed to parse MemoryMax=4g: Invalid argument", which aborts the build.
BUILD_MEMORY=${BUILD_MEMORY:-4G}
GO_PARALLEL=${GO_PARALLEL:-2}

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
die()  { printf '\n\033[31mFATAL\033[0m %s\n\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# PREFLIGHT — everything that must be true BEFORE a single CPU cycle is spent
# ---------------------------------------------------------------------------
log "Preflight"

cd "$COMPOSE_DIR" || die "compose dir $COMPOSE_DIR not found"

# Load. Building on an already-loaded box is how this went wrong the first time.
cores=$(nproc)
load1=$(awk '{print $1}' /proc/loadavg)
if awk -v l="$load1" -v c="$cores" 'BEGIN{exit !(l > c*2)}'; then
    die "load average $load1 on $cores cores is already above 2x capacity. Let it settle first."
fi
ok "load $load1 on $cores cores"

# Free memory. A Go build of this project needs headroom; without it the box swaps and thrashes.
avail_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
[ "$avail_mb" -ge 3000 ] || die "only ${avail_mb}MB available; need >=3000MB headroom to build safely"
ok "${avail_mb}MB memory available"

# THE ZK KEYS. This is the check whose absence melted the host.
[ -d "$KEYS_DIR" ] || die "$KEYS_DIR is missing.
       bls_zk_keys/ is gitignored, so 'git pull' never delivers it — stage it from key custody.
       Do NOT let anything generate it: groth16.Setup samples fresh toxic waste every run, so a
       regenerated key cannot match the deployed verifier, and every proof would be rejected on
       chain — batch attestation AND the per-intent on_demand path."
[ -f "$SUMS" ] || die "$SUMS is missing; the keys cannot be verified"
( cd "$KEYS_DIR" && sha256sum -c "$SUMS" >/dev/null 2>&1 ) \
    || die "BLS ZK key digests do not match $SUMS.
       These keys must not ship. Restore the keys that match the deployed verifier, or deploy a
       verifier generated from these keys — never ship a mismatch."
ok "BLS ZK keys present and match pinned digests"

# Period config must be identical across services: both values feed the bundleId, so a node
# configured differently can neither propose a batch its peers will co-sign nor co-sign theirs.
for v in BATCH_PERIOD_BLOCKS BATCH_LEADER_VALIDATORS; do
    n=$(grep -c "^${v}=" .env.shared || true)
    [ "$n" -eq 1 ] || die "$v appears $n times in .env.shared; it must appear exactly once"
    ok "$v=$(grep "^${v}=" .env.shared | cut -d= -f2- | cut -c1-60)"
done

# The resource caps must be well-formed, and systemd must accept them. Discovering a typo
# after the first build has already run is a waste of ten minutes of CPU on a shared host;
# discovering it when the cap is silently DROPPED would be worse, because the whole point is
# that a build can never again starve the box.
case "$BUILD_MEMORY" in
    *[0-9][KMGT]) : ;;
    *) die "BUILD_MEMORY='$BUILD_MEMORY' — systemd size suffixes are uppercase (e.g. 4G)" ;;
esac
systemd-run --scope -q -p CPUQuota="$((BUILD_CPUS * 100))%" -p MemoryMax="$BUILD_MEMORY" \
    true >/dev/null 2>&1 \
    || die "systemd rejected the resource caps (CPUQuota=$((BUILD_CPUS * 100))% MemoryMax=$BUILD_MEMORY).
       Refusing to build uncapped — that is what took the host down."
ok "resource caps accepted: cpus=$BUILD_CPUS memory=$BUILD_MEMORY go -p=$GO_PARALLEL"

# All seven must currently be up, or a rolling restart could drop the set below quorum.
running=$(docker ps --filter name=certen-validator --filter status=running -q | wc -l)
[ "$running" -eq 7 ] || die "only $running/7 validators running; fix that before rolling a deploy"
ok "7/7 validators running"

if [ "${1:-}" = "--preflight-only" ]; then
    log "Preflight passed (--preflight-only, stopping here)"
    exit 0
fi

# ---------------------------------------------------------------------------
# BUILD — one service at a time, resource-capped
# ---------------------------------------------------------------------------
log "Build (cpus=$BUILD_CPUS memory=$BUILD_MEMORY go -p=$GO_PARALLEL)"

# GOMAXPROCS and -p bound the Go toolchain; the cgroup bounds everything else including any
# child the build spawns. Belt and braces, because the failure mode is losing the whole host.
export DOCKER_BUILDKIT=1
for svc in "${SERVICES[@]}"; do
    printf '  building %s ... ' "$svc"
    if ! systemd-run --scope -q \
            -p CPUQuota="$((BUILD_CPUS * 100))%" \
            -p MemoryMax="$BUILD_MEMORY" \
            docker compose build \
                --build-arg GOFLAGS="-p=$GO_PARALLEL" \
                "$svc" >"/tmp/build-$svc.log" 2>&1; then
        printf 'FAILED\n'
        tail -30 "/tmp/build-$svc.log" >&2
        die "build of $svc failed; nothing has been restarted"
    fi
    printf 'ok\n'
done
ok "all seven images built"

# ---------------------------------------------------------------------------
# ROLLING RESTART — quorum preserved throughout
# ---------------------------------------------------------------------------
log "Rolling restart"

wait_healthy() {
    local svc=$1 deadline=$((SECONDS + 180))
    while [ $SECONDS -lt $deadline ]; do
        local st
        st=$(docker inspect -f '{{.State.Health.Status}}' "certen-$svc" 2>/dev/null || echo missing)
        [ "$st" = healthy ] && return 0
        sleep 5
    done
    return 1
}

for group in "${RESTART_GROUPS[@]}"; do
    printf '  restarting: %s\n' "$group"
    # shellcheck disable=SC2086
    docker compose up -d --no-deps $group >/dev/null
    for svc in $group; do
        if wait_healthy "$svc"; then
            ok "$svc healthy"
        else
            docker logs --tail 40 "certen-$svc" >&2 || true
            die "$svc did not become healthy; remaining validators were NOT touched"
        fi
    done

    # Identity is self-configured from the anchor's BLS registry. A node that cannot resolve it
    # refuses every peer attestation request, so the quorum would run short with nothing
    # obviously wrong. Surface it here rather than in a failed batch hours later.
    for svc in $group; do
        if docker logs "certen-$svc" 2>&1 | tail -400 | grep -q "Attesting as"; then
            ok "$svc resolved its attester identity"
        else
            printf '  \033[33mWARN\033[0m %s has not logged an attester identity yet\n' "$svc"
        fi
    done
done

log "Done"
docker ps --filter name=certen-validator --format '  {{.Names}}\t{{.Status}}'
