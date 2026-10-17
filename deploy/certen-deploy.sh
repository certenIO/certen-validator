#!/usr/bin/env bash
#
# One command to deploy merged work: pull, build, migrate, restart, check, and print one GREEN or RED line.
#
#   bash /root/certen-validators/deploy/certen-deploy.sh            # all three, in the safe order
#   bash /root/certen-validators/deploy/certen-deploy.sh validators # or bridge, gateway; several may be named
#
# Order for "all" is bridge -> gateway -> validators: each consumer is deployed after what it reads from.
# Validators go through deploy-validators.sh (resource-capped builds, migration first, rolling restart that keeps
# quorum). Every step stops the run on failure; nothing after a failure is touched.
set -uo pipefail

VALIDATORS=/root/certen-validators
BRIDGE=/root/api-bridge
GATEWAY=${GATEWAY:-/root/api-gateway}

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(bridge gateway validators)

summary=()
red() { printf '\n\033[31mRED\033[0m %s\n' "$*"; printf '%s\n' "${summary[@]}"; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

pull() {
    local dir=$1
    git -C "$dir" pull --ff-only -q || red "$dir: git pull --ff-only failed (local changes or diverged); nothing deployed from it"
    git -C "$dir" log --oneline -1
}

wait_container() {
    local name=$1 deadline=$((SECONDS + 240)) st
    while [ $SECONDS -lt $deadline ]; do
        st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name" 2>/dev/null || echo missing)
        case "$st" in healthy|running) return 0 ;; esac
        sleep 5
    done
    docker logs --tail 40 "$name" >&2 || true
    return 1
}

for t in "${targets[@]}"; do
    case "$t" in
    bridge)
        step "api-bridge"
        head=$(pull "$BRIDGE")
        (cd "$BRIDGE" && docker compose build --no-cache api-bridge >/tmp/certen-deploy-bridge.log 2>&1) \
            || { tail -30 /tmp/certen-deploy-bridge.log; red "api-bridge build failed; still running the old image"; }
        (cd "$BRIDGE" && docker compose up -d api-bridge >/dev/null 2>&1) || red "api-bridge up failed"
        wait_container api-bridge || red "api-bridge did not come up"
        summary+=("  api-bridge  $head")
        ;;
    gateway)
        step "api-gateway"
        head=$(pull "$GATEWAY")
        # The API AND the worker: one image, one env. The worker runs the FX feed, the entitlement publisher, the
        # pollers and the hold sweeper, so a worker left on the old image keeps the old code AND the old environment
        # (RB7: Adiri was enabled for hours with no TEL rate because only certen-gateway was recreated).
        (cd "$GATEWAY" && docker compose build certen-gateway certen-gateway-worker >/tmp/certen-deploy-gateway.log 2>&1) \
            || { tail -30 /tmp/certen-deploy-gateway.log; red "gateway build failed; still running the old image"; }
        # gateway-migrate runs first as the service's dependency; a failed migration stops the gateway from starting.
        (cd "$GATEWAY" && docker compose up -d certen-gateway certen-gateway-worker >/tmp/certen-deploy-gateway-up.log 2>&1) \
            || { tail -30 /tmp/certen-deploy-gateway-up.log; red "gateway up failed (check gateway-migrate)"; }
        wait_container certen-gateway || red "certen-gateway did not become healthy"
        wait_container certen-gateway-worker || red "certen-gateway-worker did not become healthy"
        summary+=("  gateway     $head")
        ;;
    validators)
        step "validators"
        head=$(pull "$VALIDATORS")
        bash "$VALIDATORS/deploy/deploy-validators.sh" || red "validator deploy stopped (see above); validators not yet restarted are untouched"
        summary+=("  validators  $head")
        ;;
    *)
        red "unknown target '$t' (use bridge, gateway, validators)"
        ;;
    esac
done

printf '\n\033[32mGREEN\033[0m deployed:\n'
printf '%s\n' "${summary[@]}"
