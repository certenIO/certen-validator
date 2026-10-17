#!/usr/bin/env bash
# The gateway deploy must rebuild, recreate AND wait on certen-gateway-worker as well as certen-gateway: the worker runs the
# FX feed, the entitlement publisher, the pollers and the hold sweeper, and shares the image and env. Run against a fake
# docker and git that record their calls; nothing real is touched.
# usage: test-certen-deploy-gateway.sh [path-to-certen-deploy.sh]
set -uo pipefail
script=${1:-$(dirname "$0")/certen-deploy.sh}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/gw"
log="$tmp/calls.log"; : > "$log"
cat > "$tmp/bin/docker" <<SH
#!/usr/bin/env bash
echo "docker \$*" >> "$log"
case "\$1" in inspect) echo healthy ;; esac
exit 0
SH
cat > "$tmp/bin/git" <<SH
#!/usr/bin/env bash
echo "git \$*" >> "$log"
case "\$*" in *"log --oneline"*) echo "abc1234 fake head" ;; esac
exit 0
SH
chmod +x "$tmp/bin/docker" "$tmp/bin/git"
PATH="$tmp/bin:$PATH" GATEWAY="$tmp/gw" bash "$script" gateway >"$tmp/out.txt" 2>&1
rc=$?
fail=0
check() { if grep -q -- "$1" "$log"; then echo "ok   $2"; else echo "FAIL $2"; fail=1; fi; }
[ $rc -eq 0 ] || { echo "FAIL deploy script exited $rc"; cat "$tmp/out.txt"; fail=1; }
check "compose build certen-gateway certen-gateway-worker" "builds the API and the worker"
check "compose up -d certen-gateway certen-gateway-worker" "recreates the API and the worker"
check "inspect.*certen-gateway-worker" "waits for the worker to be healthy"
exit $fail
