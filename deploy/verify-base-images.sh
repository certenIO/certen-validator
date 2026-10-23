#!/bin/sh
# verify-base-images.sh - prove, on a host with Docker, that the validator image builds from the base images with no apk.
#
#   sh deploy/verify-base-images.sh              full check: tags, manifests vs the lock, a --no-cache build of the builder
#                                                stage whose log must hold no apk invocation, then the binaries' SHA-256
#   sh deploy/verify-base-images.sh --no-build   only the first two checks (seconds; no Go build)
#
# Run it after the one-time `sh deploy/make-base-images.sh` (docs/l4/REPRODUCIBLE_BUILD.md). It checks:
#   1. certen/validator-builder:<tag> and certen/validator-runtime:<tag> exist (the tags deploy/base-images/Dockerfile.*
#      produce, which `sh deploy/make-base-images.sh --check` already tied to the validator Dockerfile);
#   2. each image's /etc/certen-apk-manifest has the SHA-256 the lock records and contains every pinned package;
#   3. `docker build --no-cache --progress=plain --target builder .` succeeds and its log contains no apk invocation and no
#      request to Alpine's repository (a build that talks to Alpine is the failure this design removes);
#   4. it prints the SHA-256 of the six binaries in that image: run the script twice and `diff` the two outputs to compare
#      two builds of one commit (docs/l4/REPRODUCIBLE_BUILD.md).
# The full check compiles the validator (minutes, one CPU-heavy Go build) and needs bls_zk_keys/ in the build context, like
# any build; on a host that serves the fleet use deploy/deploy-validators.sh's resource caps or pass --no-build.
# Every failure names its cause and the script exits non-zero; it prints nothing secret.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
lock=${BASE_IMAGES_LOCK:-$here/base-images.lock}
die() { echo "verify-base-images: FATAL: $*" >&2; exit 1; }
say() { echo "verify-base-images: $*"; }

build=1
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option '$a' (try --help)" ;;
  esac
done

command -v docker >/dev/null 2>&1 || die "docker is not on PATH"
docker info >/dev/null 2>&1 || die "the Docker daemon does not answer 'docker info'"
[ -f "$lock" ] || die "$lock does not exist, so the manifests cannot be compared to it; record it first: sh deploy/make-base-images.sh --write-lock (then commit it)"

# lock_get <section> <key>
lock_get() { awk -v s="[$1]" -v k="$2" 'BEGIN{FS="="} $0==s{on=1; next} /^\[/{on=0} on && $1==k{sub(/^[^=]*=/,""); print; exit}' "$lock"; }
# lock_pkgs <section> -> "pkg-version" lines
lock_pkgs() { awk -v s="[$1]" 'BEGIN{FS="="} $0==s{on=1; next} /^\[/{on=0} on && $1 ~ /^apk\./{k=$1; sub(/^apk\./,"",k); v=$0; sub(/^[^=]*=/,"",v); print k "-" v}' "$lock"; }

for kind in builder runtime; do
  tag=$(lock_get $kind tag)
  [ -n "$tag" ] || die "$lock has no [$kind] tag"
  docker image inspect "$tag" >/dev/null 2>&1 || die "base image $tag does not exist on this host; run: sh deploy/make-base-images.sh"
  manifest=$(docker run --rm --entrypoint cat "$tag" /etc/certen-apk-manifest) || die "cannot read /etc/certen-apk-manifest from $tag"
  want=$(lock_get $kind manifest_sha256)
  have=$(echo "$manifest" | sha256sum | sed 's/ .*//')
  [ "$have" = "$want" ] || die "$tag: /etc/certen-apk-manifest has SHA-256 $have, the lock records $want (the host's base was built from different package versions; rebuild it with: sh deploy/make-base-images.sh --force --from-lock)"
  for pv in $(lock_pkgs $kind); do
    echo "$manifest" | grep -q -x -- "$pv" || die "$tag: /etc/certen-apk-manifest does not contain $pv, which the lock pins"
  done
  say "OK: $tag exists and its apk manifest ($(echo "$manifest" | wc -l | tr -d ' ') packages) matches the lock ($want)"
done

[ "$build" = 1 ] || { say "OK (--no-build): tags and manifests verified; the build and binary checks were not run"; exit 0; }

log=$(mktemp)
trap 'rm -f "$log"' EXIT
img=certen-validator-build-verify
say "building the builder stage of the validator Dockerfile with --no-cache (this compiles the validator)"
(cd "$root" && DOCKER_BUILDKIT=1 docker build --no-cache --progress=plain --target builder -t "$img" .) > "$log" 2>&1 || { tail -n 40 "$log" >&2; die "docker build of the validator Dockerfile failed (log tail above; a missing base image or bls_zk_keys/ stops it by name)"; }
if grep -n -i -E '(^|[^A-Za-z0-9_-])apk[[:space:]]+(add|update|upgrade|fetch|del|cache)|dl-cdn\.alpinelinux\.org|APKINDEX|fetch https?://[^ ]*alpine' "$log" >&2; then
  die "the validator build log above shows apk activity or a request to Alpine's repository; the Dockerfile must start FROM the base images and run no apk"
fi
say "OK: the build succeeded and its log ($(wc -l < "$log" | tr -d ' ') lines) holds no apk invocation and no request to Alpine's repository"
docker run --rm --entrypoint sh "$img" -c 'cd /build && sha256sum validator govproof txhash schemamigrate proofv2report blockproofcheck' || die "cannot hash the binaries in $img"
say "done: compare these SHA-256 with the release's (and, run twice, with each other)"
