#!/bin/sh
# make-base-images.sh - build the validator's two BASE images, once, so a normal build never talks to Alpine.
#
#   certen/validator-builder:go<go version>-alpine<branch>   golang:<go>-alpine<branch>@<digest> + git gcc musl-dev
#   certen/validator-runtime:alpine<branch>                  alpine:<branch>@<digest>            + ca-certificates tzdata
#
# WHY. The validator Dockerfile used to run `apk add` against Alpine's repository on every build, and Alpine withdraws old
# package versions every few weeks, so `docker-compose build --no-cache` broke the day a pinned version left the
# repository. Now the Dockerfile has no apk step: it starts FROM these two images. They are built here, when a base changes
# (first use on a host, a security bump), from digest-pinned images and the exact versions Alpine serves today. The
# resulting `apk info -v | sort` is baked into each image (/etc/certen-apk-manifest) and into deploy/base-images.lock.
#
# ONE-TIME SETUP on a host (and again when a base changes), then the normal flow works unchanged:
#   cd ~/certen-validators && sh deploy/make-base-images.sh
#   cd ~/certen-validators && git pull && docker-compose build --no-cache && docker-compose up -d
#
# Usage: sh deploy/make-base-images.sh [--force] [--from-lock] [--write-lock] [--push <registry-prefix>] [--check]
#   (no option)    resolve the current exact versions from Alpine's public APKINDEX, build whichever base image is missing
#                  or differs from them, print the lock. Idempotent: when both images already carry exactly these
#                  versions and the digests in the Dockerfiles it says so and exits 0 without building.
#   --force        rebuild both images even when they are up to date (a security bump of the same versions' base).
#   --from-lock    use the exact versions recorded in deploy/base-images.lock instead of resolving the current ones: rebuilds
#                  the recorded base (fails by name if Alpine no longer serves one of those versions).
#   --write-lock   write the result to deploy/base-images.lock. Not the default: the lock is a tracked file, and a host
#                  that rewrote it would have a local change that makes the next `git pull` refuse when the lock moves
#                  upstream. Whoever commits a new reference base (the release) passes this.
#   --push PREFIX  also tag both images PREFIX/validator-builder:.. and PREFIX/validator-runtime:.., push them and record
#                  the registry digests in the lock (needs `docker login` for PREFIX done beforehand).
#   --check        no docker, no network: verify the repository's own consistency (the Dockerfile names exactly the tags
#                  these base Dockerfiles produce, has no apk step, and deploy/base-images.lock is for the same bases; a lock
#                  nobody has recorded yet is reported by name as 'lock: UNRECORDED').
# Environment: APK_ARCH (default: the Docker daemon's architecture), APK_MIRROR (see deploy/refresh-apk-pins.sh) and BASE_IMAGES_LOCK
#   (the lock file to read and write; default deploy/base-images.lock). Verify the result with: sh deploy/verify-base-images.sh
# Every failure names its cause. Nothing here handles a secret.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
bdir=$here/base-images
lock=${BASE_IMAGES_LOCK:-$here/base-images.lock}
resolver=$here/refresh-apk-pins.sh
main_df=$root/Dockerfile

die() { echo "make-base-images: FATAL: $*" >&2; exit 1; }
say() { echo "make-base-images: $*"; }

force=0; from_lock=0; write_lock=0; check=0; push_prefix=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=1 ;;
    --from-lock) from_lock=1 ;;
    --write-lock) write_lock=1 ;;
    --check) check=1 ;;
    --push)
      [ $# -ge 2 ] || die "--push needs a registry prefix, e.g. --push ghcr.io/certenio"
      push_prefix=$2; shift ;;
    -h|--help) sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option '$1' (try --help)" ;;
  esac
  shift
done

# ---- reading the base Dockerfiles ---------------------------------------------------------------------------------------

# from_ref <Dockerfile> -> the single FROM reference, which must be <name>:<tag>@sha256:<64 hex>
from_ref() {
  [ -f "$1" ] || die "cannot read $1"
  r=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1/p' "$1")
  [ -n "$r" ] || die "$1 has no FROM line"
  [ "$(echo "$r" | wc -l | tr -d ' ')" = 1 ] || die "$1 must have exactly one FROM line"
  case "$r" in
    *:*@sha256:????????????????????????????????????????????????????????????????) ;;
    *) die "$1: FROM $r is not pinned by tag AND digest (<name>:<tag>@sha256:<64 hex>); a moving tag would make the base unreproducible" ;;
  esac
  echo "$r"
}

# branch_of <ref> -> the Alpine branch (3.24) ; go_of <ref> -> the Go version (1.25.14) or empty
branch_of() {
  n=${1%%@*}; t=${n#*:}
  case "$n" in
    alpine:*) echo "$t" ;;
    *-alpine[0-9]*) echo "${t##*-alpine}" ;;
    *) die "cannot read an Alpine branch from $1" ;;
  esac
}
go_of() { n=${1%%@*}; t=${n#*:}; case "$t" in [0-9]*-alpine*) echo "${t%%-alpine*}" ;; esac; }

builder_ref=$(from_ref "$bdir/Dockerfile.builder")
runtime_ref=$(from_ref "$bdir/Dockerfile.runtime")
builder_branch=$(branch_of "$builder_ref")
runtime_branch=$(branch_of "$runtime_ref")
go_ver=$(go_of "$builder_ref")
[ -n "$go_ver" ] || die "deploy/base-images/Dockerfile.builder: cannot read the Go version from FROM $builder_ref"
builder_tag="certen/validator-builder:go${go_ver}-alpine${builder_branch}"
runtime_tag="certen/validator-runtime:alpine${runtime_branch}"
builder_digest=${builder_ref#*@}
runtime_digest=${runtime_ref#*@}

# ---- consistency of the repository (also --check) -----------------------------------------------------------------------

check_files() {
  bad=0
  [ -f "$main_df" ] || die "cannot read $main_df"
  grep -q "^FROM ${builder_tag} AS builder\$" "$main_df" || { echo "make-base-images: the Dockerfile's builder stage must be 'FROM ${builder_tag} AS builder' (the tag deploy/base-images/Dockerfile.builder produces)" >&2; bad=1; }
  grep -q "^FROM ${runtime_tag}\$" "$main_df" || { echo "make-base-images: the Dockerfile's runtime stage must be 'FROM ${runtime_tag}' (the tag deploy/base-images/Dockerfile.runtime produces)" >&2; bad=1; }
  others=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1/p' "$main_df" | grep -v -x -e "${builder_tag}" -e "${runtime_tag}" || true)
  [ -z "$others" ] || { echo "make-base-images: the Dockerfile has a stage that is not one of the two base images: $(echo "$others" | tr '\n' ' ')" >&2; bad=1; }
  if grep -n -E '^[^#]*(^|[^A-Za-z0-9_-])apk([^A-Za-z0-9_-]|$)' "$main_df" >&2; then
    echo "make-base-images: the Dockerfile has an apk step above; packages belong in the base images (deploy/base-images/)" >&2; bad=1
  fi
  for f in "$root/docker-compose.yml.example" "$root/docker-compose.example.yml" "$here/docker-compose.schema-migrate.yml"; do
    [ -f "$f" ] || continue
    if grep -n -E '^[[:space:]]*dockerfile:' "$f" >&2; then
      echo "make-base-images: $f builds from a Dockerfile other than the root Dockerfile; convert its apk use to a base image" >&2; bad=1
    fi
    if grep -n -E '^[^#]*(^|[^A-Za-z0-9_-])apk([^A-Za-z0-9_-]|$)' "$f" >&2; then
      echo "make-base-images: $f runs apk; packages belong in the base images (deploy/base-images/)" >&2; bad=1
    fi
  done
  [ "$bad" = 0 ] || die "repository files are inconsistent (see above)"
}

# lock_get <section> <key> -> value from the lock file (empty when absent)
lock_get() {
  [ -f "$lock" ] || return 0
  awk -v s="[$1]" -v k="$2" 'BEGIN{FS="="} $0==s{on=1; next} /^\[/{on=0} on && $1==k{sub(/^[^=]*=/,""); print; exit}' "$lock"
}

check_lock() {
  [ -f "$lock" ] || die "deploy/base-images.lock does not exist (create it with: sh deploy/make-base-images.sh --write-lock)"
  bad=0
  for k in builder runtime; do
    case $k in builder) t=$builder_tag; r=$builder_ref ;; runtime) t=$runtime_tag; r=$runtime_ref ;; esac
    [ "$(lock_get $k tag)" = "$t" ] || { echo "make-base-images: lock [$k] tag is '$(lock_get $k tag)', the Dockerfile produces '$t'" >&2; bad=1; }
    [ "$(lock_get $k from)" = "$r" ] || { echo "make-base-images: lock [$k] from is '$(lock_get $k from)', the Dockerfile says '$r'" >&2; bad=1; }
    [ -n "$(lock_get $k manifest_sha256)" ] || { echo "make-base-images: lock [$k] has no manifest_sha256" >&2; bad=1; }
    [ -n "$(lock_get $k image_id)" ] || { echo "make-base-images: lock [$k] has no image_id" >&2; bad=1; }
  done
  [ "$bad" = 0 ] || die "deploy/base-images.lock is not for the base Dockerfiles in this checkout; rebuild and run: sh deploy/make-base-images.sh --write-lock"
}

check_files
if [ "$check" = 1 ]; then
  if [ -f "$lock" ]; then
    check_lock
    say "OK: the Dockerfile, the compose files and deploy/base-images.lock agree with deploy/base-images/ ($builder_tag, $runtime_tag)"
  else
    # a named state, not a pass: nothing can be compared to a lock nobody has recorded (recording needs a real build)
    say "OK: the Dockerfile and the compose files agree with deploy/base-images/ ($builder_tag, $runtime_tag)"
    say "lock: UNRECORDED - $lock does not exist; the first '--write-lock' run on a host with Docker creates it, and it is then committed"
  fi
  exit 0
fi

# ---- docker -------------------------------------------------------------------------------------------------------------

command -v docker >/dev/null 2>&1 || die "docker is not on PATH; this builds the base images and needs the Docker CLI and a running daemon"
arch_raw=$(docker info --format '{{.Architecture}}' 2>/dev/null) || die "the Docker daemon does not answer 'docker info' (is it running, and may this user use it?)"
if [ -z "${APK_ARCH:-}" ]; then
  case "$arch_raw" in
    x86_64|amd64) APK_ARCH=x86_64 ;;
    aarch64|arm64) APK_ARCH=aarch64 ;;
    *) die "unknown Docker daemon architecture '$arch_raw'; set APK_ARCH (x86_64 or aarch64)" ;;
  esac
fi
export APK_ARCH

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# lock_pins <section> -> "pkg=ver ..." recorded in the lock
lock_pins() {
  [ -f "$lock" ] || die "--from-lock needs deploy/base-images.lock, which does not exist"
  awk -v s="[$1]" 'BEGIN{FS="="} $0==s{on=1; next} /^\[/{on=0} on && $1 ~ /^apk\./{k=$1; sub(/^apk\./,"",k); v=$0; sub(/^[^=]*=/,"",v); printf "%s%s=%s", (n++?" ":""), k, v}' "$lock"
}

label() { docker image inspect --format "{{index .Config.Labels \"$2\"}}" "$1"; }

# process_base <kind> <Dockerfile> <tag> <ref> <digest>: bring one base image to the wanted versions, write $tmp/lock.<kind>
process_base() {
  kind=$1; df=$2; tag=$3; ref=$4; digest=$5
  if [ "$from_lock" = 1 ]; then
    pins=$(lock_pins "$kind")
    [ -n "$pins" ] || die "deploy/base-images.lock has no [$kind] apk.<package>=<version> lines to rebuild from"
    [ "$(lock_get "$kind" from)" = "$ref" ] || die "--from-lock: the lock's [$kind] base is '$(lock_get "$kind" from)' but $(basename "$df") says '$ref'"
    say "$kind: using the versions recorded in the lock: $pins"
  else
    pins=$(sh "$resolver" --pins "$df") || die "could not resolve the current $kind package versions (see above)"
    say "$kind: Alpine serves now: $pins"
  fi
  have=""
  if docker image inspect "$tag" >/dev/null 2>&1; then
    have="$(label "$tag" io.certen.apk.pins) $(label "$tag" org.opencontainers.image.base.digest)"
  fi
  if [ "$force" = 0 ] && [ "$have" = "$pins $digest" ]; then
    say "$kind: $tag is up to date (already carries exactly these versions on $ref); not rebuilding"
  else
    if [ -z "$have" ]; then
      say "$kind: $tag is missing; building it"
    elif [ "$force" = 1 ]; then
      say "$kind: --force: rebuilding $tag (image has '$have')"
    else
      say "$kind: $tag has '$have', not '$pins $digest'; rebuilding it"
    fi
    docker build --no-cache -f "$df" -t "$tag" \
      --build-arg "APK_PINS=$pins" --build-arg "BASE_NAME=${ref%%@*}" --build-arg "BASE_DIGEST=$digest" --build-arg "BUILD_DATE=$now" \
      "$bdir" || die "docker build of $tag failed (the apk step names the package if Alpine does not serve a requested version)"
  fi
  manifest=$(docker run --rm --entrypoint cat "$tag" /etc/certen-apk-manifest) || die "cannot read /etc/certen-apk-manifest from $tag"
  for pv in $pins; do
    p=${pv%%=*}; v=${pv#*=}
    echo "$manifest" | grep -q -x -- "$p-$v" || die "$tag does not contain $p-$v in /etc/certen-apk-manifest although it was requested; refusing to record it"
  done
  mfsha=$(echo "$manifest" | sha256sum | sed 's/ .*//')
  id=$(docker image inspect --format '{{.Id}}' "$tag") || die "cannot inspect $tag"
  built=$(label "$tag" org.opencontainers.image.created)
  {
    echo "[$kind]"
    echo "tag=$tag"
    echo "from=$ref"
    echo "base_digest=$digest"
    echo "alpine_branch=$(branch_of "$ref")"
    echo "arch=$APK_ARCH"
    for pv in $pins; do echo "apk.${pv%%=*}=${pv#*=}"; done
    echo "manifest_sha256=$mfsha"
    echo "image_id=$id"
    echo "built=$built"
  } > "$tmp/lock.$kind"
}

# push_base <kind> <Dockerfile-less: tag> : tag + push, append registry digest to $tmp/lock.<kind>
push_base() {
  kind=$1; tag=$2
  remote="${push_prefix%/}/${tag#certen/}"
  docker tag "$tag" "$remote" || die "cannot tag $tag as $remote"
  docker push "$remote" > "$tmp/push.$kind" 2>&1 || { cat "$tmp/push.$kind" >&2; die "docker push $remote failed (docker login to ${push_prefix%%/*} first?)"; }
  dg=$(sed -n 's/.*digest: \(sha256:[0-9a-f]*\).*/\1/p' "$tmp/push.$kind" | tail -n 1)
  [ -n "$dg" ] || { cat "$tmp/push.$kind" >&2; die "docker push $remote printed no digest"; }
  echo "registry=${remote%%:*}@$dg" >> "$tmp/lock.$kind"
  say "$kind: pushed $remote -> $dg"
}

process_base builder "$bdir/Dockerfile.builder" "$builder_tag" "$builder_ref" "$builder_digest"
process_base runtime "$bdir/Dockerfile.runtime" "$runtime_tag" "$runtime_ref" "$runtime_digest"
if [ -n "$push_prefix" ]; then
  push_base builder "$builder_tag"
  push_base runtime "$runtime_tag"
fi

{
  echo "# CERTEN validator base images. Written by deploy/make-base-images.sh; see docs/l4/REPRODUCIBLE_BUILD.md."
  echo "# lock-format 1"
  cat "$tmp/lock.builder"
  echo
  cat "$tmp/lock.runtime"
} > "$tmp/lock.new"

echo
cat "$tmp/lock.new"
echo

# the reference lock is compared without its host-specific lines (an image id and a build date differ on every host)
stable() { grep -v -E '^(image_id|built|registry)=' "$1" || true; }
if [ -f "$lock" ]; then
  stable "$lock" > "$tmp/ref.stable"; stable "$tmp/lock.new" > "$tmp/new.stable"
  if cmp -s "$tmp/ref.stable" "$tmp/new.stable"; then
    say "deploy/base-images.lock matches these versions, digests and manifests"
  else
    say "deploy/base-images.lock DIFFERS from the images above (reference vs this host):"
    diff "$tmp/ref.stable" "$tmp/new.stable" || true
  fi
fi
if [ "$write_lock" = 1 ]; then
  cp "$tmp/lock.new" "$lock"
  say "wrote deploy/base-images.lock; review it, then commit it"
else
  say "deploy/base-images.lock was NOT written (pass --write-lock when you are committing a new reference base)"
fi
say "done: 'docker-compose build' now starts FROM $builder_tag and $runtime_tag and runs no apk"
