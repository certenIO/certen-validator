#!/bin/sh
# refresh-apk-pins.sh - the shared resolver: which EXACT Alpine package versions would a base image install today?
#
# The validator Dockerfile has no apk step any more (docs/l4/REPRODUCIBLE_BUILD.md): git, gcc, musl-dev (builder) and
# ca-certificates, tzdata (runtime) are installed once, when deploy/make-base-images.sh builds the two base images from
# deploy/base-images/Dockerfile.builder and Dockerfile.runtime. This script is the part of that step that talks to Alpine:
# it reads the public APKINDEX of the Alpine branch named in a base Dockerfile's FROM line and prints the version Alpine
# serves now for every package on that file's `# certen-apk-packages:` line.
#
#   sh deploy/refresh-apk-pins.sh                      # human-readable preview for both base Dockerfiles
#   sh deploy/refresh-apk-pins.sh --pins <Dockerfile>  # one line, "pkg=version pkg=version", for scripts (make-base-images.sh)
#
# Needs: curl, tar, awk, sed. It never changes a file. A package missing from the index, a download that fails and an
# unreadable Dockerfile each stop it with a message that names the cause (there is no default version to fall back to).
# Environment: APK_ARCH (default x86_64; make-base-images.sh passes the Docker daemon's architecture) and APK_MIRROR
# (default https://dl-cdn.alpinelinux.org/alpine; any mirror with the same layout, file:// included).
set -eu
here=$(cd "$(dirname "$0")" && pwd)

die() { echo "refresh-apk-pins: FATAL: $*" >&2; exit 1; }

# alpine_branch <Dockerfile> -> prints the Alpine branch of its FROM line (3.24 from golang:1.25.14-alpine3.24@sha256:..
# or alpine:3.24@sha256:..)
alpine_branch() {
  froms=$(sed -n 's/^FROM[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1/p' "$1")
  [ -n "$froms" ] || die "$1 has no FROM line"
  [ "$(echo "$froms" | wc -l | tr -d ' ')" = 1 ] || die "$1 must have exactly one FROM line (found: $(echo "$froms" | tr '\n' ' '))"
  name=${froms%%@*}
  tag=${name#*:}
  case "$name" in
    alpine:*) branch=$tag ;;
    *-alpine[0-9]*) branch=${tag##*-alpine} ;;
    *) die "$1: cannot read an Alpine branch from FROM $froms (expected alpine:X.Y or <image>-alpineX.Y)" ;;
  esac
  case "$branch" in
    [0-9]*.[0-9]*) ;;
    *) die "$1: '$branch' is not an Alpine X.Y branch (FROM $froms)" ;;
  esac
  echo "$branch"
}

# packages_of <Dockerfile> -> the names on its `# certen-apk-packages:` line
packages_of() {
  pk=$(sed -n 's/^#[[:space:]]*certen-apk-packages:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$1")
  [ -n "$pk" ] || die "$1 has no '# certen-apk-packages: <names>' line"
  [ "$(echo "$pk" | wc -l | tr -d ' ')" = 1 ] || die "$1 has more than one '# certen-apk-packages:' line"
  echo "$pk"
}

# resolve <Dockerfile> -> "pkg=version pkg=version" as Alpine serves them now
resolve() {
  [ -f "$1" ] || die "cannot read $1"
  br=$(alpine_branch "$1")
  pk=$(packages_of "$1")
  arch=${APK_ARCH:-x86_64}
  mirror=${APK_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
  command -v curl >/dev/null 2>&1 || die "curl is needed to read Alpine's APKINDEX"
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  for repo in main community; do
    url="$mirror/v$br/$repo/$arch/APKINDEX.tar.gz"
    curl -sSfL -m 120 -o "$tmp/$repo.tgz" "$url" || die "cannot download $url (is the Alpine branch v$br, the architecture $arch and the network right?)"
    mkdir -p "$tmp/$repo"
    tar -xzf "$tmp/$repo.tgz" -C "$tmp/$repo" APKINDEX || die "$url is not a readable APKINDEX archive"
  done
  out=""
  for p in $pk; do
    ver=$(awk -v p="$p" 'BEGIN{RS="";FS="\n"} {n="";v="";for(i=1;i<=NF;i++){if($i~/^P:/)n=substr($i,3); if($i~/^V:/)v=substr($i,3)} if(n==p){print v; exit}}' "$tmp/main/APKINDEX" "$tmp/community/APKINDEX")
    [ -n "$ver" ] || die "package $p (named in $1) is not in Alpine v$br main or community for $arch"
    out="${out:+$out }$p=$ver"
  done
  rm -rf "$tmp"
  trap - EXIT
  echo "$out"
}

case "${1:-}" in
  --pins)
    [ $# -eq 2 ] || die "usage: refresh-apk-pins.sh --pins <Dockerfile>"
    resolve "$2"
    ;;
  "")
    for df in "$here/base-images/Dockerfile.builder" "$here/base-images/Dockerfile.runtime"; do
      printf '%s (Alpine v%s): %s\n' "deploy/base-images/$(basename "$df")" "$(alpine_branch "$df")" "$(resolve "$df")"
    done
    echo "These are the versions the next 'sh deploy/make-base-images.sh --force' would install; nothing was changed."
    ;;
  -h|--help)
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown argument '$1' (use no argument, --pins <Dockerfile> or --help)"
    ;;
esac
