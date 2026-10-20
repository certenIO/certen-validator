#!/bin/sh
# refresh-apk-pins.sh - move the BUILDER apk pins in the Dockerfile to the versions Alpine currently serves.
#
# Use it when `docker-compose build` stops with "unable to select packages ... breaks: world[git=...]" (or gcc / musl-dev):
# Alpine withdrew a pinned version. It reads the public APKINDEX of the Alpine branch named in the Dockerfile's builder
# image tag (golang:...-alpineX.Y), rewrites the `apk add` line of the builder stage, and prints the diff. Then:
#   git diff Dockerfile            # check the new versions
#   docker-compose build --no-cache && docker-compose up -d
#   git commit -am "Move the builder apk pins to the versions Alpine serves"
# Policy (docs/l4/REPRODUCIBLE_BUILD.md): a moved builder pin changes the cgo binary, so rebuild twice from the same
# commit, compare the SHA-256 of the binaries and publish the new values before you release.
# Needs: curl, tar, awk, sed. Does not touch the runtime stage (its packages are unpinned by design).
set -eu
cd "$(dirname "$0")/.."
branch=$(sed -n 's/^FROM golang:[^ ]*-alpine\([0-9][0-9]*\.[0-9][0-9]*\).*AS builder.*/\1/p' Dockerfile | head -n1)
[ -n "$branch" ] || { echo "cannot read the Alpine branch from the builder FROM line" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for repo in main community; do
  curl -sSfL -m 120 -o "$tmp/$repo.tgz" "https://dl-cdn.alpinelinux.org/alpine/v$branch/$repo/x86_64/APKINDEX.tar.gz"
  mkdir -p "$tmp/$repo"
  tar -xzf "$tmp/$repo.tgz" -C "$tmp/$repo" APKINDEX
done
line="RUN apk add --no-cache"
for pkg in $(sed -n 's/^RUN apk add --no-cache \(.*\)$/\1/p' Dockerfile | head -n1 | tr ' ' '\n' | sed 's/=.*//'); do
  ver=$(awk -v p="$pkg" 'BEGIN{RS="";FS="\n"} {n="";v="";for(i=1;i<=NF;i++){if($i~/^P:/)n=substr($i,3); if($i~/^V:/)v=substr($i,3)} if(n==p){print v; exit}}' "$tmp/main/APKINDEX" "$tmp/community/APKINDEX")
  [ -n "$ver" ] || { echo "package $pkg not found in Alpine v$branch" >&2; exit 1; }
  line="$line $pkg=$ver"
done
# only the builder stage's first apk line is rewritten (the runtime line is unpinned and does not match the pattern)
sed -i "0,/^RUN apk add --no-cache git=.*/s//$line/" Dockerfile
if [ -f docs/l4/REPRODUCIBLE_BUILD.md ]; then
  pins=$(echo "$line" | sed 's/^RUN apk add --no-cache //' | sed 's/\([^ ]*\)/`\1`/g; s/` `/`, `/g')
  sed -i "s/^| Builder packages | .* |$/| Builder packages | $pins |/" docs/l4/REPRODUCIBLE_BUILD.md
fi
git --no-pager diff --stat Dockerfile docs/l4/REPRODUCIBLE_BUILD.md 2>/dev/null || true
echo "builder pins now: $line"
