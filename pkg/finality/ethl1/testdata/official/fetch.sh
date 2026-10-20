#!/usr/bin/env bash
# Fetches the official light_client vectors of ethereum/consensus-specs release v1.7.0-beta.4 (aa16bb4c) into an EMPTY directory and
# extracts only their light_client trees. The archives are untrusted data: each is hashed against the digest GitHub publishes for the
# release asset before anything is extracted. Run from anywhere:
#   fetch.sh <empty-dir>
# then:  CERTEN_CS_TESTS=<empty-dir> go test ./pkg/finality/ethl1/ -run 'TestOfficial|TestSnappy'
# (<empty-dir>/tests/<preset>/<fork>/light_client/{single_merkle_proof,sync,update_ranking,data_collection} is the layout the tests read.)
set -euo pipefail
dest="${1:?usage: fetch.sh <empty-dir>}"
mkdir -p "$dest"
if [ -n "$(ls -A "$dest")" ]; then echo "fetch.sh: $dest is not empty" >&2; exit 2; fi
base="https://github.com/ethereum/consensus-specs/releases/download/v1.7.0-beta.4"
declare -A digest=(
  [mainnet]=67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c
  [minimal]=26d09aea70c62ed235a120a95082d544ab1c2e6fe36bd35ea1bd5da62f3b7b68
)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for preset in mainnet minimal; do
  curl -sSL --fail -o "$tmp/$preset.tar.gz" "$base/$preset.tar.gz"
  got="$(sha256sum "$tmp/$preset.tar.gz" | cut -d' ' -f1)"
  if [ "$got" != "${digest[$preset]}" ]; then echo "fetch.sh: $preset.tar.gz sha256 $got, expected ${digest[$preset]}" >&2; exit 3; fi
  tar -xzf "$tmp/$preset.tar.gz" -C "$dest" --wildcards "tests/$preset/*/light_client/*"
done
echo "extracted the light_client trees into $dest"
