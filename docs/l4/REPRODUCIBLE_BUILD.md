# Reproducible validator build

A released validator commit comes with the SHA-256 of the five binaries its image ships: `validator`, `govproof`, `txhash`,
`schemamigrate` and `proofv2report`. Anyone with the commit and the BLS ZK key files can rebuild them and get the same bytes. A running
validator can then be checked against the release.

## What is pinned (Dockerfile)

| Input | Pin |
|---|---|
| Builder image | `golang:1.25.14-alpine3.24@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59` |
| Builder packages | `git=2.54.0-r0`, `gcc=15.2.0-r5`, `musl-dev=1.2.6-r2` |
| Runtime image | `alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6` |
| Runtime packages | `ca-certificates=20260909-r0`, `tzdata=2026d-r0` |
| Go flags | `-trimpath -buildvcs=false -ldflags=-buildid=` on every binary |
| Go modules | `go.sum` |
| BLS ZK keys | `deploy/bls_zk_keys.SHA256SUMS` (checked by the build) |

A tag such as `golang:1.25-alpine` or `alpine:latest` resolves to different images over time. A digest does not.
Alpine keeps only current package versions in its repositories: when a pinned version is withdrawn, `apk add` fails by
name. The build stops rather than silently switching to another compiler or libc. To move a pin, change it, rebuild
twice from one commit, compare, and publish the new values here.

## Rebuild and compare

The build input is the commit's exact bytes. A Windows checkout with `core.autocrlf=true` rewrites line endings: the
build's own `sha256sum -c` of the key digests then fails, and embedded files would differ. Use `git archive` with
autocrlf off, or a Linux checkout.

```sh
git -c core.autocrlf=false archive <commit> | tar -x -C build/
cp -r <key custody>/bls_zk_keys <key custody>/bls_zk_keys_bls12381 build/   # the build verifies them by digest
cd build
docker build --no-cache --target builder -t certen-validator-build .
docker run --rm --entrypoint sh certen-validator-build -c \
  'cd /build && sha256sum validator govproof txhash schemamigrate proofv2report'
```

Compare with the release's checksums. For a running node:
`docker exec certen-validator-N sha256sum /app/validator /app/govproof /app/txhash /app/schemamigrate /app/proofv2report`.

## Stated limits

- The checksums cover the binaries, not the image. Image layers carry timestamps and file metadata, so image digests
  differ between builds even when every binary is identical.
- The key files are not in git (they are 590 MB). They are an input checked by digest, not built.
- A rebuild needs the pinned package versions to still be in Alpine's repositories. When one is withdrawn, the
  rebuild fails by name until the pin is moved (and the next release publishes new checksums).
