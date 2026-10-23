# Reproducible validator build

A released validator commit comes with the SHA-256 of the six binaries its image ships: `validator`, `govproof`, `txhash`,
`schemamigrate`, `proofv2report` and `blockproofcheck`. Anyone with the commit, the BLS ZK key files and the recorded base
images can rebuild them and get the same bytes. A running validator can then be checked against the release.

## The model: base images are built once, the validator build never talks to Alpine

Alpine withdraws old package versions from its repository every few weeks. A Dockerfile that runs `apk add` on every build
therefore breaks on a schedule it does not control, and either the pin is dropped (the claim is lowered) or someone patches
the host. Neither is acceptable for a host that rebuilds the validators dozens of times a day with exactly
`cd ~/certen-validators && git pull && docker-compose build --no-cache && docker-compose up -d`.

So the apk step lives in two **base images** that are built only when a base changes:

| Base image (local tag) | Built from | Adds (exact versions, recorded in the lock) | Read by |
|---|---|---|---|
| `certen/validator-builder:go1.25.14-alpine3.24` | `golang:1.25.14-alpine3.24@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59` (`deploy/base-images/Dockerfile.builder`) | `git`, `gcc`, `musl-dev` | the Dockerfile's `builder` stage |
| `certen/validator-runtime:alpine3.24` | `alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6` (`deploy/base-images/Dockerfile.runtime`) | `ca-certificates`, `tzdata` | the Dockerfile's runtime stage |

`sh deploy/make-base-images.sh` builds both. It resolves the current exact versions of those packages from Alpine's public
APKINDEX for the branch in the `FROM` line (`deploy/refresh-apk-pins.sh` is the shared resolver; run it alone to preview),
builds each image with `--no-cache` from the digest-pinned base, bakes `apk info -v | sort` into the image as
`/etc/certen-apk-manifest`, checks that every requested `package-version` is in that manifest, and prints the lock. The
validator `Dockerfile` has **no apk step at all**: both stages start `FROM` those tags, the builder stage prints the
builder manifest into the build log, and the runtime image carries it as `/etc/certen-builder-apk-manifest`, so a running node
can say which compiler and libc built its binaries (`docker exec certen-validator-N cat /etc/certen-builder-apk-manifest`).

If a base image is missing on a host the build stops by name at its `FROM` line (`pull access denied for
certen/validator-builder` or `...validator-runtime`; the Dockerfile header says what to run). There is no fallback to an apk
step, and a base image that was not built by the script (no `/etc/certen-apk-manifest`) stops the build too.

### What is pinned

| Input | Pin | Where |
|---|---|---|
| Builder and runtime base images | tag **and** digest | `deploy/base-images/Dockerfile.builder`, `Dockerfile.runtime` |
| Builder packages (decide the bytes of the cgo `validator`) | exact versions inside the builder image, SHA-256 of its manifest | `deploy/base-images.lock` |
| Runtime packages (`ca-certificates`, `tzdata`) | exact versions inside the runtime image, SHA-256 of its manifest | `deploy/base-images.lock` |
| Base tags the Dockerfile consumes | checked equal to the tags the base Dockerfiles produce | `sh deploy/make-base-images.sh --check` |
| Go flags | `-trimpath -buildvcs=false -ldflags=-buildid=` on every binary | `Dockerfile` |
| Go modules | `go.sum` | repository |
| BLS ZK keys | `deploy/bls_zk_keys.SHA256SUMS` (checked by the build) | `Dockerfile` |

`deploy/base-images.lock` is written by `sh deploy/make-base-images.sh --write-lock` (and `--push <registry-prefix>` adds the
registry digests): per base the tag, the `FROM` reference and digest, the Alpine branch and architecture, `apk.<package>=<version>`,
`manifest_sha256`, the resulting `image_id` and the build date. It is a tracked reference, written only when asked: a host that
rewrote a tracked file on every run would refuse the next `git pull` the day the lock moves upstream. Until someone has run
`--write-lock` on a Docker host and committed the file, `--check` reports `lock: UNRECORDED` by name.

## One-time setup on a validator host

```sh
cd ~/certen-validators && git pull
sh deploy/make-base-images.sh          # needs the network to Alpine once; prints the lock; idempotent
sh deploy/verify-base-images.sh        # optional, see below
docker-compose build --no-cache && docker-compose up -d     # exactly as before; no apk, no Alpine
```

Run `sh deploy/make-base-images.sh` again only when a base changes: a new host, a security bump (below), or a commit that moves
a `FROM` line in `deploy/base-images/` (the build then stops by name until you do). Running it when nothing changed is safe: both
tags exist and carry the versions Alpine serves, so it says `up to date` and builds nothing.

`sh deploy/verify-base-images.sh` proves on the host that the design holds: both tags exist, each image's manifest has the
SHA-256 the lock records and holds every pinned package, a `--no-cache` build of the validator `builder` stage succeeds with no
apk invocation and no request to Alpine in its log, and it prints the SHA-256 of the six binaries. `--no-build` runs only the
first two checks.

## Rebuild and compare (verifying the claim)

The build input is the commit's exact bytes. A Windows checkout with `core.autocrlf=true` rewrites line endings: the
build's own `sha256sum -c` of the key digests then fails, and embedded files would differ. Use `git archive` with
autocrlf off, or a Linux checkout. (`.gitattributes` pins the Dockerfiles and the deploy scripts to LF.)

```sh
git -c core.autocrlf=false archive <commit> | tar -x -C build/
cp -r <key custody>/bls_zk_keys <key custody>/bls_zk_keys_bls12381 build/   # the build verifies them by digest
cd build
sh deploy/make-base-images.sh --check                 # the Dockerfile and the base Dockerfiles agree; the lock is for them
sh deploy/verify-base-images.sh > run1.txt            # base manifests == the lock; build; binaries' SHA-256
sh deploy/verify-base-images.sh > run2.txt            # a second --no-cache build of the same commit
grep -E '^[0-9a-f]{64}  ' run1.txt > sums1.txt; grep -E '^[0-9a-f]{64}  ' run2.txt > sums2.txt
diff sums1.txt sums2.txt && echo IDENTICAL
```

Publish the six lines together with `deploy/base-images.lock`: the builder's `manifest_sha256` names the compiler and libc the
bytes depend on. For a running node:
`docker exec certen-validator-N sha256sum /app/validator /app/govproof /app/txhash /app/schemamigrate /app/proofv2report /app/blockproofcheck`.

Without the verify script the same comparison is
`docker build --no-cache --target builder -t certen-validator-build . && docker run --rm --entrypoint sh certen-validator-build -c 'cd /build && sha256sum validator govproof txhash schemamigrate proofv2report blockproofcheck'`, twice.

## When to rebuild a base, and how

Rebuild when Alpine ships a security fix to `ca-certificates`, `tzdata`, `git`, `gcc` or `musl-dev`, or when you move the Go or
Alpine version. The one line, on the machine that will commit the new reference:

```sh
sh deploy/make-base-images.sh --force --write-lock     # then: git add deploy/base-images.lock && git commit
```

Moving the **builder** base can change the `validator` binary (gcc and musl are in it): rebuild twice from one commit, compare,
and publish the new SHA-256 with the new lock before you release. Moving only the **runtime** base changes no binary. To
change a `FROM` line, edit `deploy/base-images/Dockerfile.*` and the matching tag in the `Dockerfile` together;
`--check` fails by name if they disagree. Other hosts then run `sh deploy/make-base-images.sh` (current Alpine versions) or
`sh deploy/make-base-images.sh --from-lock` (exactly the recorded versions; it fails by name if Alpine no longer serves one,
which is the signal to refresh the lock on the committing machine). A base can also be shared through a registry:
`--push ghcr.io/<org>` pushes both tags and records the registry digests in the lock.

## Why the Go binaries do not depend on the runtime packages

The runtime stage only copies finished files out of the builder stage. `ca-certificates` and `tzdata` are installed in the
runtime image and are read by the running process (`/etc/ssl/certs`, `/usr/share/zoneinfo`); they are not inputs of any `go build`.
No source file in this repository imports `time/tzdata` or `golang.org/x/crypto/x509roots/fallback` (`git grep` at `192c939`), so
neither data set is embedded in a binary. Hence the runtime base can take security updates without changing a published
SHA-256, while the builder base (`gcc`, `musl-dev` compile the cgo `validator`; `git` fetches modules) is recorded and published with them.

## Stated limits

- The checksums cover the binaries, not the image. Image layers carry timestamps and file metadata, so image digests
  differ between builds even when every binary is identical. The same holds for the base images: their `image_id` differs per
  build, their apk manifest hash does not.
- The key files are not in git (they are 590 MB). They are an input checked by digest, not built.
- The base images are local images in the Docker daemon, which `docker build` and `docker-compose build` use by default; a build driver that cannot see the daemon's images (a `docker-container` buildx builder) would look for the tags in a registry and stop by name.
- Building a base needs Alpine's repository once. The versions Alpine serves today are resolved and recorded; if a recorded
  version is later withdrawn, `--from-lock` fails by name and the recorded base must come from a copy of the image (a registry
  push, `docker save`), not from Alpine. A normal validator build is unaffected either way, because it never asks Alpine.
- `certen/validator-*` are local tag names. If a base image is missing, Docker also tries to pull that name from Docker Hub.
  On 2026-10-23 neither repository exists there (HTTP 404), so the build fails by name; but the `certen` namespace on Docker
  Hub is registered to someone else, so if a repository of that name were ever published a host without the local base would
  pull it. The manifest check in the Dockerfile and `deploy/verify-base-images.sh` catch a base that was not built by
  `make-base-images.sh`; they do not authenticate a hostile image. The stronger distribution is a copy under CERTEN's own
  registry organisation (`--push ghcr.io/<org>`, with the digests in the lock) and building the base on the host.
