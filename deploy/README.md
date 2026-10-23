# deploy/

The fleet's deployment topology, under version control.

## Why this directory exists

`docker-compose.yml` lived only on the validator host at `/root/certen-validators/`. It was not in any
repository, so the topology of a seven-validator production fleet — ports, peers, volumes, dependency
order — existed in exactly one place, unreviewable and unrecoverable if that box were lost. Changes to it
were hand-applied, which is how the schema-migrate gate came to be added by editing a live file rather
than by merging a reviewed change.

`docker-compose.yml` here is a **verbatim copy** of the running file as of 2026-09-18, sha256
`3e5611947319bbf7…`, including the `schema-migrate` gate.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | the real fleet topology, copied from the host |
| `docker-compose.schema-migrate.yml` | the migrate-before-start fragment, as an overlay for stacks that keep their own compose file |

## The one thing to know before using this

**The host's copy is still the authority.** Committing it here does not make the host follow it. Until the
host's `docker-compose.yml` is replaced by this tracked file, the two can drift, and a drift is invisible.

To adopt the tracked file on the host — only when the two are already identical, which is the point of
checking first:

```sh
cd /root/certen-validators
sha256sum docker-compose.yml deploy/docker-compose.yml   # must match before you proceed
cp docker-compose.yml docker-compose.yml.bak-before-adopting-tracked
rm docker-compose.yml                                    # git refuses to overwrite an untracked file
git pull                                                 # brings the tracked copy
ln -sf deploy/docker-compose.yml docker-compose.yml      # or keep a copy and sync deliberately
docker compose -p certen-validators config >/dev/null    # validate before anything restarts
```

## Two rules learned the hard way, both on 2026-09-18

**Always pass `-p certen-validators`.** Compose derives the project name from the working directory. Running
it from a different path — a mounted `/w`, say — makes it a *different project*: it created fifteen fresh
empty volumes and tried to build a parallel stack before aborting on a container-name conflict. Nothing
was lost, but nothing had to be at risk either.

**Migrate before rolling.** `main.go` refuses to start when its migration catalog is ahead of the database.
That is correct, and it crash-looped the fleet three times in one day before the `schema-migrate` gate in
this compose file made the order structural instead of procedural. See
`docs/runbooks/schema-and-evidence-hardening.md` §0.

## Base images and the validator build (RB11-BASEIMG)

The validator `Dockerfile` has no `apk` step: its builder and runtime stages start `FROM certen/validator-builder:...` and
`certen/validator-runtime:...`, two local images that `deploy/make-base-images.sh` builds from digest-pinned bases and the exact
Alpine package versions of the day (`deploy/refresh-apk-pins.sh` resolves them). Alpine withdrawing an old package version can
therefore no longer break `git pull && docker-compose build --no-cache && docker-compose up -d`. Full model:
`docs/l4/REPRODUCIBLE_BUILD.md`.

One time per host (and again only when a base changes), then the usual command works unchanged:

```sh
cd ~/certen-validators && git pull
sh deploy/make-base-images.sh      # builds the two base images; idempotent; prints the lock
sh deploy/verify-base-images.sh    # optional: tags, manifests vs deploy/base-images.lock, build log free of apk, binary SHA-256
docker-compose build --no-cache && docker-compose up -d
```

If the build stops with `pull access denied for certen/validator-builder` (or `-runtime`), the base image is missing on this
host: run `sh deploy/make-base-images.sh`. `sh deploy/make-base-images.sh --check` (no Docker, no network) checks that the
Dockerfile and the base Dockerfiles agree; `sh deploy/base-images/test-make-base-images.sh` tests the scripts with a fake `docker`.
