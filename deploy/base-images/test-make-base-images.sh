#!/bin/sh
# test-make-base-images.sh - adversarial test of deploy/make-base-images.sh and deploy/refresh-apk-pins.sh WITHOUT a Docker
# daemon or the network: a recording fake `docker` on PATH logs the exact command lines the script runs and keeps image
# state in a directory, and a fixture Alpine mirror (file://) serves a small APKINDEX. Run it from anywhere:
#   sh deploy/base-images/test-make-base-images.sh
# It checks, among other things, that the repository's own Dockerfile has no apk step and starts FROM the two base tags
# (the check that failed on the commit before the base images existed), that the script builds exactly the images and
# build arguments the design names, is idempotent, rebuilds only what changed, names every failure, and never rewrites the
# tracked lock unless asked. It does NOT run a real build; the real-Docker evidence is recorded in the work package report.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok() { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { failn=$((failn + 1)); echo "FAIL - $1"; [ -z "${2:-}" ] || echo "$2" | sed 's/^/         /'; }
# has <name> <output file> <text that must be in it>
has() { if grep -q -F -e "$3" "$2"; then ok "$1"; else bad "$1 (missing: $3)" "$(cat "$2")"; fi; }
hasnt() { if grep -q -F -e "$3" "$2"; then bad "$1 (unexpected: $3)" "$(cat "$2")"; else ok "$1"; fi; }

# ---- the repository itself ----------------------------------------------------------------------------------------------
if grep -n -E '^[^#]*(^|[^A-Za-z0-9_-])apk([^A-Za-z0-9_-]|$)' "$repo/Dockerfile" > "$work/apk.out"; then
  bad "the validator Dockerfile has no apk step" "$(cat "$work/apk.out")"
else
  ok "the validator Dockerfile has no apk step"
fi
if grep -q '^FROM certen/validator-builder:go[0-9.]*-alpine[0-9.]* AS builder$' "$repo/Dockerfile"; then ok "the builder stage starts FROM a certen/validator-builder tag"; else bad "the builder stage starts FROM a certen/validator-builder tag"; fi
if grep -q '^FROM certen/validator-runtime:alpine[0-9.]*$' "$repo/Dockerfile"; then ok "the runtime stage starts FROM a certen/validator-runtime tag"; else bad "the runtime stage starts FROM a certen/validator-runtime tag"; fi
[ -f "$repo/deploy/make-base-images.sh" ] || { bad "deploy/make-base-images.sh exists"; echo "$pass passed, $failn failed"; exit 1; }
if sh "$repo/deploy/make-base-images.sh" --check > "$work/check.out" 2>&1; then ok "make-base-images.sh --check passes on the repository"; else bad "make-base-images.sh --check passes on the repository" "$(cat "$work/check.out")"; fi
for f in deploy/make-base-images.sh deploy/refresh-apk-pins.sh deploy/base-images/Dockerfile.builder deploy/base-images/Dockerfile.runtime Dockerfile; do
  if grep -q "$(printf '\r')" "$repo/$f"; then bad "$f has LF line endings"; else ok "$f has LF line endings"; fi
done

# ---- a scratch copy of what the script reads ----------------------------------------------------------------------------
t=$work/tree
mkdir -p "$t/deploy/base-images" "$work/bin" "$work/state"
cp "$repo/Dockerfile" "$repo/docker-compose.yml.example" "$t/"
cp "$repo/deploy/make-base-images.sh" "$repo/deploy/refresh-apk-pins.sh" "$repo/deploy/verify-base-images.sh" "$t/deploy/"
cp "$repo/deploy/base-images/Dockerfile.builder" "$repo/deploy/base-images/Dockerfile.runtime" "$t/deploy/base-images/"
mb="sh $t/deploy/make-base-images.sh"

# a fixture Alpine mirror: git and musl-dev in main, gcc and tzdata in community, with look-alike packages that must not match
mkmirror() { # <dir> <git version> <tzdata present: 1|0>
  d=$1
  for repo_ in main community; do mkdir -p "$d/v3.24/$repo_/x86_64" "$work/idx.$repo_"; done
  {
    printf 'C:Q1aaaa\nP:git-doc\nV:9.9.9-r9\n\n'
    printf 'C:Q1bbbb\nP:git\nV:%s\n\n' "$2"
    printf 'C:Q1cccc\nP:musl-dev\nV:1.2.9-r0\n\n'
    printf 'C:Q1dddd\nP:ca-certificates\nV:20990101-r0\n\n'
  } > "$work/idx.main/APKINDEX"
  {
    printf 'C:Q1eeee\nP:gcc-doc\nV:8.8.8-r8\n\n'
    printf 'C:Q1ffff\nP:gcc\nV:15.9.0-r1\n\n'
    if [ "$3" = 1 ]; then printf 'C:Q1gggg\nP:tzdata\nV:2099a-r0\n\n'; fi
  } > "$work/idx.community/APKINDEX"
  for repo_ in main community; do tar -czf "$d/v3.24/$repo_/x86_64/APKINDEX.tar.gz" -C "$work/idx.$repo_" APKINDEX; done
}
url_of() { if command -v cygpath >/dev/null 2>&1; then echo "file:///$(cygpath -m "$1")"; else echo "file://$1"; fi; }
mkmirror "$work/mirror" 2.99.0-r0 1
mirror=$(url_of "$work/mirror")

# ---- the fake docker ----------------------------------------------------------------------------------------------------
cat > "$work/bin/docker" <<'FAKE'
#!/bin/sh
S=${FAKE_DOCKER_DIR:?}
echo "docker $*" >> "$S/calls.log"
key() { echo "$1" | tr '/:' '__'; }
case "$1" in
  info) echo "x86_64" ;;
  image)
    # image inspect [--format F] TAG
    shift 2
    fmt=""; if [ "$1" = "--format" ]; then fmt=$2; shift 2; fi
    tag=$1; k=$(key "$tag")
    [ -d "$S/img/$k" ] || { echo "Error: No such image: $tag" >&2; exit 1; }
    case "$fmt" in
      "") echo "[{}]" ;;
      "{{.Id}}") cat "$S/img/$k/id" ;;
      *'index .Config.Labels'*) l=$(echo "$fmt" | sed 's/.*Labels \\*"\([^"\\]*\)\\*".*/\1/'); cat "$S/img/$k/label.$l" 2>/dev/null; echo ;;
      *) echo "fake docker: unsupported format $fmt" >&2; exit 2 ;;
    esac ;;
  build)
    shift; pins=""; digest=""; created=""; tag=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --build-arg) case "$2" in APK_PINS=*) pins=${2#APK_PINS=};; BASE_DIGEST=*) digest=${2#BASE_DIGEST=};; BUILD_DATE=*) created=${2#BUILD_DATE=};; esac; shift ;;
        -t) tag=$2; shift ;;
        -f) shift ;;
      esac
      shift
    done
    [ -z "${FAKE_BUILD_FAIL:-}" ] || { echo "ERROR: unable to select packages: ${FAKE_BUILD_FAIL} (no such package)" >&2; exit 1; }
    k=$(key "$tag"); rm -rf "$S/img/$k"; mkdir -p "$S/img/$k"
    echo "sha256:$(echo "$tag $pins $created $(date +%s%N 2>/dev/null) $$" | sha256sum | sed 's/ .*//')" > "$S/img/$k/id"
    printf '%s' "$pins" > "$S/img/$k/label.io.certen.apk.pins"
    printf '%s' "$digest" > "$S/img/$k/label.org.opencontainers.image.base.digest"
    printf '%s' "$created" > "$S/img/$k/label.org.opencontainers.image.created"
    { echo "alpine-baselayout-3.7.0-r0"; echo "busybox-1.37.0-r0"; for pv in $pins; do
        [ "${FAKE_MANIFEST_DROP:-}" = "${pv%%=*}" ] && continue; echo "${pv%%=*}-${pv#*=}"; done; } | sort > "$S/img/$k/manifest"
    echo "#1 [builder 1/6] FROM certen/validator-builder:go1.25.14-alpine3.24"; echo "#2 [builder 2/6] RUN go mod download"
    [ -z "${FAKE_BUILD_APK:-}" ] || echo "#3 [builder 3/6] RUN apk add --no-cache git"
    echo "fake build ok: $tag" ;;
  run)
    # run --rm --entrypoint cat TAG /etc/certen-apk-manifest
    if [ "$4" = sh ]; then for b in validator govproof txhash schemamigrate proofv2report blockproofcheck; do echo "$(echo "fake $b" | sha256sum | sed "s/ .*//")  $b"; done
    else k=$(key "$5"); cat "$S/img/$k/manifest"; fi ;;
  tag) k=$(key "$2"); r=$(key "$3"); rm -rf "$S/img/$r"; cp -r "$S/img/$k" "$S/img/$r" ;;
  push) echo "The push refers to repository [$2]"; echo "fake: digest: sha256:$(echo "$2" | sha256sum | sed 's/ .*//') size: 1234" ;;
  *) echo "fake docker: unsupported command $1" >&2; exit 2 ;;
esac
FAKE
chmod +x "$work/bin/docker"
export FAKE_DOCKER_DIR=$work/state PATH="$work/bin:$PATH" APK_MIRROR=$mirror
calls() { grep -c "^docker build" "$work/state/calls.log" 2>/dev/null || echo 0; }

# 1. with no lock recorded, --check passes the files and names the state
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ]; then ok "--check on files that agree passes while no lock is recorded"; else bad "--check on files that agree passes while no lock is recorded" "$(cat "$work/o")"; fi
has "  ... and names the state, not a pass of the lock" "$work/o" "lock: UNRECORDED"

# 2. first run builds both images with the resolved exact versions, the Dockerfile digests, --no-cache
$mb > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ]; then ok "first run exits 0"; else bad "first run exits 0" "$(cat "$work/o")"; fi
if [ "$(calls)" = 2 ]; then ok "first run builds exactly two images"; else bad "first run builds exactly two images" "$(cat "$work/state/calls.log")"; fi
has "builder build args carry the resolved exact versions" "$work/state/calls.log" "APK_PINS=git=2.99.0-r0 gcc=15.9.0-r1 musl-dev=1.2.9-r0"
has "runtime build args carry the resolved exact versions" "$work/state/calls.log" "APK_PINS=ca-certificates=20990101-r0 tzdata=2099a-r0"
has "builder tag is certen/validator-builder:go<ver>-alpine<branch>" "$work/state/calls.log" "-t certen/validator-builder:go1.25.14-alpine3.24"
has "runtime tag is certen/validator-runtime:alpine<branch>" "$work/state/calls.log" "-t certen/validator-runtime:alpine3.24"
has "builds use --no-cache" "$work/state/calls.log" "build --no-cache"
bdig=$(sed -n 's/^FROM golang:[^@]*@\(sha256:[0-9a-f]*\).*/\1/p' "$t/deploy/base-images/Dockerfile.builder")
has "builder BASE_DIGEST is the Dockerfile's digest" "$work/state/calls.log" "BASE_DIGEST=$bdig"
has "the lock text is printed" "$work/o" "apk.musl-dev=1.2.9-r0"
has "the lock text names the manifest hash" "$work/o" "manifest_sha256="
has "the lock is not written by default" "$work/o" "was NOT written"
if [ ! -f "$t/deploy/base-images.lock" ]; then ok "no lock file appeared without --write-lock"; else bad "no lock file appeared without --write-lock"; fi
hasnt "no registry operation without --push" "$work/state/calls.log" "docker push"

# 3. idempotent
before=$(calls)
$mb > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && [ "$(calls)" = "$before" ]; then ok "second run exits 0 and builds nothing"; else bad "second run exits 0 and builds nothing" "$(cat "$work/o")"; fi
if [ "$(grep -c 'is up to date' "$work/o")" = 2 ]; then ok "second run says both images are up to date"; else bad "second run says both images are up to date" "$(cat "$work/o")"; fi

# 4. --force rebuilds both
before=$(calls)
$mb --force > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && [ "$(calls)" = $((before + 2)) ]; then ok "--force rebuilds both images"; else bad "--force rebuilds both images" "$(cat "$work/o")"; fi

# 5. --write-lock writes the lock; --check then passes; the lock carries every recorded field
$mb --write-lock > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && [ -f "$t/deploy/base-images.lock" ]; then ok "--write-lock writes deploy/base-images.lock"; else bad "--write-lock writes deploy/base-images.lock" "$(cat "$work/o")"; fi
for k in "tag=certen/validator-builder:go1.25.14-alpine3.24" "tag=certen/validator-runtime:alpine3.24" "apk.git=2.99.0-r0" "apk.gcc=15.9.0-r1" "apk.tzdata=2099a-r0" "base_digest=$bdig" "alpine_branch=3.24" "arch=x86_64"; do
  has "lock records $k" "$t/deploy/base-images.lock" "$k"
done
if grep -q '^manifest_sha256=[0-9a-f]\{64\}$' "$t/deploy/base-images.lock"; then ok "lock records a 64-hex manifest hash"; else bad "lock records a 64-hex manifest hash"; fi
if grep -q '^image_id=sha256:[0-9a-f]\{64\}$' "$t/deploy/base-images.lock"; then ok "lock records the image id"; else bad "lock records the image id"; fi
if grep -q '^built=[0-9]\{4\}-[0-9][0-9]-[0-9][0-9]T[0-9:]*Z$' "$t/deploy/base-images.lock"; then ok "lock records the build date"; else bad "lock records the build date"; fi
if $mb --check > "$work/o" 2>&1; then ok "--check passes once the lock exists"; else bad "--check passes once the lock exists" "$(cat "$work/o")"; fi
has "  ... and says what agrees" "$work/o" "agree"
$mb > "$work/o" 2>&1
has "a run on matching versions reports the lock matches" "$work/o" "base-images.lock matches"
cp "$t/deploy/base-images.lock" "$work/lock.ref"

# 6. Alpine moves git: only the builder is rebuilt, the lock is reported as differing and NOT rewritten
mkmirror "$work/mirror2" 2.99.1-r0 1
before=$(calls)
APK_MIRROR=$(url_of "$work/mirror2") $mb > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && [ "$(calls)" = $((before + 1)) ]; then ok "a new git version rebuilds only the builder"; else bad "a new git version rebuilds only the builder" "$(cat "$work/o")"; fi
has "the lock difference is reported" "$work/o" "base-images.lock DIFFERS"
if cmp -s "$t/deploy/base-images.lock" "$work/lock.ref"; then ok "the tracked lock is left untouched without --write-lock"; else bad "the tracked lock is left untouched without --write-lock"; fi

# 7. --from-lock rebuilds the recorded versions and never asks the mirror
before=$(calls)
APK_MIRROR=file:///nonexistent $mb --from-lock > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ] && [ "$(calls)" = $((before + 1)) ]; then ok "--from-lock rebuilds the builder back to the recorded versions"; else bad "--from-lock rebuilds the builder back to the recorded versions" "$(cat "$work/o")"; fi
if grep "^docker build" "$work/state/calls.log" | tail -n 1 | grep -q "APK_PINS=git=2.99.0-r0 gcc=15.9.0-r1 musl-dev=1.2.9-r0"; then ok "--from-lock passes the lock's pins"; else bad "--from-lock passes the lock's pins"; fi

# 7b. verify-base-images.sh: tags, manifests against the lock, a build log free of apk, the binaries' SHA-256
vb="sh $t/deploy/verify-base-images.sh"
$vb --no-build > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ]; then ok "verify --no-build passes on the images the lock describes"; else bad "verify --no-build passes on the images the lock describes" "$(cat "$work/o")"; fi
has "  ... for both bases" "$work/o" "validator-runtime:alpine3.24 exists and its apk manifest"
has "  ... and says what it did not run" "$work/o" "the build and binary checks were not run"
$vb > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ]; then ok "verify (full) passes"; else bad "verify (full) passes" "$(cat "$work/o")"; fi
has "  ... builds the builder stage with --no-cache" "$work/state/calls.log" "build --no-cache --progress=plain --target builder -t certen-validator-build-verify ."
has "  ... reports the log has no apk" "$work/o" "holds no apk invocation"
if [ "$(grep -c '^[0-9a-f]\{64\}  ' "$work/o")" = 6 ]; then ok "  ... prints the SHA-256 of the six binaries"; else bad "  ... prints the SHA-256 of the six binaries" "$(cat "$work/o")"; fi
FAKE_BUILD_APK=1 $vb > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "verify fails when the build log shows an apk invocation"; else bad "verify fails when the build log shows an apk invocation"; fi
has "  ... naming apk" "$work/o" "shows apk activity"
sed -i 's|^manifest_sha256=\(.*\)$|manifest_sha256=0000000000000000000000000000000000000000000000000000000000000000|' "$t/deploy/base-images.lock"
$vb --no-build > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "verify fails when an image's manifest differs from the lock"; else bad "verify fails when an image's manifest differs from the lock"; fi
has "  ... naming both hashes" "$work/o" "the lock records 0000000000000000000000000000000000000000000000000000000000000000"
cp "$work/lock.ref" "$t/deploy/base-images.lock"
BASE_IMAGES_LOCK=$work/absent.lock $vb --no-build > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "verify fails when there is no lock to compare to"; else bad "verify fails when there is no lock to compare to"; fi
has "  ... by name" "$work/o" "does not exist, so the manifests cannot be compared to it"
rm -rf "$work/state/img/certen_validator-runtime_alpine3.24"
$vb --no-build > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "verify fails when a base image is missing"; else bad "verify fails when a base image is missing"; fi
has "  ... and tells the operator the command" "$work/o" "run: sh deploy/make-base-images.sh"
$mb > "$work/o" 2>&1

# 8. failures name their cause
APK_MIRROR=file:///nonexistent $mb --force > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "an unreachable mirror fails"; else bad "an unreachable mirror fails"; fi
has "  ... naming the URL that could not be read" "$work/o" "cannot download file:///nonexistent/v3.24/main/x86_64/APKINDEX.tar.gz"
mkmirror "$work/mirror3" 2.99.0-r0 0
APK_MIRROR=$(url_of "$work/mirror3") $mb --force > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "a package missing from the index fails"; else bad "a package missing from the index fails"; fi
has "  ... naming the package" "$work/o" "package tzdata (named in"
has "  ... and the Alpine branch" "$work/o" "is not in Alpine v3.24 main or community for x86_64"
FAKE_BUILD_FAIL="git=9.9" $mb --force > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "a failing docker build fails the script"; else bad "a failing docker build fails the script"; fi
has "  ... naming the tag" "$work/o" "docker build of certen/validator-builder:go1.25.14-alpine3.24 failed"
FAKE_MANIFEST_DROP=git $mb --force > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "an image whose manifest lacks a requested package is refused"; else bad "an image whose manifest lacks a requested package is refused"; fi
has "  ... naming the package" "$work/o" "does not contain git-"
$mb --bogus > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "an unknown option fails"; else bad "an unknown option fails"; fi
has "  ... by name" "$work/o" "unknown option '--bogus'"

# 9. --push tags, pushes and records registry digests
$mb --force --push registry.invalid/certenio > "$work/o" 2>&1; rc=$?
if [ $rc -eq 0 ]; then ok "--push exits 0"; else bad "--push exits 0" "$(cat "$work/o")"; fi
has "--push tags the builder under the prefix" "$work/state/calls.log" "docker tag certen/validator-builder:go1.25.14-alpine3.24 registry.invalid/certenio/validator-builder:go1.25.14-alpine3.24"
has "--push pushes the runtime" "$work/state/calls.log" "docker push registry.invalid/certenio/validator-runtime:alpine3.24"
if grep -q '^registry=registry.invalid/certenio/validator-builder@sha256:[0-9a-f]\{64\}$' "$work/o"; then ok "--push records the builder's registry digest"; else bad "--push records the builder's registry digest" "$(cat "$work/o")"; fi
$mb --push > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--push without a prefix fails"; else bad "--push without a prefix fails"; fi

# 10. the consistency check refuses a Dockerfile or a lock that drifted
cp "$t/Dockerfile" "$work/Dockerfile.good"
printf 'RUN apk add --no-cache curl\n' >> "$t/Dockerfile"
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--check refuses a Dockerfile with an apk step"; else bad "--check refuses a Dockerfile with an apk step"; fi
has "  ... naming it" "$work/o" "has an apk step"
cp "$work/Dockerfile.good" "$t/Dockerfile"
sed -i 's|^FROM certen/validator-runtime:alpine3.24$|FROM alpine:3.24|' "$t/Dockerfile"
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--check refuses a runtime stage that is not the base image"; else bad "--check refuses a runtime stage that is not the base image"; fi
has "  ... naming the expected tag" "$work/o" "must be 'FROM certen/validator-runtime:alpine3.24'"
cp "$work/Dockerfile.good" "$t/Dockerfile"
sed -i 's|^FROM certen/validator-builder:go1.25.14-alpine3.24 AS builder$|FROM certen/validator-builder:go1.24.0-alpine3.24 AS builder|' "$t/Dockerfile"
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--check refuses a builder tag that Dockerfile.builder does not produce"; else bad "--check refuses a builder tag that Dockerfile.builder does not produce"; fi
cp "$work/Dockerfile.good" "$t/Dockerfile"
sed -i 's|^\(FROM golang:[^@]*\)@sha256:[0-9a-f]*|\1|' "$t/deploy/base-images/Dockerfile.builder"
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--check refuses a base FROM without a digest"; else bad "--check refuses a base FROM without a digest"; fi
has "  ... by name" "$work/o" "not pinned by tag AND digest"
cp "$repo/deploy/base-images/Dockerfile.builder" "$t/deploy/base-images/Dockerfile.builder"
sed -i 's|^\(FROM golang:[^@]*\)@sha256:[0-9a-f]*|\1@sha256:0000000000000000000000000000000000000000000000000000000000000000|' "$t/deploy/base-images/Dockerfile.builder"
$mb --check > "$work/o" 2>&1; rc=$?
if [ $rc -ne 0 ]; then ok "--check refuses a lock recorded for a different base digest"; else bad "--check refuses a lock recorded for a different base digest"; fi
has "  ... naming the lock's base" "$work/o" "lock [builder] from is"

# 11. the resolver alone
sh "$repo/deploy/refresh-apk-pins.sh" --pins "$repo/deploy/base-images/Dockerfile.runtime" > "$work/o" 2>&1
if [ "$(cat "$work/o")" = "ca-certificates=20990101-r0 tzdata=2099a-r0" ]; then ok "refresh-apk-pins.sh --pins prints the exact versions on one line"; else bad "refresh-apk-pins.sh --pins prints the exact versions on one line" "$(cat "$work/o")"; fi
sh "$repo/deploy/refresh-apk-pins.sh" > "$work/o" 2>&1
has "refresh-apk-pins.sh with no argument previews both bases" "$work/o" "Dockerfile.builder (Alpine v3.24): git=2.99.0-r0 gcc=15.9.0-r1 musl-dev=1.2.9-r0"

echo
echo "$pass passed, $failn failed"
[ "$failn" = 0 ]
