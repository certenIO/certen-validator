# BASE IMAGE for the validator's build stage: certen/validator-builder:go<go version>-alpine<branch>.
#
# Built ONCE per base change by `sh deploy/make-base-images.sh`, never by a normal `docker-compose build` (the validator
# Dockerfile has no apk step at all). That is the point: Alpine withdraws old package versions every few weeks, and a
# build that talks to Alpine's repository on every run breaks the day a version leaves it.
#
# What is pinned: the FROM line below, by tag AND digest, and the exact versions of the packages named on the
# `certen-apk-packages` line (git, gcc and musl-dev decide the bytes of the cgo validator binary). make-base-images.sh
# resolves the CURRENT exact versions from Alpine's public APKINDEX for the Alpine branch in the tag, passes them in
# APK_PINS (git=2.54.0-r0 gcc=... musl-dev=...), builds this file, and records the result in deploy/base-images.lock.
# `--from-lock` rebuilds with the versions recorded in that lock instead, and fails by name if Alpine no longer serves one.
# The FROM line is read by make-base-images.sh and by the validator Dockerfile's consistency check
# (`sh deploy/make-base-images.sh --check`): change the tag or digest here, then run the script and commit the new lock.
#
# certen-apk-packages: git gcc musl-dev
FROM golang:1.25.14-alpine3.24@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59

ARG APK_PINS
ARG BASE_NAME
ARG BASE_DIGEST
ARG BUILD_DATE

# The exact package versions come in as build arguments; an empty value is a named failure, never a bare `apk add git gcc
# musl-dev` that would install whatever the repository serves today.
RUN set -eu; \
    [ -n "${APK_PINS}" ] || { \
        echo "FATAL: APK_PINS is empty. This file is built by 'sh deploy/make-base-images.sh', which resolves the exact"; \
        echo "       package versions and passes them in; do not run 'docker build' on it directly."; \
        exit 1; }; \
    apk add --no-cache ${APK_PINS}; \
    apk info -v | sort > /etc/certen-apk-manifest

LABEL org.opencontainers.image.title="CERTEN validator builder base" \
      org.opencontainers.image.base.name="${BASE_NAME}" \
      org.opencontainers.image.base.digest="${BASE_DIGEST}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      io.certen.base.kind="builder" \
      io.certen.apk.pins="${APK_PINS}"
