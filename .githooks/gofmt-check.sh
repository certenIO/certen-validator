#!/bin/sh
# Fail if any Go file in the main module is not gofmt-clean.
#
# Run with no arguments to check the whole main module; run with --staged to
# check only what is about to be committed (used by the pre-commit hook).
#
# The vendored accumulate-lite-client-2/liteclient module is excluded on
# purpose: it tracks upstream, and reformatting it would make every future
# comparison against upstream unreadable.

set -e
cd "$(git rev-parse --show-toplevel)"

if [ "$1" = "--fix" ]; then
    git ls-files '*.go' | grep -v '^accumulate-lite-client-2/' |
        xargs -d '\n' gofmt -w
    echo "gofmt applied to the main module."
    exit 0
fi

if [ "$1" = "--staged" ]; then
    files=$(git diff --cached --name-only --diff-filter=ACM -- '*.go' |
        grep -v '^accumulate-lite-client-2/' || true)
else
    # Tracked files PLUS untracked new ones: a brand-new .go file is invisible
    # to `git ls-files`, so a whole-repo check would report clean while the
    # pre-commit hook rejects the very next commit.
    files=$( { git ls-files '*.go'; git ls-files --others --exclude-standard '*.go'; } |
        grep -v '^accumulate-lite-client-2/' | sort -u || true)
fi

[ -z "$files" ] && exit 0

# gofmt's doc-comment reformatter can need a second pass to converge, so a file
# is only clean if gofmt reports nothing on it.
unformatted=$(printf '%s\n' "$files" | xargs -d '\n' gofmt -l)

if [ -n "$unformatted" ]; then
    echo "These files are not gofmt-clean:" >&2
    printf '%s\n' "$unformatted" >&2
    echo >&2
    echo "Fix with:  sh .githooks/gofmt-check.sh --fix" >&2
    echo "Never mix the fix into a logic commit - commit it alone and add the" >&2
    echo "hash to .git-blame-ignore-revs." >&2
    exit 1
fi
