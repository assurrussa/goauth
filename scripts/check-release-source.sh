#!/bin/sh
# Read-only guard: verify the checkout being tested is exactly the chosen tag.
set -eu

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail 'Usage: sh scripts/check-release-source.sh <version-tag>'
version=$1
[ -n "$version" ] || fail 'VERSION is required; select an explicit release tag.'
case "$version" in
    v[0-9]*) ;;
    *) fail 'VERSION must be a Go version tag beginning with v and a digit.' ;;
esac
git check-ref-format "refs/tags/$version" >/dev/null 2>&1 || fail 'Invalid release tag name.'
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail 'Run this check in a Git checkout.'

tag_commit=$(git rev-parse --verify "refs/tags/$version^{commit}" 2>/dev/null) ||
    fail 'The selected tag is not available locally; fetch the intended immutable tag first.'
head_commit=$(git rev-parse --verify HEAD)
[ "$tag_commit" = "$head_commit" ] ||
    fail 'HEAD does not match VERSION. Check out the selected tag before release verification.'
status=$(git status --porcelain --untracked-files=normal) || fail 'Unable to inspect the checkout status.'
[ -z "$status" ] ||
    fail 'Release verification requires a clean checkout, including untracked files.'

printf 'Release source verified: %s at %s\n' "$version" "$head_commit"
