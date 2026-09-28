#!/bin/sh
# Exercise the source guard without network access or a Go toolchain.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
guard=$script_dir/check-release-source.sh
fixture=$(mktemp -d "${TMPDIR:-/tmp}/goauth-release-source-test.XXXXXX")
trap 'rm -rf "$fixture"' 0
trap 'exit 1' HUP INT TERM

# Do not inherit signing, hook, ignore, or identity settings into the fixture.
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_CONFIG_COUNT

git init -q --template= "$fixture"
cd "$fixture"
git config user.name 'goauth release tests'
git config user.email 'release-tests@example.invalid'
printf 'initial\n' > tracked
git add tracked
git -c commit.gpgsign=false commit -qm initial
git tag v0.0.1
git -c tag.gpgsign=false tag -a v0.0.1-rc.1 -m candidate

passed=0
expect_success() {
    if ! sh "$guard" "$@" >/dev/null 2>&1; then
        printf 'Expected success for: %s\n' "$*" >&2
        exit 1
    fi
    passed=$((passed + 1))
}
expect_failure() {
    if sh "$guard" "$@" >/dev/null 2>&1; then
        printf 'Expected failure for: %s\n' "$*" >&2
        exit 1
    fi
    passed=$((passed + 1))
}

expect_success v0.0.1
expect_success v0.0.1-rc.1
expect_failure
expect_failure ''
expect_failure latest
expect_failure 'v0.0.1..bad'
expect_failure v9.9.9
expect_failure v0.0.1 extra

printf 'untracked\n' > untracked
expect_failure v0.0.1
rm untracked
printf 'modified\n' >> tracked
expect_failure v0.0.1
git add tracked
expect_failure v0.0.1
git -c commit.gpgsign=false commit -qm second
expect_failure v0.0.1
git tag v0.0.2
expect_success v0.0.2

# A Git-status failure must not be mistaken for an empty (clean) status.
printf 'broken index\n' > bad-index
export GIT_INDEX_FILE="$fixture/bad-index"
expect_failure v0.0.2
unset GIT_INDEX_FILE
rm bad-index

printf 'Release source guard: %s checks passed.\n' "$passed"
