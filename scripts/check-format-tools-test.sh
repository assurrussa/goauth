#!/bin/sh
# Exercise formatter failures and nonterminal stdin without modifying Go files.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/goauth-format-tools-test.XXXXXX")
trap 'rm -rf "$fixture"' 0
trap 'exit 1' HUP INT TERM

mkdir "$fixture/bin"
cat > "$fixture/bin/gofumpt" <<'EOF'
#!/bin/sh
case "$FORMAT_TEST_MODE" in
    gofumpt-failure) printf 'gofumpt failed\n' >&2; exit 42 ;;
    gofumpt-diff) printf 'needs-format.go\n' ;;
esac
EOF
cat > "$fixture/bin/gci" <<'EOF'
#!/bin/sh
case "$FORMAT_TEST_MODE" in
    gci-failure) printf 'gci failed\n' >&2; exit 43 ;;
    gci-diff) printf 'diff --git a/fixture.go b/fixture.go\n' ;;
    stdin) test -c /dev/stdin || { printf 'gci would consume piped stdin\n' >&2; exit 44; } ;;
esac
EOF
chmod +x "$fixture/bin/gofumpt" "$fixture/bin/gci"
export PATH="$fixture/bin:$PATH"
passed=0

expect_result() {
    FORMAT_TEST_MODE=$1
    export FORMAT_TEST_MODE
    status=0
    # A pipe reproduces the nonterminal stdin presented by hosted CI.
    printf '' | make --no-print-directory -C "$repo_dir" fmt-check GO_FILES=fixture.go > "$fixture/log" 2>&1 || status=$?
    if { test "$2" = success && test "$status" -ne 0; } || { test "$2" = failure && test "$status" -eq 0; }; then
        cat "$fixture/log" >&2
        printf 'Unexpected formatter gate result for %s: %s\n' "$1" "$status" >&2
        exit 1
    fi
    passed=$((passed + 1))
}

expect_result clean success
expect_result gofumpt-failure failure
expect_result gci-failure failure
expect_result gofumpt-diff failure
expect_result gci-diff failure
expect_result stdin success
printf 'Formatter gate: %s checks passed.\n' "$passed"
