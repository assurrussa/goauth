# Contributing to goauth

Changes should improve a reusable PostgreSQL-first authentication Runtime,
not couple it to one host application's users, UI, cookies, or permissions.
Read [AGENTS.md](AGENTS.md) and [AUTH_INVARIANTS.md](AUTH_INVARIANTS.md) first.

## Development prerequisites

Use the Go version and toolchain declared in `go.mod`. Install the formatting
and lint tools at the versions recorded in `.github/workflows/ci.yml`.
PostgreSQL and Redis integration tests require Docker Compose or equivalent
**disposable** services. Never point integration tests at production data.

Work in a branch and keep each PR focused. Add a regression test before fixing
a security-state transition. Changes to supported imports must update the
manifest and contract tests described in [docs/public-surface.md](docs/public-surface.md).

## Checks

During development, run tests for affected packages. Before submitting, run:

```sh
make prepare
# Review any formatting, generated-code, or dependency changes.
make check
make integration-local
make vulnerability-check
```

`make prepare` modifies files; `make check` does not. Do not repeatedly run
all gates on an unchanged tree. The release gate and exact-tag verification
are documented in [RELEASING.md](RELEASING.md).

In the PR description, record the tested commit, actual commands and results,
and anything not run. A workflow that never starts is not evidence that tests
passed or failed. Do not report simulated or file-scoped tests as a full
repository verification.

## Reporting problems

Ordinary bug reports should include the version, Go/PostgreSQL versions,
minimal configuration, reproduction, and expected versus actual behavior.
Remove credentials, raw tokens, notification payloads, and personal data.

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md), not a public
issue or PR. Do not post an exploit in a public discussion.

## Compatibility and releases

No published tag may be moved or reused. Changes to persisted semantics,
public interfaces, or security defaults need an explicit compatibility note.
Schema rollback is not `postgres.Down`; follow the migration guidance in
[RELEASING.md](RELEASING.md). New authentication methods, additional databases,
and a general IAM server are not prerequisites for the first public preview.
