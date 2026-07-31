# Repository Guidelines

## Purpose

`goauth` is the standalone canonical auth/RBAC library published as
`github.com/assurrussa/goauth`. Treat this repository as a reusable Go module
and release artifact, not as code owned by any single host application.

The module owns transport-neutral auth behavior, canonical `auth_*` storage,
canonical migrations, subject-based RBAC, sessions, refresh tokens,
password-reset and confirmation state, email-change state, and SSO identity
links.

Host projects own HTTP UX, cookies, frontend policy, host projection tables,
process wiring, and app-specific permission catalog extensions.

## Source Of Truth

Use this order when facts conflict:

1. Current code, tests, migrations, and generated contracts in this repository.
2. `README.md`, `RELEASING.md`, `AUTH_INVARIANTS.md`, `reference/`, and
   focused docs under `docs/`.
3. Shared agent-context wiki pages.

If local verified repo state conflicts with shared wiki, treat the wiki as stale
and report the drift. Update shared wiki only when the task explicitly includes
that maintenance or the project-context workflow requires it after a public
contract change.

## Project Map

- `core/`: stable subject, profile, token, credential, transaction, and store
  contracts.
- `shared/`: small shared auth DTOs and subject helpers.
- `local/`: local auth services for registration, login, tokens, password
  reset/change, email change, confirmation, and related flows.
- `session/`: session runtime and admin-account support.
- `domain/roles/`: reusable subject RBAC model, storage contracts, services,
  guards, use cases, cache, and seeders.
- `integration/`: preferred host-facing wiring kits for storage, Local JWT,
  OIDC, admin session, and roles.
- `migrations/`: canonical auth/RBAC PostgreSQL migrations and public migration
  entrypoints.
- `storage/`, `infrastructure/`, `http/`: concrete adapters and transport glue.
- `oidc/`, `sso/`: OIDC/JWK, verifier/provider, embedded/external identity,
  and identity-link support.
- `service/`, `usecases/`: transport-neutral auth services and application
  use cases used by integration kits.
- `reference/externalconsumer`: compile-checked supported package manifest.
- `cmd/externalconsumerprobe`: release helper for clean temporary consumers.

## Public Surface Rules

`reference/externalconsumer.SupportedPackages` is the source of truth for
published import support. A Go package is not stable public API just because it
is exported or importable.

When making public API changes:

- Add new supported packages intentionally in
  `reference/externalconsumer/packages.go`.
- Keep `reference/externalconsumer/imports.go` aligned with the supported list.
- Update `public_surface_test.go` when new exported symbols are release-visible.
- Prefer `integration/*`, `core`, `shared`, `migrations`, `oidc`, `sso`, and
  explicitly supported service packages over direct implementation packages.
- Keep `HostSupportPackages` empty unless there is an unavoidable, temporary
  host-wiring gap with a documented migration path.

RBAC internals should stay behind `integration/roles`. Storage adapters should
stay behind `integration/storage`. Fiber auth adapters should stay behind
integration facades unless a package is deliberately promoted to the stable
surface.

See `docs/public-surface.md` for the working checklist.

## Architecture Invariants

Read `AUTH_INVARIANTS.md` before touching identity, subject, projection, or
password flows.

Important invariants:

- `auth_subjects` is the canonical identity table.
- `auth_local_credentials` stores local secret material keyed by canonical
  `subject_id`.
- Canonical auth relations must use the real canonical `subject_id`.
- Host `users` and `administrations` rows are projections or memberships keyed
  by canonical `subject_id`.
- `Subject.Kind` is routing metadata, not the admin security boundary.
- Projection IDs, public IDs, and numeric admin IDs must not be used as runtime
  auth fallback identities.

## Commands

- Full local run: `make`
- Mutating preparation only: `make prepare`
- Verification only: `make check` — one race+coverage test pass, formatting,
  vet, lint, and the local consumer probe.
- Explicit stress rerun: `make test-race`.
- Explicit HTML coverage artifact: `make cover-html`.
- Published release readiness: `make release-readiness VERSION=v0.1.4`
- Local clean-consumer probe: `make externalconsumer-local`
- Published clean-consumer probe: `make externalconsumer-published VERSION=v0.1.4`

The Makefile exports repo-local `GOCACHE`, `GOMODCACHE`, and `GOPATH` under
`.go-cache/`. Prefer Makefile targets for verification. If running raw `go`
commands in this sandbox, use the same cache layout:

```sh
GOCACHE=$PWD/.go-cache/gocache \
GOMODCACHE=$PWD/.go-cache/gomodcache \
GOPATH=$PWD/.go-cache/gopath \
go list ./...
```

During implementation, run package-scoped `go test` commands. Run `make check`
once after a coherent batch; do not stack it with `make test`,
`make test-race`, and `make cover-html` on an unchanged tree.

## Release Rules

Do not rewrite existing tags. If `make` changes generated code, formatting,
`go.mod`, or `go.sum`, commit those changes and publish a new semver tag.

Current verified baseline for this split pass is `v0.1.4`.

Before claiming release readiness:

- Run `make check`.
- Run `make release-readiness VERSION=<tag>` for the intended tag.
- Verify the published module resolves from a clean external consumer, not only
  from local `replace` directives.

See `RELEASING.md` and `docs/release-verification.md`.

## Documentation Rules

Keep durable project knowledge in focused files:

- `README.md`: concise consumer-facing overview.
- `RELEASING.md`: release checklist and current baseline.
- `AUTH_INVARIANTS.md`: identity and projection invariants.
- `docs/project-contract.md`: ownership, package map, and boundaries.
- `docs/public-surface.md`: supported-import workflow and API promotion rules.
- `docs/release-verification.md`: verification gates and clean-consumer probes.
- `implementation-notes.md`: running notes for agent decisions made while
  implementing a requested spec.

Do not copy whole README files into shared wiki. Shared pages should stay
concise and contract-focused.

## Shared Agent Context

Use `$project-context-router` when a task needs cross-project context
from a local shared wiki.

Do not hard-code machine-local absolute paths in this public repository.
If a local shared wiki is available, expose its root through
`AGENT_CONTEXT_ROOT` or let `$project-context-router` resolve it for the
current session.

Local docs and code in this repository remain the source of truth for
commands, public APIs, config keys, supported imports, runtime behavior,
and release gates. Read this repo's `AGENTS.md`, `README.md`, `docs/`
or `reference/`, task files, code, tests, and configs before shared wiki
pages.

When shared context is available, read these paths from the resolved wiki
root:
- `streams/wiki/index.md`
- `streams/wiki/glossary.md`
- `streams/wiki/platforms/goauth.md`
- `streams/wiki/platforms/goadmin.md`

If local verified docs/code conflict with the shared wiki, treat the wiki
as stale and update the relevant platform page after verification. Do not
copy whole README files into wiki; keep shared pages concise and
contract-focused.

## Dependency Documentation

When the task asks about a library, framework, SDK, API, CLI tool, or cloud
service, fetch current docs with the Context7 CLI before answering or changing
library-specific code:

```sh
npx ctx7@latest library <name> "<user question>"
npx ctx7@latest docs <libraryId> "<user question>"
```

Use the official library name and do not run more than three Context7 commands
per question. If the command fails with DNS or network errors inside the
sandbox, rerun it outside the sandbox with approval. If it fails because of
quota, tell the user to run `npx ctx7@latest login` or set `CONTEXT7_API_KEY`.

Do not use Context7 for general refactors, scripts from scratch, business-logic
debugging, code review, or general programming concepts.

## Working Tree Discipline

The repository may contain unrelated user changes. Do not revert, restage, or
rewrite files you did not change unless the user explicitly asks for that.
Before editing public contracts, inspect current diffs and work with existing
changes instead of assuming a clean baseline.
