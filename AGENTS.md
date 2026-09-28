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

- Root package: stable identity models, Runtime contracts, local auth,
  recovery, sessions, refresh rotation, and identity-link policy.
- `postgres/`: v0.2 baseline migrations, Runtime assembly, canonical storage,
  native encrypted notification queue and worker, audit persistence, cleanup,
  rate limiting, and RBAC storage.
- `redis/`: atomic Redis-backed OIDC one-time state.
- `fiber/`: JSON handlers, typed error mapping, and realm middleware.
- `oidc/`: OIDC protocol, provider, and verifier contracts.
- `rbac/`: hierarchy-free role and permission service.
- `testkit/`: supported in-memory Runtime fixture and encrypted-event helpers.
- `internal/legacy/`: compile-checked v0.1 use cases retained through the v0.2
  transition; external consumers cannot import them.
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
- Prefer the root Runtime and the explicit `postgres`, `redis`, `fiber`,
  `oidc`, `rbac`, and `testkit` adapters. Preserve the earlier v0.1 use cases
  in `internal/legacy` until their fate is decided explicitly; they are not
  supported imports for external consumers.
- Keep `HostSupportPackages` empty unless there is an unavoidable, temporary
  host-wiring gap with a documented migration path.

Concrete SQL repositories and migration implementation stay behind
`postgres`; Fiber transport internals stay behind `fiber`; RBAC storage stays
behind `postgres.NewRBAC`.

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
- Realm and host membership, not a subject kind, are the admin security
  boundary.
- Projection IDs, public IDs, and numeric admin IDs must not be used as runtime
  auth fallback identities.

## Commands

- Full local run: `make`
- Mutating preparation only: `make prepare`
- Verification only: `make check` — one race+coverage test pass, formatting,
  vet, lint, and the local consumer probe.
- Explicit stress rerun: `make test-race`.
- Explicit HTML coverage artifact: `make cover-html`.
- Candidate release readiness: `make release-candidate-readiness`
- Published release readiness after tagging: `make release-readiness VERSION=v0.4.0`
- Local clean-consumer probe: `make externalconsumer-local`
- Published clean-consumer probe after tagging: `make externalconsumer-published VERSION=v0.4.0`

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

The frozen v0.1 compatibility baseline ends at `v0.1.7`. The current release
tag is `v0.4.0`.

The repository currently needs private modules to compile-check the retained
v0.1 tree, and CI uses `PRIVATE_GO_MODULES_TOKEN`. Resolve this before public
distribution. The intended public module and CI must resolve without private
credentials; a local candidate gate does not prove that requirement.

Before claiming candidate readiness, run `make release-candidate-readiness`.
Before claiming published release readiness:

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

When shared context is needed, follow `streams/AGENTS.md` and its query route.
Reuse already loaded root rules, PII policy and glossary. Open the known hub
and only the topic relevant to the task:

- `streams/wiki/platforms/goauth.md`

For integration work, open only the affected neighbour hub:

- `streams/wiki/platforms/goadmin.md`

Use `streams/wiki/index.md` only to locate an unknown area or answer an overview
question. This is a task router, not a mandatory list of wiki pages.

If local verified docs/code conflict with the shared wiki, treat the wiki
as stale. When documentation upkeep is in scope, update the relevant
platform page after verification. Do not
copy whole README files into wiki; keep shared pages concise and
contract-focused.

## Dependency Documentation

Use `$find-docs` for version-sensitive library, framework, SDK, API and CLI
questions. It selects an available documentation tool, resolves the version and
owns query limits and fallback. Reuse applicable docs already fetched in this
task. Ordinary refactors, scripts, business logic and reviews need no lookup
unless an external API contract is the unresolved question.

## Working Tree Discipline

The repository may contain unrelated user changes. Do not revert, restage, or
rewrite files you did not change unless the user explicitly asks for that.
Before editing public contracts, inspect current diffs and work with existing
changes instead of assuming a clean baseline.
