# Releasing goauth

The module path is `github.com/assurrussa/goauth`.
Read [docs/public-release-plan.md](docs/public-release-plan.md) for the owner,
acceptance criteria and sequence of the first public release.

## Version state

The latest published release is [`v0.14.0`](https://github.com/assurrussa/goauth/releases/tag/v0.14.0),
using schema 14. It adds the trusted-host
`RequestEmailChangeWithPreviousEmailNotice` API. Successful opt-in issuance
atomically queues a credential-free security notice to the captured previous
mailbox. See [requested email-change notices](docs/email-change-requested-notice.md).

The proposed `v0.15.0` candidate adds optional trusted `SessionAuthentication`
evidence to the session-bound OIDC provider. The provider signs standard `amr`
in ID tokens independently of profile scope, validates the exact authentication
event time, and copies and deduplicates method identifiers. Explicit empty
evidence emits `amr: []`; absent evidence preserves legacy omission. Enrollment
is not authentication proof, and existing legacy-provider behavior is unchanged.
No canonical migration, dependency change, mandatory MFA policy or deployment
is included. See [session authentication methods](docs/session-bound-oidc.md#authentication-methods).
This is a release proposal, not a published version or a claim that all release
gates are complete. Existing tags must never be reused or moved.

The [v0.7.0 preparation record](docs/v0.7-release-preparation.md) is historical
evidence for its recorded source, not verification of this candidate. Record the
final source commit and separately reviewed documentation delta. Candidate
verification does not establish exact-tag public availability, host acceptance,
adoption or deployment.

Upgrading from `v0.10.0` applies the additive schema 13→14 step for assisted
recovery invitations. The opt-in service preserves existing MFA and requires
explicit authorization, managed transactions and encrypted notification delivery.
See [assisted recovery](docs/assisted-recovery.md) for its authority and lifecycle
contract. Password reset authenticates tokens before expensive hashing when the
store supports the existing preparation interface; legacy custom-store fallback
remains compatible.

For installations still on `v0.9.0`, schema 12→13 adds five nullable sender-diagnostic
fields without historical backfill. See
[safe sender diagnostics](docs/notification-delivery.md#safe-sender-diagnostics-schema-13).

For installations still on `v0.7.0`, the preceding additive steps remain:

- 8→9: local factor, recovery, attempt-budget, login-continuation and enrollment
  storage; see [local MFA](docs/local-mfa.md).
- 9→10: required-MFA setup fields and immutable session-admission provenance;
  see [required MFA](docs/required-mfa.md).
- 10→11: host-scoped email-change snapshots;
  see [scoped email changes](docs/scoped-email-change.md).
- 11→12: notification cancellation and bounded receipt cleanup;
  see [notification lifecycle](docs/notification-lifecycle.md).

`postgres.Migrate` applies the pending steps and verifies the resulting schema
inside its owned transaction. Preserve published migration bytes and existing
auth state, identifiers, credentials, host projections, keys and security history.
Do not reset the database or lower migration history. The
[v0.6 migration guide](docs/v0.6-migration.md) remains the historical schema 3→8
upgrade contract for older installations; it does not verify the current upgrade path.

Optional MFA remains the default. Enabling required mode rejects legacy sessions
with unknown admission and password-only sessions on their next canonical
authentication or refresh check; affected users must authenticate again.
Required mode fails construction without a configured valid MFA key ring and
compatible transactional storage. Verified external admissions remain separate. Offline
`VerifyJWT` cannot enforce a policy change or revocation before token expiry.

Before upgrading, retain a recoverable database backup and verify its restore
procedure in disposable storage. Preserve the durable MFA encryption key ring,
including historical keys needed by existing ciphertext, alongside the other
required application keys. Do not generate new MFA keys on each process start.
A database backup without its required keys does not establish recoverability.

Current source requires Go 1.27.2 or newer. Hosts must rebuild with a supported
patched compiler; a module requirement cannot patch an already-built binary.

Stop and join old notification workers and coordinate application writers before
migration; resume them only with the schema-14-compatible binary. Mixed older
writers/workers are not a supported rollout. Preserve queued envelopes, key
rings, delivery IDs and original deadlines; migration must not resend mail.

`postgres.Migrate` does not downgrade schemas. The published schema-13 `v0.10.0` library
rejects schema 14 as newer than it supports; do not assume an older binary can
run against an upgraded database. Review rollback to a schema-compatible binary
or restoration of a pre-upgrade snapshot with its required keys, accounting for
writes made since that snapshot. `postgres.Down` is a destructive development/
test reset, not a production rollback mechanism. Review adopted MFA/recovery
policies, host-scoped email changes, queued notifications and host integration
before changing binaries; schema compatibility alone does not prove equivalent
policy enforcement. Drain or invalidate affected recovery notifications before
removing an adopted recovery-recipient policy.

Before any selected release, run host acceptance at its exact source SHA and
record each host commit and complete resolved module graph, including the
resolved GoAdmin/GoAuth versions and replacement status. A host test must resolve
the exact candidate without a local replacement. A pre-tag commit may resolve as a Go pseudo-version; record its full origin SHA. Temporary host
acceptance is not consumer adoption or deployment.

Never publish a committed local `replace` or describe a private tag as a verified
public release. The frozen v0.1 compatibility line ends at `v0.1.7`; its
implementation is absent from the current source tree. Publication, independent
review, consumer adoption and deployment are separate claims. Fix a failed
published candidate in a new commit and tag. A future narrow backport requires
its own explicit scope, review and verification.

## Published v0.5 migration

The published v0.5.0/v0.5.1 code changes Runtime/store contracts and HTTP authorization defaults.
It preserves the version-3 database and existing rows; no `Down` is required.
That historical claim does not apply to the current schema-14 candidate.
Read [docs/v0.5-migration.md](docs/v0.5-migration.md), including exact external
issuer keys and custom transaction wiring. Candidate verification does not
publish a tag, change visibility, or establish production adoption.

## Breaking v0.1 to v0.2 migration

v0.2 installs a clean baseline schema. `postgres.Migrate` detects a v0.1 auth
schema and returns `postgres.ErrLegacySchemaRequiresReset` without deleting
data. Only isolated development and test databases may call:

```go
postgres.Down(ctx, db, postgres.ConfirmResetAuthState)
```

There is no automatic v0.1 data conversion. A production-data migration would
require a separately reviewed migration product and is outside this release.
The reset is transactional and refuses to drop `auth_subjects` while host
projection foreign keys still depend on it; each consumer reset must remove its
own auth projections first.

The v0.4 notification migration advances the schema version from 2 to 3 while
preserving v0.2 auth rows. An older binary that verifies version 2 will reject
the upgraded database, even if its `AutoMigrate` option is enabled. Roll back
the application only to a binary that accepts version 3; otherwise restore a
pre-migration database snapshot after accounting for writes made since it was
taken. Do not run `Down` against production data as a rollback mechanism.

## Candidate gate (before tagging)

Use the project's declared Go toolchain. Run `make prepare` once, inspect and
commit any resulting changes, then run the non-mutating candidate gate against
that exact SHA with disposable PostgreSQL and Redis services:

Select an installed Playwright module and Chromium executable as described in
[release verification](docs/release-verification.md); the candidate gate
requires those tools and does not install them automatically.

```sh
make integration-up
make release-candidate-readiness
make integration-down
```

Always tear down the disposable services even if verification fails.
The candidate gate includes format/tidy/vet/lint, one race/coverage unit pass,
public API checks, local consumer, PostgreSQL/Redis integration and real
PostgreSQL consumer, reachable vulnerability analysis, and aggregate coverage.
`make check` also runs the network-free source-guard regression tests.
The candidate gate additionally exercises real PostgreSQL dump/restore and
Chromium/HTTPS browser acceptance.
The current `CI` workflow runs the source/unit, integration, aggregate coverage
and vulnerability checks, but not dump/restore or browser acceptance. A green
CI run therefore does not replace the complete candidate gate.

The `CI` workflow runs only by manual dispatch for a selected candidate branch;
pushes and pull requests do not start it. Record its SHA and outcome. A job that cannot acquire a runner is
not a successful test run; resolve account/runner availability separately.
Do not lower security checks or change visibility merely to bypass CI failure.

## First public-release prerequisites

Before changing visibility, close release-blocking security findings and
review all history/refs that will become visible for secrets, internal data
and redistribution rights. A HEAD-only scan is insufficient. Record the scope
and outcome privately without publishing secrets. Changes of visibility or
history require the maintainer's explicit approval.

Immediately after opening visibility, enable and verify private vulnerability
reporting as described in [SECURITY.md](SECURITY.md), before announcing or
tagging the public release. Review branch/tag protection and support scope.

## Exact-tag publication gate

Create a **new unused tag** at the reviewed, candidate-tested commit only after
the prerequisites above. From a clean checkout at that tag, run:

```sh
make public-module-check VERSION=<tag>
```

`release-source-check` first checks that the tag exists locally, resolves to
HEAD, and the checkout has no staged, unstaged or untracked changes. It changes
no files or Git refs. `externalconsumer-published` then runs an executable
consumer against exactly that public version. No credentials, user Go
configuration, local module/build cache, workspace or direct-VCS fallback are
available to the child Go commands. The public checksum service stays enabled.
The selected module must still have the requested version and no replacement
after test dependencies resolve.

For the full candidate and publication gates on that same tag, with disposable
integration services running:

```sh
make release-readiness VERSION=<tag>
```

Alternatively, dispatch `Public module verification` with the existing tag.
It checks out `refs/tags/<version>`, disables persisted checkout credentials
and the setup-go cache, and runs `make public-module-check`. It fails while the
repository is private. It does not publish anything or alter settings.

The public gate deliberately requires access to `proxy.golang.org` and
`sum.golang.org`. Proxy propagation or network errors are not success; rerun
after resolving them rather than adding a private proxy, disabling checksums,
or reusing a developer cache. The installed Go executable, helper build and
OS trust store are trusted inputs; this is not a hostile-code sandbox.

Publish release notes/announce only after the gate passes. Include migrations,
support limitations and actual evidence, not a blanket production-ready claim.

## Full public-preview acceptance

The v0.6.0 release plan required bounded candidate, publication and separate
AuthHub/GoAdmin host records in [its upgrade guide](docs/v0.6-migration.md).
The broader program below retains historical v0.5.0 `site`/`admin` evidence
mapping and is not a v0.6 acceptance path. Rebaseline its target, scenarios and
host mapping explicitly before making a v0.6 full-public-preview claim; do not
reuse old host observations or substitute the v0.6 release record for it.

Candidate and anonymous publication gates prove only their declared scope.
Before announcing a fully accepted public preview, complete the
[scenario and evidence specification](docs/public-preview/README.md#completion)
and run the [full acceptance gate](docs/release-verification.md#full-public-preview-acceptance):

```sh
make public-preview-readiness VERSION=<tag> EVIDENCE="$RELEASE_EVIDENCE_FILE"
```

Set `RELEASE_EVIDENCE_FILE` to the absolute path of the reviewed manifest outside
the clean checkout. Use the [template](docs/public-preview/release-evidence.example.yaml)
to record all 38 scenarios, both host checks, release gates and owner approval
at the selected SHA/tag. An unfilled template or historical passing summary is
insufficient. The validator checks declared evidence and source identity; it
does not execute every scenario or certify the truth of recorded observations.

## Consumer evidence

The historical `v0.5.0` plan selected `goadmin` composed with
`site`. Record the site's host flows as `host_checks.site` and its goadmin
administration flow as `host_checks.admin`; include the resolved goadmin
version/SHA in the admin evidence. Passing the library's synthetic consumer
does not substitute for these host observations.

Each consumer records its resolved version and absence of local replacements,
its own format/lint/test/migration gates, realm membership and permission
checks, any explicit disposable-data resets, and unperformed/manual smoke
checks separately. The historical matrix in [docs/compatibility.md](docs/compatibility.md)
does not prove adoption of v0.5 or a newer release. Do not infer deployment from tags
or local tests alone.

### Session-bound profile baseline

The schema-8 session-bound OIDC surface and its
[compatibility and rollout checks](docs/session-bound-oidc.md) remain relevant
to the schema-14 candidate. Keep published migration bytes frozen. That baseline
removes legacy refresh Get replay side effects while preserving source compatibility;
release notes must call out the inactive snapshot and authenticated mutation
replacement. Do not publish a schema change independently of its API and a verified
host consumer. Coordinated migration/restart is required; mixed older writers
are not supported.

