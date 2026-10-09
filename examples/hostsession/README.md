# Email-less login with a host-owned session

This independent CLI example complements the [browser/email example](../nethttp/README.md).
It provisions a synthetic identity under the exact, case-sensitive `host_login`
scheme, checks host project membership and creates/uses an opaque host session.
It calls the existing supported GoAuth PostgreSQL APIs; it adds no auth endpoints,
SSO policy, fake email or exception to the default realm/email rules.

## Run

With Go 1.27.2 and an **existing disposable PostgreSQL database**, run from the
repository root:

```sh
DATABASE_URL='postgres://localhost/goauth_hostsession_demo?sslmode=disable' go run ./examples/hostsession
```

Use your local database's connection details. The role must be allowed to create
tables and apply the canonical migrations. Never point this at a production or
shared application database. The host opens one `*sql.DB` and passes it through
`postgres.Config{DB: db}`; GoAuth neither opens a second pool nor closes this one.
In an application, pass its existing pool to this wiring instead of calling
`sql.Open` again. No Redis, SMTP, Docker, browser or HTTP server is required.

Expected output:

```text
Email-less identity authenticated; host membership checked; host session accepted.
```

Each invocation uses a fresh random login/password and ephemeral Runtime keys.
Passwords, tokens, keys and connection errors are never printed. It applies auth
migrations and adds synthetic auth, audit, rate-limit, membership and session
rows; repeated runs deliberately add new subjects rather than adopt existing
ones. Dispose of the demo database yourself afterward. No existing account is
imported, modified or assigned demo membership.

## Security boundary

- `ProvisionLocalIdentity` is privileged host seeding, not public registration.
  Primary email stays absent and `EmailVerified()` stays false.
- `PrepareCredential` performs durable credential admission and Argon2 work
  outside the final transaction. The explicit limit is ten attempts per fifteen
  minutes. This is credential verification, not a generic realm login.
- `InOwnedAuthTransaction` must own the response-producing boundary.
  `RevalidateCredential` locks the canonical subject and rejects a disabled
  subject or stale security version. Only then does the host lock/check its
  membership and insert its session using the scoped `SQLExecutor`.
- The random 256-bit bearer secret stays in memory; the host table stores only
  its SHA-256 digest, canonical subject ID, project, security version and expiry.
  No token or successful account is returned until the outer commit succeeds.
  Any error, including an unknown commit outcome, withholds success; never blindly
  retry an uncertain operation. A production host needs durable operation receipts
  if it must reconcile an unknown outcome.
- A host session is **not** a GoAuth realm session. Canonical revocation does not
  delete host rows. Every use rechecks canonical active status/security version,
  current project membership and absolute expiry. Password/security changes and
  membership removal therefore deny subsequent use. Use canonical subject locks
  before host membership locks for all related mutations.
- Authentication returns a snapshot, not durable authorization. Protected host
  database writes must execute inside the marked transaction boundary with its
  scoped executor. Do not authorize later work from a cached account snapshot.

## Tests

The integration suite creates synthetic rows in its disposable database and
covers successful login, wrong password, missing membership, disabled subjects,
stale prepared proofs, ambient-transaction refusal, pool ownership, project
binding, and session rejection after status/version/membership/expiry changes.
It does not drop or reset tables. Integration invocation fails if its dedicated
DSN is absent:

```sh
GOAUTH_HOSTSESSION_TEST_DSN='postgres://localhost/goauth_hostsession_test?sslmode=disable' go test -race -tags=integration ./examples/hostsession
```

`go test ./examples/hostsession` only checks the custom identifier resolver;
it is not PostgreSQL/session evidence. The repository's ordinary `make check`
does not replace the explicit integration command above.

## Limits

This is a transaction/wiring demonstration, not a production session server.
The host must supply durable distinct keys, reviewed migrations, operator
provisioning authorization/audit, ingress limits, TLS/cookies/CSRF when applicable,
logout/revocation, session cleanup and operational monitoring. The example has
no HTTP transport, session renewal, RBAC permission policy or SSO integration.
The existing browser/admin/custom realm verified-email policies are unchanged.
See [email-less identities](../../docs/local-identities.md) and
[credential admission](../../docs/credential-admission.md) for the library contract.
