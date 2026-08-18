# goauth

`goauth` is the canonical authentication, identity, OIDC, session, and RBAC
Runtime for Go hosts using PostgreSQL, Redis, and Fiber.

The current stable compatibility line is `v0.2.0`. The frozen v0.1 line ends
at `v0.1.6`; consumers crossing that boundary must explicitly reset isolated
development or test auth state. Existing v0.1 tags and migrations remain
immutable.

## Supported API

The supported v0.2 imports are intentionally small:

- `github.com/assurrussa/goauth`
- `github.com/assurrussa/goauth/postgres`
- `github.com/assurrussa/goauth/redis`
- `github.com/assurrussa/goauth/fiber`
- `github.com/assurrussa/goauth/oidc`
- `github.com/assurrussa/goauth/oidc/provider`
- `github.com/assurrussa/goauth/oidc/verifier`
- `github.com/assurrussa/goauth/rbac`
- `github.com/assurrussa/goauth/testkit`

`reference/externalconsumer.SupportedPackages` is the machine-readable source
of truth. The compile-checked v0.1 implementation is isolated under
`internal/legacy`; Go's internal-package rule prevents consumers from using it.

## Runtime contract

`postgres.NewRuntime` assembles the canonical store, Argon2id password hashing,
realm sessions, refresh families, password reset, email confirmation, identity
links, trusted bootstrap, password/profile/email lifecycle, logout, audit
persistence, cleanup, atomic rate limiting, and a digest-only OIDC refresh
store. Optional OIDC and RBAC are assembled through Runtime methods.
The host supplies:

- a PostgreSQL connection or DSN;
- distinct versioned keys for JWT signing, token HMAC, and outbox AES-256-GCM;
- an encrypted event sink with delivery acknowledgement and retention cleanup;
- a password-reset URL builder;
- optional membership, claims, identifier, notification, and audit hooks.

Fiber owns only JSON handlers, typed error mapping, and realm middleware. Hosts
continue to own route prefixes, cookies, redirects, UI, projection tables, and
application permission catalogs.

See [docs/v0.2-runtime.md](docs/v0.2-runtime.md) for the model,
[docs/compatibility.md](docs/compatibility.md) for the verified consumer line,
and [AUTH_INVARIANTS.md](AUTH_INVARIANTS.md) for security invariants.

## Verification

```sh
make prepare
make check
make integration
make vulnerability-check
make externalconsumer-local
```

For the current stable tag:

```sh
make release-readiness VERSION=v0.2.0
```

The published clean-consumer probe runs an executable wiring example for the
Runtime, Fiber, OIDC/Redis, and RBAC; it is not a blank-import check.
