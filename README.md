# goauth

`goauth` is a reusable authentication, identity, session, and RBAC Runtime for
Go hosts. PostgreSQL stores canonical auth state; net/http and Fiber are optional HTTP
adapters, and Redis is needed only for optional OIDC one-time state.

This checkout prepares unpublished `v0.5.0` from the `v0.4.1` tagged baseline.
See [the v0.5 migration](docs/v0.5-migration.md) for changed contracts.

**Pre-v1, public-release preparation.** A Git tag is not proof of public
availability, an independent security audit, or production adoption. See
[the release plan](docs/public-release-plan.md) for the remaining acceptance
criteria and [RELEASING.md](RELEASING.md) for exact-tag verification.
The frozen v0.1 line ends at `v0.1.7`; consumers crossing that schema
boundary must explicitly reset isolated development or test auth state.
Existing tags remain immutable.

## Supported API

The supported imports are intentionally small:

- `github.com/assurrussa/goauth`
- `github.com/assurrussa/goauth/postgres`
- `github.com/assurrussa/goauth/redis`
- `github.com/assurrussa/goauth/fiber`
- `github.com/assurrussa/goauth/nethttp`
- `github.com/assurrussa/goauth/oidc`
- `github.com/assurrussa/goauth/oidc/provider`
- `github.com/assurrussa/goauth/oidc/verifier`
- `github.com/assurrussa/goauth/rbac`
- `github.com/assurrussa/goauth/testkit`

`reference/externalconsumer.SupportedPackages` is the machine-readable source
of truth. Earlier v0.1 releases remain available at their immutable tags; the
retired implementation is absent from this repository.

## Runnable browser and JSON API example

[examples/nethttp](examples/nethttp/README.md) runs one PostgreSQL-backed Runtime
with standard net/http, browser cookies, coordinated refresh, a bearer-only JSON
API, and a local SMTP catcher. Its host owns CSRF, cookies, UI and worker lifetime.
The `nethttp` middleware checks current sessions by default; `OfflineJWT` is an
explicit opt-out. `AuthContext(request.Context())` retrieves the checked identity.
The accepted [profile contracts and evidence](docs/public-preview/README.md)
separate browser cookies from explicit native/API credentials. The candidate gate
includes a real HTTPS browser and backup/restore; see release verification for
the required installed browser selection.

Passwords are bounded before hashing/verification, and each Runtime admits four
concurrent hash operations by default (`MaxConcurrentPasswordHashes` is configurable).
Saturation returns `ErrPasswordHashOverloaded` with 503/Retry-After in HTTP adapters.
Returned token lifetimes never exceed their canonical absolute session expiry.
OIDC verifier defaults to the embedded access profile; selecting `zitadel-jwt`
is explicit and does not enable acceptance of ID tokens.

## PostgreSQL and Fiber quickstart

The host supplies a PostgreSQL DSN, three distinct 32-byte versioned key
rings, and a `goauth.NotificationSender` implementation backed by its email or
other delivery provider. This wiring mounts a minimal user-realm API:

```go
import (
    "context"
    "net/url"

    "github.com/assurrussa/goauth"
    goauthfiber "github.com/assurrussa/goauth/fiber"
    "github.com/assurrussa/goauth/postgres"
    "github.com/gofiber/fiber/v3"
)

func wireAuth(
    dsn string,
    signingKeys, tokenKeys, notificationKeys goauth.KeyRing,
    sender goauth.NotificationSender,
) (*fiber.App, *postgres.Runtime, error) {
    auth, err := postgres.NewRuntime(postgres.Config{
        DSN:                dsn,
        AutoMigrate:        true, // use the host's migration lifecycle in production
        NotificationSender: sender,
        Runtime: goauth.Config{
            Signing: goauth.SigningConfig{
                Issuer: "https://auth.example.com", Audience: "example-app", Keys: signingKeys,
            },
            TokenHMACKeys:  tokenKeys,
            OutboxAEADKeys: notificationKeys,
            URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
                return "https://app.example.com/reset?token=" + url.QueryEscape(token), nil
            }),
        },
    })
    if err != nil {
        return nil, nil, err
    }
    adapter, err := goauthfiber.New(auth)
    if err != nil {
        _ = auth.Close()
        return nil, nil, err
    }
    app := fiber.New()
    app.Post("/auth/register", adapter.Register)
    app.Post("/auth/login", adapter.Login)
    app.Post("/auth/refresh", adapter.Refresh)
    app.Post("/auth/password-reset", adapter.RequestPasswordReset)
    app.Post("/auth/email-challenge", adapter.RequireRealm(goauth.RealmUser,
        goauthfiber.RealmMiddlewareOptions{AllowConfirmation: true}),
        adapter.SendEmailChallenge)
    app.Post("/auth/email-challenge/verify", adapter.RequireRealm(goauth.RealmUser,
        goauthfiber.RealmMiddlewareOptions{AllowConfirmation: true}),
        adapter.VerifyEmailChallenge)
    app.Get("/me", adapter.RequireRealm(goauth.RealmUser,
        goauthfiber.RealmMiddlewareOptions{}), func(c fiber.Ctx) error {
        authContext, _ := goauthfiber.AuthContext(c)
        return c.JSON(fiber.Map{"subjectId": authContext.SubjectID.String()})
    })
    return app, auth, nil
}
```

To sign in, send `POST /auth/login` with JSON such as
`{"scheme":"email","identifier":"user@example.com","password":"...","realm":"user"}`.
The response contains `account` and `tokens` (`accessToken`, `refreshToken`,
expiry, realm, and scope). Send `Authorization: Bearer <accessToken>` to `/me`;
the middleware checks the realm and, by default, the current
server-side session and subject status. Send `POST /auth/refresh` with
`{"refreshToken":"..."}` to rotate the refresh token. Registration returns a
confirmation-scoped session; use that access token to request an email code,
then verify it with `{"code":"..."}`. After verification, log in again to
obtain a full-scope session. `Runtime.Logout` and `LogoutAll` revoke sessions;
the host must expose its chosen logout routes and token storage policy.

`NotificationSender.SendNotification(ctx, delivery)` receives the typed
notification, a stable delivery ID, and its validity deadline. Return success
only after the host delivery provider accepts responsibility; it does not mean
that the recipient received the message. Retries may repeat an ID, and expiry
or the attempt limit can end processing without a successful send. The sender
must honor context cancellation and set network timeouts so shutdown can join
the worker. `NotificationWorkerConfig.OnBlocked` reports a delivery ID and safe
reason when decryption fails; alert on this signal without logging payloads.
Run `auth.RunNotifications(ctx)` in a supervised worker, cancel and join it on
shutdown, schedule `auth.Cleanup(ctx, postgres.CleanupPolicy{})`, and close the
Runtime when the process stops. The host chooses how to serve the Fiber app.
The queue checks one-time state before sending; an account change during an
in-flight external send can still reach the provider. Token validity is always
enforced by the Runtime when the recipient acts on the message.
Use `goauth.NewKeyRing` with separate random material for signing, token HMAC,
and notification encryption; retain prior key versions through rotation.
Managed delivery cannot be combined with custom event, renderer, audit or
transaction hooks. PostgreSQL assembles `AuthTransaction` for all participating
auth writes, audit records and native encrypted events. Advanced direct root
assembly requires an `AuthTransaction` and transactional `AuditSink`; custom
stores and event sinks must join the supplied context, including reads. The old
`NotificationTransaction` configuration is rejected instead of silently running
without the full transaction contract. See [migration details](docs/v0.5-migration.md).
Direct `RuntimeStore` implementations must guard reset issuance
against the expected primary email, security version, and active status and
invalidate outstanding reset records on password, email, or status changes.
They must also reject email-challenge issuance when the expected primary email
or security version no longer matches, and invalidate old challenges when the
primary email changes.

## Runtime contract

`postgres.NewRuntime` assembles the canonical store, Argon2id password hashing,
realm sessions, refresh families, password reset, email confirmation, identity
links, trusted bootstrap, password/profile/email lifecycle, logout, audit
persistence, cleanup, atomic rate limiting, and a digest-only OIDC refresh
store. The native PostgreSQL notification queue is selected by providing a
`goauth.NotificationSender`; it stores encrypted deliveries and exposes a
worker and cleanup operation. Optional OIDC and RBAC are assembled through
Runtime methods. The host supplies:

- a PostgreSQL connection or DSN;
- distinct versioned keys for JWT signing, token HMAC, and outbox AES-256-GCM;
- a notification sender and a supervised worker lifecycle;
- a password-reset URL builder;
- optional membership, claims, and identifier hooks.

Custom encrypted event sinks, rendering and transactional audit wiring require
direct root Runtime assembly. `postgres.NewRuntime` rejects custom `EventSink`,
`AuditSink` and `AuthTransaction` overrides before database side effects. All
participants in direct root assembly must enlist in the same auth transaction;
receiving its context alone does not guarantee that an external sink will roll
back with the canonical writes.

The HTTP adapters own only JSON handlers, typed error mapping, and realm middleware. Hosts
continue to own route prefixes, cookies, redirects, UI, projection tables, and
application permission catalogs. `auth_subjects` is the canonical principal;
host users and admin rows are projections or memberships keyed by its
`subject_id`. Realm plus host membership is the admin boundary. RBAC role
assignments use that same canonical ID; hosts extend the permission catalog and
own their presentation DTOs.

See [docs/v0.2-runtime.md](docs/v0.2-runtime.md) for the underlying model,
[docs/compatibility.md](docs/compatibility.md) for the verified consumer line,
and [AUTH_INVARIANTS.md](AUTH_INVARIANTS.md) for security invariants. See
[LICENSE](LICENSE) and [SECURITY.md](SECURITY.md) for reuse and private security
reporting.

## Verification

Use the Go version/toolchain in `go.mod` and the tool versions in
`.github/workflows/ci.yml`; see [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
make prepare
make check
make integration-local
make vulnerability-check
```

For the unpublished v0.5 candidate, select the installed browser tools as
described in [release verification](docs/release-verification.md), then start
disposable integration services:

```sh
make integration-up
make release-candidate-readiness
make integration-down
```

After a new public tag exists, check out that tag and run
`make public-module-check VERSION=<tag>`. For candidate and public gates
together, use `make release-readiness VERSION=<tag>` with integration services
running. An explicit version is required; there is no stale default tag.

The published probe runs the Runtime/nethttp/Fiber/OIDC/Redis/RBAC wiring example in a
fresh consumer environment through the public Go proxy and checksum service,
without credentials, reused caches, a workspace, or a local `replace`. It
checks the exact selected version after the test as well as before it.
Database-backed acceptance runs through the separate local PostgreSQL consumer.
Candidate checks do not establish publication; the public probe does not
establish a security audit or production deployment.
