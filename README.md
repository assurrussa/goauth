# goauth

`goauth` is a reusable authentication, identity, session, and RBAC Runtime for
Go hosts. PostgreSQL stores canonical auth state, Fiber is an optional HTTP
adapter, and Redis is needed only for optional OIDC one-time state.

The latest existing tag is `v0.3.0`. The standalone public-ready changes in
this checkout target an unpublished `v0.4.0` release. The frozen v0.1 line
ends at `v0.1.7`; consumers crossing that schema boundary must explicitly
reset isolated development or test auth state. Existing tags remain immutable.

## Supported API

The supported imports are intentionally small:

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
of truth. The retired v0.1 implementation is absent from the current source
tree; its published tags remain available.

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
    return app, auth, nil
}
```

`NotificationSender.SendNotification(ctx, delivery)` receives the typed
notification, a stable delivery ID, and its validity deadline. Return success
only after the host delivery provider accepts it; retries may repeat an ID.
Run `auth.RunNotifications(ctx)` in a supervised worker, cancel and join it on
shutdown, schedule `auth.Cleanup(ctx, postgres.CleanupPolicy{})`, and close the
Runtime when the process stops. The host chooses how to serve the Fiber app.
The queue checks one-time state before sending; an account change during an
in-flight external send can still reach the provider. Token validity is always
enforced by the Runtime when the recipient acts on the message.
Use `goauth.NewKeyRing` with separate random material for signing, token HMAC,
and notification encryption; retain prior key versions through rotation.
Managed delivery cannot be combined with a custom `EventSink`,
`NotificationRenderer`, `AuditSink`, or `NotificationTransaction` hook. The
PostgreSQL adapter can use a custom event sink without managed delivery; custom
transaction wiring belongs to direct root Runtime assembly. A custom
`NotificationTransaction` keeps its configured `NotificationRenderer` and
event sink. Direct `RuntimeStore` implementations must guard reset issuance
against the expected primary email, security version, and active status and
invalidate outstanding reset records on password, email, or status changes.

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
- a notification sender and a supervised worker lifecycle, or an advanced
  encrypted event sink with delivery acknowledgement and retention cleanup;
- a password-reset URL builder;
- optional membership, claims, and identifier hooks. Custom rendering and audit
  sinks are available with the advanced event-sink integration path.

Fiber owns only JSON handlers, typed error mapping, and realm middleware. Hosts
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

```sh
make prepare
make check
make integration-local
make vulnerability-check
```

For the unpublished v0.4 candidate, start the integration services and run
the combined gate:

```sh
make integration-up
make release-candidate-readiness
make integration-down
```

After the new tag is published, run `make release-readiness VERSION=v0.4.0`.
The published clean-consumer probe runs an executable wiring example for the
Runtime, Fiber, OIDC/Redis, and RBAC without a local `replace`. The candidate
gate does not establish publication.
