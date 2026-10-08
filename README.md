# goauth

`goauth` is a PostgreSQL-first authentication Runtime for Go applications, with
sessions, recovery, encrypted notification delivery, OIDC and RBAC.
PostgreSQL stores canonical auth state; net/http and Fiber are optional HTTP
adapters, and Redis is needed only for optional OIDC one-time state.

The latest published release is [`v0.6.0`](https://github.com/assurrussa/goauth/releases/tag/v0.6.0)
(schema 8). Upgrading from `v0.5.1` (schema 3) includes the intervening migrations
and needs an explicit rollout and rollback plan. Read the
[v0.6 migration guide](docs/v0.6-migration.md),
[release boundaries](docs/session-security-fixes.md#release-boundary) and
[RELEASING.md](RELEASING.md) before adopting.
The [v0.5 migration guide](docs/v0.5-migration.md) describes the earlier v0.5
contract transition, not the complete schema 3→8 upgrade.

**Pre-v1, public release.** A Git tag is not proof of public
availability, an independent security audit, or production adoption. See
[the release plan](docs/public-release-plan.md) for the remaining acceptance
criteria and [RELEASING.md](RELEASING.md) for exact-tag verification.
The frozen v0.1 line ends at `v0.1.7`; consumers crossing that schema
boundary must explicitly reset isolated development or test auth state.
Existing tags remain immutable.

## Documentation

- [Runnable quickstart](examples/nethttp/README.md): browser and JSON API wiring.
- [Notification outcomes and bounded expiry](docs/notification-outcomes.md): explicit
  terminal non-delivery and queue-only, transaction-aware maintenance.
- [Bounded rate-event maintenance](docs/rate-event-maintenance.md): independent
  cleanup batches, shared-consumer retention and the schema 7 upgrade.
- [Production notification delivery](docs/notification-delivery.md): host sender
  contract and optional confidential NotifyHub integration.
- [Project contract](docs/project-contract.md) and
  [auth invariants](AUTH_INVARIANTS.md): ownership and security boundaries.
- [PostgreSQL Runtime](docs/v0.2-runtime.md): canonical storage and lifecycle.
- [OIDC policy](docs/oidc-provider-policy.md) and [RBAC API](rbac/rbac.go).
- [v0.6 migration](docs/v0.6-migration.md): schema 3→8 upgrade and rollback guidance.
- [v0.5 migration](docs/v0.5-migration.md): changed contracts and upgrade guidance.
- [Security policy](SECURITY.md): private reporting and support scope.
- [Releasing](RELEASING.md): candidate, publication and full acceptance gates.

The [public-preview specification](docs/public-preview/README.md) defines release
acceptance criteria. Engineering review notes record historical work and checks;
they do not replace consumer guidance or acceptance evidence at the release SHA.

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

## HTTP adapter capabilities

| Capability | net/http | Fiber |
| --- | --- | --- |
| Register, login, refresh | Built in | Built in |
| Password reset and email verification | Built in | Built in |
| Logout, logout-all, password change, email change | Built in | Host handlers call the root Runtime |
| Realm middleware with current-session checks | Default | Default |
| Offline JWT verification | Explicit opt-in | Explicit opt-in |
| Request body cap | 1 MiB | 1 MiB in auth handlers |

Fiber hosts should also configure `fiber.Config.BodyLimit` to bound request
buffering before handlers run. Each adapter returns HTTP 501 with
`notification_delivery_disabled` for `ErrNotificationDeliveryDisabled`; hosts
may choose to omit recovery/email routes in disabled delivery mode.
See [OIDC provider policy](docs/oidc-provider-policy.md) for client authentication,
public-client S256 PKCE, confidential-client policy and persistent secret
verification.

## Runnable browser and JSON API example

[examples/nethttp](examples/nethttp/README.md) runs one PostgreSQL-backed Runtime
with standard net/http, browser cookies, coordinated refresh, a bearer-only JSON
API, and a local SMTP catcher. Its host owns CSRF, cookies, UI and worker lifetime.
The `nethttp` middleware checks current sessions by default; `OfflineJWT` is an
explicit opt-out. `AuthContext(request.Context())` retrieves the checked identity.
The [profile contracts and required evidence](docs/public-preview/README.md)
separate browser cookies from explicit native/API credentials. The candidate gate
includes a real HTTPS browser and backup/restore; see release verification for
the required installed browser selection.

Passwords are bounded before hashing/verification, and each Runtime admits four
concurrent hash operations by default (`MaxConcurrentPasswordHashes` is configurable).
Saturation returns `ErrPasswordHashOverloaded` with 503/Retry-After in HTTP adapters.

`CredentialVerificationRateLimit` can set a separate bounded policy for repeated
`VerifyCredential`/PostgreSQL `PrepareCredential` calls. Zero preserves the current
`LoginRateLimit` behavior; browser login, password change and recovery keep their
existing policies. Successful checks still count. See
[credential admission](docs/credential-admission.md) before using per-request Basic.
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
shutdown, and close the Runtime when the process stops. Schedule broad
`auth.Cleanup(ctx, postgres.CleanupPolicy{})` only with a host retention policy.
Canonical refresh replay evidence remains until family/session termination plus
retention; see [session security and release boundaries](docs/session-security-fixes.md).
For rate-event-only maintenance, use bounded `auth.CleanupRateLimitEvents` calls
outside managed transactions; preserve the longest window across all shared
consumers plus clock skew and request latency. See [the maintenance contract](docs/rate-event-maintenance.md).
The host chooses how to serve the Fiber app.
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

For an unreleased candidate, select the installed browser tools as
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

### Delivery-free operator administration

`Config.NotificationDelivery = NotificationDeliveryDisabled` explicitly disables
password-reset issuance/consumption, email challenge issuance/verification, and
email-change commands. Commands return `ErrNotificationDeliveryDisabled` before
attempt bookkeeping or storage writes. Password login, profile updates, and
password changes remain available; password changes still commit mandatory audit
and security-state revocation. No sender, URL builder, or outbox AEAD keys are
required in this mode. The zero policy retains required encrypted delivery.

PostgreSQL hosts can use `Runtime.InAuthTransaction` and `Runtime.SQLExecutor(ctx)`
to commit host projections with canonical writes, audit, and RBAC. The executor
exposes only SQL execution/query methods, never transaction ownership. Participating
adapters must share `Runtime.Database()` exactly; a separate handle is rejected.
Response-producing entry points can require ownership with
`Runtime.InOwnedAuthTransaction`: an ambient same-handle transaction returns
`postgres.ErrAuthTransactionAlreadyActive` before the callback or a second BEGIN.
Ordinary `InAuthTransaction` and low-level calls still join inside its callback.
Publish prepared secrets, tokens or authorization results only after the owned
method returns nil; callbacks must not publish them early. Every error withholds
these results, including `ErrOperationOutcomeUnknown`, which does not prove rollback
and must not trigger a blind retry. See [owned transactions](docs/owned-auth-transactions.md).

The unreleased additive `rbac.Service.Check(ctx, subjectID, key) (bool, error)`
distinguishes ordinary denial (`false, nil`) from a failed authorization check.
A zero subject returns `goauth.ErrInvalidSubjectID` before permission-key
validation; an invalid key returns an error matching
`rbac.ErrInvalidPermissionKey`. Cache and store errors retain their causes for
`errors.Is`/`errors.As` and always return `false`. Cache failures do not fall
back to storage. The selected dependency receives the caller's context;
cancellation and deadline errors it returns remain identifiable. Check does not
independently reject a canceled context when that dependency returns success,
preserving existing cache-hit and store behavior.

Existing `Can` remains a boolean fail-closed wrapper, and `Require` continues
to return `ErrPermissionDenied` for every unsuccessful check, including
dependency failures. Hosts can adopt Check explicitly when they need separate
denial and dependency-failure handling; HTTP status policy remains host-owned.
This API addition is not present in the published v0.6.0 tag.

RBAC authorization reads join the transaction and bypass caches. `Snapshot` needs
a standalone repeatable-read transaction; invoking it in a managed auth transaction
returns `rbac.ErrSnapshotTransactionUnsupported`. Supplied caches must implement
`rbac.CacheInvalidator`; invalidation follows successful outer commit, never rollback.
RBAC writes reserve cache bypass before SQL mutation, including standalone
transactions. Managed operations use savepoints: an operation error restores its
changes even if the host handles it and commits other writes. RBAC mutations on
the same managed connection are serialized. Failure to restore a savepoint aborts
the outer transaction. Rollback releases only its own reservations. While a write
is pending, other authorization checks read committed PostgreSQL state.
Each transaction/cache pair shares one guard and one invalidation regardless of
write count. Each invalidation, including waiting for pending cache fills, has a two-second
deadline detached from the request cancellation. Invalidators must honor that
deadline and return after clearing the cache. Timeout leaves committed writes
successful and the cache bypassed; an older completion cannot clear a newer failure.
Failed cache invalidation bypasses the cache and reads authoritative PostgreSQL
permissions; successful invalidation restores normal cached reads. An uncertain
RBAC write commit returns `ErrOperationOutcomeUnknown` and keeps this cache wrapper
bypassed for its lifetime. A read-only snapshot commit error keeps its classification
without changing cache trust. Database read failures still deny authorization.

Repeated `NewRBAC` or `Runtime.RBAC` calls with the same live, comparable cache
value and exact `*sql.DB` share the cache guard, invalidation lock and outcome
state. Keep these services alive to retain cache acceleration. The registry uses
weak references and does not own the database or cache. Mixing different cache
values, adding an uncached service, repeating a noncomparable value cache, or
reassembling after its wrapper is collected permanently switches cached reads to
PostgreSQL for that DB handle. Invalidation still follows management commits.
This conservative fallback cannot be cleared by later assembly or invalidation.
Cache backends must belong to one canonical database; distinct DB handles and
external SQL writers are outside this coordination contract.

Managed `NotificationDelivery.EncryptedEvent` contains the original sealed envelope
for hosts that forward delivery into durable transports. The native queue remains
the initiating auth transaction owner; downstream transports persist ciphertext
only and deduplicate by delivery ID. `Notification` plaintext is ephemeral; never
persist its reset URLs or codes. Acceptance is at least once, so SMTP or downstream
transport acceptance may repeat after an uncertain acknowledgement. The worker
renews its owned unexpired lease while reserving the attempt before sending;
reservation and send share a bounded deadline. Expiry of that delivery deadline
expires, retries or exhausts only the delivery; it does not stop the worker pool.
After an ambiguous reservation timeout, the worker reads the persisted attempt
count under the same lease token before settling the delivery. Parent cancellation
stops the worker. Senders must honor cancellation and should deduplicate by delivery ID.

Privileged hosts can use `Runtime.RequestPasswordResetWithReceipt` to bind a
`PasswordResetReceipt` (subject ID and public selector only) within the same
transaction as the reset record, encrypted enqueue and mandatory audit. A callback
failure rolls back those writes; no callback runs when issuance is suppressed.
Use the PostgreSQL runtime's context SQL executor in the callback. Keep receipt
presence private from unauthenticated clients. On `ErrOperationOutcomeUnknown`,
preserve the host claim and reconcile durable state before attempting issuance
again; never clear a cooldown and resend blindly.

PostgreSQL trusted bootstrap flows can call `PrepareCredential` before the host
transaction. Its opaque, runtime-bound proof expires after five minutes. Inside
`InAuthTransaction`, call `RevalidateCredential` before granting membership: it
holds the canonical subject row lock through outer commit and checks active
status, security version and normalized primary email. It creates no session and
does not bypass durable rate admission. Fresh trusted provisioning can remain
inside the transaction.

## Email-less local identity foundation

Privileged hosts can provision or import canonical local identities using a
registered non-email login scheme, without fabricating email. See
[the local identity contract](docs/local-identities.md) for create-only imports,
transactional host mappings, narrowly bounded legacy password compatibility,
schema-4 migration, privileged `SetTrustedLocalPassword`, and host admission/SSO integration steps.
The privileged setter preserves subject status, advances security version even for
identical plaintext, and joins managed host transactions with mandatory audit.

Terminal authentication-subject retirement and scoped custom-login release are
available through optional lifecycle APIs, with an explicit schema 6 upgrade.
See [the retirement contract](docs/subject-retirement.md) for retained bindings,
managed transaction receipts, compatibility and rollback requirements.

## Session-bound confidential OIDC

Hosts with their own opaque SSO sessions can use the additive
`provider.NewSessionBound` and `postgres.NewSessionOIDCState` integration.
[The session-bound profile](docs/session-bound-oidc.md) documents owned
transactions, request-specific reauthentication, client-aware live admission,
fixed-deadline refresh, project claims and schema 8 rollout. It leaves generic
realm/email policy and legacy provider DTO layouts unchanged.

`OIDCRefreshTokenStore.Get` is now read-only. A consumed token is reported as an
inactive snapshot; authenticated replay revocation/audit occurs on the owning
provider's mutation path. See the compatibility notes before upgrading direct
adapter consumers.
