# v0.5 candidate assembly decisions

Status: accepted implementation specification for the unpublished v0.5 candidate.
The requirement IDs and release criteria remain in [auth contracts](auth-contracts.md)
and [verification](security-verification.md). Verification results are recorded
separately; this document is not test evidence.

The canonical library owns subjects, credentials, sessions, refresh rotation,
recovery/confirmation, identity links, RBAC and native encrypted notification
state. Hosts own HTTP, cookies, CSRF, frontend, memberships/projections, permission
catalog additions, transport delivery and process supervision. Canonical relations
always use the real `subject_id`; a projection ID or public/numeric admin ID is
never an authentication fallback. See [AUTH_INVARIANTS](../../AUTH_INVARIANTS.md).

## P1: explicit API and native clients

The client supplies a single Bearer access JWT and explicit JSON refresh secret.
The profile never reads cookies or emits Set-Cookie. Missing, invalid, duplicate
or mixed credentials fail without choosing a weaker source. JSON credentials
are allowed only in this profile. Native clients keep them in the operating
system's protected credential storage; a mobile application is outside this
implementation. The site exposes the complete `/api/v1/token-auth/*` lifecycle.

`VerifyJWT` checks a signed, bounded, purpose/issuer/audience/time-valid JWT.
`AuthenticateSession` additionally checks the current canonical subject and
session. Online checks are the default in HTTP realm middleware. `OfflineJWT`
is an explicit trade-off: logout/status changes cannot revoke an already issued
JWT before its capped expiry. Refresh is single use in both profiles.

## P2: browser cookie profile

Production credentials are `__Host-SSID` and `__Host-UUIDR`, Secure, HttpOnly,
SameSite=Lax, Path=/, with no Domain attribute. Development HTTP uses distinct
names and an explicit loopback exception. A browser response never returns the
same secrets in JSON. JavaScript never reads/stores them or adds Bearer headers.
The nonsecret readable `SSIDR=1` is only a startup hint: an ordinary guest without
it makes no auth/me, refresh or CSRF startup calls. Presence grants nothing;
server authentication remains authoritative. Only this marker may have a
configured parent Domain for an allowlisted split frontend/API deployment.

A short-lived access JWT authorizes requests. A longer-lived refresh secret
renews access without exposing credentials to JavaScript. HttpOnly changes
transport/storage access, not the reason refresh exists. Canonical absolute
session expiry caps every returned access/refresh expiry and persistent cookie.
Without remember-me, credentials remain browser-session cookies. A persistent
marker never proves a current account or entitlement.

Every state-changing browser route, including anonymous login/register/recovery,
requires the selected CSRF/origin policy. The site uses a thin wrapper over its
pinned gofiber CSRF Create/Check API. Its proof is bound to a dedicated HttpOnly
context; a raw refresh or opaque authentication secret never appears in readable
proof. Only an exact configured Origin is accepted. A bad/null/present Origin
cannot fall back to Referer; absent Origin requires a matching parsed Referer.
An expired access token does not prevent valid context-bound refresh. `/api/csrf`
returns a JSON proof for the allowlisted split API; it does not authenticate.

Refresh has per-tab singleflight and an origin Web Lock. A waiter rechecks shared
nonsecret expiry after acquiring the lock; it does not submit an old token after
another tab succeeded. Unsupported Web Locks fail closed for automatic refresh.
A submitted request with uncertain network/commit outcome is never retried
with the same refresh secret. Clear the client session and require login.

## P3: existing opaque admin cookie

The admin browser keeps a random opaque credential. Canonical `sid` is not a
client authentication secret. Supported host assembly validates current canonical
realm/session/account, admin membership and permissions on every request.

An encrypted server journal holds the token pair outside Fiber session snapshots.
Redis single-key Lua and the PostgreSQL alternative use an atomic owner/version
claim before refresh. Only one node submits the secret; losers read the saved
new version. A stale whole-session save cannot overwrite credentials. A crashed
or unknown owner never becomes a second owner of the old secret; reauthenticate.
Opaque identifier rotation fences and removes the old journal. Production opaque
cookies use a host prefix and host-only attributes while preserving their format.
Readable CSRF contains only a purpose-separated irreversible binding of that
opaque identifier. Idle and absolute policy remain server-enforced.

The additive journal migration preserves canonical identities. Frontend/backend
cut over together, legacy browser state is discarded and users log in again.
No legacy token exchange or production reset is part of migration. Rollback also
requires coordinated binaries and re-login; it does not undo canonical revocation.

## P4: optional OIDC

The embedded profile defaults to exact `token_use=access`. The explicit
`zitadel-jwt` profile validates the signed access JWT with jti/nbf and rejects
ID/logout-only claims, even for a shared audience. Both retain exact signature,
issuer, audience and temporal checks, discovery/JWKS bounds and key-refresh
coordination. Provider protocol checks are separate from resource-server access
verification. A live ZITADEL subset pilot is not generic OIDC conformance.

## Runtime resource bounds and delivery

Hash admission defaults to four concurrent operations per Runtime and accepts
1..64 explicitly. Busy admission returns `ErrPasswordHashOverloaded`, HTTP 503
with Retry-After; it does not create an unbounded queue. All hash/verify inputs
are valid UTF-8 and at most 128 code points before the hasher is called. Login
never applies a new-secret minimum/blocklist to an existing legacy credential.
Infrastructure errors retain their cause; HTTP errors expose only safe messages.

Reset URLs are absolute HTTPS URLs, with an explicit loopback HTTP allowance.
They exclude URL user information and an email query parameter. Hosts may put
the one-time secret in a fragment; the public example removes that fragment
after copying it into the reset form, avoiding a secret in page requests.

New site events use managed native encrypted delivery through the supported
host `NotificationSender` facade. The host must inspect individual transport
acceptance, supervise RunNotifications and cleanup, and keep legacy job handlers
to drain/expire old encrypted jobs. Delivery is at least once, not a promise of
exactly-once external email. No queued payload or sender error enters logs.
