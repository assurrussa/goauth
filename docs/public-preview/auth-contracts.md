# Authentication profile contracts

Status: target behavior for public-preview acceptance; read the
[baseline and scope](README.md) first. Requirement IDs below are local to goauth,
not OWASP certification identifiers.

[Candidate assembly decisions](candidate-assembly.md) describe the selected v0.5
composition. The AUTH requirement IDs below retain their original meanings;
implementation details and local observations do not replace their acceptance.

## Ownership and trust boundaries

### Core and canonical storage

The root Runtime owns principal identity, credential verification, limited versus
full session scope, session/security-version transitions, one-time credentials,
and security-event semantics. PostgreSQL owns the atomic implementation of
these transitions and its migrations. No Fiber or other transport context may
be required by root contracts.

The store API must describe complete security operations, not require consumers
to reproduce atomicity with Get followed by Update/Delete. Custom stores must
pass shared behavioral/concurrency tests. A compiling mock is not a conforming
production store.

Core methods accepting SubjectID are trusted application APIs, not automatically
permission-checked remote endpoints. A SubjectID or AuthContext built from JSON
is not authentication. Before invoking account mutations, logout-all, role
management or trusted provisioning, the host must resolve the actor and enforce
actor-to-target authorization. ProvisionTrustedLocalAccount must never become
public self-registration through generic handler generation.

### Supported HTTP integration

An optional adapter owns credential extraction, cookie encoding/clearing, CSRF
validation, response safety and HTTP error mapping for the selected profile.
The host provides deployment origins, route choices, membership policy, storage
of keys, TLS/proxy configuration and process supervision. If library-provided
adapter defaults or examples are unsafe, that is a library defect; the host
boundary must not become a disclaimer for unsafe defaults.

UI, resource ownership/tenant rules and application permission catalogs stay in
the host. A verified identity alone does not authorize a resource operation.
Client-selected realm, subject, claims or URL parameters never confer rights.

### Extensions

Custom delivery providers, extra claims, profile data and membership rules are
supported extension directions. Key validation, reserved claims, one-time
consumption and revocation must not be silently bypassed by extension hooks.
Specify for every hook: trusted input, whether it runs inside a transaction,
retry/cancellation semantics, and whether it may perform external side effects.
Do not call arbitrary remote hooks while holding long-lived auth row locks.
Custom host code and forks must re-run the applicable contract suite.

## Profiles

### P1: explicitly presented JWT / Bearer API

Current building blocks: root Runtime, PostgreSQL and Fiber/nethttp Bearer middleware.
This profile uses access JWT plus refresh token and a canonical server-side
session. It does not require a browser or cookies.

Select exactly one documented credential source for each endpoint. P1 must not
silently fall back from an invalid/missing Authorization header to cookies, URL
parameters or request JSON. A separate CSRF token is not intrinsically required
for a strictly explicit-Bearer endpoint without ambient browser credentials.
A refresh endpoint that accepts a cookie is a cookie endpoint even when the
business API otherwise uses Bearer tokens.

Offer explicitly named verification policies: signature/claims-only verification
and online authentication against session state. Naming is conceptual here;
this spec does not introduce new exported functions. Keep existing API compatible
or use a reviewed versioned change. Sensitive/admin routes use online state and
current authorization; offline verification documents its revocation delay.

### P2: browser JWT cookies

Target: a supported optional integration/example, not cookies inside root Runtime.
For the initial reference deployment use HTTPS and a same-origin frontend/API;
other origin topologies need explicit configuration and browser tests.

Authentication cookies are Secure and HttpOnly, host-only by default, with
explicit SameSite and bounded expiry. Use compatible __Host- names when Path=/
and no Domain are appropriate; do not combine that prefix with narrower paths.
Host-owned alternative names/paths are explicit. Deletion must match the original
cookie scope. Do not expose access/refresh secrets again in a JSON login response
in the cookie profile. Credential-bearing responses use Cache-Control: no-store.

The client may read a separate CSRF value, not authentication secrets. The chosen
CSRF mechanism must bind proof to authenticated session state or to a bounded
pre-login context, and validate explicitly submitted proof before protected side
effects. Login/registration transitions rotate the relevant context; logout and
session expiry invalidate it. Refresh must remain possible after the access JWT
expires: validate against the still-valid refresh/session context, not solely
the expired JWT. Multi-tab refresh must follow the chosen replay policy.

The browser assembly must select managed CSRF protection or an explicit host
validator integration with equivalent contract tests. A missing validator must
fail construction or deny protected requests. A bare boolean assertion that
"upstream handles it" is not evidence. Standalone core/HTTP components may remain
composable; that alone does not make an arbitrary composition the supported P2.

Require the protected route inventory to include login, refresh, logout, account
changes and reset/confirmation submissions. GET may display a reset page but
must not consume a reset token or mutate credentials. Specify exact allowed
origins and treatment of absent/null Origin, proxies, preflights and form posts.
SameSite and CORS are additional controls, not universal substitutes for the
selected CSRF validation. Do not accept only a cookie as CSRF proof.

[OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
informs this integration. CSRF protection addresses involuntary browser requests;
it is not protection against XSS or an attacker who already possesses usable
credentials. Host XSS prevention and incident response remain necessary.

### P3: admin session integration

Required business outcome: preserve the maintainer's working admin login and
session controls. Local inspection identified an opaque browser credential and
a canonical session bridge; see the candidate assembly and local evidence.
The deployed production version and full ADM acceptance remain unverified.

If the admin uses JWT cookies plus online state, apply P2 with admin membership,
current permission checks and its session policy. Do not build a redundant model.
If it uses an independent opaque credential, preserve or implement an optional
bridge whose server-side record is bound to canonical SubjectID, realm, scope,
security version and expiry. Keep the reviewed session implementation when it
can honor these rules; do not invent cryptography for a bridge.

The client credential must be a secret, not just a database primary key or the
`sid` disclosed inside a JWT. Use an unpredictable secret and verified lookup
mechanism, rotate on authentication/elevation, enforce absolute and chosen idle
expiry, and propagate revocation. Do not refresh/rotate a one-use refresh token
on every admin HTTP request as a substitute for session authentication.

Use the same credential invalidation authority; a host session must not outlive a
canonical revocation because it cached "authenticated=true". Specify cache lag
if any. Cookies and CSRF follow P2. Recent-auth requirements use a real fresh
authentication event, not the iat of a refreshed access token.

[OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
provides the baseline for credential handling, renewal and timeout review.

### P4: optional OIDC / SSO

Existing provider and verifier packages remain in the current supported import
manifest; this document does not remove or demote existing API compatibility.
The local-auth release does not require expanding their feature set. Fix known
security defects or explicitly disable unsafe entry points before publication;
"optional" is not a waiver.

Distinguish an application acting as an OIDC client of an external identity
provider from goauth acting as a provider for other applications. For future SSO,
first prove one selected external-provider integration; keep project-specific
membership and resource authorization local. A verifier for API access tokens
is not automatically an OIDC login client/ID-token validator. Provider protocol
coverage/conformance is a separate, explicitly bounded workstream.

## Core acceptance requirements

- **AUTH-01**: invalid credentials never produce an authenticated result;
  unverified accounts receive only documented confirmation scope. Account
  enumeration policy is explicit for login, registration and recovery; do not
  claim identical responses where registration deliberately exposes conflicts.
- **AUTH-02**: validate algorithm, key selection, issuer, audience, expiry,
  subject, session, realm, scope and security-version claims. Reject reserved
  claim override and token-kind confusion. No untrusted URL controls key fetches.
- **AUTH-03**: online authentication checks active session/subject and matching
  identity, realm, scope and version. Storage failures deny access without an
  offline fallback. Distinguish infrastructure failure from invalid credentials
  in safe error/telemetry channels; it must not force false client logout loops.
- **AUTH-04**: refresh consumption/replacement is atomic; replay follows the
  documented family/session revocation policy. No two successful rotations of
  one current credential. Hooks/signing failures before commit must not consume
  it. Post-commit lost responses have an explicit recovery policy; no promise
  of exactly-once HTTP delivery and no unreviewed replay grace period.
- **AUTH-05**: security-sensitive password/email/status transitions invalidate
  the intended sessions and one-time records atomically. Online revocation is
  observed on a subsequent state check; it does not cancel already authorized
  in-flight business transactions. Offline tokens remain usable until expiry
  within the configured bound (currently at most five minutes).
- **AUTH-06**: logout is ownership-checked at the integration boundary, revokes
  server state and clears the selected cookies. Repeated logout is safe and its
  HTTP mapping is specified. Logout-all covers canonical and bridged sessions.
- **AUTH-07**: reset/confirmation issuance and consumption enforce expiry,
  attempts, destination and current security state. Concurrent changes cannot
  revive a superseded credential. Password hashing has bounded parameters and
  input/resource limits; partial policy overrides must not silently disable
  advertised safeguards.
- **AUTH-08**: document transaction boundaries and outcomes for each mutation:
  not committed, committed, or outcome unknown. Audit/notification failure must
  not disguise committed state as a safely retryable no-op. Retry guidance
  differs between these outcomes; arbitrary retries are not acceptable.
- **AUTH-09**: unknown keys fail closed; key rings stay purpose-separated;
  rotation covers simultaneous old/new processes and live credential retention.
  HS256 verifiers holding the signing secret are within the issuer trust
  boundary; do not share it with unrelated projects as an SSO shortcut.
- **AUTH-10**: role/membership changes have explicit enforcement points and
  revocation latency. Authenticated user scope never grants admin access.
  External identity comes only from trusted verification, never caller JSON.

These requirements must be linked to the [test scenarios](security-verification.md)
and recorded with current source/version evidence before advertising support.
