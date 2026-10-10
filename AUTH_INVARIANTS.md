# Auth invariants

## Canonical identity

- `auth_subjects` contains only canonical ID, `active|suspended|disabled`
  status, security version, timestamps, and an optional terminal retirement marker.
- Identifiers, basic profile, local credentials, memberships, identity links,
  sessions, and RBAC assignments are separate relations keyed by canonical
  `subject_id`.
- Host `users` and `administrations` rows are projections or memberships. Host
  numeric IDs and public IDs never substitute for canonical `subject_id`.
- Privileged local identity provisioning/import may omit email and use an explicitly
  registered non-email identifier scheme. A missing PrimaryEmail is the zero
  Identifier, never a fabricated or verified email.
- Primary custom-login rename is subject/version/old-value CAS. It preserves
  subject/status/credential/profile, advances once for every real display or identity
  edit, and atomically invalidates canonical security state with mandatory audit.
  Old login reuse creates a fresh subject; aliases are never promoted or merged.
- Terminal subject retirement requires an exact primary custom login and positive
  subject-version CAS. It disables the entire subject, advances once, releases only
  that login and removes local credentials with mandatory audit/invalidation.
  UUID/profile/audit/RBAC and other identifier/external bindings remain reserved;
  retained email ownership can block reuse and never silently links a replacement.
  Retired subjects cannot reactivate or receive credentials/identity links. The
  separate optional lifecycle view preserves the public Subject layout and reads
  account plus marker from one snapshot. See `docs/subject-retirement.md`.
- Email uniqueness is `(scheme, normalized_value)`. Display spelling is stored
  separately; built-in email normalization is lowercase after validation.

## Realms and authorization

- `user` and `admin` are realms, not subject kinds.
- An unverified user can receive only a confirmation-scoped user session.
- Admin and custom realms require a verified email and a successful host
  `MembershipGate`; RBAC remains the permission boundary.
- Realm and scope are persisted in the session and included in access claims.
  HTTP middleware authenticates server-side session state by default. Admin and
  custom realms recheck the host membership gate. Offline JWT verification is explicit.
- Suspending, disabling, resetting, changing or privileged-setting a password, or confirming an
  email change or renaming a primary custom login increments security version and
  revokes sessions and refresh families in one PostgreSQL transaction.
  Offline access tokens never live longer than five minutes.

## One-time state

- Refresh, password-reset, OIDC code, and OIDC challenge paths are atomic
  consume or rotate operations. A public `Get` followed by `Delete` is not an
  acceptable single-use contract.
- Hooks, hashing and JWT preparation precede session writes and refresh rotation.
  A refresh snapshot authenticates without consumption; the final transaction
  locks the canonical subject and revalidates state before consuming the token.
- Auth writes, mandatory audit and encrypted enqueue commit together. Explicit
  disabled delivery prohibits email/recovery commands before writes; password
  changes retain mandatory audit without enqueue. Managed PostgreSQL host and
  RBAC writes share the outer transaction; cache invalidation follows commit.
  Concurrent RBAC operations register their commit/unknown hooks atomically;
  hooks execute outside the registration lock. Hosts must join all operations
  using a managed context before its callback returns. Callback errors roll back;
  business denials that update attempt/replay protection commit.
- Response-producing host boundaries can require an outermost managed transaction
  with `postgres.Runtime.InOwnedAuthTransaction`. Ambient same-handle scopes reject
  before callbacks or writes; joined internal operations remain atomic. Prepared
  secrets, tokens and allow results are withheld until its nil return, never
  published by its callback. An unknown commit outcome is not a confirmed rollback.
- Refresh replay revokes its family and session and emits a security event.
  Replay processing bypasses token preparation. There is no grace interval.
  Canonical consumed-token evidence survives until family/session termination
  plus retention; individual token expiry does not end replay protection.
- Security writes lock the canonical subject before dependent state. Logout-all
  increments its security version so an already prepared login cannot escape it.
- OIDC refresh tokens also persist only selector plus HMAC digest; replay of a
  rotated token revokes the complete OIDC family and emits an audit event.
- Password reset is selector-based, contains no email in the URL, and updates
  the credential, security version, reset record, sessions, and refresh
  families in one transaction.
- Default reset issuance checks the active subject, current primary email, and
  security version under the subject lock. An explicitly configured host recipient
  resolver may authorize a recovery alias for the same canonical subject, requiring
  an existing local credential, current version, and locked recipient revalidation.
  Password, email, status, and host recovery-alias changes invalidate outstanding
  reset records atomically; change-away-and-back cannot revive them. Custom stores
  and senders must preserve these guards. See docs/password-reset-recipients.md.
- Email confirmation records are append-only. Wrong attempts commit before the
  typed error returns. Issuance uses atomic rolling-window events and rejects
  an account snapshot whose primary email or security version changed before
  the challenge was stored. Direct store implementations must honor these
  expected fields when the Runtime supplies them.
- Email-change records are separate from account verification, digest-only,
  attempt-limited, and consumed in the same transaction as identifier update
  and security-state revocation.
- Email changes and verification reject inactive subjects under the subject
  lock. Security-version changes invalidate outstanding email changes and
  unverified challenges; reactivation does not revive them.
- Password-reset and email-code consumption checks current expiry after the
  subject and one-time-record locks are acquired, before the protected mutation.
  This does not promise that commit or response delivery finishes before expiry.
- Logout-all counts newly revoked sessions, not previously revoked rows, while
  retaining version advancement and family revocation on repeated calls.

## Secret material

- Passwords use versioned Argon2id PHC strings with at least 19 MiB, two
  iterations, and one lane. Runtime policy is 8-128 Unicode code points plus a
  common-password deny list.
- An explicitly imported legacy credential may carry the bounded `legacy_bytes_256`
  verification policy for the exact documented Argon2id profile. Runtime legacy
  verification is separately opt-in and executes both supported profiles sequentially
  in one shared slot for known and missing accounts; unsupported profiles deny. All new passwords
  retain the standard issuance policy; password change/reset/trusted-set clears the marker.
  See `docs/local-identities.md` for the privileged transaction and retry contract.
- Refresh and reset tokens are selector plus HMAC-protected secret. Email codes
  are stored only as HMAC digests.
- JWT, token-HMAC, and outbox-AEAD key rings are distinct and versioned. Runtime
  construction rejects reused key material.
- A raw reset token or email code may exist only in memory and inside an
  AES-256-GCM encrypted event envelope. Delivery acknowledgement deletes the
  ciphertext; retention cleanup removes undelivered expired envelopes.
- Security audit attributes must never contain credentials, raw tokens, codes,
  connection strings, or cryptographic key material.
- Password-change attempts use a subject-keyed rate bucket independently of the
  bounded concurrent hash budget. Auth responses must not be cached.

## SSO and OIDC

- Email-based auto-linking requires the same normalized email to be verified by
  both the IdP and the local identifier, plus the configured issuer policy.
  Nil policy defaults to `["*"]`; an explicitly empty list disables new auto-links. Otherwise linking requires a recent,
  introspected authenticated session.
- External identity keys are exact issuer/sub strings, without trimming. Existing
  links do not require an email claim. Only validated provider output is trusted.
- An SSO-only account has no local credential row.
- OIDC authorization code and challenge stores consume state atomically.
- OIDC authorization codes persist the subject security version from issuance.
  The provider rejects stale authentication before issuance and changed, missing
  or wrong-subject version bindings on exchange. Versionless old codes require
  new authorization and are never upgraded implicitly.
- The verifier selects compatible RS256 signing keys, rejects ambiguous signing
  key IDs and reports the audience actually validated. Discovery failures are
  bounded and backed off without enabling stale-cache acceptance.
- OIDC `email_verified` comes only from identifier verification state.

## Session-bound OIDC profile

- The explicit session provider owns one transaction for final client/session
  admission, one-time state and expected-denial effects. No token, code redirect
  or cookie is released before confirmed commit. Unknown commit never permits
  an automatic replay of a rotating secret.
- Password interaction is proven by the exact request's immutable completion
  marker and cookie generation, not a recent/equal timestamp or another login.
- Required canonical project_id is a distinct claim; opaque host authorization
  stamps and namespaced display metadata are never substituted for it.
- Bound families keep sid, stamp, authentication evidence and absolute end
  immutable. Legacy and bound adapters cannot cross profiles, including direct
  Get/Rotate/Revoke. Canonical subject-wide revocation still covers both.
- OIDC refresh Get is read-only, including consumed-token lookup. Only an
  authenticated owner's mutation path records replay/revokes the family.
