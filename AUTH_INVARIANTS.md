# Auth invariants

## Canonical identity

- `auth_subjects` contains only canonical ID, `active|suspended|disabled`
  status, security version, and timestamps.
- Identifiers, basic profile, local credentials, memberships, identity links,
  sessions, and RBAC assignments are separate relations keyed by canonical
  `subject_id`.
- Host `users` and `administrations` rows are projections or memberships. Host
  numeric IDs and public IDs never substitute for canonical `subject_id`.
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
- Suspending, disabling, resetting or changing a password, or confirming an
  email change increments security version and revokes sessions and refresh
  families in one PostgreSQL transaction.
  Offline access tokens never live longer than five minutes.

## One-time state

- Refresh, password-reset, OIDC code, and OIDC challenge paths are atomic
  consume or rotate operations. A public `Get` followed by `Delete` is not an
  acceptable single-use contract.
- Hooks, hashing and JWT preparation precede session writes and refresh rotation.
  A refresh snapshot authenticates without consumption; the final transaction
  locks the canonical subject and revalidates state before consuming the token.
- Auth writes, mandatory audit and encrypted enqueue commit together. Callback
  errors roll back; business denials that update attempt/replay protection commit.
- Refresh replay revokes its family and session and emits a security event.
  Replay processing bypasses token preparation. There is no grace interval.
- Security writes lock the canonical subject before dependent state. Logout-all
  increments its security version so an already prepared login cannot escape it.
- OIDC refresh tokens also persist only selector plus HMAC digest; replay of a
  rotated token revokes the complete OIDC family and emits an audit event.
- Password reset is selector-based, contains no email in the URL, and updates
  the credential, security version, reset record, sessions, and refresh
  families in one transaction.
- Reset issuance checks the active subject, current primary email, and
  security version under the subject lock. Password, email, or status changes
  invalidate outstanding reset records; custom stores must preserve these
  guards.
- Email confirmation records are append-only. Wrong attempts commit before the
  typed error returns. Issuance uses atomic rolling-window events and rejects
  an account snapshot whose primary email or security version changed before
  the challenge was stored. Direct store implementations must honor these
  expected fields when the Runtime supplies them.
- Email-change records are separate from account verification, digest-only,
  attempt-limited, and consumed in the same transaction as identifier update
  and security-state revocation.

## Secret material

- Passwords use versioned Argon2id PHC strings with at least 19 MiB, two
  iterations, and one lane. Runtime policy is 8-128 Unicode code points plus a
  common-password deny list.
- Refresh and reset tokens are selector plus HMAC-protected secret. Email codes
  are stored only as HMAC digests.
- JWT, token-HMAC, and outbox-AEAD key rings are distinct and versioned. Runtime
  construction rejects reused key material.
- A raw reset token or email code may exist only in memory and inside an
  AES-256-GCM encrypted event envelope. Delivery acknowledgement deletes the
  ciphertext; retention cleanup removes undelivered expired envelopes.
- Security audit attributes must never contain credentials, raw tokens, codes,
  connection strings, or cryptographic key material.

## SSO and OIDC

- Email-based auto-linking requires the same normalized email to be verified by
  both the IdP and the local identifier, plus the configured issuer policy.
  Nil policy defaults to `["*"]`; an explicitly empty list disables new auto-links. Otherwise linking requires a recent,
  introspected authenticated session.
- External identity keys are exact issuer/sub strings, without trimming. Existing
  links do not require an email claim. Only validated provider output is trusted.
- An SSO-only account has no local credential row.
- OIDC authorization code and challenge stores consume state atomically.
- OIDC `email_verified` comes only from identifier verification state.
