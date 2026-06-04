# Auth Invariants

## Canonical identity split

- `auth_subjects` is the canonical identity table.
- It owns stable auth identity and state:
  - `subject_id`
  - `kind`
  - `public_id`
  - `email`
  - `confirmed_email_at`
  - `password_version`
- `auth_local_credentials` is intentionally separate.
- It stores only the local secret material keyed by canonical `subject_id`:
  - `password_hash`
  - `password_algo`

## Transaction boundary

- `local/passwordchange.Service` stays thin when only a password writer is
  configured because `storage/pgsql/subjectrepo.UpdatePassword` already performs
  the atomic write for:
  - `auth_local_credentials.password_hash`
  - `auth_subjects.password_version`
- When password-change notifications are configured, the service may use the
  provided transaction manager to wrap the password write and outbox enqueue in
  one transaction.
- `local/passwordreset.Service` keeps an outer transaction because it spans multiple
  storages and side effects:
  - password write
  - reset-token deletion
  - auth artifact invalidation
  - outbox notifications
- `local/emailchange.Service` is also a multi-step flow and therefore remains an
  outer transaction/outbox workflow rather than a single writer call.

## Subject IDs

- Canonical auth relations must always use the real canonical `subject_id`.
- Admin flows must not rebuild canonical IDs from numeric admin IDs when the UUID-backed
  subject already exists.
- Admin auth adapters must hard-fail when a canonical subject lacks `subject_id`.
  Projection `uuid` / `PublicID` and numeric admin IDs are projection identifiers
  only; they must not be used as runtime auth fallback identities.

## Host projections

- Host `users` and `administrations` rows are projections or memberships keyed
  by canonical `subject_id`.
- Projection provisioning must return a real canonical `subject_id`; otherwise
  the canonical write plus projection write is considered failed and must be
  retried or repaired outside the runtime auth path.
