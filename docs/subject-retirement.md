# Terminal authentication-subject retirement

`Runtime.RetireLocalIdentity` is a privileged, transport-neutral host API. It
retires the **entire authentication subject** while releasing exactly one selected
primary custom login. It is not alias deletion, business-account erasure or a
reversible disabled status. No HTTP endpoint, email template, UI button or new
notification delivery is added.

## Authorization and storage contract

Authorize the exact immutable `SubjectID`, explicitly registered non-email
`ExpectedIdentifier` and positive `ExpectedSecurityVersion`. The configured
identifier resolver defines normalization; GoAuth does not lowercase custom
logins implicitly. The store locks the canonical subject before the selected
primary identifier and local credential, then compares current lifecycle,
security version, normalized old login and credential existence. Secondary aliases
are never selected, promoted or bulk-deleted.

One transaction:

1. Sets `status=disabled` and the previously absent `retired_at` timestamp.
2. Advances security version exactly once, including for an ordinary-disabled
   subject. Overflow fails without mutation.
3. Deletes only the selected custom primary identifier and the subject's local
   credential, including its password-input policy.
4. Revokes local sessions, local and OIDC refresh families, password resets,
   pending email changes and pending email challenges.
5. Records mandatory `SecurityEventSubjectRetired` audit without credentials,
   login values, email codes or tokens. No notification is enqueued.

Subject UUID, creation timestamp, profile, audit references, RBAC assignments,
other primary/secondary email and custom identifiers, and external issuer/sub
links remain owned by the terminal old subject. Retained identifiers and links
are **reserved, deny-only bindings**. In particular, retained emails can block a
new account using those emails; they are never silently transferred or linked.
The released login can be provisioned only as a new subject, with no old grants,
roles, families or external links. Hosts retain their own business records.

Retirement is terminal. Status setters, rename, local-password/credential writes
and identity linking cannot revive or attach authentication to a tombstone.
Existing reads may still show it. Ordinary disabled subjects remain reversible
and retain existing trusted-password and rename behavior. Repeating retirement
returns `ErrSubjectRetired` with no additional audit, timestamp or version change.

## Safe read model and compatibility

`Runtime.GetSubjectLifecycle(ctx, subjectID)` returns `SubjectLifecycleView`:
`Account` plus optional `RetiredAt`. It reads both from one consistent storage
snapshot, includes tombstones and exposes no credential material. PostgreSQL
returns actual persisted timestamps, including PostgreSQL timestamp precision.
The marker is separate from `Subject`, whose struct layout is unchanged.

`SubjectLifecycleReader` and `LocalIdentityRetirementStore` are additive optional
store capabilities. Required `RuntimeStore`, `AccountStore` and
`LocalIdentityStore` interfaces are unchanged. Legacy custom stores continue to
compile and return typed unsupported errors for the new Runtime methods. A custom
store advertising retirement must enforce the marker across every supported
status, rename, password, credential and link mutation, as well as consistent
lifecycle reads and atomic canonical invalidation. A read-only capability alone
does not assert that the store supports retirement.

## Host transaction and unknown outcomes

Call before acquiring host project/client/grant locks. Compose authorized host
grant changes, host audit, operation receipt and any host-owned durable event
outbox in the same `postgres.Runtime.InAuthTransaction`. Use `SQLExecutor` only
for host-owned tables; hosts must not write canonical `auth_*` tables.

The returned lifecycle inside an outer callback is provisional until that outer
transaction succeeds. All errors from the retirement method return a zero result.
Mandatory audit failure or outer grant/receipt/outbox failure rolls everything
back, including released login, credential deletion and all revocations. Contexts
belonging to another database handle or testkit store are rejected.

`ErrOperationOutcomeUnknown` is not success or proof of rollback. Fail closed and
reconcile a durable host operation receipt from a healthy transaction. The receipt
must bind the operation and authorized old subject/request. A matching committed
receipt establishes the old-subject result; authoritative evidence of noncommit
allows a new attempt against fresh state. An ambiguous result remains unavailable.
Do not blindly retry or adopt whichever subject now occupies the released login.
`GetSubjectLifecycle` aids reconciliation but is not an operation receipt.

The integration tests use a host-owned outbox **stub** to prove transaction
composition. GoAuth's existing encrypted notification queue is not a new AuthHub
project event or back-channel logout outbox.

## Explicit schema 6 upgrade and compatible rollback

Run the supported `postgres.Migrate` before using schema-6 code, or use the host's
existing authorized `AutoMigrate` startup policy. This is an explicit database
upgrade; this source change does not authorize a production migration.
Fresh installs and schema 2, 3, 4 and 5 upgrades preserve existing subject IDs,
versions, credentials, assignments and existing migration checksums. All existing
subjects start with `retired_at=NULL`. The old local-identity migration remains
version 4 with its original bytes and checksum. The notification-expiry migration
remains version 5 with its original index, bytes and checksum.

Schema 6 adds a nullable `timestamptz` marker and a validated disabled-only CHECK:
`retired_at IS NULL OR status='disabled'`. It fences older processes that were
already running before upgrade: their attempts to set active/suspended fail and
their transaction rolls back. `VerifySchema` checks the actual column and effective
validated canonical fence, not just schema history. Unsupported or weakened fence
definitions fail closed. Even an equivalent hand-written constraint is not a
supported substitute for the canonical migration.

Older binaries refuse future schema at startup. Do not clear retirement markers,
downgrade the schema/version rows or restore a pre-retirement backup to make an
older binary start. Roll back application code only to a schema-6-compatible
version; otherwise restore a compatible backup preserving tombstones, current
revocations and host source mappings, with host reconciliation. The CHECK is a
compatibility fence, not protection against a DBA deliberately clearing markers.

## Security scope still outstanding

Retirement invalidates local proofs, local security state, existing OIDC families
and sequentially checked old version-bound authorization codes. A replacement
login cannot validate a proof for the former subject. These guarantees do not
close the OIDC provider's separately planned final-write races for code issuance,
exchange, family Save/Rotate or tokens without offline access. Those require
atomic final guards in the issuer transaction and remain later work. Already
issued offline tokens retain their documented bounded lifetime/freshness limits.
