# Assisted account recovery

This unreleased candidate adds schema 14 and an opt-in transport-neutral service.
It is not a release, deployment, or verification receipt.

## Flow and authority

An administrator with the dedicated `account_recovery:create` permission first
verifies the existing person's identity through independently established records
or a known channel. A name or a new email alone is insufficient. The operator
records a reason and a nonsecret evidence reference and freshly proves their
password and existing MFA. The host owns the evidence-verification procedure;
the service records the attestation and requires a nonnil authorization policy.

`NewAssistedRecovery` composes existing local credentials and primary email.
`NewScopedAssistedRecovery` adds a trusted, fixed host scope whose target owns its
email/version CAS, password policy, MFA verification and host-session invalidation.
Both require managed owned auth transactions and encrypted notification delivery.

Initiation queues a single-use, 15-minute invitation to the new email. It changes
no account credential, enrollment, role, identifier or session. Only a keyed token
digest is persisted. Raw invitation material lives in memory and the existing
encrypted notification queue; it is never returned by the initiation API.

Completion proves the invitation, validates the new password and requires the
existing authenticator or an unused recovery code if MFA is enrolled. Missing
factor keys fail closed. Invalid MFA attempts commit their durable admission.
The email and password change together with invitation consumption, security
version advancement, mandatory audit, old-email notification, and revocation of
sessions, refresh families, resets and pending email security state. Identity,
roles and enabled MFA remain unchanged. Concurrent completion has one winner.

## Lifecycle

There is at most one invitation row per subject, shared across all scopes. New
issuance supersedes its predecessor. Security-version or target-version drift
invalidates outstanding invitations; expiry is checked after locks and factor
verification. A completed row is consumed in the credential transaction. Existing
cleanup policy is unchanged; expired uncompleted snapshots remain inert until
superseded. Do not infer inbox delivery from an accepted queue operation.

`InitiateOwner` is server-CLI-only authority, with a separate authorization
interface that must verify a sole active owner and an exact subject/new-email
confirmation phrase. Never expose this method through HTTP. Completion still
requires the owner's existing MFA. Loss of MFA is a separate support procedure.

## Verification status

Focused unit and PostgreSQL integration tests are supplied for validation,
authorization denial, unchanged initiation, single-use concurrent completion,
credential/session invalidation, old-email notification and existing-factor
preservation. These candidate tests have not executed in the source-editing
environment: a Go toolchain and writable build/test environment are unavailable.
Run formatting and the repository's aggregate checks, then the relevant isolated
PostgreSQL integration suite, before review, release or deployment.
