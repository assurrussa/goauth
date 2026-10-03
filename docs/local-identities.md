# Privileged email-less local identities

This additive foundation follows published v0.5.1 (commit
`0862228fd3d3e33d5cc46ed7fc92136df247bdbe`, source tree
`a3a12b3fbdb14487c8c9283a070332cda60b5327`). It does not implement a new login
transport, project admission, email-less SSO policy, or an OIDC SDK.

## Supported boundary

Register a dedicated custom `IdentifierResolver`, then use root Runtime
`ProvisionLocalIdentity` or `ImportLocalIdentity`, also available through
`postgres.Runtime`. These are privileged host APIs, not public registration
handlers. The host authorizes its operator and supplies its own actor audit.
The root Runtime adds mandatory `local_identity.provisioned` or
`local_identity.imported` audit in the account transaction, with no password,
PHC, login or other secret in attributes.

Both APIs create one canonical subject, one custom login identifier, one basic
profile and one authoritative local credential. The login scheme must be
non-email and registered. Scheme-specific normalization is respected exactly; privileged creation/import
bounds display and normalized values to 256 UTF-8 bytes without NUL. Lookup
accepts primary identifiers only, preserving the existing email login boundary. No match against another scheme, profile username
or operator email links accounts. `Account.PrimaryEmail` is the zero Identifier
and `EmailVerified()` is false. Email remains a separate optional identifier.

`ProvisionLocalIdentityRequest` accepts `Identifier`, `Password` and `Profile`;
it generates an ID and uses the standard password issuance policy.
`ImportLocalIdentityRequest` requires a nonzero host-assigned `SubjectID`, an
explicit `Status`, `Identifier`, `PasswordPHC`, `PasswordInputPolicy`, and optional
`Profile`. It accepts canonical, bounded Argon2id PHC only. Imports require the
built-in Argon2id verifier. Custom verifiers fail closed rather than pretending
to support the import format.

Root custom stores must deliberately implement the additive `LocalIdentityStore`
capability. The existing `RuntimeStore` interface is unchanged. Implementations
must persist `LocalAccountRecord.PasswordInputPolicy`, return it on credential
reads, and clear it on every password change/reset. An unsupported store refuses
privileged creation. PostgreSQL and testkit implement the capability. Existing
strict records use the zero policy or `PasswordInputPolicyUnicode`.

## Transactions, retries and ownership

Creation is **create-only**. An existing subject ID or `(scheme, normalized_value)`
is an error, including an identical repeated request. There is no upsert,
password overwrite, status restoration, identity merge, or silent adoption.

A migration host owns a durable legacy-key-to-subject mapping and its completion
version. Under the host's agreed migration lock, use
`postgres.Runtime.InAuthTransaction` and its context-scoped `SQLExecutor` to:

1. Read the durable mapping. If already mapped, keep that canonical ID and
   current security state; do not import again or restore an old password.
2. Validate all source references and choose a new subject ID.
3. Call `ImportLocalIdentity` and write mapping, grants and host audit in the same
   transaction. Host SQL writes host tables only.
4. Treat rollback and unknown commit outcome as failure. Reconcile an unknown
   outcome by rereading the durable mapping before a retry.

Nested calls join and never commit the outer transaction. All dependent results
are provisional until the outer commit succeeds. Conflicting identifiers or
mappings require operator resolution, not an inferred merge. Serialize migration
coordination before subject locks; later security/grant mutations lock the
canonical subject before dependent project state.

No production data is migrated by library construction beyond an explicitly
requested schema migration. Schema version 4 adds only the credential input
policy column with a strict default and validates its recorded migration checksum.
The v2 baseline and v3 notification migration stay byte-for-byte immutable.
v2/v3 upgrades preserve IDs, identifiers, password hashes, status, security
versions and grants. v0.5.1 rejects schema 4 as a future schema: do not force an
older binary to use it or drop the version marker. Roll back application code
only to a schema-4-compatible build; preserve canonical state and mappings.

## Narrow legacy password compatibility

`PasswordInputPolicyLegacyBytes256` is an explicit per-credential import marker.
Only Argon2id v19, `m=65536,t=3,p=1`, 16-byte salt, 32-byte digest, canonical PHC
encoding is accepted with it. Verification accepts at most 256 original bytes,
including invalid UTF-8, without rewriting or normalizing them. It uses the same
Runtime-wide bounded concurrent hash budget as standard passwords. Unknown
markers, nonstandard profiles and unsupported custom verifiers fail closed.

`VerifyCredential`, PostgreSQL `PrepareCredential`, login, password-change and
email-change reauthentication all read the marker. A new password always uses
current Unicode issuance rules (8–128 code points and the configured blocklist);
password change/reset clears the marker, advances security version and revokes
security state through the existing atomic path. Imports do not need plaintext
or a mass reset, and no second password authority remains after host migration.

Default browser and admin realm security is unchanged. An email-less user login
can obtain only confirmation scope; admin/custom realms still require verified
email and membership. Email recovery is not a substitute for an operator API:
email-less accounts cannot request email challenges or change an absent email.
Password changes retain mandatory audit and send no email when no primary email
exists. Notification enqueue refuses invalid/empty destinations.

## Required follow-ups before replacing an existing Basic authority

- A separate per-request credential-admission policy. `VerifyCredential` and
  `PrepareCredential` still charge every attempt, including success, to the
  existing login policy (normally ten per 15 minutes). Do not disable all auth
  rate limits or claim this is ready for continuous Basic traffic.
- A supported privileged operator password-set path preserving status,
  security-version advancement, local/OIDC revocation and mandatory audit. Current
  `ChangePassword` needs the old password; email recovery cannot cover email-less
  accounts. Preserve the existing host operator capability until this is supplied.
- Explicit trusted email-less SSO account/realm policy and local membership before
  enabling SSO consumers. No fake email or `email_verified` assertion is permitted.

No tag, release, production credential, signing key or deployment is part of this
foundation. Public consumer and PostgreSQL tests exercise the supported import,
verification and host transaction boundaries.
