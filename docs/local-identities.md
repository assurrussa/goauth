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

`Config.EnableLegacyBytes256` is **off by default**. Enable it deliberately on
all runtimes that import or verify marked legacy identities, only after the
profile preflight below. It requires the built-in Argon2id hasher. Existing
strict-only consumers keep their original verification costs and historical
profile support with this option off.

`PasswordInputPolicyLegacyBytes256` is additionally required on each imported
credential. Only Argon2id v19, `m=65536,t=3,p=1`, 16-byte salt, 32-byte digest,
canonical PHC encoding is accepted with it. The marker permits at most 256
original bytes, including invalid UTF-8, without rewriting or normalizing them.
Enabling compatibility does not grant these input permissions to strict records.
A strict credential may use either supported cost profile and still accepts only
valid UTF-8 with at most 128 code points.

An enabled mixed-profile Runtime supports exactly two verification profiles:
its configured built-in current profile (including salt/digest lengths), and the
fixed legacy profile. For every input within either supported input bound, it
performs both profiles sequentially, substituting a dummy for any unused slot.
Known current, known legacy, missing, malformed, unknown-policy and unsupported-
profile records therefore perform the same bounded work schedule. Invalid Unicode
or 129-code-point input also gets both jobs; a strict record still denies it.
Inputs outside both bounds deny before hashing. Dummy matches never authenticate
missing, malformed, unsupported, or otherwise denied records.

The complete two-job attempt holds one shared Runtime hash-budget slot. There is
no parallel second hash, second concurrency budget, or unbounded work queue.
This deliberately costs more CPU per attempt. Capacity planning must include
both Argon2 allocations plus runtime/GC headroom: sequential execution does not
promise that Go reclaims the first allocation before the next. Both jobs use the
same original bounded input, including in dummy slots; only real-slot selection
can authorize it. Even if the configured current profile equals the legacy
profile, the schedule remains two sequential jobs. Rate limits are not
removed or relaxed.

New Unicode imports must match the configured current profile with compatibility
off, or one of the two supported profiles with it on. Legacy-marker imports need
the opt-in and exact legacy profile. This prevents the new import API introducing
unmatched work costs into strict-only runtimes. An enabled mixed Runtime refuses
any existing credential at another cost after the same two dummy jobs; it does
not silently hash that profile, widen its limits, or pretend it was verified.

### Deployment profile preflight

Before enabling mixed mode, the operator must check every existing local
credential's profile against the configured current profile and the fixed legacy
profile. This read-only migration query shows bounded profile metadata and
counts, without returning any PHC, salt, digest or password contents:

```sql
SELECT password_input_policy,
       CASE WHEN split_part(password_phc, '$', 2) = 'argon2id'
            THEN 'argon2id' ELSE 'invalid' END AS algorithm,
       CASE WHEN split_part(password_phc, '$', 3) = 'v=19'
            THEN 'v=19' ELSE 'invalid' END AS version,
       CASE WHEN split_part(password_phc, '$', 4)
                      ~ '^m=[0-9]{1,7},t=[0-9]{1,2},p=[0-9]{1,2}$'
            THEN split_part(password_phc, '$', 4) ELSE 'invalid' END AS parameters,
       length(split_part(password_phc, '$', 5)) AS salt_encoded_length,
       length(split_part(password_phc, '$', 6)) AS digest_encoded_length,
       count(*)
FROM auth_local_credentials
GROUP BY 1, 2, 3, 4, 5, 6;
```

For the default current profile, expect `argon2id`, `v=19`,
`m=19456,t=2,p=1`, salt length 22 and digest length 43 in unpadded Base64. The legacy
profile has `m=65536,t=3,p=1` and the same encoded lengths. Use the actual configured
current parameters and lengths if customized. A legacy marker must always have
the exact legacy profile. This grouping detects unsupported cost/length groups;
it does not replace the Runtime's bounded PHC parser and cryptographic checks.
Investigate malformed/noncanonical groups and any unmatched historical profile
before enabling. Do not enable mixed mode over unexplained groups, rewrite PHCs,
reset everybody's passwords, or create a second credential authority to make the
preflight pass. Keep an explicit compatible rollout plan for historical profiles.

`VerifyCredential`, PostgreSQL `PrepareCredential`, login, password-change and
email-change reauthentication all honor the marker and mode. A new password
always uses current Unicode issuance rules (8–128 code points and the configured
blocklist); password change/reset clears the marker, advances security version
and revokes security state through the existing atomic path. Imports do not need
plaintext or a mass reset.

Default browser and admin realm security is unchanged. An email-less user login
can obtain only confirmation scope; admin/custom realms still require verified
email and membership. Email recovery is not a substitute for an operator API:
email-less accounts cannot request email challenges or change an absent email.
Password changes retain mandatory audit and send no email when no primary email
exists. Notification enqueue refuses invalid/empty destinations.

## Required follow-ups before replacing an existing Basic authority

- Explicitly configure a bounded per-request credential-admission policy with
  `CredentialVerificationRateLimit`, alongside host project/client ingress limits.
  `VerifyCredential` and `PrepareCredential` count every attempt, including
  success. Zero still inherits the login policy (normally ten per 15 minutes).
  See [credential admission](credential-admission.md); browser login, password
  change and recovery keep their existing independent policies.
- A supported privileged operator password-set path preserving status,
  security-version advancement, local/OIDC revocation and mandatory audit. Current
  `ChangePassword` needs the old password; email recovery cannot cover email-less
  accounts. Preserve the existing host operator capability until this is supplied.
- Explicit trusted email-less SSO account/realm policy and local membership before
  enabling SSO consumers. No fake email or `email_verified` assertion is permitted.

No tag, release, production credential, signing key or deployment is part of this
foundation. Public consumer and PostgreSQL tests exercise the supported import,
verification and host transaction boundaries.
