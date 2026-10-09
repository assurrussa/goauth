# Host-authorized password-reset recipients

The default Runtime still accepts only the canonical primary email of an active
account with a local credential. Hosts may opt into administrator-managed recovery
addresses with Config.PasswordResetRecipientResolver. This policy grants the
destination mailbox owner the ability to change the existing local password; it
does not verify email, attach an identity, provision a credential, or grant a realm.

## Resolver contract

Implement PasswordResetRecipientResolver:

- LookupPasswordResetSubject receives a normalized email and returns exactly one
  real canonical SubjectID across primary emails and all host recovery aliases.
  Missing ownership or any collision must return ErrAccountNotFound. Never prefer
  one match over another or use a host projection ID.
- ResolvePasswordResetRecipient runs in the auth transaction with that active
  subject locked. Recheck current ownership using the supplied transaction context.
  A nonempty requestedEmail must still belong uniquely to this subject, and the
  returned destination must be currently authorized. Empty requestedEmail selects
  the current password-reset success destination. Fail closed on collisions,
  missing projection data, inactive host membership, or unauthorized recipients.
- PreparePasswordResetPassword runs only after token authentication, current-state
  checks and the subject/reset locks. Hosts enforce their existing password policy,
  bounded hash budget and hash profile, returning the prepared PHC or an error.
  Empty PHC with nil error selects the unchanged Runtime password policy and hasher
  for subjects outside the host policy. Do not mutate state or log/persist the
  plaintext. Stores recheck cancellation and expiry using the configured clock after
  preparation, before credential/token mutation; any error rolls back together.
- Do not cache security decisions or use an unrelated database/transaction.
  Unknown storage failures should remain errors. No email or raw token belongs
  in audit attributes.

Both root issuance and consumption use the resolver. Issuance independently checks
the existing nonempty local credential and expected security version under the
canonical subject lock. Configuring a resolver requires the optional
PasswordResetSubjectStore capability; unsupported custom stores fail construction.
CreatePasswordResetForSubject requires an empty ExpectedNormalizedEmail and an
exact ExpectedSecurityVersion. Existing CreatePasswordReset semantics are unchanged.

Consumption rechecks the current success recipient before committing. Rejection
rolls back the password, token consumption, security version, session revocation,
notification, and audit together. A user who has only an SSO identity does not gain
a local credential through password recovery.

## Address changes and queued delivery

Every host alias change, removal, reassignment, and projection retirement must
lock the affected canonical subject first and call
postgres.Runtime.InvalidatePasswordResets in the SAME managed auth transaction as
the host mutation. Abort the transaction on error. This helper joins rather than
committing the host transaction. An address changed away and later restored must
not revive a previously issued token. Coordinate uniqueness across primary email
and host aliases as well; an application-only lookup is not a uniqueness constraint.

The PostgreSQL managed worker checks the decrypted recipient again for both
password_reset and password_reset_success. It rechecks token currency after taking
the subject lock, requires a current local credential, and holds that lock through
the bounded sender call. The returned normalized recipient must equal the
encrypted notification destination; the worker never reroutes a queued secret.
The sender receives the same transaction context. Stale deliveries expire without
sending. Receipt IDs, AEAD binding, leases, retry budgets and delivery outcomes are
unchanged. Senders must not open a second transaction to acquire the same subject
lock; join through the supplied context. At-least-once delivery remains possible
after an uncertain send or commit.

Custom delivery adapters must enforce equivalent locked recipient revalidation and
token currency checks themselves. DecryptNotificationEvent alone is not delivery
authorization. Switching an established recovery policy off while its notifications
remain queued requires draining or invalidating that queue first.

No schema, token encoding, reset URL, primary identifier, or email-verification
state changes are needed. Tokens retain the configured lifetime (15 minutes by
default), HMAC protection, encrypted queue, single-use behavior, transactional audit,
enumeration-safe accepted response, and existing identifier rate admission.

The testkit Store provides the same subject-bound creation guard and
InvalidatePasswordResets(ctx, subjectID, now) for transactional fixture hosts.
