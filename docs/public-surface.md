# Public surface guide

`reference/externalconsumer/packages.go` is the authoritative supported import
manifest. `imports.go`, `manifest_test.go`, `public_surface_test.go`, and the
runnable external-consumer probe keep the declaration executable.

The supported packages are root Runtime, PostgreSQL, Redis, net/http, Fiber, OIDC
protocol/provider/verifier, RBAC, and testkit. `HostSupportPackages` stays
empty.

When adding or changing public API:

1. Verify the behavior belongs to a reusable Runtime or adapter boundary.
2. Search all workspace consumers before changing an exported symbol.
3. Keep PGX, Fiber internals, concrete SQL repositories, SQL rows, and host
   DTOs out of root contracts. Keep the supported dependency graph publicly
   resolvable without private module credentials.
4. Update `SupportedPackages`, the matching import manifest, and the public
   symbol compile test.
5. Extend the runnable clean-consumer example so it exercises the capability.
6. Update contract and migration documentation.
7. Run `make release-candidate-readiness` before tagging and the published
   clean-consumer probe for the intended tag after publication.

Only manifest packages are supported. The retired v0.1 implementation is absent
from the current source tree; its immutable tags remain available for consumers
that have not migrated. Importability alone does not make a package supported.

The runnable consumer exercises optional delivery policy rather than only naming
its exported symbols. The database-free path proves explicit disabled mode keeps
password login/change usable, blocks email/reset commands before account changes
or enqueue, and still rejects missing transactional audit. The PostgreSQL path
uses the supported runtime's SQL executor for host projections: commit/rollback
includes canonical auth, audit and RBAC, nested calls do not commit early, and a
different database handle cannot join. It also proves opaque credential proof
revalidation fails after a security-version change and reset receipt callbacks
commit or roll back reset, encrypted enqueue, audit and host correlation together.
No internal imports or additional supported packages are needed.

Email-less local provisioning/import lives in the existing root, PostgreSQL and
testkit packages; no package or host-support import is added. Public symbol and
runnable consumer checks cover the optional LocalIdentityStore contract, persisted
credential input policy, create-only import and managed host transaction/proof.
See `local-identities.md` for compatibility and required follow-ups.

Privileged password replacement uses the additive `TrustedLocalPasswordStore`
capability and `Runtime.SetTrustedLocalPassword`, promoted by `postgres.Runtime`.
The external consumer exercises same-password version advancement on a disabled
account and atomic email-less host event/audit commit or rollback. No public
transport or new import package is added.

## Custom-login read and rename

The existing root, `postgres` and `testkit` surfaces expose additive
`LocalIdentifierReader` and `LocalIdentityRenameStore` capabilities. No supported
package or host-support import was added; `HostSupportPackages` remains empty.
`public_surface_test.go` compiles every new request/view/interface/error/event and
Runtime method. Clean external-consumer probes execute read/rename/CAS in testkit
and read/rename/host-rollback composition on PostgreSQL. Existing local identity,
admission and trusted-password consumer templates remain included. See
[local identity semantics](local-identities.md#read-and-rename-a-primary-custom-login).

## Managed notification outcomes

`goauth.ErrNotificationRejected` explicitly stops retries only for confirmed terminal
non-delivery. `postgres.Runtime.ExpireNotifications(ctx, limit)` performs bounded
queue-only expiry using the Runtime clock and managed transaction scope. Neither
operation claims inbox delivery; ordinary sender errors keep their retry behavior.
See [notification outcomes](notification-outcomes.md).

## Terminal subject retirement

The optional `SubjectLifecycleReader` and `LocalIdentityRetirementStore`
capabilities and root/PostgreSQL Runtime lifecycle methods are supported without
changing `Subject` or required store interfaces. The clean consumer includes
root/testkit retirement, managed PostgreSQL rollback/receipt and fresh-subject
login reuse while retaining every earlier local-identity/admission/password/
rename/notification-outcome probe. No new supported package or host-support
exception is introduced.

## Bounded rate-event maintenance

`postgres.RateLimitCleanupRequest` and
`postgres.Runtime.CleanupRateLimitEvents(ctx, request) (int64, error)` are
supported in the existing PostgreSQL package, without changing root store
interfaces or adding a package. The API deletes one bounded candidate batch in
its own transaction and reports counts only for confirmed commits. See
[rate-event maintenance](rate-event-maintenance.md) for retention, managed-scope
rejection and schema 7 compatibility.

## Owned auth transactions

`postgres.Runtime.InOwnedAuthTransaction` and
`postgres.ErrAuthTransactionAlreadyActive` add an outermost-owner capability in the
existing PostgreSQL package. No root interface, supported package, host-support
package, Subject layout or migration changes. Public symbol and ordinary consumer
checks compile the signature/sentinel and exercise uninitialized rejection; the
PostgreSQL consumer verifies ambient rejection, joining, commit/rollback and
withholding provisional responses. See [owned transactions](owned-auth-transactions.md).

## Local common-password dictionaries

The root package adds `NewLocalCommonPasswordChecker`,
`LocalCommonPasswordCheckerOption`, and `WithBuiltInCommonPasswords`.
The constructor returns the existing `CommonPasswordChecker` interface for
injection into `PasswordPolicy.Blocklist`; no supported package or required
interface changes. Public-surface compilation and the runnable clean consumer
exercise construction, defensive copying, built-in inclusion, default isolation,
and Runtime policy injection. See [local dictionary semantics](local-password-blocklist.md).

Optional host-authorized recovery adds PasswordResetRecipientResolver,
PasswordResetSubjectStore, Config.PasswordResetRecipientResolver, and
postgres.Runtime.InvalidatePasswordResets within existing supported packages.
The testkit Store mirrors creation and invalidation. No package, schema, token
format or default primary-email behavior changes. See password-reset-recipients.md.
