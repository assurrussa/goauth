# Email reauthentication and browser logout follow-up

Base: `c29d8d90d083edbc4ffb3509143f43a8facb12a2` (merged PR #9).
Branch: `fix/reauth-email-and-browser-logout`.

This change builds on the existing subject-lock, pending-state invalidation,
rate-limit, HTTP-header and OIDC corrections. It does not repeat those changes
or change schema version 3, dependencies, tags or repository visibility.

## Local password proof and actor ownership

`Runtime.RequestEmailChangeWithPassword` accepts `PasswordEmailChangeRequest`
with a trusted `SubjectID`, `CurrentPassword` and `NewEmail`. The host must first
authenticate the session and authorize the actor to operate on that subject.
The method resolves credentials by subject, not by a caller-supplied email, and
checks the current password before issuing a pending change.

Verification uses the existing bounded password hasher and the same durable
subject-keyed admission bucket as `ChangePassword`. Its persisted action remains
`password_change` to preserve outstanding counters during deployment. Both kinds
of attempt spend this budget, including correct passwords followed by an enqueue
failure; the later auth transaction cannot refund an admission. Operation-specific
email send/resend quotas remain separate.

The credential-verified account snapshot is retained through preparation and
rechecked under the canonical subject lock. A concurrent password/email/status
change or logout-all cannot be hidden by loading a newer account snapshot after
password verification. There are no reusable bearer proof tokens, new tables or
remote calls under an auth row lock.

The net/http handler requires `currentPassword` in JSON and derives subject ID
only from the checked auth context. Confirmation scope is rejected. Custom
Runtime implementations that do not implement `PasswordEmailChangeRuntime`
receive a safe 503; the handler never calls the trusted fallback. Incorrect or
missing passwords use 422 `current_password_invalid`, not a session logout.
Infrastructure/overload/rate-limit errors retain their existing mappings.

`Runtime.RequestEmailChange` remains explicitly trusted for host-owned workflows.
For an SSO-only account, the host must perform genuine fresh IdP authentication,
verify that it belongs to the authenticated subject, then call that trusted API.
This change does not implement an SSO step-up UI or waive that requirement.

## Notification transaction

The existing `email_changed` notification is addressed to the previous mailbox,
snapshotted under the account lock. It contains neither the new confirmation
code nor a reusable credential. New-address confirmation still uses `email_change`.
The email mutation, pending-record consumption, notification enqueue and audit
remain in the same transaction; failure to enqueue the previous-address notice
rolls the confirmation back. Actual delivery still follows the existing worker's
at-least-once and expiry contract, not guaranteed recipient receipt.

Hosts with a higher-risk policy may additionally require confirmation of the
previous address. That is not implemented or advertised by this follow-up.

## Browser exit

The example's `logout()` coordinates the entire refresh-then-logout sequence
with the same origin-wide Web Lock as ordinary refresh. It refreshes an expired
access credential when needed, waits for server revocation, then blocks queued
tabs from performing another refresh. Both logout buttons use this coordinator.

Only successful responses clear the server's HttpOnly cookies through the
existing host wrapper. Failed/uncertain refresh is never replayed automatically;
failed/uncertain logout blocks further coordinated refresh and does not claim
that the server revoked anything. A new successful login resets the local block.
This is a reference same-origin browser policy, not a new root cookie dependency.

## PostgreSQL identifiers

The PostgreSQL constructor rejects configured non-email resolvers before DB
access. Root Runtime still supports custom resolvers with a conforming custom
store. Nil resolver entries retain the root's ignored-entry semantics. This
makes the existing email-only lookup boundary explicit rather than introducing
a partially implemented username/phone identity lifecycle.

## Checks and evidence boundary

Added tests cover missing/wrong/cross-subject password proof, stale snapshots,
shared rate admission, enqueue rollback, previous-mailbox notification, SSO
rejection, HTTP capability absence and safe error mapping. PostgreSQL integration
cases cover admission across Runtime instances and a security mutation after
password verification. Public surface checks include the new request, method and
promoted PostgreSQL capability.

The Node tests execute the actual example `app.js` with mocked DOM/network/storage
and a serialized Web Lock. They cover expired/current access, both logout actions,
queued tabs, lost/failed responses, missing Web Locks and login after logout. They
are unit tests, not evidence of a real browser or PostgreSQL run. `go test` invokes
them through `TestBrowserSessionCoordinator` when Node is installed; the explicit
browser gate still requires Node and an installed browser engine.

The existing real HTTPS/PostgreSQL acceptance script now exercises expired-access
logout and mandatory email reauthentication, and observes the previous-address
notification. Its existence is not a passing run.

Performed in this implementation session: the 14 Node coordinator tests passed
on Node 22.16.0. The logout-button regression failed on the unchanged base
`app.js` (logout was sent without refresh) and passed on the new code. The Go
1.23.2 parser accepted all 11 changed/added Go files; import-use syntax checks
also passed. This is not Go type checking, repository test execution or lint.

The implementation environment has Go 1.23.2. Obtaining the repository's Go 1.27.1
toolchain failed at DNS/network access to the public Go proxy. Full module tests,
race tests, lint, integration, browser acceptance, govulncheck and the complete
candidate gate must therefore run on the final branch before merge. Historical
release evidence is deliberately unchanged and is not evidence for this branch.

Suggested verification on the declared toolchain and disposable services:

```sh
node --test examples/nethttp/app.test.mjs
make check
make integration
make vulnerability-check
make browser-acceptance
```

Use the documented full `make release-candidate-readiness` gate before claiming
candidate readiness; the scoped checks above do not replace it. No source-history
exposure review, external host acceptance, publication or deployment is claimed.
