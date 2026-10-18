# Host-verified OIDC email projection

Session-bound providers may set `oidc.SessionProjection.Email` to an
`*oidc.VerifiedEmail{Address: normalizedAddress}`. This explicitly attests that
the host verified mailbox ownership for that exact current address through a
successful challenge. Read its current address/version/verification marker
under the same canonical subject lock as code issuance, exchange, refresh and
UserInfo. Never populate it from a matching alias, profile metadata, operator
entry, caller JSON or successful mail-provider acceptance alone.

The provider validates canonical GoAuth email normalization and emits
`email` plus `email_verified: true` only with the granted `email` scope.
It signs ID tokens through the existing RS256 path and uses the same current
projection for UserInfo. Access tokens do not acquire email authorization.
No new endpoints, schema, token lifetime or identity/session binding are added.

The projection is optional. Nil preserves the existing canonical Account
primary-email behavior, including its actual verification flag and scope
checks. A mandatory-email host must return `Allowed=false` when its current
verification evidence is missing/stale; nil is not a new global denial policy.
When changing/removing an address, invalidate the host session/policy binding
so old codes/refresh families cannot revive the previous evidence. Existing
offline relying-party proofs retain only their original bounded freshness.

Login, display names and email can change without changing issuer plus subject.
A true verification claim does not grant roles, membership or automatic linking.
Root Runtime external provisioning and admin-realm verified-email gates are
unchanged; this API does not create accounts, verify mailboxes or issue roles.

Focused checks:
`go test -race ./oidc/provider -run '^TestSessionHostVerifiedEmail'`,
then the existing session-provider tests and the repository's `make check`
once for the coherent batch. No production mail or configuration is required.
