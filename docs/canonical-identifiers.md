# Session canonical identifiers

Session-bound hosts may provide `SessionProjection.Identifiers` using the typed
`oidc.CanonicalIdentifiers` contract. Nil preserves the previous wire format.
For the `profile` scope, the provider copies this value into userinfo and the
signed ID token as a distinct top-level `authhub_identifiers` object. It is not
included in access tokens. Discovery advertises the optional claim.

Version 1 contains a required case-sensitive ASCII `login` matching
`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`, and an optional canonical lowercase ASCII
`email_alias` (maximum 254 bytes, local part maximum 64). Alias validation uses
the AuthHub mailbox-shaped alias grammar, preserves dots and plus tags, and
does not normalize invalid input. Unknown versions or malformed values reject
the admission projection. An absent alias is omitted from JSON.

The host must read current authoritative identifiers under its existing
subject/admission transaction. Display metadata, including historical `login`
or `email` attributes, must never populate this object. There is no arbitrary
claims map, and neither roles nor permissions are imported by this contract.

An email alias is an administrative lookup identifier, not proof of mailbox
ownership. It never sets standard `email` or `email_verified`; their existing
canonical verification policy remains unchanged. Consumers may use these
identifiers only under an explicit issuer-specific matching policy after full
token verification. They must reject unsupported versions/malformed present
claims and must not fall back to display metadata. Existing issuer/subject
bindings remain authoritative.

Identifiers are current projection snapshots and may change on refresh or
userinfo reads under the same subject. They are not pinned session-binding
fields. This feature does not change session, security-version, refresh,
verification, or default GoAuth identity-linking policy.
