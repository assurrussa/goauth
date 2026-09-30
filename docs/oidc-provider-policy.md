# OIDC provider policy

`provider.Options.TokenEndpointAuthMethods` controls both discovery and actual
client authentication on token and revocation requests. Nil enables the three
implemented methods: `none`, `client_secret_basic`, `client_secret_post`. An
explicitly empty list, blank entry or unknown method is a construction error.
A client must use its configured method and that method must be enabled.
Unknown client/request methods are rejected; an omitted client method retains
legacy defaults based on whether its static secret is present.

`Client.RequirePKCE` controls whether a challenge is mandatory. Any supplied
challenge requires S256, including for clients whose PKCE is optional. A method
without a challenge is invalid. Code exchange validates persisted metadata and
the verifier whenever a challenge exists. Hosts should require PKCE for public
clients; allowing its omission is an explicit client policy.

The provider validates access-token signatures using only RS256 and requires
issuer, expiration and issued-at claims. Its configured clock controls time
validation. This strengthens the provider's internal token parser and does not
constitute OIDC conformance certification.

## Persistent client secrets

`oidc.ClientSecretVerifier` and `ClientSecretVerifierFunc` let a host verify a
presented secret against hashed or externally managed storage. Set
`provider.Options.ClientSecretVerifier`; any error denies authentication with a
safe `invalid_client` response. The provider never falls back to `Client.Secret`
after rejection, and never calls the hook for a public client using `none`.

A persistent confidential registry must set `Client.TokenEndpointAuthMethod`
explicitly to `client_secret_basic` or `client_secret_post` when it leaves
`Client.Secret` empty. This avoids the legacy empty-secret default of `none`.
The host owns hash policy, verifier availability, rotation and lookup behavior.
Treat the raw presented secret as ephemeral and never log or persist it.

A nil verifier preserves `Client.Secret` for legacy static configuration. That
field is a plaintext expected value; it is not a persistent-registry storage
recommendation. This additive extension does not remove the existing field.
