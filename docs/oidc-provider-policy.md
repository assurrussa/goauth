# OIDC provider policy

`provider.Options.TokenEndpointAuthMethods` controls both discovery and actual
client authentication on token and revocation requests. Nil enables the three
implemented methods: `none`, `client_secret_basic`, `client_secret_post`. An
explicitly empty list, blank entry or unknown method is a construction error.
A client must use its configured method and that method must be enabled.
Unknown client/request methods are rejected; an omitted client method retains
legacy defaults based on whether its static secret is present.

Public clients using `none`, including an omitted method with an empty static
secret, always require S256 PKCE. `Client.RequirePKCE` controls whether PKCE is
mandatory for confidential clients using `client_secret_basic` or
`client_secret_post`. Any supplied challenge requires S256; a method without a
challenge is invalid. Both authorization and code exchange enforce this policy,
including persisted code metadata. This follows [RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1).

The token endpoint accepts `code_verifier` only as 43-128 ASCII unreserved
characters (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`), without trimming whitespace.
An S256 challenge must be the canonical unpadded base64url encoding of a 32-byte
SHA-256 digest (43 characters). Authorization rejects malformed challenges;
exchange revalidates persisted metadata and rejects malformed or mismatched
verifiers. Clients must generate a fresh cryptographically random verifier for
each request: server-side grammar checks cannot prove entropy. See
[RFC 7636 sections 4.1 and 7.1](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1).

OIDC RSA signing and verification keys must have a modulus of at least 2048 bits
and a valid exponent, as required by [RFC 7518 section 3.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3).
`oidc.ValidateRSAPublicKey` exposes the same validation used by JWK encoding,
decoding, the provider and verifier. Invalid keys from custom stores fail closed;
signing additionally validates the private key and matching public key.

`oidc.ValidateRS256SigningJWKMetadata` requires RSA and a nonblank `kid`, permits
an omitted `use`/`alg`, and otherwise requires `sig`/`RS256`. RSA material is
validated separately by `oidc.DecodeRSAPublicKeyJWK`. The provider rejects
incompatible publication metadata from custom key stores; the verifier filters
incompatible entries from third-party sets before decoding compatible keys.
Both reject a `kid` shared by different RSA public keys; identical duplicates are
allowed. `EncodeRSAPublicKeyJWK` rejects blank signing key IDs. A provider
`SigningKey.Algorithm` may be omitted (RS256) or set to `RS256`; other values fail
signing instead of silently being overridden.

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

A nil verifier interface preserves `Client.Secret` for legacy static
configuration. That field is a plaintext expected value; it is not a
persistent-registry storage
recommendation. This additive extension does not remove the existing field.

A typed nil `ClientSecretVerifierFunc` returns an error and denies confidential
client authentication; it never panics or triggers static-secret fallback.
