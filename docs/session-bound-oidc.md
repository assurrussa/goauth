# Session-bound OIDC profile

`provider.NewSessionBound` is an additive, explicit profile for a confidential
web client backed by a host's live opaque SSO session. It reuses the provider's
RS256/JWK, PKCE, scope and canonical account primitives. Existing `provider.New`
and public DTO layouts remain source-compatible. No new supported import or
host-support package is needed.

The fixed profile supports authorization code with mandatory S256, registered
exact HTTPS callbacks, `client_secret_basic`, `openid` and optional `profile` and
`email`. Rotating refresh is issued independently of `offline_access`, which
this profile rejects. Refresh requires a live central session and is not offline
access. Access/ID tokens last at most five minutes; codes at most 60 seconds;
authorization requests ten minutes; session/family absolute ends at most seven
days from their authentication. Ordinary use never advances that end.

## Host integration

Construct `postgres.NewSessionOIDCState(runtime)`, then pass it, a
`SessionAdmission`, `ClientSecretVerifier`, signing-key store, exact HTTPS issuer
and configured login URL to `provider.NewSessionBound`. Never supply fallback
subject-only claims or legacy independently committing stores. The host owns
HTTP parsing, client registrations, project/grant policy, opaque cookies, CSRF,
login and logout, and operator-provisioned persistent signing keys.

Every final provider operation enters exactly one `InOwnedAuthTransaction`.
Admission joins that exact runtime/DB scope and locks canonical subject, project,
client, retained grant, then sid. It obtains the subject through a read-only hint
and revalidates under locks. An unauthenticated start takes project/client locks
only. The provider then locks request/code, family and token in that order.
Admission must not upgrade an accountless lock path into a subject path.

`SessionAdmissionResult.Allowed` reports ordinary live-session/grant denial.
Return the recognized client and its current method even when availability,
subject, session or grant prevents issuance. `Client.Trusted` is false for a
disabled/retired client or disabled project. The secret verifier authenticates
the current secret under the client lock independently of issuance availability:
a valid owner can revoke and commit stale-code/family denial effects. Wrong
clients or invalid/rotated secrets must not burn or revoke another grant.
Infrastructure errors remain errors and roll the transaction back.

The host returns a canonical nonzero lowercase UUID `SessionProjection.ProjectID`
independently of metadata. The opaque printable ASCII stamp (1–192 bytes) binds
host authorization versions; GoAuth only compares it. Typed subject version,
sid, authentication time and absolute end are separate. Reauthentication may
advance the live session's authentication time, but existing code/family evidence
retains its original authentication time. The host must preserve that expected
time while comparing the other immutable fields.

The public state setters are privileged storage operations, not authentication
endpoints. The host's login POST prepares a fresh runtime-bound CredentialProof
for the exact request, enters the runtime's owned transaction, revalidates the
proof, checks host membership and the exact current sid/cookie generation,
creates/replaces the opaque cookie, then calls `MarkLoginComplete`. That one-way
marker binds the challenge to the resulting sid, cookie digest and actual
password-authentication time. Recheck proof and request/session expiry after
waits. Any failure rolls all tentative session and marker changes back. Release
cookies only on confirmed nil commit; unknown commit never permits a blind retry.
No timestamp heuristic or unrelated login can satisfy a missing marker.

`ContinueAuthorization` takes the stored challenge, current BrowserSession and
browser-binding digest, never an account or supplied marker. Forced login and
max_age=0 require the exact stored marker, even under equal/frozen clocks.
Positive max_age is checked after waits and before callback exit. `prompt=none`
cannot cause interaction; consent/account selection return explicit protocol
errors. The login redirect query key is `oidc_challenge`.

All strict-profile error callbacks, including initial protocol errors and
`prompt=none` failures, preserve the exact opaque request state (including
whitespace). Request state replaces any registered callback `state` query value;
absent state is not inherited from the registration. Other callback query
parameters are preserved. Legacy provider behavior is unchanged.

A completed continuation that loses policy admission or its client revision
returns `access_denied` and the exact stored `state` to the current registered
callback. The current client ID must still match the request, the client must
remain trusted, and that exact HTTPS callback must still be registered under
the admission locks. This is a terminal, single-use request consumption in the
same owned transaction, with no code, family or token issuance. The provider
rechecks the locked request's completion marker, browser binding, sid, cookie
generation and expiry before preparing the error redirect. It releases the
existing `AuthorizeResult` only after confirmed commit and before request
expiry; hosts use their ordinary redirect path. This replaces the earlier
local `access_denied` response for a valid, safe continuation callback, as
required by [OIDC authorization errors](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).

Missing, malformed, expired, consumed or mismatched challenges remain local
errors. A removed callback or unknown/untrusted client also stays local; this
includes disabled/retired clients and disabled projects. Revoked membership on
an otherwise enabled client/project can receive the safe callback denial.
Callback edits must use the same project/client locks, so either the edit wins
and the target is refused, or the denial commits against the still-registered
target first. Infrastructure failures and unknown commit withhold all redirect
output. Expiry detected by the in-transaction check rolls consumption back;
expiry detected only after confirmed commit may leave the terminal consumption
committed without delivery.

## Claims and verification

Strict access tokens use typ `at+jwt`, token_use `access`; ID tokens use typ
`JWT`, token_use `id`. Both contain required `project_id`. Optional profile maps
are sibling `authhub_profile` and `authhub_project` string maps, emitted only for
profile scope. Their existing metadata limits are eight keys, 32-byte lowercase
keys, 256-byte UTF-8 plain values and 2048 bytes per map, with reserved
security/protocol keys blocked. A namespaced `email` value never becomes a
verified canonical email. The account's actual optional email remains governed
by identifier verification state. Metadata-only changes do not change bindings.

Provider-private typed claims include sid, subject security version, family ID,
authorization stamp, and full-precision `binding_auth_time`/`session_expires_at`.
The separate standard `auth_time` is seconds since epoch. These precise times
avoid silently weakening the persisted binding through JWT timestamp rounding;
relying parties do not parse them or the stamp for authorization.

The strict profile accepts signing key IDs of 1–256 printable ASCII bytes
without spaces. This is an implementation profile, not a universal JWK rule.
Issuance validates the active ID with the same predicate as verification,
before any code consumption or refresh rotation; legacy key rules are unchanged.

UserInfo requires exact issuer, one client audience matching client_id, RS256,
a nonempty matching kid (no active-key fallback), access-token purpose/type,
required timestamps and every session/project/family binding. It re-admits the
current session and checks family revocation under locks. ID tokens cannot be
UserInfo bearer tokens. The central provider conservatively permits zero clock
skew. Applications may separately permit up to 30 seconds only for JWT
verification, never for code/session/family expiry or application freshness.
Current project metadata is projected under the same host lock snapshot.

Access/ID issuance shares one captured time and deadline, capped by the original
absolute end. Times are checked after lock waits/signing/writes, immediately
before callback exit and after confirmed commit. Expired results are suppressed;
consumption may remain committed in that safe-loss case. No source promises
network delivery before expiry. App freshness must be bounded by verified iat
plus five minutes and exp, never reset by a cached token or receipt time.

## Compatibility and schema 8 rollout

Schema 8 is additive; previous migration bytes/checksums are frozen. Deploy with
coordinated migration/restart and strict readiness; old writers are unsupported
during the transition. Bound and legacy families remain separate profiles;
legacy Get/Rotate see bound state as absent, legacy Revoke is an unknown-token
no-op, and strict operations reject unbound rows. Database guards prohibit
profile conversion, partial binding, expiry extension, binding mutation,
consumed-token resurrection and successor reversal. Canonical subject-wide
security invalidation can still revoke either profile.

Intentional legacy behavioral change: `OIDCRefreshTokenStore.Get` is now strictly
read-only. A consumed token returns an inactive snapshot using the existing
`RefreshToken.RevokedAt` field; this does not prove the family's revoked_at was
persisted. Callers must not rely on Get to revoke/audit. The legacy provider
first authenticates the exact owner and then invokes Revoke, which commits
correct-owner consumed-token replay/audit. Infrastructure failures from this
mutation are propagated. Direct adapter Revoke is still a trusted mutation API;
applications must establish ownership before calling it. Existing public struct
layouts and method signatures are unchanged.

Requests/codes persist only keyed digests of high-entropy secrets. Refresh uses
the existing selector/HMAC key ring. Consumed digests/tombstones survive while
the family can be live. No raw cookie/challenge/code/refresh is stored. Bounded
cleanup must preserve live replay evidence and use the documented lock order.

Hosts that deliberately avoid broad Runtime.Cleanup call the concrete state
adapter’s CleanupExpired(ctx). Its SessionOIDCCleanupResult reports bounded
request, code, refresh-token and family deletions only after confirmed commit.
It touches only expired strict-profile OIDC state, not legacy families, audit,
recovery, generic sessions or host sid rows. The host separately maintains its
opaque sessions. Runtime.Cleanup reuses the OIDC retention routine in a separate
transaction released before generic cleanup locks. Cleanup is successive
maintenance batches: OIDC progress may already be committed if a later generic
cleanup phase fails; it is not globally atomic. Authentication/issuance/replay
operations still remain one owned transaction each.

HTTP adapters must parse bounded query/form inputs exactly once, reject decoded
name duplicates (including empty duplicates), then treat sole empty values as
absent and ignore genuinely unknown parameters. GET/POST authorize and POST
form token are supported. Never merge protocol parameters across query/body;
reject credentials in URI, extra authentication mechanisms and unsupported
request objects/claims features. Basic plus a lone matching body client_id is
permitted. Unsupported response_mode is local400; callback errors are redirected
only after exact registered-client/callback validation. This library is
transport-neutral and does not implement that HTTP parser or an RP SDK.

No end_session_endpoint, pushed logout, events/outbox or generic role system is
advertised by this profile. Apps own durable local sessions and refresh ownership;
central logout invalidates sid and future issuance/UserInfo immediately, while
already verified app proofs remain bounded by their original deadline.
