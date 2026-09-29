# Security verification specification
Status: required scenarios, not executed tests. Scenario IDs are goauth-local.
Use [auth contracts](auth-contracts.md) and the [evidence template](release-evidence.example.yaml).
Do not infer test coverage or success merely because a corresponding test file
exists. Reuse existing tests where they prove the required observations.
Threat model and release scope
Assume an attacker can read every public source/tag, submit arbitrary requests,
register normal accounts, run a hostile website, obtain their own cookies and
race/replay requests. Include an untrusted sibling subdomain in browser tests
unless the host explicitly excludes that deployment. Exercise database/queue
outages, cancellation, key rotation and lost responses as environmental faults.
Protect credentials, account recovery, identity-to-session binding, separation
of user/admin access, secret material at rest and in logs, and release integrity.
A runtime/host takeover, stolen live credential or hostile trusted extension is
not magically solved by CSRF or JWT signatures. Limit impact, support revocation
and record these trust boundaries rather than promising impossible immunity.
Use the applicable auth/session/access-control requirements of
OWASP ASVS 5.0.0
as a review checklist, recording exact versioned requirement references during
review. This pack is not a complete ASVS mapping or a conformance claim.
JWT BCP and
OAuth Security BCP apply to their
respective profiles, not interchangeably to every local token operation.
Test discipline
Each case records preconditions, action, HTTP/core outcome, durable state and
security-event observations. Negative cases must check that no forbidden side
effect occurred, not only status codes. Use disposable databases, synthetic
accounts and fake notification delivery. Never send test resets to real people.
Concurrent SQL tests use independent connections and barriers, not sleeps alone.
Go's race detector does not prove database transaction correctness.
Use deterministic time/random injection where supported; also test real browser
cookie behavior and a real PostgreSQL/Redis deployment. Mocks and httptest do not
enforce browser SameSite/CORS rules. Capture redacted evidence only: no passwords,
raw cookies, reset URLs with secrets, DSNs or cryptographic keys in artifacts.
Required scenario catalog
Core identity and JWT (AUTH-01, AUTH-02, AUTH-09)
- SEC-01: correct/incorrect/missing-account credentials and suspended subjects.
  Assert no tokens on failure, limited scope before verification and no public
  error containing secret/account internals. Measure enumeration behavior across
  repeated samples; one timing assertion is not proof of indistinguishability.
- SEC-02: mutate/sign test JWTs with wrong algorithm/key/issuer/audience,
  missing/expired exp, malformed subject/session/version/scope and invalid time
  bounds. Assert denial before any protected operation.
- SEC-03: attempt reserved claim override and present access/reset/refresh or
  OIDC ID tokens to the wrong endpoint. Assert domain separation and no fallback
  to another credential source after failed verification.
- SEC-04: rotate keys across two processes with overlapping old/new keys.
  Assert live old credentials survive intended overlap, new issuance uses the
  new active key and removed/unknown keys fail. Exercise emergency compromise
  handling separately from routine rotation, including encrypted queue records.
- SEC-05: partial password-policy overrides, malformed PHC parameters,
  oversized/invalid input and simultaneous distinct-identifier attempts. Assert
  configured limits, bounded allocations/concurrency and no silent blocklist
  removal. Test input limits on login as well as new-password operations.
Sessions, refresh and failure boundaries (AUTH-03 through AUTH-08)
- SEC-06: logout then retry old access/refresh, using online and offline
  verification separately. Assert immediate subsequent online rejection and the
  documented offline expiry bound, not fictitious instant JWT revocation.
- SEC-07: concurrent refresh of the same token on independent connections.
  Assert at most one rotation succeeds, durable lineage is consistent and replay
  revokes exactly the intended family/session. Inspect other active sessions.
- SEC-08: injected membership/claims/signing failure around refresh. Assert
  deterministic pre-commit failure leaves the token usable and cannot issue
  extra credentials; post-commit outcomes match documented retry behavior.
- SEC-09: lose response after refresh commit; then retry as a real client.
  Assert the strict replay/re-authentication policy, or a separately reviewed
  alternative. Verify single-flight/multi-tab orchestration, not unlimited retries.
- SEC-10: login/session issuance versus suspend/password change/logout-all.
  Assert no usable new online session is created from stale security state after
  the losing operation; test permitted serializations and offline-token bounds.
- SEC-11: session/refresh expiry boundaries, clock skew policy and absolute
  lifetime caps. Returned expiry must describe actual usable lifetime; refresh
  must not extend the session beyond its documented absolute deadline.
- SEC-12: database unavailable, context canceled, audit failure and lost
  commit acknowledgement during register/logout/status change. Inspect canonical
  state and verify not-committed/committed/unknown semantics and retry guidance.
  Denial is required, but an internal outage must not be misreported as success.
Recovery, notifications and authorization (AUTH-05 through AUTH-10)
- SEC-13: simultaneous reset consumption and repeated confirmation codes.
  Assert one-time credential semantics, bounded attempts and correct durable
  counters even when a typed business error is returned.
- SEC-14: reset/challenge issuance versus email/password/status change.
  Assert stale destination/version rejection, old credential invalidation and
  notification validity checks; consumed/expired records cannot become active.
- SEC-15: account/email/password change versus enqueue/audit failure.
  Assert the declared transaction boundary and outcome; no committed secret
  without the recovery/delivery semantics promised for that mode.
- SEC-16: sender timeout, cancellation, worker crash before/after provider
  acceptance, lease loss and key decryption failure. Assert bounded retries,
  stable delivery identity, no false exactly-once claim and payload-free alerts.
- SEC-17: inspect DB, captured logs and test artifacts after each flow.
  Assert no raw reusable credentials in inappropriate storage/logging; encrypted
  envelopes are bounded by acknowledgement/retention policy. Review cleanup/WAL
  and backup limitations rather than claiming secure erasure of every copy.
- SEC-18: user token against admin routes, forged target SubjectID and
  unauthorized role/provisioning calls through the host. Assert deny-by-default,
  object ownership enforcement and no trusted bootstrap route exposure.
- SEC-19: remove membership/permission while an admin session is active.
  Assert the chosen on-request check or canonical revocation propagation and its
  maximum lag. Role catalogs are not evidence of endpoint authorization.
- SEC-20: verified/unverified external email linking and missing/changing email
  on a previously bound issuer/subject. Assert the reviewed linking policy,
  exact identity binding and no client-supplied ExternalIdentity trust.
Browser JWT/cookie/CSRF integration (P2)
- WEB-01: successful browser login, expired-access refresh and logout.
  Assert cookie flags/scope/lifetime, no auth secrets in JSON/JS storage, no-store
  responses and cookie removal on the correct path/domain.
- WEB-02: valid cookie with absent, wrong, expired or another session's CSRF
  proof on each state-changing route. Assert denial before mutation, including
  refresh/logout and account changes. Valid cookie alone is insufficient.
- WEB-03: cross-origin form POST, text/plain or unexpected content-type,
  credentialed CORS, null/missing Origin, untrusted sibling origin and forged
  forwarding headers. Assert the configured CSRF/origin policy; test with a
  browser, not just a hand-crafted HTTP request.
- WEB-04: guest/pre-login CSRF bootstrap, login/register, token/session rotation
  and logout. Assert correct proof lifecycle and login-CSRF prevention without
  deadlocking unauthenticated users out of login or password recovery.
- WEB-05: access expiry while refresh cookie remains valid. Assert valid
  session-bound CSRF still permits refresh; an old access JWT is not required to
  be valid solely to validate CSRF. Concurrent tabs follow SEC-09.
- WEB-06: session fixation attempt and duplicate/conflicting credential
  sources or same-name cookies. Assert selected-source behavior, context renewal
  and no successful weaker-source fallback.
- WEB-07: GET/HEAD/preflight across auth routes and reset-link navigation.
  Assert no credential mutation/one-time consumption via safe methods, while
  genuine preflight and page loading still work. Do not broadly exempt arbitrary
  auth mutation routes from CSRF just because they are unauthenticated.
- WEB-08: managed/browser assembly with missing CSRF config, invalid cookie
  combinations, wildcard credentialed origin policy and HTTP production URL.
  Assert safe failure. Test equivalent host-validator mode separately. Test-mode
  loopback HTTP exceptions must be explicit and absent from release examples.
Admin and host migration (P3)
- ADM-01: record the actual cookie credential format, verification call chain,
  deployed goauth version, session store and middleware order locally. Conclude
  JWT-backed or independent opaque, without sharing live credentials.
- ADM-02: login/elevation renews credential/context; inactivity and absolute
  expiry work. A disclosed canonical sid is not accepted as a bearer secret.
- ADM-03: disable/reset/logout-all through core and retry the admin session.
  Assert no independent host session bypasses canonical invalidation.
- ADM-04: run the site's and admin's real local lifecycle against the candidate
  dependency with existing data fixtures; test migration and documented rollback.
  Assert behavior parity or explicit reviewed breaking-change guidance.
Optional OIDC, persistence and distribution
- OID-01: verifier rejects missing required claims, wrong discovery issuer,
  token kind and unsafe fetch destinations; bound responses, timeouts and
  unknown-kid refresh concurrency/rate. Do not mistake access-token validation
  for completed OIDC browser login validation.
- OID-02: provider code replay, redirect/client binding, PKCE, client auth,
  nonce and refresh-family behavior. Interoperability uses an independent client
  for the claimed subset. Conformance is not inferred from self-issued tokens.
- OPS-01: migrations preserve existing canonical rows, refuse unsupported
  schemas without deletion, serialize concurrent startup and recover after
  failure/cancellation. Review reset ownership; no unrelated host table removal.
- OPS-02: restore a test backup with required key versions, schema and queue
  state. Assert recovery plus controlled session revocation when needed. Confirm
  least-privilege application DB access, separate migration authority and no
  mandatory Redis dependency for local-only runtime assembly.
- OPS-03: clean public consumer resolves the exact tag without private
  credentials, replace, workspace or reused private cache. Confirm real dependency
  selection after compilation and no private imports in supported examples.
- OPS-04: all refs/history and publishable artifacts undergo secret/internal
  data/redistribution review. CI/release permissions and untrusted PR execution
  are reviewed; check release-tag protection and dependency update mechanism.
Existing test locations to extend
Start with runtime_security_test.go, runtime_validation_test.go,
runtime_outcomes_test.go, account_lifecycle_test.go,
account_lifecycle_outcomes_test.go, email_challenge_race_test.go,
postgres/integration_test.go, postgres/notification_integration_test.go,
postgres/migration_upgrade_integration_test.go, fiber/adapter_test.go,
oidc/provider/service_test.go, oidc/verifier/service_test.go and the public
consumer tests. This is a routing list, not confirmation that cases pass.
Acceptance and triage
All applicable cases start not_run. Record pass, fail, blocked or
not_applicable only with evidence. Not-applicable requires a scope reason and
reviewer approval; it cannot hide an untested advertised profile. Map every
AUTH requirement to at least one case and include all relevant cases for P1/P2/P3.
Release blockers include bypass/takeover, privilege escalation, exposed secrets,
reusable one-time credentials, broken canonical revocation, unsafe default
cookie integration and destructive migration. A medium-labelled issue can still
block if it violates a promised boundary. Known exploitable blockers are fixed
or the affected capability is actually disabled/removed through a reviewed
compatibility decision; documentation alone is not remediation.
Run an independent focused security review of the selected release scope before
recommending external production adoption. If unavailable, do not represent it
as completed: a source-only preview requires explicit owner approval and must
not claim the corresponding readiness level. Go security guidance
supports race/fuzz/vulnerability checks as useful evidence, not an audit substitute.