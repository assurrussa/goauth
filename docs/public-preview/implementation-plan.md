# Implementation work packages

Status: ordered specification, not claims of completed runtime work. Read
[contracts](auth-contracts.md) and [verification](security-verification.md).
The docs-only change introducing this pack must not modify cryptography,
migrations, dependencies, supported imports, tags or visibility.

The v0.5 implementation decisions are recorded in
[candidate assembly](candidate-assembly.md). The dated
[local evidence](release-evidence.local.yaml) records completed narrow checks
and open catalog acceptance; W0-W5 criteria below remain the required work.

## W0: establish a reproducible baseline and local host handoff

Owner: library maintainer; host maintainer runs the private site/admin checks.

Pin the library SHA/tag, host SHA and resolved dependency independently. Read
actual host code locally: login handler, cookie writes, CSRF middleware, session
lookup, refresh and logout, authorization checks and startup/migrations. Record
middleware order and credential sources, not only configuration names. Check
whether the deployed host still uses a historical API after legacy retirement.
No production data reset or automatic live dependency upgrade is allowed.

Fill ADM-01 and the host fields in the evidence template. Trace account state
through registration -> confirmation -> login -> refresh -> protected request ->
logout -> recovery and password/email/status changes. User experience reported
before the latest rewrite is a valuable baseline, not candidate regression proof.

Deliver: exact P1/P2/P3 mapping and a reproducible local fixture, with private
host details retained locally. Accept: both host profiles identified; unknown
fields remain explicit. Cookie work can start from the declared P2 requirements,
but the opaque-session implementation branch must wait for this evidence.

## W1: close core state-transition and token-verification gaps

Likely areas: `runtime.go`, `account.go`, `recovery.go`, `email_change.go`,
`identity.go`, `password.go`, `jwt.go`, `contracts.go` and participating stores.
Use the pinned code and existing tests; do not reimplement already correct paths.

Reproduce each earlier review concern before closing it. Cover SEC-01 through
SEC-20, beginning with verification, refresh-after-hook-failure, issuance versus
revocation, identity trust and mutation outcomes. The inspected baseline ordering
in Runtime.Refresh rotated before post-rotation authorization/signing. The v0.5
candidate prepares fallible work first and revalidates canonical state at commit;
targeted failure injection is still required for the full SEC-08/09 catalog.

For refresh, prepare fallible work before irreversible consumption where safe,
then revalidate expected security state atomically at the commit boundary.
Do not create a stale-read bypass in the process. Do not hold DB locks across
arbitrary network hooks. Choose and document strict replay/lost-response behavior
before adding idempotency or a grace window. No plain-text refresh storage.

Document not-committed/committed/unknown outcomes and audit guarantees per
operation. Separate permission denial, revoked credentials and infrastructure
failure without leaking account internals. Reconcile issuance TTLs with canonical
session lifetime. Review password-policy merging, hash-upgrade needs and bounded
Argon2 execution without inventing cryptography.

Deliver: small independently reviewable fixes, regression cases and compatibility
notes. Accept: applicable core cases pass against memory and real PostgreSQL
where supported; no weakened invariant or claimed success from compile-only tests.

## W2: complete the optional browser integration

Depends on W1 where core guarantees change; it does not require a new core auth
engine. First extract/reuse the host's working composition locally. Prefer a
thin wrapper around a maintained framework CSRF/session component that passes
this contract over another custom security subsystem. Review that component's
actual version/API before selecting it.

Place HTTP policy in an adapter/example, not root Runtime. The v0.5 reference
promotes the supported net/http adapter alongside existing Fiber support and
uses one same-origin HTTPS example. Other origin topologies require separate
host acceptance. Build a complete runnable flow with a fake mail receiver,
supervised notification worker and orderly shutdown.

Implement explicit Bearer versus cookie credential selection, cookie flags and
clearing, bounded bodies, no-store responses, safe errors and full route coverage.
Cookie-profile responses do not also leak auth tokens in JSON. CSRF integration
supports guest bootstrap and authenticated state, survives legitimate refresh
with expired access tokens, and denies protected effects when proof is absent.
Host-provided equivalent protection remains possible through an explicit tested
integration; no silent disable flag in the supported browser assembly.

Reference routes cover register/login, email challenge request/verification,
password reset request/consumption, refresh, logout/logout-all and account changes.
Host authorization is enforced before SubjectID-targeted mutations. Reserve trusted
provisioning for operator-controlled bootstrap. UI-specific business flows remain
outside the library.

Deliver: optional adapter/composition, runnable reference and WEB-01 through
WEB-08 using actual browser origin behavior. Accept: no Go API/mandatory import
forces cookies/CSRF on core users; cookie users receive safe working defaults.
If a new supported package is necessary, update the package manifest, imports,
public-surface compile tests and clean consumer deliberately.

## W3: preserve admin sessions based on W0 evidence

If P3 already uses JWT with online state, reuse W2 and add current admin
membership/permission and session-policy checks. No new token format is required.
If an independent opaque cookie is confirmed, add only the bridge needed to
validate that credential and join canonical identity, realm and revocation.
Model idle/absolute lifetimes and any cache delay explicitly. Do not store raw
canonical sid as the client secret or use rotating refresh as a per-request
session cookie.

Any new schema is additive with upgrade/rollback guidance; existing migration
files/tags remain immutable. Keep bridge state and canonical invalidation linked
in every password/reset/status/logout-all path. Verify an old host binary's
schema compatibility rather than claiming generic rollback support.

Deliver: ADM-01 through ADM-04 plus browser cases for the actual admin mode.
Accept: both real host flows pass locally at the candidate version. Publishing
P1 alone instead is a product-scope change requiring explicit approval, not a
way to silently drop the requested admin/browser compatibility.

## W4: optional-module containment and security review

Run OID-01/OID-02 for currently exposed OIDC functionality. Do not expand provider
features or promise compatibility with every IdP before publication. Existing
imports are not deleted merely because OIDC is outside the main positioning.
Unsafe behavior needs remediation or a real, reviewed disabling change.
RBAC remains part of admin acceptance, including host endpoint enforcement.

A focused independent reviewer receives the threat model, scenario evidence,
small diffs, dependency versions and residual risks. Use their findings to
repair the implementation and rerun relevant regression tests. Review JWT,
recovery, browser integration and state transitions, not only crypto primitives.
Deliver: findings with affected/fixed SHAs and dispositions. Accept: no open
exploitable blocker in the advertised profile; review scope/limitations recorded.

## W5: converge on one candidate and finish distribution

Integrate release tooling from PR #6 after its own review/gates, then combine it
with the accepted behavioral changes. Rebase/merge conflicts must not overwrite
another contributor's work. Full checks must refer to the resulting SHA, not
only to component PRs or an older tag.

Use the declared Go toolchain and pinned formatting/lint tooling. During work run
scoped tests; run one coherent candidate gate with disposable services:

Select installed Playwright/Chromium tools using the environment variables in
[release verification](../release-verification.md) before running this gate.

```sh
(
    set -eu
    trap 'make integration-down' EXIT
    make integration-up
    make release-candidate-readiness
)
```

The existing gate covers root/static/race/coverage/consumer and PostgreSQL/Redis
checks plus govulncheck. Extend it to execute the new profile suites; an added
specification is not an executable gate. Browser tests must not silently skip
when their engine is unavailable. Record toolchain, services and all failures.
Do not downgrade go.mod to fit an editing sandbox.

Then follow [publication and support](release-and-support.md). Candidate checks
alone do not establish anonymous installability. PR #6 tooling, including
`make public-module-check VERSION=<tag>`, is included in the candidate merge and
must be present in the chosen new tag; it was absent from the inspected baseline.

## Work intentionally excluded

No Authboss migration, general IAM service, automatic multi-project SSO rollout,
passkeys/MFA implementation, multi-tenancy, new database support or broad transport
rewrite is required just to publish. Record demand for those separately. Do not
claim the absence of MFA is harmless for every host risk level; privileged hosts
may need compensating controls or a later MFA requirement before their own launch.

## Agent handoff

For each W item: inspect actual inputs and existing diffs; link its scenario IDs;
write the smallest failing regression; implement; run scoped tests; record
compatibility changes; run the complete applicable gate once. Report files,
commit, commands, actual outcomes and missing evidence. Never mark local host
checks, an independent audit, public distribution or deployment done by inference.
