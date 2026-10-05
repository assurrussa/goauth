# Public release plan

Historical plan for `v0.5.0`. That version and `v0.5.1` are already tagged; do
not rerun the tag-creation instructions below. Current master is unreleased
and uses schema 8, while published `v0.5.1` uses schema 3. Follow
[the current release decision](../RELEASING.md#version-state) for a new release
or a narrow backport. This historical plan is not evidence that all acceptance
checks were performed.

## Goal and scope

Publish a reusable PostgreSQL-first Go authentication Runtime as the **pre-v1
release `v0.5.0`**, with reproducible evidence and explicit limitations. This is
not a claim of independent security certification, OIDC conformance, or
production adoption. Opening the source, publishing a module, and production
readiness are separate milestones.

Release `v0.5.0` directly, without alpha, beta or RC tags. Before tagging, run
integration acceptance in the `goadmin` administration flow composed with
`site`, pinned to the selected goauth source SHA. This is the selected host
acceptance environment; it does not mark testing as completed.

The initial supported path is the root Runtime with PostgreSQL, optional Fiber,
and the existing documented adapters. Host applications own browser token
storage, CSRF, membership policy, UI, delivery providers, and process wiring.
Do not add MFA, passkeys, multi-tenancy, another database, or another transport
just to complete this release.

## 1. Available release tooling

- Published probes use fresh home, module/build caches and Go settings. They
  cannot inherit private module rules, auth helpers, workspaces, proxy
  credentials, or the caller's database credentials.
- Both initial resolution and the module selected after the executable test
  must match the requested exact version, without a replacement.
- `make public-module-check VERSION=<tag>` requires a clean checkout at that
  tag before performing the public-proxy check.
- A manual `Public module verification` workflow verifies an existing tag. It
  never creates tags, publishes releases, or changes visibility.
- The existing CI can be dispatched manually while the repository is private.
- `make public-preview-readiness VERSION=<tag> EVIDENCE="$RELEASE_EVIDENCE_FILE"`
  combines executable release gates with the reviewed release-SHA manifest;
  see [full acceptance](release-verification.md#full-public-preview-acceptance).

Available tooling is not passing evidence. Run the matching gates on the
project's declared toolchain and record their exact source SHA and outcomes.

## 2. Before opening repository visibility

Owner: maintainer; code fixes go through reviewed PRs.

- Re-check the security-review findings against the actual candidate SHA.
  Close the token-verification and refresh-failure findings with regression
  tests. Decide and document external-identity trust, membership revocation,
  password defaults, and partial-success behavior. Do not infer completion
  from an unrelated merge or from coverage percentage.
- Review all Git refs/history that will become visible, not only HEAD, for
  credentials, personal/internal data and redistribution rights. Use a
  secret scanner plus manual review; a negative scan is not a proof of absence.
  Rotate any exposed secret. Resolve necessary history remediation explicitly
  before publication; do not silently rewrite tags.
- Run `make release-candidate-readiness` with disposable PostgreSQL and Redis
  and archive the candidate SHA and command results. Restore working CI or
  record equivalent reproducible local evidence; a runner/billing failure is
  not a code-test result.
- Exercise the documented Runtime/notification lifecycle and account,
  session, recovery and RBAC flows in `site` with `goadmin`. Record the site
  commit, resolved goadmin version/SHA and resolved goauth version/SHA, commands,
  outcomes and integration problems in the private site/admin evidence.
  The synthetic consumer alone does not demonstrate host integration.
- Review the MIT license, public README, support scope and security-reporting
  instructions. Decide whether optional OIDC packages remain preview-only;
  do not advertise untested protocol conformance.

Acceptance: no known unmitigated release-blocking security finding, recorded
history review, passing candidate gates at one SHA, and an owner-approved
release scope. These checks are not completed merely by adding this document.

## 3. Visibility and distribution

Owner: maintainer. These are explicit administrative actions, not code gates.

1. Approve and change repository visibility after step 2. Review the exposure
   of history, tags, issues and PRs before doing so.
2. Enable and verify private vulnerability reporting immediately after the
   repository is public, before announcing or tagging the public release.
   Verify the reporting link from a non-maintainer account.
3. Configure required successful checks/review and protection of release tags.
   Do not weaken security checks to work around a CI-account problem.
4. Confirm that `v0.5.0` is unused and create it at the reviewed,
   candidate-tested SHA after site/goadmin acceptance. There is no alpha,
   beta or RC stage for this release. Preserve the documented v0.5 migration
   for its changed API and security defaults.
5. From a clean checkout of that tag, run:

   ```sh
   make public-module-check VERSION=v0.5.0
   ```

   Or dispatch `Public module verification` for the same tag. A private
   repository, inaccessible public proxy, mismatched version, replacement, or
   failed test must fail the gate. Never fall back to authenticated access.
6. Complete all 38 scenario records, both host checks and required release-gate
   records in the private evidence manifest. From the clean tagged checkout,
   with integration services and browser tools available, run
   `make public-preview-readiness VERSION=v0.5.0 EVIDENCE="$RELEASE_EVIDENCE_FILE"`.
   History/scoped review, operational drills, reporting/protection and owner
   approval must be evidenced too; executable tests do not stand in for them.
7. Publish release notes and announce `v0.5.0` only after these gates pass.
   Include compatibility/migration guidance and actual verification evidence.
   A failed published candidate is superseded by a new tag, never moved.

Acceptance: an unauthenticated consumer resolves and tests the exact tag via
the public Go proxy and checksum service; the reporting channel works; notes
state the supported scope. Proxy propagation/network failures remain failures
until rerun successfully, not a reason to disable checksums.

## 4. After the public release

Collect feedback from independent consumers, document deployment/key-rotation
operations, and commission an independent security review before stronger
production claims. Expand features only for a concrete consumer need.
No star, download, tag, or synthetic probe is evidence of a production rollout.

## Evidence record for each candidate

Record the source SHA, tag (if created), toolchain, candidate gate output,
PostgreSQL/Redis versions, public probe run, history-review scope, remaining
limitations and maintainer approval. Mark unavailable checks as not run. Keep
secret-scanner findings private and never attach raw credentials or payloads.

Protocol/environment references:

- [Go command environment and authentication](https://pkg.go.dev/cmd/go)
- [Go module publication and proxies](https://go.dev/ref/mod)
- [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
