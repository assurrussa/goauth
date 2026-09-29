# Public release plan

## Goal and scope

Publish a reusable PostgreSQL-first Go authentication Runtime as a **pre-v1
preview**, with reproducible evidence and explicit limitations. This is not a
claim of independent security certification, OIDC conformance, or production
adoption. Opening the source, publishing a module, and production readiness
are separate milestones.

The initial supported path is the root Runtime with PostgreSQL, optional Fiber,
and the existing documented adapters. Host applications own browser token
storage, CSRF, membership policy, UI, delivery providers, and process wiring.
Do not add MFA, passkeys, multi-tenancy, another database, or another transport
just to complete this release.

## 1. Release tooling (this change)

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

Implementation and test evidence are distinct: merge this change only after
its normal repository checks have run on the project's declared toolchain.

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
- Have another developer follow the documented Runtime/notification lifecycle
  in an application outside the maintainer's platform. Record integration
  problems; the synthetic consumer alone does not demonstrate usability.
- Review the MIT license, public README, support scope and security-reporting
  instructions. Decide whether optional OIDC packages remain preview-only;
  do not advertise untested protocol conformance.

Acceptance: no known unmitigated release-blocking security finding, recorded
history review, passing candidate gates at one SHA, and an owner-approved
preview scope. These checks are not completed merely by adding this document.

## 3. Visibility and distribution

Owner: maintainer. These are explicit administrative actions, not code gates.

1. Approve and change repository visibility after step 2. Review the exposure
   of history, tags, issues and PRs before doing so.
2. Enable and verify private vulnerability reporting immediately after the
   repository is public, before announcing or tagging the public release.
   Verify the reporting link from a non-maintainer account.
3. Configure required successful checks/review and protection of release tags.
   Do not weaken security checks to work around a CI-account problem.
4. Select a new unused semver tag at the reviewed SHA. A patch/pre-release tag
   is appropriate only if supported API and persisted semantics remain
   compatible; security-default or API changes may require a new minor line.
5. From a clean checkout of that tag, run:

   ```sh
   make public-module-check VERSION=<tag>
   ```

   Or dispatch `Public module verification` for the same tag. A private
   repository, inaccessible public proxy, mismatched version, replacement, or
   failed test must fail the gate. Never fall back to authenticated access.
6. Publish release notes and announce the preview only after the gate passes.
   Include compatibility/migration guidance and actual verification evidence.
   A failed published candidate is superseded by a new tag, never moved.

Acceptance: an unauthenticated consumer resolves and tests the exact tag via
the public Go proxy and checksum service; the reporting channel works; notes
state the supported scope. Proxy propagation/network failures remain failures
until rerun successfully, not a reason to disable checksums.

## 4. After the public preview

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
