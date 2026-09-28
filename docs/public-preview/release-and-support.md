# Publication, operations and ongoing support

Status: proposed release/support process. It does not enable repository settings,
publish a tag, promise an SLA or certify security. Existing
[RELEASING.md](../../RELEASING.md) and [SECURITY.md](../../SECURITY.md) remain the
current instructions until implementation PRs align them with this specification.

## R1: security and compatibility evidence before exposure

Freeze one source SHA after W0-W4, record the toolchain and run the candidate
suite. Re-run affected host checks after behavior/schema changes. Review public
API, defaults, error semantics, supported Go/service versions and migrations.
Preserve immutable tags and migration history. If security defaults or supported
behavior change incompatibly, use an explicit new pre-v1 minor line and migration
notes rather than disguising the change as a harmless patch.

Record all applicable SEC/WEB/ADM/OID/OPS outcomes, remaining findings and reviewer
approval. Unknown is not pass. Dependency scanning, package coverage and ordinary
host success cannot substitute for the negative state-transition/browser tests.

Review the entire reachable history, branches, tags, PR/issue content and release
artifacts that would become visible for secrets, internal data and redistribution
rights. Scan plus manually inspect; retain detailed findings privately. Rotate
compromised credentials before exposure. If history remediation is necessary,
obtain a separate explicit decision and plan; do not rewrite existing tags as an
incidental cleanup. Do not assume changing visibility hides earlier PR discussions.
A license file alone is not a third-party rights review.

Accept: reviewed exposure scope, no unresolved exploitable release blocker,
passing candidate and host checks at recorded versions, and owner approval for
the stated preview readiness level. Without independent review, label that gap
and restrict the release claim as specified in the verification document.

## R2: repository administration

The maintainer separately approves visibility changes after R1. Enable and verify
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
as soon as public visibility permits it, before release announcement. Test the
reporting path as a non-maintainer; never publish unverified contact details.

Protect the default branch and release tags, require appropriate successful
checks/review, and secure maintainer accounts. CI must run untrusted fork PRs
without secrets or write privileges. Do not execute untrusted code through a
privileged pull_request_target workflow. Review actions/dependency provenance
and pin trusted workflow dependencies to reviewed immutable revisions.

Runner/account/billing failures are infrastructure failures, not test outcomes.
Do not remove gates or expose a repository just to bypass that problem. A
reproducible local run can supply evidence, but its scope must be explicit.

## R3: exact-version public distribution

Create an unused tag at the candidate-tested SHA only after R1/R2. From its clean
checkout, with accepted PR #6 tooling included, run:

```sh
make public-module-check VERSION=<new-tag>
```

Or run the corresponding existing-tag workflow. It must resolve through the
public Go proxy/checksum service without inherited private credentials, local
replace/workspace or reused private caches. Verify the version selected after
the consumer builds/tests, not only the requested version string. Public module
verification must exercise the newly promoted profile API as it evolves.

Network/proxy propagation failure is blocked/failed, never success. Do not turn
off checksums or enable authenticated fallback to obtain a green result. If a
published version is defective, publish a new version and assess a Go retraction;
never move the original tag. A retraction is not deletion or automatic remediation
for existing users. Follow [Go module publication guidance](https://go.dev/doc/modules/publishing).

Only then publish release notes: exact version, supported profiles and versions,
installation/example, migration guidance, known limitations, security-reporting
channel and actual verification evidence. Separate source-preview availability
from recommendation for production adoption. Existing private/deployed releases
must not be silently described as tested at the new SHA.

## R4: operations needed by every supported deployment

Publish runbooks for routine overlapping key rotation, emergency key compromise,
DB restore and session invalidation, migration failure/rollback constraints,
notification worker lag/decryption failures and retention/cleanup. Exercises use
test data and are linked to SEC-04, SEC-16, OPS-01 and OPS-02.

Document canonical revocation timing, host-cache delays, offline JWT windows and
in-flight-request limitations. Monitor denial reasons separately from storage
outages, refresh replay, throttling, worker backlog and blocked delivery. Keep
labels low-cardinality; never log raw credentials or identifiers unnecessarily.
Avoid infrastructure errors triggering client retry storms or endless refresh.

A stopped worker does not mean auth commits rolled back; queue acceptance does
not mean a user received email. Specify responsibilities and recovery actions
for the host's sender, worker supervision, cleanup and migrations.

## R5: support policy without unsustainable promises

Before release, the maintainer approves and copies an achievable policy into
SECURITY/CONTRIBUTING/release notes. Proposed default: active maintenance on the
latest released pre-v1 minor line; older lines receive no automatic backport
promise. State the actual policy prominently, including response availability;
no 24/7 or response-time guarantee is implied by this plan.

Every change to an auth invariant needs a linked scenario and regression test.
Changes to exported APIs, defaults, schema, error outcomes or token policy need
compatibility notes. Keep a versioned support/profile list and an upgrade example;
do not make every possible host customization a supported configuration.

Configure repository CI (not an external promise of background work) for PR
checks and periodic dependency/vulnerability scans. A daily lightweight security
scan and a weekly bounded extended/fuzz run are suggested starting policies;
the maintainer selects cadence/runtime budgets. Pin tool versions, retain the
fuzz corpus and report missing infrastructure instead of silently skipping.
[Go security tooling](https://go.dev/doc/security/best-practices) complements
manual review; zero reported reachable vulnerabilities is not proof of safety.

For an incident: private intake -> reproduce and assess affected versions ->
contain/mitigate -> minimal fix plus regression -> reviewed new release -> private
coordination and public advisory -> upgrade/key/session guidance -> follow-up.
State affected and fixed versions, exploit prerequisites and remaining scope.
Never expose reporters' secrets or working attacks unnecessarily. Have a backup
contact/reviewer only after a real person agrees; do not invent a support team.

Community patches are welcome through explicit extension points. A maintainer
reviews security-sensitive changes; neither AI-authored code nor a passing test
suite alone supplies independent review. Feature growth follows observed consumer
needs after the core flows are stable.
