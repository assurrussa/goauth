# Public preview: contracts, verification and release work

Status: implementation specification; not a security attestation or a change to
supported Go symbols. Prepared 2026-09-28 against master
`070b1f37e8139d5796cb266b57d07cdd16b659c9`.

The current unpublished v0.5 candidate has local profile validation recorded in
[the dated local evidence snapshot](release-evidence.local.yaml): 17 catalog
cases are recorded as passed and 21 remain `not_run`. That pre-commit snapshot
does not constitute release-SHA acceptance under the complete template below.
The aggregate site platform gate also remains failed at the unrelated gouploads
generation/formatting boundary. Public-preview readiness is not established.

## Outcome

Make goauth installable and maintainable by developers outside the maintainer's
private dependency environment, while preserving the useful local-auth flows.
The deliverable is a bounded, verified pre-v1 library, not a new general IAM
server. Opening source and proving security are separate activities.

Use these documents in order:

1. [Auth contracts](auth-contracts.md): ownership, profiles, extension boundaries
   and required behavior.
2. [Verification specification](security-verification.md): threat assumptions,
   scenario IDs, observations and release blockers.
3. [Implementation work packages](implementation-plan.md): order, affected areas,
   acceptance criteria and the local host handoff.
4. [Publication and support](release-and-support.md): candidate, distribution,
   compatibility and incident handling.
5. [Evidence template](release-evidence.example.yaml): fill from actual runs;
   `not_run` is never success.
6. [Candidate assembly decisions](candidate-assembly.md): the selected v0.5
   browser/native/admin/OIDC wiring, distinct from required acceptance evidence.

The existing [project contract](../project-contract.md),
[public surface guide](../public-surface.md), and
[auth invariants](../../AUTH_INVARIANTS.md) remain authoritative for the current
implementation. MUST in this specification denotes a target acceptance
condition, not a claim that the code already satisfies it. Promote a condition
to an advertised guarantee only with evidence at the release SHA.

## Confirmed scope and evidence boundaries

The maintainer reports existing site integrations using JWT/cookies/CSRF and an
admin integration using sessions. Their current deployed versions and middleware
were not inspected in this task. Treat this as host experience to preserve, not
proof that every behavior is present in the current library tag.

The current [Runtime](../../runtime.go) issues JWT/refresh pairs associated
with server-side sessions. HTTP realm middleware uses current-session checks
by default; offline JWT verification is an explicit policy with a revocation
window. The [Fiber adapter](../../fiber/adapter.go) and supported net/http adapter
extract explicit Bearer credentials; the project contract leaves cookie policy
to hosts and the reference composition. The existence
of a Session record is not evidence of a separate opaque-cookie login protocol.
Public package boundaries and security invariants already exist; the missing
work is profile-specific acceptance evidence and integration guidance, not a
wholesale creation of contracts from scratch.

Release tooling from [PR #6](https://github.com/assurrussa/goauth/pull/6) is included
in the candidate merge. Do not mark its gates passed from this specification.
Keep its anonymous exact-tag publication mechanism; use this pack to define
which behavior must be tested before release.

## Decisions

- Preserve the transport-neutral core and PostgreSQL-first storage guarantees.
- Keep cookies and CSRF optional for core users. A supported cookie-authenticated
  browser profile must select a verified CSRF integration; disabling the package
  is not permission to omit the protection from that profile.
- Stabilize local authentication, JWT verification, canonical sessions, recovery
  and the two real host integrations before adding new auth methods.
- Do not replace goauth with Authboss or layer two account/session state machines
  together without a concrete missing capability and migration justification.
- Keep existing OIDC/RBAC imports compatible. Do not claim OIDC conformance or
  unrestricted SSO interoperability. Optional code still requires security
  review and safe defaults; it is not exempt because it is optional.
- Preserve the opaque admin credential identified by local ADM-01 inspection;
  its server-side bridge must honor canonical revocation and current permission
  checks. Local identification does not establish production deployment state.

## Completion

The implementation is ready for a public preview only when all of the following
conditions hold at the release SHA:

- Every release-blocking scenario in the
  [catalog](security-verification.md#required-scenario-catalog) has recorded
  evidence and an outcome of `pass`, or `not_applicable` with a scope reason and
  reviewer approval. All 38 catalog cases are release-blocking when applicable;
  the template marks each with `release_blocking: true`. `fail`, `blocked` and
  `not_run` prevent readiness; the presence of evidence alone is insufficient.
- `make release-candidate-readiness` passes at that same SHA, with its command,
  source SHA, successful status and evidence recorded in
  `release_gates.candidate`. A missing or unsuccessful gate prevents readiness.
- Both reported host flows pass local acceptance at the candidate version, with
  their host and resolved goauth versions recorded.
- No unresolved exploitable release blocker remains and the exposure review is
  complete.
- An anonymous consumer successfully resolves the exact new tag at the tested
  SHA, with the result recorded in `release_gates.anonymous_exact_tag`.

A reviewer records residual limitations and support scope. Neither successful
production use, coverage, scanners nor an independent review proves absence of
all vulnerabilities. Do not promise that public source is impossible to attack.
