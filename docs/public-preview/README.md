# Public preview: contracts, verification and release work

Status: implementation specification; not a security attestation or a change to
supported Go symbols. Prepared 2026-09-28 against master
`070b1f37e8139d5796cb266b57d07cdd16b659c9`.

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

The inspected [Runtime](../../runtime.go) issues JWT/refresh pairs associated
with server-side sessions. Its token verification supports optional server-side
introspection. The current [Fiber adapter](../../fiber/adapter.go) extracts a
Bearer token; the project contract leaves cookie policy to hosts. The existence
of a Session record is not evidence of a separate opaque-cookie login protocol.
Public package boundaries and security invariants already exist; the missing
work is profile-specific acceptance evidence and integration guidance, not a
wholesale creation of contracts from scratch.

Release tooling is a separate dependency: [PR #6](https://github.com/assurrussa/goauth/pull/6),
observed open/draft at head `d5ed6459944f27fe7ab04c9cdadf49f8d33ea2e5`.
Do not mark its gates passed from this specification. Keep its publication
mechanism; use this pack to define which behavior must be tested before release.

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
- Do not add opaque session credentials until local evidence determines whether
  the admin actually needs them. Do not silently replace the admin's behavior
  with JWT either.

## Completion

The implementation is ready for a public preview when every applicable blocking
scenario has release-SHA evidence, both reported host flows have local acceptance
records, no unresolved exploitable release blocker remains, the exposure review
is complete, and an anonymous consumer resolves the exact new tag.

A reviewer records residual limitations and support scope. Neither successful
production use, coverage, scanners nor an independent review proves absence of
all vulnerabilities. Do not promise that public source is impossible to attack.
