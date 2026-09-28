# Security policy

## Private reports

Once the repository is public and its private vulnerability reporting is
enabled, report a suspected vulnerability through **Security → Advisories →
Report a vulnerability**. Do not open a public issue or PR containing an
exploit, credentials, or personal data. The maintainer must enable and verify
this channel immediately after changing visibility, before announcing or
tagging the public release. Until then, use an existing private communication
channel with the maintainer; this document does not assert the GitHub channel
is already enabled.

Include the affected version or commit, a minimal reproduction, the expected
and observed impact, and known mitigations. Allow time to reproduce and
coordinate a fix before disclosure. Do not include real production secrets.

## Support and evidence

Security fixes are evaluated against the latest tagged release. An advisory
must state affected and fixed versions; older lines have no standing support
guarantee. A Git tag is not evidence of public module availability, completed
security review, or production suitability.

This is a pre-v1 project. Do not assume independent security audit or OIDC
conformance. The maintainer must close known release-blocking findings and
record actual checks before announcing a public candidate; see
[docs/public-release-plan.md](docs/public-release-plan.md).
