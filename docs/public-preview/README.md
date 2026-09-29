# Auth implementation and verification

The accepted local candidate includes explicit API/native auth, browser cookies,
existing opaque admin sessions and an explicit ZITADEL resource-server profile.
Publication, immutable release tags and production deployment are separate.

Local profile gates passed. Full release acceptance remains open: 17 of the 38
catalog cases are fully passed; 21 retain not_run with any narrower evidence
recorded separately. The aggregate site platform gate failed on unrelated
gouploads generation reproducibility; affected auth boundaries passed separately.

- [Contracts](auth-contracts.md): ownership, four profiles and AUTH-01..10.
- [Work packages](implementation-plan.md): dependency-ordered W0..W5.
- [Security scenarios](security-verification.md): 38 preserved scenario IDs.
- [Release and support](release-and-support.md): compatibility and operations.
- [Evidence template](release-evidence.example.yaml): starts entirely not_run.
- [Local evidence](release-evidence.local.yaml): executed commands, snapshot and
  precise limits; a narrow check cannot close an entire broad scenario.

See [v0.5 migration](../v0.5-migration.md) and
[release verification](../release-verification.md) for runnable candidate gates.
