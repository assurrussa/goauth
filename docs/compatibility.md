# Compatibility policy

The tagged baseline is `v0.4.1`; `v0.5.0` is an unpublished pre-v1 candidate.
The selected release goes directly to `v0.5.0`, without alpha, beta or RC tags,
after integration acceptance in `goadmin` composed with `site` at the selected
goauth SHA. This planned acceptance is not evidence of completed host adoption.
Host adoption is verified separately from this library's release gates. Private
host inventories and acceptance observations belong outside published sources.

## Compatibility guarantees

- The exact packages in `reference/externalconsumer.SupportedPackages` are the
  supported import surface. Other exported implementation details do not imply
  a compatibility promise.
- Patch releases add compatible symbols and security fixes. Breaking public
  contracts require an explicit new pre-v1 minor line and migration guidance.
- Published tags are immutable; a failed or superseded release gets a new tag.
- A committed local `replace` is unsupported release state. Temporary sibling
  replacements establish only local integration evidence.
- The Fiber Runtime interface now uses `AuthenticateSession` and `VerifyJWT`.
  Custom adapter fixtures must implement these methods. The root Runtime and
  PostgreSQL Runtime already implement them. See [the migration](v0.5-migration.md).

## Schema compatibility

v0.2 introduced the canonical schema baseline. `postgres.Migrate` refuses a
legacy v0.1 schema with `postgres.ErrLegacySchemaRequiresReset` and never deletes
it. Only isolated development and test databases may use the explicit confirmed
reset. Production conversion requires a separately reviewed migration.

Publication, host adoption and production deployment are separate events.
See [release verification](release-verification.md) for exact-tag distribution
checks; previous local observations do not certify a later release SHA.
