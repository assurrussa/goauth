# Compatibility policy

## Historical v0.2 release train

`goauth v0.2.1` was a backward-compatible
security and dependency update over `v0.2.0`; the supported package manifest was
unchanged. The coordinated downstream target is `goadmin v0.5.0` and
`site v0.0.30`, verified and published separately after this module release.

The previous `v0.2.0` platform verification baseline was:

| Component | Published version or branch | Verified commit |
| --- | --- | --- |
| goauth | `v0.2.0` | `cd8bb98` |
| goadmin | `v0.5.0-alpha.1` | `aab6030` |
| platformctl | `v0.3.0-alpha.1` | `42b3542` |
| site/backend, OIDC demo, second host | `tasks/goauth-v0.2-consumer` | `033ae548` |
| vaultkey | `tasks/goauth-v0.2-consumer` | `6480982` |
| gocms | `tasks/goauth-v0.2-consumer` | `8f59727` |
| gowebhooks | `tasks/goauth-v0.2-consumer` | `57abb66` |

The platformctl BOM for that historical baseline was
`cms-platform-2026-08-18.1`. Generated hosts and direct consumers pinned
`goauth v0.2.0` and `goadmin v0.5.0-alpha.1` without committed local `replace`
directives.

## Compatibility guarantees

- The exact packages in `reference/externalconsumer.SupportedPackages` are the
  supported v0.2 import surface. Exported implementation packages are not an
  implied compatibility promise.
- Patch releases may add backward-compatible symbols and security fixes. They
  do not remove supported symbols or change persisted semantics without a new
  breaking release line.
- Prerelease `goadmin` and `platformctl` consumers must use the exact versions
  in this matrix; their prerelease APIs may change in a later alpha.
- Published tags are immutable. A failed or superseded release is followed by
  a new tag; tags and history are never moved or rewritten.
- A committed local `replace` is unsupported release state. Local sibling
  replaces are allowed only as temporary development evidence.

## Schema compatibility

v0.2 is a clean schema baseline. `postgres.Migrate` refuses a detected v0.1
schema with `postgres.ErrLegacySchemaRequiresReset` and never deletes it.
Only isolated development and test databases may perform the explicit,
confirmed reset. Production data conversion requires a separately designed and
reviewed migration; it is not part of v0.2.

Publication, consumer adoption, and production deployment are separate events.
This matrix records local and published-module verification, not a production
rollout.

The current goauth tag is `v0.4.0`. This historical matrix reflects the v0.2/v0.3
baseline; see host project repositories for adoption of v0.4.0.
