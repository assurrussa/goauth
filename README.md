# goauth

`goauth` is the standalone canonical auth/RBAC module for Go host applications.
It owns transport-neutral auth behavior, canonical auth storage, canonical
migrations, and subject-based RBAC.

## Scope

`goauth` owns:

- canonical auth reads and writes for subjects, local credentials, sessions,
  refresh tokens, OIDC refresh tokens, password reset state, confirmation state,
  email-change state, and SSO identity links;
- reusable subject RBAC storage, services, use cases, cache, guards, and seeders
  under `domain/roles`;
- canonical migrations under `migrations/`;
- transport-neutral services and integration kits used by host apps and
  `goadmin`.

`goauth` does not own host HTTP UX, cookies, frontend policy, host projection
tables, or app-specific permission catalogs.

## Supported External Surface

`reference/externalconsumer` is the source of truth for supported package
imports. If a package is not listed in `SupportedPackages`, it is not stable
public API even if it exists in the module.

New consumers should prefer `integration/*`, `core`, `shared`, `migrations`, and
other packages listed in the manifest instead of direct implementation packages.

`integration/roles` lets hosts extend the canonical seed with permission
definitions and idempotent role presets. A preset may reference only permissions
from the combined seed catalog; built-in role slugs cannot be overridden.

## Commands

```sh
make
make prepare
make check
make test-race
make cover-html
make release-readiness VERSION=v0.1.7
make externalconsumer-local
make externalconsumer-published VERSION=v0.1.7
```

See [RELEASING.md](RELEASING.md) for the release checklist and
[AUTH_INVARIANTS.md](AUTH_INVARIANTS.md) for identity, projection, and subject
ID invariants.
